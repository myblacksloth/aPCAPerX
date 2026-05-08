/**
 * Dashboard dedicata alle sole richieste DNS.
 *
 * La vista lavora prima in locale sui pacchetti gia estratti dal PCAP:
 * identifica query, client, resolver, frequenze e domini sospetti con regole
 * euristiche. Solo se l'utente conferma il popup invia i domini a liste
 * esterne aperte per ottenere reputazione aggiuntiva.
 */
import { useMemo, useState } from 'react'
import { AlertTriangle, Database, ExternalLink, Globe2, Loader2, Search, ShieldAlert, ShieldCheck } from 'lucide-react'
import type { AnalysisResult, DNSDomainIntel, DNSReputationResponse, PacketEntry } from '../types/analysis'
import { formatCount } from '../utils/format'

interface DNSAnalysisViewProps {
  result: AnalysisResult
}

interface DNSQueryRow {
  domain: string
  client: string
  resolver: string
  timestamp: string
  packetNumber: number
  qtype: string
}

interface DNSDomainSummary {
  domain: string
  count: number
  clients: Set<string>
  resolvers: Set<string>
  firstSeen: string
  lastSeen: string
  localCategories: Set<string>
  localReasons: string[]
}

const TRACKING_TOKENS = [
  'track', 'tracker', 'tracking', 'analytics', 'metric', 'metrics', 'telemetry',
  'pixel', 'beacon', 'doubleclick', 'googlesyndication', 'adservice', 'adsystem',
  'facebook', 'segment', 'mixpanel', 'amplitude',
]

const RISK_TOKENS = [
  'malware', 'phish', 'phishing', 'scam', 'botnet', 'c2', 'command', 'payload',
  'download', 'miner', 'crypto', 'pastebin', 'duckdns', 'no-ip', 'hopto',
]

const SUSPICIOUS_TLDS = new Set(['zip', 'mov', 'top', 'xyz', 'click', 'quest', 'country', 'gq', 'tk', 'ml', 'cf'])

function normalizeDomain(value: string): string | null {
  // Pulisce il dominio estratto dal campo info o dai layer DNS.
  const cleaned = value.trim().toLowerCase().replace(/\.$/, '')
  if (!cleaned || cleaned.includes(' ') || !cleaned.includes('.')) return null
  return cleaned
}

function layerField(packet: PacketEntry, names: string[]): string | null {
  // Cerca un campo DNS nei layer Scapy serializzati dal backend.
  const wanted = new Set(names.map((name) => name.toLowerCase()))
  for (const layer of packet.layers ?? []) {
    for (const field of layer.fields ?? []) {
      if (wanted.has(field.name.toLowerCase()) && field.value) {
        return field.value
      }
    }
  }
  return null
}

function extractDomain(packet: PacketEntry): string | null {
  // Prima usa l'info sintetico, poi tenta il campo qname del layer DNSQR.
  const infoMatch = packet.info.match(/^DNS\s+Query:\s+(.+)$/i)
  if (infoMatch) return normalizeDomain(infoMatch[1])

  const qname = layerField(packet, ['qname'])
  if (qname) return normalizeDomain(qname.replace(/^b['"]|['"]$/g, ''))

  return null
}

function extractQtype(packet: PacketEntry): string {
  // Il tipo query non e sempre presente nel sommario, quindi fallback su "A/AAAA/altro".
  const qtype = layerField(packet, ['qtype'])
  return qtype ?? 'n/d'
}

function extractDnsQueries(packets: PacketEntry[]): DNSQueryRow[] {
  // Estrae solo richieste DNS; le risposte vengono escluse dalla dashboard principale.
  return packets
    .filter((packet) => packet.protocol === 'DNS' && /^DNS\s+Query:/i.test(packet.info))
    .map((packet) => {
      const domain = extractDomain(packet)
      if (!domain) return null
      return {
        domain,
        client: packet.src_ip ?? 'n/d',
        resolver: packet.dst_ip ?? 'n/d',
        timestamp: packet.timestamp,
        packetNumber: packet.number,
        qtype: extractQtype(packet),
      }
    })
    .filter((row): row is DNSQueryRow => row !== null)
}

function classifyLocal(domain: string): { categories: string[]; reasons: string[] } {
  // Regole locali rapide: non chiamano servizi esterni e servono per triage immediato.
  const labels = new Set<string>()
  const reasons: string[] = []
  const labelsFromTokens = (tokens: string[], category: string, reason: string) => {
    const hit = tokens.find((token) => domain.includes(token))
    if (hit) {
      labels.add(category)
      reasons.push(`${reason}: "${hit}"`)
    }
  }

  labelsFromTokens(TRACKING_TOKENS, 'tracking/ads', 'Pattern tipico di tracking o advertising')
  labelsFromTokens(RISK_TOKENS, 'rischio', 'Pattern spesso associato a domini rischiosi')

  const parts = domain.split('.')
  const tld = parts[parts.length - 1]
  if (SUSPICIOUS_TLDS.has(tld)) {
    labels.add('tld sensibile')
    reasons.push(`TLD spesso abusato o da verificare: .${tld}`)
  }

  if (domain.length > 55 || parts.some((part) => part.length > 24)) {
    labels.add('anomalia')
    reasons.push('Dominio o label molto lungo: possibile DGA, tracking parametrico o CDN opaco')
  }

  if (/\d{4,}/.test(domain) || /[a-z]{8,}\d{3,}/.test(domain)) {
    labels.add('anomalia')
    reasons.push('Sequenze alfanumeriche insolite nel dominio')
  }

  return { categories: [...labels], reasons }
}

function summarizeDomains(queries: DNSQueryRow[], intel: Record<string, DNSDomainIntel>): DNSDomainSummary[] {
  // Aggrega le query per dominio e fonde classificazione locale + reputazione esterna.
  const map = new Map<string, DNSDomainSummary>()

  for (const query of queries) {
    const current = map.get(query.domain) ?? {
      domain: query.domain,
      count: 0,
      clients: new Set<string>(),
      resolvers: new Set<string>(),
      firstSeen: query.timestamp,
      lastSeen: query.timestamp,
      localCategories: new Set<string>(),
      localReasons: [],
    }

    current.count += 1
    current.clients.add(query.client)
    current.resolvers.add(query.resolver)
    current.lastSeen = query.timestamp

    const local = classifyLocal(query.domain)
    local.categories.forEach((category) => current.localCategories.add(category))
    local.reasons.forEach((reason) => {
      if (!current.localReasons.includes(reason)) current.localReasons.push(reason)
    })

    const external = intel[query.domain]
    if (external?.status === 'listed') {
      external.categories.forEach((category) => current.localCategories.add(category))
    }

    map.set(query.domain, current)
  }

  return [...map.values()].sort((a, b) => {
    const scoreA = (intel[a.domain]?.score ?? 0) + a.localCategories.size * 20 + a.count
    const scoreB = (intel[b.domain]?.score ?? 0) + b.localCategories.size * 20 + b.count
    return scoreB - scoreA
  })
}

function riskLevel(summary: DNSDomainSummary, intel?: DNSDomainIntel) {
  // Calcola severita finale usando reputazione esterna, categorie locali e frequenza.
  const score = Math.max(intel?.score ?? 0, summary.localCategories.size * 22 + Math.min(summary.count, 25))
  if (score >= 80) return { label: 'Bloccabile', className: 'border-red-500/30 bg-red-500/10 text-red-100', icon: <ShieldAlert className="h-4 w-4 text-red-300" /> }
  if (score >= 45) return { label: 'Da verificare', className: 'border-amber-500/30 bg-amber-500/10 text-amber-100', icon: <AlertTriangle className="h-4 w-4 text-amber-300" /> }
  if (score >= 20) return { label: 'Osservato', className: 'border-sky-500/30 bg-sky-500/10 text-sky-100', icon: <Search className="h-4 w-4 text-sky-300" /> }
  return { label: 'Pulito', className: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-100', icon: <ShieldCheck className="h-4 w-4 text-emerald-300" /> }
}

export default function DNSAnalysisView({ result }: DNSAnalysisViewProps) {
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [reputation, setReputation] = useState<DNSReputationResponse | null>(null)

  const queries = useMemo(() => extractDnsQueries(result.packets), [result.packets])
  const externalIntel = reputation?.results ?? {}
  const summaries = useMemo(() => summarizeDomains(queries, externalIntel), [queries, externalIntel])
  const listedCount = summaries.filter((item) => externalIntel[item.domain]?.status === 'listed').length
  const notableCount = summaries.filter((item) => item.localCategories.size > 0 || externalIntel[item.domain]?.status === 'listed').length
  const clients = new Set(queries.map((query) => query.client)).size
  const resolvers = new Set(queries.map((query) => query.resolver)).size

  const runExternalReputation = async () => {
    // Solo questo handler invia domini a servizi esterni, dopo consenso nel popup.
    setConfirmOpen(false)
    setLoading(true)
    setError(null)

    try {
      const response = await fetch('/api/dns-reputation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domains: summaries.map((item) => item.domain), max_domains: 250 }),
      })

      if (!response.ok) {
        const data = await response.json().catch(() => ({}))
        throw new Error(data.detail ?? `Errore ${response.status}: ${response.statusText}`)
      }

      const payload: DNSReputationResponse = await response.json()
      setReputation(payload)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Errore sconosciuto durante l'analisi DNS esterna")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="card">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-slate-200">DNS</h2>
            <p className="mt-1 max-w-3xl text-xs text-slate-500">
              Dashboard in stile AdGuard per richieste DNS, domini frequenti, client, resolver e endpoint di tracking o rischio.
            </p>
          </div>
          <button
            onClick={() => setConfirmOpen(true)}
            disabled={loading || summaries.length === 0}
            className={`flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold transition-colors ${
              loading || summaries.length === 0
                ? 'cursor-not-allowed bg-slate-700 text-slate-400'
                : 'bg-emerald-500/90 text-white hover:bg-emerald-500'
            }`}
          >
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Database className="h-4 w-4" />}
            {loading ? 'Controllo liste...' : 'Controlla liste esterne'}
          </button>
        </div>

        {error && (
          <div className="mt-4 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-100">
            {error}
          </div>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        {[
          ['Query DNS', queries.length, 'text-white'],
          ['Domini', summaries.length, 'text-slate-200'],
          ['Notevoli', notableCount, 'text-amber-300'],
          ['In liste', listedCount, 'text-red-300'],
          ['Client/Resolver', `${clients}/${resolvers}`, 'text-emerald-300'],
        ].map(([label, value, color]) => (
          <div key={label} className="rounded-lg border border-slate-700 bg-slate-800 p-4">
            <p className="text-xs text-slate-500">{label}</p>
            <p className={`mt-1 text-2xl font-bold ${color}`}>{value}</p>
          </div>
        ))}
      </div>

      {queries.length === 0 ? (
        <div className="card text-sm text-slate-300">
          Nessuna richiesta DNS rilevata nei pacchetti disponibili.
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1.35fr_0.65fr]">
          <section className="card overflow-hidden">
            <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-semibold text-slate-200">Domini richiesti</h3>
                <p className="mt-0.5 text-xs text-slate-500">Ordinati per rischio stimato, match esterni e frequenza</p>
              </div>
              {reputation && (
                <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 text-xs text-emerald-100">
                  Reputazione esterna attiva
                </span>
              )}
            </div>

            <div className="overflow-x-auto">
              <table className="min-w-full text-sm">
                <thead className="text-left text-xs text-slate-500">
                  <tr>
                    <th className="pb-2 pr-4">Dominio</th>
                    <th className="pb-2 pr-4">Stato</th>
                    <th className="pb-2 pr-4">Query</th>
                    <th className="pb-2 pr-4">Client</th>
                    <th className="pb-2 pr-4">Resolver</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/70">
                  {summaries.slice(0, 120).map((summary) => {
                    const intel = externalIntel[summary.domain]
                    const level = riskLevel(summary, intel)
                    const categories = [...summary.localCategories]
                    return (
                      <tr key={summary.domain}>
                        <td className="py-3 pr-4 align-top">
                          <div className="font-mono text-xs text-slate-100">{summary.domain}</div>
                          <div className="mt-1 flex flex-wrap gap-1">
                            {categories.slice(0, 4).map((category) => (
                              <span key={category} className="rounded bg-slate-700 px-1.5 py-0.5 text-[11px] text-slate-300">
                                {category}
                              </span>
                            ))}
                            {intel?.sources.map((source) => (
                              <span key={source} className="rounded border border-emerald-500/30 bg-emerald-500/10 px-1.5 py-0.5 text-[11px] text-emerald-100">
                                {source}
                              </span>
                            ))}
                          </div>
                          {(summary.localReasons.length > 0 || (intel?.matched_rules.length ?? 0) > 0) && (
                            <div className="mt-1 text-[11px] text-slate-500">
                              {[...summary.localReasons, ...(intel?.matched_rules ?? [])].slice(0, 2).join(' | ')}
                            </div>
                          )}
                        </td>
                        <td className="py-3 pr-4 align-top">
                          <span className={`inline-flex items-center gap-1 rounded border px-2 py-1 text-xs font-semibold ${level.className}`}>
                            {level.icon}
                            {level.label}
                          </span>
                        </td>
                        <td className="py-3 pr-4 align-top text-slate-300">{formatCount(summary.count)}</td>
                        <td className="py-3 pr-4 align-top text-xs text-slate-400">{summary.clients.size}</td>
                        <td className="py-3 pr-4 align-top text-xs text-slate-400">{[...summary.resolvers].slice(0, 2).join(', ')}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </section>

          <aside className="space-y-4">
            <div className="card">
              <h3 className="text-sm font-semibold text-slate-200">Resolver DNS</h3>
              <div className="mt-3 space-y-2">
                {[...queries.reduce((map, query) => map.set(query.resolver, (map.get(query.resolver) ?? 0) + 1), new Map<string, number>()).entries()]
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 8)
                  .map(([resolver, count]) => (
                    <div key={resolver} className="flex items-center justify-between rounded-lg bg-slate-900/70 px-3 py-2">
                      <span className="font-mono text-xs text-slate-200">{resolver}</span>
                      <span className="text-xs text-slate-500">{formatCount(count)}</span>
                    </div>
                  ))}
              </div>
            </div>

            <div className="card">
              <h3 className="text-sm font-semibold text-slate-200">Client più attivi</h3>
              <div className="mt-3 space-y-2">
                {[...queries.reduce((map, query) => map.set(query.client, (map.get(query.client) ?? 0) + 1), new Map<string, number>()).entries()]
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 8)
                  .map(([client, count]) => (
                    <div key={client} className="flex items-center justify-between rounded-lg bg-slate-900/70 px-3 py-2">
                      <span className="font-mono text-xs text-slate-200">{client}</span>
                      <span className="text-xs text-slate-500">{formatCount(count)}</span>
                    </div>
                  ))}
              </div>
            </div>

            {reputation && (
              <div className="card">
                <h3 className="text-sm font-semibold text-slate-200">Fonti esterne</h3>
                <div className="mt-3 space-y-2">
                  {reputation.sources.map((source) => (
                    <div key={source.source} className="rounded-lg bg-slate-900/70 p-3">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-semibold text-slate-200">{source.source}</span>
                        <span className="rounded bg-slate-700 px-2 py-0.5 text-[11px] text-slate-300">{source.status}</span>
                      </div>
                      <p className="mt-1 text-xs text-slate-500">{source.detail}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </aside>
        </div>
      )}

      {confirmOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 px-4">
          <div className="w-full max-w-lg rounded-xl border border-slate-700 bg-slate-900 p-5 shadow-2xl">
            <div className="flex items-start gap-3">
              <Globe2 className="mt-0.5 h-5 w-5 flex-shrink-0 text-emerald-300" />
              <div>
                <h3 className="text-base font-semibold text-white">Conferma controllo DNS esterno</h3>
                <p className="mt-2 text-sm text-slate-300">
                  Verranno inviati i domini DNS osservati nel PCAP a liste e servizi esterni aperti:
                  AdGuard DNS filter, StevenBlack hosts e URLhaus se configurato con Auth-Key sul backend.
                </p>
                <p className="mt-2 text-xs text-slate-500">
                  Nessuna query esterna viene eseguita prima di questa conferma. I risultati servono solo a classificare tracking, ads, malware e domini sospetti.
                </p>
                <a
                  href="https://github.com/AdguardTeam/AdGuardSDNSFilter"
                  target="_blank"
                  rel="noreferrer"
                  className="mt-3 inline-flex items-center gap-1 text-xs text-brand-300 hover:text-brand-200"
                >
                  Documentazione AdGuard DNS filter <ExternalLink className="h-3 w-3" />
                </a>
              </div>
            </div>

            <div className="mt-5 flex justify-end gap-2">
              <button
                onClick={() => setConfirmOpen(false)}
                className="rounded-lg bg-slate-700 px-4 py-2 text-sm text-slate-200 hover:bg-slate-600"
              >
                Annulla
              </button>
              <button
                onClick={runExternalReputation}
                className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-white hover:bg-emerald-400"
              >
                Confermo e controlla
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
