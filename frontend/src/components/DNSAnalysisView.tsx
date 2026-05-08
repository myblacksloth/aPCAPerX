/**
 * Dashboard DNS avanzata.
 *
 * La vista usa prima la nuova sezione `dns` prodotta dal backend: query,
 * risposte, rcode, TTL, indicatori di tunneling e correlazioni dominio -> IP
 * -> flow. Le liste esterne restano opt-in e partono solo dopo conferma.
 */
import { useMemo, useState } from 'react'
import { AlertTriangle, Database, ExternalLink, Filter, Globe2, Loader2, Search, ShieldAlert, ShieldCheck } from 'lucide-react'
import type { AnalysisResult, DNSDomainIntel, DNSQueryEntry, DNSReputationResponse } from '../types/analysis'
import { formatCount } from '../utils/format'

interface DNSAnalysisViewProps {
  result: AnalysisResult
}

function emptyDns() {
  // Oggetto fallback per report vecchi che non contengono ancora la sezione `dns`.
  return {
    stats: {
      total_queries: 0,
      total_responses: 0,
      unique_domains: 0,
      nxdomain_count: 0,
      nxdomain_ratio: 0,
      txt_query_count: 0,
      suspicious_txt_count: 0,
    },
    queries: [],
    top_domains: [],
    top_clients: [],
    top_resolvers: [],
    tunneling_indicators: [],
    flow_correlations: [],
  }
}

function answerSummary(query: DNSQueryEntry): string {
  // Produce una risposta compatta per la tabella senza perdere IP e CNAME.
  if (query.answers.length === 0) return 'n/d'
  return query.answers
    .slice(0, 3)
    .map((answer) => `${answer.record_type} ${answer.value}`)
    .join(', ')
}

function riskForQuery(query: DNSQueryEntry, intel?: DNSDomainIntel) {
  // Combina segnali locali e reputazione esterna per evidenziare query degne di nota.
  if (intel?.status === 'listed') {
    return {
      label: 'In lista',
      className: 'border-red-500/30 bg-red-500/10 text-red-100',
      icon: <ShieldAlert className="h-4 w-4 text-red-300" />,
    }
  }
  if (query.suspicious_txt || query.indicators.length > 0) {
    return {
      label: 'Sospetta',
      className: 'border-amber-500/30 bg-amber-500/10 text-amber-100',
      icon: <AlertTriangle className="h-4 w-4 text-amber-300" />,
    }
  }
  if (query.response_code_name === 'NXDOMAIN' || query.response_code_name === 'SERVFAIL') {
    return {
      label: query.response_code_name,
      className: 'border-sky-500/30 bg-sky-500/10 text-sky-100',
      icon: <Search className="h-4 w-4 text-sky-300" />,
    }
  }
  return {
    label: 'OK',
    className: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-100',
    icon: <ShieldCheck className="h-4 w-4 text-emerald-300" />,
  }
}

export default function DNSAnalysisView({ result }: DNSAnalysisViewProps) {
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [reputation, setReputation] = useState<DNSReputationResponse | null>(null)
  const [domainFilter, setDomainFilter] = useState('')
  const [clientFilter, setClientFilter] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')
  const [rcodeFilter, setRcodeFilter] = useState('all')

  const dns = result.dns ?? emptyDns()
  const externalIntel = reputation?.results ?? {}
  const recordTypes = useMemo(() => ['all', ...new Set(dns.queries.map((query) => query.record_type).sort())], [dns.queries])
  const rcodes = useMemo(
    () => ['all', ...new Set(dns.queries.map((query) => query.response_code_name ?? 'NO_RESPONSE').sort())],
    [dns.queries],
  )

  const filteredQueries = useMemo(() => {
    // Applica i filtri richiesti: dominio, client, tipo record e rcode.
    const domain = domainFilter.trim().toLowerCase()
    const client = clientFilter.trim().toLowerCase()
    return dns.queries.filter((query) => {
      if (domain && !query.query.toLowerCase().includes(domain)) return false
      if (client && !(query.client ?? '').toLowerCase().includes(client)) return false
      if (typeFilter !== 'all' && query.record_type !== typeFilter) return false
      const rcode = query.response_code_name ?? 'NO_RESPONSE'
      if (rcodeFilter !== 'all' && rcode !== rcodeFilter) return false
      return true
    })
  }, [clientFilter, dns.queries, domainFilter, rcodeFilter, typeFilter])

  const listedCount = dns.queries.filter((query) => externalIntel[query.query]?.status === 'listed').length
  const runExternalReputation = async () => {
    // La reputazione esterna invia solo domini e solo dopo conferma esplicita.
    setConfirmOpen(false)
    setLoading(true)
    setError(null)

    try {
      const domains = dns.top_domains.map((item) => item.value)
      const response = await fetch('/api/dns-reputation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domains, max_domains: 250 }),
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
              Query, risposte, rcode, TTL, NXDOMAIN ratio, TXT sospette, tunneling DNS e correlazioni con flow successivi.
            </p>
          </div>
          <button
            onClick={() => setConfirmOpen(true)}
            disabled={loading || dns.top_domains.length === 0}
            className={`flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold transition-colors ${
              loading || dns.top_domains.length === 0
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

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-6">
        {[
          ['Query', dns.stats.total_queries, 'text-white'],
          ['Risposte', dns.stats.total_responses, 'text-slate-200'],
          ['Domini', dns.stats.unique_domains, 'text-slate-200'],
          ['NXDOMAIN', `${(dns.stats.nxdomain_ratio * 100).toFixed(1)}%`, 'text-sky-300'],
          ['TXT sospette', dns.stats.suspicious_txt_count, 'text-amber-300'],
          ['In liste', listedCount, 'text-red-300'],
        ].map(([label, value, color]) => (
          <div key={label} className="rounded-lg border border-slate-700 bg-slate-800 p-4">
            <p className="text-xs text-slate-500">{label}</p>
            <p className={`mt-1 text-2xl font-bold ${color}`}>{value}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1.35fr_0.65fr]">
        <section className="card overflow-hidden">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Query DNS</h3>
              <p className="mt-0.5 text-xs text-slate-500">
                {filteredQueries.length} righe filtrate su {dns.queries.length}
              </p>
            </div>
            {reputation && (
              <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 text-xs text-emerald-100">
                Reputazione esterna attiva
              </span>
            )}
          </div>

          <div className="mb-4 grid grid-cols-1 gap-2 lg:grid-cols-[1fr_180px_150px_150px]">
            <div className="relative">
              <Filter className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
              <input
                value={domainFilter}
                onChange={(event) => setDomainFilter(event.target.value)}
                placeholder="Filtra dominio..."
                className="w-full rounded-lg border border-slate-700 bg-slate-900 py-2 pl-9 pr-3 text-sm text-slate-100 placeholder-slate-600"
              />
            </div>
            <input
              value={clientFilter}
              onChange={(event) => setClientFilter(event.target.value)}
              placeholder="Client..."
              className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder-slate-600"
            />
            <select value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)} className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200">
              {recordTypes.map((item) => <option key={item} value={item}>{item === 'all' ? 'Tipo record' : item}</option>)}
            </select>
            <select value={rcodeFilter} onChange={(event) => setRcodeFilter(event.target.value)} className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200">
              {rcodes.map((item) => <option key={item} value={item}>{item === 'all' ? 'Rcode' : item}</option>)}
            </select>
          </div>

          <div className="overflow-x-auto">
            <table className="min-w-full text-xs">
              <thead className="text-left text-slate-500">
                <tr>
                  <th className="pb-2 pr-3">Dominio</th>
                  <th className="pb-2 pr-3">Tipo</th>
                  <th className="pb-2 pr-3">Rcode</th>
                  <th className="pb-2 pr-3">Risposta</th>
                  <th className="pb-2 pr-3">TTL</th>
                  <th className="pb-2 pr-3">Client</th>
                  <th className="pb-2 pr-3">Resolver</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/70">
                {filteredQueries.slice(0, 300).map((query) => {
                  const intel = externalIntel[query.query]
                  const risk = riskForQuery(query, intel)
                  return (
                    <tr key={`${query.packet_number}-${query.query}-${query.record_type}`}>
                      <td className="py-3 pr-3 align-top">
                        <div className="font-mono text-slate-100">{query.query}</div>
                        <div className="mt-1 flex flex-wrap gap-1">
                          <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] ${risk.className}`}>
                            {risk.icon}
                            {risk.label}
                          </span>
                          {query.indicators.map((item) => (
                            <span key={item} className="rounded bg-amber-500/10 px-1.5 py-0.5 text-[11px] text-amber-100">{item}</span>
                          ))}
                          {intel?.sources.map((source) => (
                            <span key={source} className="rounded bg-emerald-500/10 px-1.5 py-0.5 text-[11px] text-emerald-100">{source}</span>
                          ))}
                        </div>
                      </td>
                      <td className="py-3 pr-3 align-top text-slate-300">{query.record_type}</td>
                      <td className="py-3 pr-3 align-top text-slate-300">{query.response_code_name ?? 'NO_RESPONSE'}</td>
                      <td className="max-w-md py-3 pr-3 align-top text-slate-400">{answerSummary(query)}</td>
                      <td className="py-3 pr-3 align-top text-slate-400">{query.ttls.length ? query.ttls.join(', ') : 'n/d'}</td>
                      <td className="py-3 pr-3 align-top font-mono text-slate-400">{query.client ?? 'n/d'}</td>
                      <td className="py-3 pr-3 align-top font-mono text-slate-400">{query.resolver ?? 'n/d'}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </section>

        <aside className="space-y-4">
          <div className="card">
            <h3 className="text-sm font-semibold text-slate-200">Domini più richiesti</h3>
            <div className="mt-3 space-y-2">
              {dns.top_domains.slice(0, 10).map((item) => (
                <div key={item.value} className="flex items-center justify-between gap-3 rounded-lg bg-slate-900/70 px-3 py-2">
                  <span className="truncate font-mono text-xs text-slate-200">{item.value}</span>
                  <span className="text-xs text-slate-500">{formatCount(item.count)}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <h3 className="text-sm font-semibold text-slate-200">Indicatori sospetti</h3>
            <div className="mt-3 space-y-2">
              {dns.tunneling_indicators.slice(0, 8).map((item) => (
                <div key={item.domain} className="rounded-lg border border-amber-500/20 bg-amber-500/10 p-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate font-mono text-xs text-amber-100">{item.domain}</span>
                    <span className="text-xs font-semibold text-amber-200">{item.score}/100</span>
                  </div>
                  <p className="mt-1 text-xs text-amber-100/80">{item.reasons.join(' | ')}</p>
                </div>
              ))}
              {dns.tunneling_indicators.length === 0 && (
                <p className="text-xs text-slate-500">Nessun indicatore DNS tunneling evidente.</p>
              )}
            </div>
          </div>

          <div className="card">
            <h3 className="text-sm font-semibold text-slate-200">Dominio → IP → Flow</h3>
            <div className="mt-3 space-y-2">
              {dns.flow_correlations.slice(0, 8).map((item) => (
                <div key={`${item.domain}-${item.answer_ip}`} className="rounded-lg bg-slate-900/70 p-3">
                  <p className="truncate font-mono text-xs text-slate-200">{item.domain}</p>
                  <p className="mt-1 text-xs text-slate-500">{item.answer_ip} · {item.flow_ids.length} flow</p>
                </div>
              ))}
              {dns.flow_correlations.length === 0 && (
                <p className="text-xs text-slate-500">Nessuna correlazione con flow successivi rilevata.</p>
              )}
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
                  L'analisi DNS locale, inclusi rcode, TTL, tunneling e correlazioni con flow, non invia dati all'esterno.
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
              <button onClick={() => setConfirmOpen(false)} className="rounded-lg bg-slate-700 px-4 py-2 text-sm text-slate-200 hover:bg-slate-600">
                Annulla
              </button>
              <button onClick={runExternalReputation} className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-white hover:bg-emerald-400">
                Confermo e controlla
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
