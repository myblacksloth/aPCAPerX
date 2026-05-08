/**
 * Vista dettaglio host/IP.
 *
 * La vista usa la sezione `hosts` prodotta dal backend. Per compatibilità con
 * risultati vecchi, ricostruisce un profilo minimo dai pacchetti quando `hosts`
 * non esiste ancora. Le informazioni ASN/geo vengono lette da `external_ip_info`
 * quando l'utente ha eseguito l'arricchimento esterno.
 */
import { useEffect, useMemo, useState } from 'react'
import { ChevronDown, ChevronRight, Globe2, Monitor, Search, Server, ShieldAlert } from 'lucide-react'
import type { AnalysisResult, HostAnalysisResult, HostEntry, IPExternalInfo } from '../types/analysis'
import { formatBytes, formatCount } from '../utils/format'

interface HostsViewProps {
  result: AnalysisResult
  selectedHostIp?: string | null
}

function emptyHosts(): HostAnalysisResult {
  // Fallback neutro per report privi della nuova sezione `hosts`.
  return { total_hosts: 0, hosts: [] }
}

function fallbackHosts(result: AnalysisResult): HostAnalysisResult {
  // Ricostruzione minima lato frontend per mantenere compatibilità con JSON vecchi.
  const map = new Map<string, HostEntry>()
  const get = (ip: string): HostEntry => {
    const current = map.get(ip)
    if (current) return current
    const created: HostEntry = {
      ip,
      role: 'ignoto',
      is_private: /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|127\.|169\.254\.)/.test(ip),
      hostnames: [],
      protocols: [],
      contacted_ports: [],
      exposed_ports: [],
      bytes_sent: 0,
      bytes_received: 0,
      packets_sent: 0,
      packets_received: 0,
      flow_ids: [],
      dns_queries: [],
      sni_hosts: [],
      http_hosts: [],
      findings: [],
      timeline: [],
    }
    map.set(ip, created)
    return created
  }

  for (const packet of result.packets) {
    if (packet.src_ip) {
      const host = get(packet.src_ip)
      host.packets_sent += 1
      host.bytes_sent += packet.length
      if (!host.protocols.includes(packet.protocol)) host.protocols.push(packet.protocol)
    }
    if (packet.dst_ip) {
      const host = get(packet.dst_ip)
      host.packets_received += 1
      host.bytes_received += packet.length
      if (!host.protocols.includes(packet.protocol)) host.protocols.push(packet.protocol)
    }
  }

  const hosts = [...map.values()].sort((a, b) => (b.bytes_sent + b.bytes_received) - (a.bytes_sent + a.bytes_received))
  return { total_hosts: hosts.length, hosts }
}

function externalForHost(result: AnalysisResult, ip: string): IPExternalInfo | null {
  // Recupera ASN/geo da external_ip_info o dalle top list gia fuse dopo enrichment.
  return (
    result.external_ip_info?.[ip]
    ?? result.top_src_ips.find((entry) => entry.ip === ip)?.external
    ?? result.top_dst_ips.find((entry) => entry.ip === ip)?.external
    ?? null
  )
}

function roleIcon(role: string) {
  // Icona coerente con il ruolo stimato dal backend.
  if (role === 'server') return <Server className="h-4 w-4 text-sky-300" />
  if (role === 'misto') return <Globe2 className="h-4 w-4 text-brand-300" />
  return <Monitor className="h-4 w-4 text-slate-300" />
}

function chips(values: Array<string | number>, empty = 'n/d') {
  // Render compatto per liste di protocolli, porte e hostname.
  if (values.length === 0) return <span className="text-xs text-slate-600">{empty}</span>
  return (
    <div className="flex flex-wrap gap-1.5">
      {values.slice(0, 20).map((value) => (
        <span key={value} className="rounded bg-slate-700 px-2 py-1 text-[11px] text-slate-200">{value}</span>
      ))}
      {values.length > 20 && <span className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-500">+{values.length - 20}</span>}
    </div>
  )
}

function HostDetails({ host, external }: { host: HostEntry; external: IPExternalInfo | null }) {
  const totalBytes = host.bytes_sent + host.bytes_received
  const flowPreview = host.flow_ids.slice(0, 18)

  return (
    <div className="border-t border-slate-700/60 bg-slate-900/35 px-4 py-4">
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <section className="rounded-lg border border-slate-700 bg-slate-800/60 p-4">
          <h4 className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-500">Identità</h4>
          <div className="space-y-3 text-xs text-slate-300">
            <p><span className="text-slate-500">Tipo:</span> {host.is_private ? 'privato/locale' : 'pubblico'}</p>
            <p><span className="text-slate-500">Traffico totale:</span> {formatBytes(totalBytes)}</p>
            <div>
              <p className="mb-1 text-slate-500">Hostname DNS/DHCP/NetBIOS/tool esterni</p>
              {chips([
                ...host.hostnames,
                ...(external?.reverse_dns ? [external.reverse_dns] : []),
              ])}
            </div>
            {external?.status === 'enriched' && (
              <div className="rounded-lg border border-brand-500/20 bg-brand-500/10 p-3">
                <p className="font-semibold text-brand-100">ASN/Geo</p>
                <p className="mt-1 text-slate-300">{external.asn ? `AS${external.asn}` : 'ASN n/d'} {external.as_name ? `- ${external.as_name}` : ''}</p>
                <p className="text-slate-400">{[external.city, external.region, external.country].filter(Boolean).join(', ') || 'Località n/d'}</p>
                {(external.lat !== null && external.lon !== null) && (
                  <p className="text-slate-500">Coordinate: {external.lat}, {external.lon}</p>
                )}
              </div>
            )}
          </div>
        </section>

        <section className="rounded-lg border border-slate-700 bg-slate-800/60 p-4">
          <h4 className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-500">Rete</h4>
          <div className="space-y-3">
            <div>
              <p className="mb-1 text-xs text-slate-500">Protocolli</p>
              {chips(host.protocols)}
            </div>
            <div>
              <p className="mb-1 text-xs text-slate-500">Porte contattate</p>
              {chips(host.contacted_ports)}
            </div>
            <div>
              <p className="mb-1 text-xs text-slate-500">Porte esposte/osservate</p>
              {chips(host.exposed_ports)}
            </div>
            <div>
              <p className="mb-1 text-xs text-slate-500">Flow collegati</p>
              {chips(flowPreview, 'nessun flow')}
            </div>
          </div>
        </section>

        <section className="rounded-lg border border-slate-700 bg-slate-800/60 p-4">
          <h4 className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-500">Applicativo e sicurezza</h4>
          <div className="space-y-3">
            <div>
              <p className="mb-1 text-xs text-slate-500">DNS query generate</p>
              {chips(host.dns_queries, 'nessuna query')}
            </div>
            <div>
              <p className="mb-1 text-xs text-slate-500">SNI osservati</p>
              {chips(host.sni_hosts, 'nessun SNI')}
            </div>
            <div>
              <p className="mb-1 text-xs text-slate-500">HTTP host osservati</p>
              {chips(host.http_hosts, 'nessun host HTTP')}
            </div>
            <div>
              <p className="mb-1 text-xs text-slate-500">Finding associati</p>
              {host.findings.length === 0 ? (
                <span className="text-xs text-slate-600">nessun finding</span>
              ) : (
                <div className="space-y-1">
                  {host.findings.slice(0, 8).map((finding) => (
                    <div key={finding} className="flex items-start gap-2 rounded bg-amber-500/10 px-2 py-1 text-xs text-amber-100">
                      <ShieldAlert className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" />
                      <span>{finding}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </section>
      </div>

      <section className="mt-4 rounded-lg border border-slate-700 bg-slate-800/60 p-4">
        <h4 className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-500">Timeline attività</h4>
        {host.timeline.length === 0 ? (
          <p className="text-xs text-slate-600">Timeline non disponibile per questo risultato.</p>
        ) : (
          <div className="space-y-2">
            {host.timeline.slice(0, 80).map((point) => {
              const sent = point.bytes_sent
              const received = point.bytes_received
              const total = Math.max(sent + received, 1)
              return (
                <div key={point.timestamp} className="grid grid-cols-[80px_1fr_160px] items-center gap-3 text-xs">
                  <span className="font-mono text-slate-500">{point.timestamp}</span>
                  <div className="flex h-2 overflow-hidden rounded bg-slate-700">
                    <div className="bg-brand-400" style={{ width: `${(sent / total) * 100}%` }} />
                    <div className="bg-emerald-400" style={{ width: `${(received / total) * 100}%` }} />
                  </div>
                  <span className="text-right text-slate-500">
                    ↑ {formatBytes(sent)} · ↓ {formatBytes(received)}
                  </span>
                </div>
              )
            })}
          </div>
        )}
      </section>
    </div>
  )
}

export default function HostsView({ result, selectedHostIp }: HostsViewProps) {
  const [query, setQuery] = useState('')
  const [roleFilter, setRoleFilter] = useState('all')
  const [expanded, setExpanded] = useState<Set<string>>(new Set())

  const hosts = result.hosts ?? (result.packets.length ? fallbackHosts(result) : emptyHosts())
  const filtered = useMemo(() => {
    // Filtra per IP, hostname, SNI, HTTP host e ruolo stimato.
    const text = query.trim().toLowerCase()
    return hosts.hosts.filter((host) => {
      if (roleFilter !== 'all' && host.role !== roleFilter) return false
      if (!text) return true
      const haystack = [
        host.ip,
        ...host.hostnames,
        ...host.sni_hosts,
        ...host.http_hosts,
        ...host.dns_queries,
      ].join(' ').toLowerCase()
      return haystack.includes(text)
    })
  }, [hosts.hosts, query, roleFilter])

  const toggle = (ip: string) => {
    // Mantiene le sezioni collapsable come nella tab Tracce avanzate.
    setExpanded((current) => {
      const next = new Set(current)
      if (next.has(ip)) next.delete(ip)
      else next.add(ip)
      return next
    })
  }

  useEffect(() => {
    // Quando l'utente clicca un IP da altre viste, apre la relativa sezione host.
    if (!selectedHostIp) return
    setQuery(selectedHostIp)
    setRoleFilter('all')
    setExpanded((current) => new Set([...current, selectedHostIp]))
  }, [selectedHostIp])

  return (
    <div className="space-y-4">
      <div className="card">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-slate-200">Hosts</h2>
            <p className="mt-1 max-w-3xl text-xs text-slate-500">
              Vista aggregata per IP: ruolo, traffico, flow, DNS, SNI, HTTP host, finding e dati esterni quando disponibili.
            </p>
          </div>
          <div className="text-right text-xs text-slate-500">
            <strong className="text-slate-200">{formatCount(hosts.total_hosts)}</strong> host osservati
          </div>
        </div>
      </div>

      <div className="card">
        <div className="grid grid-cols-1 gap-2 md:grid-cols-[1fr_180px]">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Cerca IP, hostname, SNI, HTTP host o query DNS..."
              className="w-full rounded-lg border border-slate-700 bg-slate-900 py-2 pl-9 pr-3 text-sm text-slate-100 placeholder-slate-600"
            />
          </div>
          <select value={roleFilter} onChange={(event) => setRoleFilter(event.target.value)} className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200">
            <option value="all">Tutti i ruoli</option>
            <option value="client">Client</option>
            <option value="server">Server</option>
            <option value="misto">Misto</option>
            <option value="ignoto">Ignoto</option>
          </select>
        </div>
      </div>

      <div className="space-y-2">
        {filtered.slice(0, 500).map((host) => {
          const isOpen = expanded.has(host.ip)
          const external = externalForHost(result, host.ip)
          const totalBytes = host.bytes_sent + host.bytes_received
          return (
            <section key={host.ip} className="overflow-hidden rounded-lg border border-slate-700 bg-slate-800">
              <button
                type="button"
                onClick={() => toggle(host.ip)}
                className="grid w-full grid-cols-[24px_minmax(0,1fr)] items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-slate-700/45 lg:grid-cols-[24px_minmax(220px,1fr)_130px_160px_190px]"
              >
                {isOpen ? <ChevronDown className="h-4 w-4 text-slate-400" /> : <ChevronRight className="h-4 w-4 text-slate-400" />}
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    {roleIcon(host.role)}
                    <span className="font-mono text-sm font-semibold text-slate-100">{host.ip}</span>
                    <span className="rounded bg-slate-700 px-2 py-0.5 text-[11px] text-slate-300">{host.role}</span>
                    <span className={`rounded px-2 py-0.5 text-[11px] ${host.is_private ? 'bg-sky-500/10 text-sky-200' : 'bg-emerald-500/10 text-emerald-200'}`}>
                      {host.is_private ? 'privato' : 'pubblico'}
                    </span>
                  </div>
                  <p className="mt-1 truncate text-xs text-slate-500">
                    {[...host.hostnames, ...host.sni_hosts, ...host.http_hosts].slice(0, 4).join(', ') || external?.reverse_dns || 'hostname n/d'}
                  </p>
                </div>
                <div className="text-xs text-slate-400">
                  <div>↑ {formatBytes(host.bytes_sent)}</div>
                  <div>↓ {formatBytes(host.bytes_received)}</div>
                </div>
                <div className="text-xs text-slate-400">
                  <div>{formatCount(host.packets_sent)} pkt inviati</div>
                  <div>{formatCount(host.packets_received)} pkt ricevuti</div>
                </div>
                <div className="min-w-0 text-xs text-slate-500">
                  <div className="truncate">{external?.asn ? `AS${external.asn}` : 'ASN n/d'} {external?.country_code ? `· ${external.country_code}` : ''}</div>
                  <div className="truncate">{formatBytes(totalBytes)} totali · {host.flow_ids.length} flow</div>
                </div>
              </button>
              {isOpen && <HostDetails host={host} external={external} />}
            </section>
          )
        })}

        {filtered.length === 0 && (
          <p className="rounded-lg border border-slate-700 bg-slate-800 px-4 py-8 text-center text-sm text-slate-500">
            Nessun host corrisponde ai filtri.
          </p>
        )}
      </div>
    </div>
  )
}
