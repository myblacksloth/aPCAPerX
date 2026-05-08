/**
 * Vista HTTP analysis.
 *
 * Mostra solo metadati HTTP in chiaro già estratti dal backend. Non effettua
 * chiamate esterne e non prova a interpretare HTTPS/TLS.
 */
import { useMemo, useState } from 'react'
import { AlertTriangle, FileText, Filter, Globe2, ShieldCheck } from 'lucide-react'
import type { AnalysisResult, HTTPAnalysisResult, HTTPRequestEntry } from '../types/analysis'
import { formatCount } from '../utils/format'

interface HTTPAnalysisViewProps {
  result: AnalysisResult
}

function emptyHttp(): HTTPAnalysisResult {
  // Fallback per risultati vecchi che non contengono ancora la sezione `http`.
  return {
    stats: {
      total_requests: 0,
      total_responses: 0,
      correlated_responses: 0,
      partial_requests: 0,
      partial_responses: 0,
      unique_hosts: 0,
    },
    requests: [],
    top_hosts: [],
    top_user_agents: [],
    limitations: [],
  }
}

function endpoint(ip: string | null, port: number | null) {
  // Formatta endpoint con porta quando disponibile.
  return ip ? `${ip}${port ? `:${port}` : ''}` : 'n/d'
}

function statusBadge(request: HTTPRequestEntry) {
  // Colora lo stato HTTP con una semantica semplice: 2xx ok, 3xx redirect, 4xx/5xx errore.
  const status = request.response_status_code
  if (!status) {
    return <span className="rounded border border-slate-600 bg-slate-700/40 px-2 py-1 text-[11px] text-slate-300">No response</span>
  }
  if (status >= 500) return <span className="rounded border border-red-500/30 bg-red-500/10 px-2 py-1 text-[11px] text-red-100">{status}</span>
  if (status >= 400) return <span className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-1 text-[11px] text-amber-100">{status}</span>
  if (status >= 300) return <span className="rounded border border-sky-500/30 bg-sky-500/10 px-2 py-1 text-[11px] text-sky-100">{status}</span>
  return <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 text-[11px] text-emerald-100">{status}</span>
}

export default function HTTPAnalysisView({ result }: HTTPAnalysisViewProps) {
  const http = result.http ?? emptyHttp()
  const [hostFilter, setHostFilter] = useState('')
  const [methodFilter, setMethodFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')
  const [uaFilter, setUaFilter] = useState('')

  const methods = useMemo(() => ['all', ...new Set(http.requests.map((request) => request.method).sort())], [http.requests])
  const statuses = useMemo(() => {
    // Include anche NO_RESPONSE per filtrare richieste senza risposta correlata.
    const values = http.requests.map((request) => request.response_status_code?.toString() ?? 'NO_RESPONSE')
    return ['all', ...new Set(values.sort())]
  }, [http.requests])

  const filtered = useMemo(() => {
    // Filtra per host, metodo, status code e User-Agent come richiesto.
    const host = hostFilter.trim().toLowerCase()
    const ua = uaFilter.trim().toLowerCase()
    return http.requests.filter((request) => {
      if (host && !(request.host ?? '').toLowerCase().includes(host)) return false
      if (methodFilter !== 'all' && request.method !== methodFilter) return false
      const status = request.response_status_code?.toString() ?? 'NO_RESPONSE'
      if (statusFilter !== 'all' && status !== statusFilter) return false
      if (ua && !(request.user_agent ?? '').toLowerCase().includes(ua)) return false
      return true
    })
  }, [hostFilter, http.requests, methodFilter, statusFilter, uaFilter])

  return (
    <div className="space-y-4">
      <div className="card">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-slate-200">HTTP analysis</h2>
            <p className="mt-1 max-w-3xl text-xs text-slate-500">
              Metadati HTTP estratti solo da traffico in chiaro. HTTPS/TLS non viene decifrato.
            </p>
          </div>
          <div className="flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-100">
            <ShieldCheck className="h-4 w-4" />
            Privacy by default
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-6">
        {[
          ['Richieste', http.stats.total_requests, 'text-white'],
          ['Risposte', http.stats.total_responses, 'text-slate-200'],
          ['Correlate', http.stats.correlated_responses, 'text-emerald-300'],
          ['Host', http.stats.unique_hosts, 'text-sky-300'],
          ['Req parziali', http.stats.partial_requests, 'text-amber-300'],
          ['Resp parziali', http.stats.partial_responses, 'text-amber-300'],
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
              <h3 className="text-sm font-semibold text-slate-200">Richieste e risposte correlate</h3>
              <p className="mt-0.5 text-xs text-slate-500">{filtered.length} righe filtrate su {http.requests.length}</p>
            </div>
          </div>

          <div className="mb-4 grid grid-cols-1 gap-2 lg:grid-cols-[1fr_150px_150px_1fr]">
            <div className="relative">
              <Filter className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
              <input
                value={hostFilter}
                onChange={(event) => setHostFilter(event.target.value)}
                placeholder="Filtra host..."
                className="w-full rounded-lg border border-slate-700 bg-slate-900 py-2 pl-9 pr-3 text-sm text-slate-100 placeholder-slate-600"
              />
            </div>
            <select value={methodFilter} onChange={(event) => setMethodFilter(event.target.value)} className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200">
              {methods.map((item) => <option key={item} value={item}>{item === 'all' ? 'Metodo' : item}</option>)}
            </select>
            <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)} className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200">
              {statuses.map((item) => <option key={item} value={item}>{item === 'all' ? 'Status' : item}</option>)}
            </select>
            <input
              value={uaFilter}
              onChange={(event) => setUaFilter(event.target.value)}
              placeholder="Filtra user-agent..."
              className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder-slate-600"
            />
          </div>

          <div className="overflow-x-auto">
            <table className="min-w-full text-xs">
              <thead className="text-left text-slate-500">
                <tr>
                  <th className="pb-2 pr-3">Richiesta</th>
                  <th className="pb-2 pr-3">Client</th>
                  <th className="pb-2 pr-3">Server</th>
                  <th className="pb-2 pr-3">Risposta</th>
                  <th className="pb-2 pr-3">Content</th>
                  <th className="pb-2 pr-3">User-Agent</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/70">
                {filtered.slice(0, 300).map((request) => (
                  <tr key={`${request.packet_number}-${request.method}-${request.uri}`}>
                    <td className="py-3 pr-3 align-top">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="rounded bg-slate-700 px-2 py-1 text-[11px] font-semibold text-slate-200">{request.method}</span>
                        {request.partial && <span className="rounded bg-amber-500/10 px-2 py-1 text-[11px] text-amber-100">parziale</span>}
                      </div>
                      <div className="mt-1 font-mono text-slate-100">{request.host ?? 'host n/d'}</div>
                      <div className="mt-0.5 max-w-md truncate font-mono text-slate-500">{request.uri}</div>
                      {request.referer && <div className="mt-1 max-w-md truncate text-slate-500">Referer: {request.referer}</div>}
                    </td>
                    <td className="py-3 pr-3 align-top font-mono text-slate-400">{endpoint(request.client_ip, request.client_port)}</td>
                    <td className="py-3 pr-3 align-top font-mono text-slate-400">{endpoint(request.server_ip, request.server_port)}</td>
                    <td className="py-3 pr-3 align-top">
                      {statusBadge(request)}
                      <div className="mt-1 text-slate-500">{request.response_reason ?? ''}</div>
                      {request.response_server && <div className="text-slate-500">Server: {request.response_server}</div>}
                    </td>
                    <td className="py-3 pr-3 align-top text-slate-400">
                      <div>{request.response_content_type ?? request.content_type ?? 'n/d'}</div>
                      <div className="text-slate-500">Len: {request.response_content_length ?? request.payload_size ?? 'n/d'}</div>
                      {request.response_file_name && <div className="max-w-40 truncate text-slate-500">File: {request.response_file_name}</div>}
                    </td>
                    <td className="max-w-sm py-3 pr-3 align-top text-slate-400">
                      <div className="truncate">{request.user_agent ?? 'n/d'}</div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {filtered.length === 0 && (
              <p className="py-8 text-center text-sm text-slate-500">Nessuna richiesta HTTP corrisponde ai filtri.</p>
            )}
          </div>
        </section>

        <aside className="space-y-4">
          <div className="card">
            <div className="mb-3 flex items-center gap-2">
              <Globe2 className="h-4 w-4 text-brand-300" />
              <h3 className="text-sm font-semibold text-slate-200">Host più contattati</h3>
            </div>
            <div className="space-y-2">
              {http.top_hosts.slice(0, 10).map((item) => (
                <div key={item.value} className="flex items-center justify-between gap-3 rounded-lg bg-slate-900/70 px-3 py-2">
                  <span className="truncate font-mono text-xs text-slate-200">{item.value}</span>
                  <span className="text-xs text-slate-500">{formatCount(item.count)}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <div className="mb-3 flex items-center gap-2">
              <FileText className="h-4 w-4 text-brand-300" />
              <h3 className="text-sm font-semibold text-slate-200">User-Agent frequenti</h3>
            </div>
            <div className="space-y-2">
              {http.top_user_agents.slice(0, 10).map((item) => (
                <div key={item.value} className="rounded-lg bg-slate-900/70 px-3 py-2">
                  <div className="truncate text-xs text-slate-200">{item.value}</div>
                  <div className="mt-1 text-xs text-slate-500">{formatCount(item.count)} richieste</div>
                </div>
              ))}
            </div>
          </div>

          <div className="card border-amber-500/20">
            <div className="mb-2 flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-300" />
              <h3 className="text-sm font-semibold text-amber-100">Limiti parser</h3>
            </div>
            <ul className="space-y-1 text-xs text-amber-100/80">
              {http.limitations.map((item) => <li key={item}>{item}</li>)}
            </ul>
          </div>
        </aside>
      </div>
    </div>
  )
}
