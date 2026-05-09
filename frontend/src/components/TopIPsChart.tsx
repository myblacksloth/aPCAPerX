/**
 * Component for rendering degli IP addresses most active.
 *
 * Mostra due tab separati:
 *   - "Sorgenti" → IP che hanno inviato il maggior numero di packets
 *   - "Destinazioni" → IP che hanno ricevuto il maggior numero di packets
 *
 * Per ogni tab viene renderizzato un grafico a barre orizzontali (Recharts)
 * che permette di confrontare visivamente i volumi di traffico.
 */
import { useState } from 'react'
import { createPortal } from 'react-dom'
import { X } from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, Cell,
} from 'recharts'
import type { AnalysisResult, IPEntry } from '../types/analysis'
import { formatBytes, formatCount, CHART_COLORS } from '../utils/format'

interface TopIPsChartProps {
  result: AnalysisResult
}

// Tooltip personalizzato per le barre IP
function IPTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ value: number; payload: IPEntry }>; label?: string }) {
  if (!active || !payload?.length) return null
  const services = getServices(payload[0].payload).slice(0, 3)
  return (
    <div className="bg-slate-700 border border-slate-600 rounded-lg p-3 text-sm shadow-xl">
      <p className="font-mono text-white mb-1 text-xs">{label}</p>
      <p className="text-slate-300">{payload[0].value.toLocaleString('it-IT')} packets</p>
      <p className="text-slate-400">{formatBytes(payload[0].payload.bytes)}</p>
      {services.length > 0 && (
        <p className="text-slate-300 mt-2 text-xs">
          {services.map((s) => s.port ? `${s.service}/${s.port}` : s.service).join(', ')}
        </p>
      )}
    </div>
  )
}

// Tick dell'asse Y personalizzato: shows l'IP in font monospace
function IPTick({ x, y, payload }: { x?: number; y?: number; payload?: { value: string } }) {
  if (!x || !y || !payload) return null
  return (
    <text
      x={x}
      y={y}
      dy={4}
      textAnchor="end"
      className="fill-slate-400"
      style={{ fontSize: 10, fontFamily: 'monospace' }}
    >
      {/* Tronca gli IP molto lunghi (IPv6) */}
      {payload.value.length > 18 ? payload.value.slice(0, 16) + '…' : payload.value}
    </text>
  )
}

function directionLabel(direction: string) {
  if (direction === 'server') return 'exposed service'
  if (direction === 'client') return 'client'
  return 'endpoint'
}

function getServices(ip: IPEntry) {
  return Array.isArray(ip.services) ? ip.services : []
}

function getProtocols(ip: IPEntry) {
  return Array.isArray(ip.protocols) ? ip.protocols : []
}

function getHostnames(ip: IPEntry) {
  return Array.isArray(ip.hostnames) ? ip.hostnames : []
}

function getPeers(ip: IPEntry) {
  return Array.isArray(ip.peers) ? ip.peers : []
}

function externalBadge(value: boolean | null | undefined, label: string) {
  // Shows only indicators actually available from external services.
  if (value === null || value === undefined) return null
  return (
    <span className={`rounded px-2 py-1 text-[11px] font-medium ${
      value ? 'bg-amber-500/15 text-amber-200' : 'bg-emerald-500/10 text-emerald-200'
    }`}>
      {label}: {value ? 'si' : 'no'}
    </span>
  )
}

function IPDetailsModal({
  title,
  ips,
  onClose,
}: {
  title: string
  ips: IPEntry[]
  onClose: () => void
}) {
  return createPortal(
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center bg-slate-950/75 p-4"
      onClick={(event) => {
        event.stopPropagation()
        onClose()
      }}
    >
      <div
        className="w-full max-w-5xl max-h-[85vh] overflow-hidden rounded-lg border border-slate-700 bg-slate-900 shadow-2xl"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-slate-700 px-5 py-4">
          <div>
            <h3 className="text-base font-semibold text-slate-100">IP service details</h3>
            <p className="text-xs text-slate-400">{title} - {ips.length} analyzed addresses</p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-md p-2 text-slate-400 hover:bg-slate-800 hover:text-slate-100"
            aria-label="Close IP service details"
          >
            <X size={18} />
          </button>
        </div>

        <div className="max-h-[calc(85vh-73px)] overflow-y-auto px-5 py-4">
          <div className="space-y-4">
            {ips.map((ip) => (
              <section key={ip.ip} className="rounded-lg border border-slate-700 bg-slate-800/70 p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <p className="font-mono text-sm font-semibold text-white">{ip.ip}</p>
                    <p className="mt-1 text-xs text-slate-400">
                      {formatCount(ip.count)} packets - {formatBytes(ip.bytes)}
                    </p>
                  </div>
                  <div className="flex flex-wrap justify-end gap-1.5">
                    {getProtocols(ip).slice(0, 8).map((protocol) => (
                      <span key={protocol} className="rounded bg-slate-700 px-2 py-1 text-[11px] font-medium text-slate-200">
                        {protocol}
                      </span>
                    ))}
                  </div>
                </div>

                {getHostnames(ip).length > 0 && (
                  <div className="mt-3">
                    <p className="mb-1 text-xs font-medium uppercase tracking-wide text-slate-500">Observed DNS names</p>
                    <div className="flex flex-wrap gap-1.5">
                      {getHostnames(ip).map((hostname) => (
                        <span key={hostname} className="rounded bg-emerald-500/10 px-2 py-1 font-mono text-[11px] text-emerald-200">
                          {hostname}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {ip.external && (
                  <div className="mt-4 rounded-lg border border-brand-500/20 bg-brand-500/10 p-3">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <p className="text-xs font-semibold uppercase tracking-wide text-brand-100">
                          External-tool information
                        </p>
                        <p className="mt-1 text-xs text-slate-400">
                          {ip.external.status === 'enriched'
                            ? `Sources: ${ip.external.sources.join(', ')}`
                            : ip.external.reason ?? 'No external data available'}
                        </p>
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {externalBadge(ip.external.proxy, 'Proxy/VPN')}
                        {externalBadge(ip.external.hosting, 'Hosting')}
                        {externalBadge(ip.external.mobile, 'Mobile')}
                      </div>
                    </div>

                    {ip.external.status === 'enriched' && (
                      <div className="mt-3 grid grid-cols-1 gap-2 text-xs text-slate-300 sm:grid-cols-2 lg:grid-cols-3">
                        {ip.external.reverse_dns && <p><span className="text-slate-500">Reverse DNS:</span> {ip.external.reverse_dns}</p>}
                        {ip.external.asn && <p><span className="text-slate-500">ASN:</span> AS{ip.external.asn}</p>}
                        {ip.external.as_name && <p><span className="text-slate-500">AS name:</span> {ip.external.as_name}</p>}
                        {ip.external.bgp_prefix && <p><span className="text-slate-500">BGP prefix:</span> {ip.external.bgp_prefix}</p>}
                        {ip.external.registry && <p><span className="text-slate-500">Registry:</span> {ip.external.registry}</p>}
                        {ip.external.allocated && <p><span className="text-slate-500">Allocated:</span> {ip.external.allocated}</p>}
                        {ip.external.country && <p><span className="text-slate-500">Country:</span> {ip.external.country} {ip.external.country_code ? `(${ip.external.country_code})` : ''}</p>}
                        {(ip.external.region || ip.external.city) && <p><span className="text-slate-500">Area:</span> {[ip.external.city, ip.external.region].filter(Boolean).join(', ')}</p>}
                        {ip.external.timezone && <p><span className="text-slate-500">Timezone:</span> {ip.external.timezone}</p>}
                        {ip.external.isp && <p><span className="text-slate-500">ISP:</span> {ip.external.isp}</p>}
                        {ip.external.org && <p><span className="text-slate-500">Org:</span> {ip.external.org}</p>}
                        {ip.external.rdap_name && <p><span className="text-slate-500">RDAP:</span> {ip.external.rdap_name}</p>}
                        {ip.external.rdap_handle && <p><span className="text-slate-500">Handle:</span> {ip.external.rdap_handle}</p>}
                        {(ip.external.lat !== null && ip.external.lon !== null) && (
                          <p><span className="text-slate-500">Coordinate:</span> {ip.external.lat}, {ip.external.lon}</p>
                        )}
                      </div>
                    )}

                    {ip.external.rdap_entities.length > 0 && (
                      <p className="mt-3 text-xs text-slate-400">
                        RDAP entities: <span className="text-slate-300">{ip.external.rdap_entities.join(', ')}</span>
                      </p>
                    )}

                    {ip.external.rdap_remarks.length > 0 && (
                      <div className="mt-3 space-y-1 text-xs text-slate-400">
                        {ip.external.rdap_remarks.map((remark) => (
                          <p key={remark}>{remark}</p>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                <div className="mt-4 overflow-x-auto">
                  {getServices(ip).length > 0 ? (
                    <table className="w-full min-w-[720px] text-left text-xs">
                      <thead className="text-slate-500">
                        <tr className="border-b border-slate-700">
                          <th className="pb-2 font-medium">Servizio</th>
                          <th className="pb-2 font-medium">Porta</th>
                          <th className="pb-2 font-medium">Protocol</th>
                          <th className="pb-2 font-medium">Ruolo</th>
                          <th className="pb-2 text-right font-medium">Packets</th>
                          <th className="pb-2 font-medium">Peer principali</th>
                        </tr>
                      </thead>
                      <tbody>
                        {getServices(ip).map((service) => (
                          <tr
                            key={`${service.service}-${service.port ?? 'none'}-${service.protocol}-${service.direction}`}
                            className="border-b border-slate-700/60 last:border-b-0"
                          >
                            <td className="py-2 pr-3 font-medium text-slate-100">{service.service}</td>
                            <td className="py-2 pr-3 font-mono text-slate-300">{service.port ?? '-'}</td>
                            <td className="py-2 pr-3 text-slate-300">{service.protocol}</td>
                            <td className="py-2 pr-3 text-slate-300">{directionLabel(service.direction)}</td>
                            <td className="py-2 pr-3 text-right font-mono text-slate-300">{formatCount(service.count)}</td>
                            <td className="py-2 text-slate-400">
                              {service.peers.length > 0 ? service.peers.join(', ') : '-'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <p className="rounded border border-slate-700 bg-slate-900/60 px-3 py-2 text-xs text-slate-400">
                      No TCP/UDP service was identified for this address. Only network protocols or traffic without ports are available.
                    </p>
                  )}
                </div>

                {getPeers(ip).length > 0 && (
                  <p className="mt-3 text-xs text-slate-500">
                    Observed peers: <span className="font-mono text-slate-400">{getPeers(ip).join(', ')}</span>
                  </p>
                )}
              </section>
            ))}
          </div>
        </div>
      </div>
    </div>,
    document.body,
  )
}

export default function TopIPsChart({ result }: TopIPsChartProps) {
  // Active tab state: 0 = sources, 1 = destinations
  const [tab, setTab] = useState<0 | 1>(0)
  const [detailsOpen, setDetailsOpen] = useState(false)

  const tabs = [
    { label: 'IP Sorgenti',     data: result.top_src_ips.slice(0, 10) },
    { label: 'IP Destinazione', data: result.top_dst_ips.slice(0, 10) },
  ]

  // I data correnti della tab selezionata
  const currentData = tabs[tab].data
  const openDetails = () => {
    if (currentData.length > 0) setDetailsOpen(true)
  }

  return (
    <div
      className="card cursor-pointer transition-colors hover:border-slate-600"
      onClick={openDetails}
      onKeyDown={(event) => {
        if ((event.key === 'Enter' || event.key === ' ') && currentData.length > 0) {
          event.preventDefault()
          openDetails()
        }
      }}
      role="button"
      tabIndex={0}
      aria-label="Open service details for top IPs"
    >
      {/* ── Header con tab selector ──────────────────────────────────── */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-base font-semibold text-slate-200">Top IP</h2>
          <p className="mt-0.5 text-xs text-slate-500">Click to view services, DNS, and peers</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex bg-slate-700 rounded-lg p-0.5 gap-0.5">
            {tabs.map((t, i) => (
              <button
                key={t.label}
                onClick={(event) => {
                  event.stopPropagation()
                  setTab(i as 0 | 1)
                }}
                onKeyDown={(event) => event.stopPropagation()}
                className={[
                  'px-3 py-1 text-xs rounded-md transition-colors',
                  tab === i
                    ? 'bg-brand-500 text-white font-medium'
                    : 'text-slate-400 hover:text-slate-200',
                ].join(' ')}
              >
                {t.label}
              </button>
            ))}
          </div>

        </div>
      </div>

      {/* ── Grafico a barre orizzontali ───────────────────────────────── */}
      {currentData.length > 0 ? (
        <ResponsiveContainer width="100%" height={currentData.length * 32 + 20}>
          <BarChart
            data={currentData}
            layout="vertical"       /* barre orizzontali per leggere gli IP */
            margin={{ left: 10, right: 40, top: 0, bottom: 0 }}
            onClick={openDetails}
          >
            {/* Asse Y: IP addresses (il valore categorico) */}
            <YAxis
              type="category"
              dataKey="ip"
              width={120}
              tick={<IPTick />}
              axisLine={false}
              tickLine={false}
            />
            {/* Asse X: numero di packets (il valore numerico) */}
            <XAxis
              type="number"
              tick={{ fill: '#64748b', fontSize: 10 }}
              axisLine={false}
              tickLine={false}
              tickFormatter={(v) => formatCount(v)}
            />
            <Tooltip content={<IPTooltip />} cursor={{ fill: 'rgba(99,102,241,0.1)' }} />
            <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={20}>
              {/* Assegna un colore diverso a ogni barra */}
              {currentData.map((_, i) => (
                <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      ) : (
        <p className="text-slate-500 text-sm text-center py-8">
          No IP address found in this category
        </p>
      )}
      <button
        type="button"
        onClick={(event) => {
          event.stopPropagation()
          openDetails()
        }}
        disabled={currentData.length === 0}
        className="mt-4 w-full rounded-lg border border-brand-500/40 bg-brand-500/15 px-4 py-2.5 text-sm font-semibold text-brand-100 transition-colors hover:bg-brand-500/25 disabled:cursor-not-allowed disabled:border-slate-700 disabled:bg-slate-800 disabled:text-slate-500"
      >
        View IP service details
      </button>
      {detailsOpen && (
        <IPDetailsModal
          title={tabs[tab].label}
          ips={currentData}
          onClose={() => setDetailsOpen(false)}
        />
      )}
    </div>
  )
}
