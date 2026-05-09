/**
 * Component for rendering delle ports di rete most used.
 *
 * Mostra due tab:
 *   - "Ports Destinazione" → ports most contattate (services remoti usati)
 *   - "Ports Sorgente"     → ports source most usate (ports effimere)
 *
 * Each bar shows the port number and associated service name
 * (es. "80 HTTP", "443 HTTPS", "53 DNS").
 */
import { useState } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, Cell,
} from 'recharts'
import type { PortEntry, AnalysisResult } from '../types/analysis'
import { formatCount, CHART_COLORS } from '../utils/format'

interface TopPortsChartProps {
  result: AnalysisResult
}

// Tooltip personalizzato per le ports
function PortTooltip({ active, payload }: { active?: boolean; payload?: Array<{ payload: PortEntry; value: number }> }) {
  if (!active || !payload?.length) return null
  const d = payload[0].payload
  return (
    <div className="bg-slate-700 border border-slate-600 rounded-lg p-3 text-sm shadow-xl">
      <p className="font-bold text-white">
        {d.port} <span className="text-brand-300 font-mono text-xs">{d.service}</span>
      </p>
      <p className="text-slate-300">{payload[0].value.toLocaleString('it-IT')} packets</p>
      <p className="text-slate-400 text-xs">Protocol: {d.protocol}</p>
    </div>
  )
}

// Custom Y tick: shows "PORT · service" on two virtual lines
function PortTick({ x, y, payload }: { x?: number; y?: number; payload?: { value: string | number } }) {
  if (!x || !y || !payload) return null
  return (
    <text
      x={x}
      y={y}
      dy={4}
      textAnchor="end"
      className="fill-slate-400"
      style={{ fontSize: 11, fontFamily: 'monospace' }}
    >
      {payload.value}
    </text>
  )
}

export default function TopPortsChart({ result }: TopPortsChartProps) {
  const [tab, setTab] = useState<0 | 1>(0)

  const tabs = [
    {
      label: 'Dst ports',
      data: result.top_dst_ports.slice(0, 12).map(p => ({
        ...p,
        label: `${p.port} · ${p.service}`,
      })),
    },
    {
      label: 'Src ports',
      data: result.top_src_ports.slice(0, 12).map(p => ({
        ...p,
        label: `${p.port} · ${p.service}`,
      })),
    },
  ]

  const currentData = tabs[tab].data

  return (
    <div className="card">
      {/* ── Header con tab selector ──────────────────────────────────── */}
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-base font-semibold text-slate-200">Top ports</h2>
        <div className="flex bg-slate-700 rounded-lg p-0.5 gap-0.5">
          {tabs.map((t, i) => (
            <button
              key={t.label}
              onClick={() => setTab(i as 0 | 1)}
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

      {/* ── Grafico a barre orizzontali ───────────────────────────────── */}
      {currentData.length > 0 ? (
        <ResponsiveContainer width="100%" height={currentData.length * 30 + 20}>
          <BarChart
            data={currentData}
            layout="vertical"
            margin={{ left: 10, right: 40, top: 0, bottom: 0 }}
          >
            <YAxis
              type="category"
              dataKey="label"          /* shows "PORT · SERVIZIO" */
              width={110}
              tick={<PortTick />}
              axisLine={false}
              tickLine={false}
            />
            <XAxis
              type="number"
              tick={{ fill: '#64748b', fontSize: 10 }}
              axisLine={false}
              tickLine={false}
              tickFormatter={(v) => formatCount(v)}
            />
            <Tooltip content={<PortTooltip />} cursor={{ fill: 'rgba(99,102,241,0.1)' }} />
            <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={18}>
              {currentData.map((_, i) => (
                <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      ) : (
        <p className="text-slate-500 text-sm text-center py-8">
          No port found in this category
        </p>
      )}
    </div>
  )
}
