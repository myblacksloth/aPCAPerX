/**
 * Component for rendering della distribuzione dei protocolli.
 *
 * Layout:
 *   - Sinistra: grafico a ciambella (donut) con Recharts
 *   - Destra: tabella con nome, count, byte e percentuale per ogni protocol
 *
 * I protocolli vengono colorati in modo coerente con protocolColor(),
 * so il colore di "TCP" is sempre lo stesso in tutti i grafici dell'app.
 */
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
} from 'recharts'
import type { AnalysisResult } from '../types/analysis'
import { formatBytes, formatCount, protocolColor } from '../utils/format'

interface ProtocolChartProps {
  result: AnalysisResult
}

// Componente tooltip personalizzato per il grafico a torta
function CustomTooltip({ active, payload }: { active?: boolean; payload?: Array<{payload: {protocol: string; count: number; bytes: number; percentage: number}; value: number }> }) {
  if (!active || !payload?.length) return null
  const d = payload[0].payload
  return (
    <div className="bg-slate-700 border border-slate-600 rounded-lg p-3 text-sm shadow-xl">
      <p className="font-semibold text-white mb-1">{d.protocol}</p>
      <p className="text-slate-300">{d.count.toLocaleString('it-IT')} packets</p>
      <p className="text-slate-300">{formatBytes(d.bytes)}</p>
      <p className="text-brand-300 font-medium">{d.percentage}%</p>
    </div>
  )
}

export default function ProtocolChart({ result }: ProtocolChartProps) {
  // Prepara i data per Recharts: prende i primi 10 protocolli e raggruppa il resto
  const top10 = result.protocols.slice(0, 10)
  const others = result.protocols.slice(10)

  const chartData = others.length > 0
    ? [
        ...top10,
        {
          protocol:   'Altri',
          count:      others.reduce((s, p) => s + p.count, 0),
          bytes:      others.reduce((s, p) => s + p.bytes, 0),
          percentage: others.reduce((s, p) => s + p.percentage, 0),
        },
      ]
    : top10

  return (
    <div className="card">
      <h2 className="text-base font-semibold text-slate-200 mb-4">
        Protocol distribution
      </h2>

      <div className="flex flex-col lg:flex-row gap-6">

        {/* ── Grafico a ciambella ────────────────────────────────────── */}
        <div className="w-full lg:w-48 h-48 flex-shrink-0">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={chartData}
                dataKey="count"
                nameKey="protocol"
                cx="50%"
                cy="50%"
                innerRadius="55%"   /* foro centrale: rende il pie un donut */
                outerRadius="80%"
                paddingAngle={2}
              >
                {chartData.map((entry) => (
                  <Cell
                    key={entry.protocol}
                    fill={protocolColor(entry.protocol)}
                    stroke="transparent"
                  />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* ── Tabella protocolli ─────────────────────────────────────── */}
        <div className="flex-1 overflow-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-slate-500 border-b border-slate-700">
                <th className="pb-2 font-medium">Protocol</th>
                <th className="pb-2 font-medium text-right">Packets</th>
                <th className="pb-2 font-medium text-right hidden sm:table-cell">Byte</th>
                <th className="pb-2 font-medium text-right">%</th>
              </tr>
            </thead>
            <tbody>
              {result.protocols.map((p) => (
                <tr key={p.protocol} className="border-b border-slate-700/50 hover:bg-slate-700/20">
                  <td className="py-1.5">
                    <div className="flex items-center gap-2">
                      {/* Pallino colorato identificativo del protocol */}
                      <span
                        className="w-2.5 h-2.5 rounded-full flex-shrink-0"
                        style={{ backgroundColor: protocolColor(p.protocol) }}
                      />
                      <span className="font-mono text-slate-200 text-xs">{p.protocol}</span>
                    </div>
                  </td>
                  <td className="py-1.5 text-right text-slate-300">
                    {formatCount(p.count)}
                  </td>
                  <td className="py-1.5 text-right text-slate-400 hidden sm:table-cell">
                    {formatBytes(p.bytes)}
                  </td>
                  <td className="py-1.5 text-right">
                    {/* Barra di percentuale visiva */}
                    <div className="flex items-center justify-end gap-2">
                      <div className="w-12 bg-slate-700 rounded-full h-1.5 hidden sm:block">
                        <div
                          className="h-1.5 rounded-full"
                          style={{
                            width: `${Math.min(p.percentage, 100)}%`,
                            backgroundColor: protocolColor(p.protocol),
                          }}
                        />
                      </div>
                      <span className="text-slate-300 text-xs w-10 text-right">
                        {p.percentage.toFixed(1)}%
                      </span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
