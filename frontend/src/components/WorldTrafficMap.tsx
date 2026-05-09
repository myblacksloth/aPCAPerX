/**
 * Geographic map of traffic to public IPs.
 *
 * This component colors countries based on bytes observed toward IPs from
 * destination per cui l'arricchimento external ha restituito un paese.
 * Le geometrie arrivano da world-atlas in format TopoJSON e vengono
 * proiettate in SVG con una semplice proiezione equirettangolare.
 */
import { useEffect, useMemo, useState } from 'react'
import { X } from 'lucide-react'
import type { AnalysisResult, FlowEntry, IPExternalInfo } from '../types/analysis'
import { formatBytes, formatCount } from '../utils/format'

interface WorldTrafficMapProps {
  result: AnalysisResult
}

interface TopologyTransform {
  scale: [number, number]
  translate: [number, number]
}

interface TopologyGeometry {
  id: string
  type: 'Polygon' | 'MultiPolygon'
  arcs: number[][] | number[][][]
  properties: {
    name: string
  }
}

interface WorldTopology {
  transform: TopologyTransform
  arcs: number[][][]
  objects: {
    countries: {
      geometries: TopologyGeometry[]
    }
  }
}

interface CountryShape {
  id: string
  name: string
  path: string
}

interface CountryTraffic {
  country: string
  countryCode: string | null
  bytes: number
  packets: number
  ips: string[]
}

interface CountryFlowEntry {
  flow: FlowEntry
  matchedIps: string[]
  matchedBytes: number
  matchedPackets: number
}

interface SelectedCountry {
  traffic: CountryTraffic
  flows: CountryFlowEntry[]
}

const WORLD_ATLAS_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json'
const MAP_WIDTH = 960
const MAP_HEIGHT = 500

function normalizeCountry(value: string) {
  // Normalizza i nomi per confrontare fonti diverse riducendo differenze banali.
  return value
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/^the\s+/, '')
    .replace(/&/g, 'and')
    .replace(/[^a-z0-9]+/g, ' ')
    .trim()
}

function countryAliases(country: string) {
  // Alcuni services GeoIP e Natural Earth usano nomi diversi per lo stesso paese.
  const aliases: Record<string, string> = {
    'united states': 'united states of america',
    'russian federation': 'russia',
    'viet nam': 'vietnam',
    'iran islamic republic of': 'iran',
    'tanzania united republic of': 'tanzania',
    'moldova republic of': 'moldova',
    'bolivia plurinational state of': 'bolivia',
    'venezuela bolivarian republic of': 'venezuela',
    'syrian arab republic': 'syria',
    'lao people s democratic republic': 'laos',
    'korea republic of': 'south korea',
    'korea democratic people s republic of': 'north korea',
    'czechia': 'czech republic',
    'brunei darussalam': 'brunei',
  }

  return aliases[country] ?? country
}

function decodeArc(topology: WorldTopology, arcIndex: number) {
  // TopoJSON salva gli archi come delta compressi: qui li trasformiamo in lon/lat.
  // Gli indici negativi non indicano "-id", ma il complemento bitwise dell'id.
  const source = topology.arcs[arcIndex < 0 ? ~arcIndex : arcIndex]
  const points: Array<[number, number]> = []
  let x = 0
  let y = 0

  for (const point of source) {
    x += point[0]
    y += point[1]
    points.push([
      x * topology.transform.scale[0] + topology.transform.translate[0],
      y * topology.transform.scale[1] + topology.transform.translate[1],
    ])
  }

  return arcIndex < 0 ? points.reverse() : points
}

function projectPoint([lon, lat]: [number, number]) {
  // Proiezione equirettangolare centrata e leggermente compressa sui poli.
  // Manteniamo il calcolo manuale per evitare nuove dipendenze grafiche.
  const visibleTop = 84
  const visibleBottom = -60
  const clampedLat = Math.max(visibleBottom, Math.min(visibleTop, lat))
  const x = ((lon + 180) / 360) * MAP_WIDTH
  const y = ((visibleTop - clampedLat) / (visibleTop - visibleBottom)) * MAP_HEIGHT
  return [x, y]
}

function ringToPath(ring: Array<[number, number]>) {
  // Converte una sequenza lon/lat in comandi SVG path.
  if (ring.length === 0) return ''

  const commands: string[] = []
  let previousX: number | null = null

  for (const point of ring) {
    const [x, y] = projectPoint(point)

    // Se un anello attraversa l'antimeridiano, evitiamo una linea lunga da un
    // lato all'altro della mappa: ripartiamo con un nuovo sotto-tracciato.
    if (previousX !== null && Math.abs(x - previousX) > MAP_WIDTH * 0.55) {
      commands.push('Z')
      commands.push(`M${x.toFixed(1)},${y.toFixed(1)}`)
    } else {
      commands.push(`${commands.length === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`)
    }

    previousX = x
  }

  return commands.join(' ') + ' Z'
}

function polygonToPath(topology: WorldTopology, polygon: number[][]) {
  // A polygon can have multiple rings: outer boundary and inner holes.
  return polygon
    .map((ring) => {
      const points = ring.flatMap((arcIndex, index) => {
        const arcPoints = decodeArc(topology, arcIndex)
        return index === 0 ? arcPoints : arcPoints.slice(1)
      })
      return ringToPath(points)
    })
    .join(' ')
}

function geometryToPath(topology: WorldTopology, geometry: TopologyGeometry) {
  // Gestisce sia Polygon sia MultiPolygon restituendo un singolo path SVG.
  if (geometry.type === 'Polygon') {
    return polygonToPath(topology, geometry.arcs as number[][])
  }

  return (geometry.arcs as number[][][])
    .map((polygon) => polygonToPath(topology, polygon))
    .join(' ')
}

function topologyToShapes(topology: WorldTopology): CountryShape[] {
  // Trasforma le geometrie TopoJSON in una lista pronta per il rendering SVG.
  return topology.objects.countries.geometries
    .filter((geometry) => geometry.properties.name !== 'Antarctica')
    .map((geometry) => ({
      id: geometry.id,
      name: geometry.properties.name,
      path: geometryToPath(topology, geometry),
    }))
}

function getExternalInfo(result: AnalysisResult, ip: string): IPExternalInfo | null {
  // Looks for external data first in the global map, then in enriched top lists.
  const fromMap = result.external_ip_info?.[ip]
  if (fromMap) return fromMap

  const fromTopDst = result.top_dst_ips.find((entry) => entry.ip === ip)?.external
  if (fromTopDst) return fromTopDst

  const fromTopSrc = result.top_src_ips.find((entry) => entry.ip === ip)?.external
  return fromTopSrc ?? null
}

function aggregateTrafficByCountry(result: AnalysisResult) {
  // Uses bytes from top destinations and completes with detailed packets when available.
  const bytesByIp = new Map<string, { bytes: number; packets: number }>()

  for (const entry of result.top_dst_ips) {
    bytesByIp.set(entry.ip, {
      bytes: entry.bytes,
      packets: entry.count,
    })
  }

  for (const packet of result.packets) {
    if (!packet.dst_ip || bytesByIp.has(packet.dst_ip)) continue
    const current = bytesByIp.get(packet.dst_ip) ?? { bytes: 0, packets: 0 }
    current.bytes += packet.length
    current.packets += 1
    bytesByIp.set(packet.dst_ip, current)
  }

  const countries = new Map<string, CountryTraffic>()

  for (const [ip, traffic] of bytesByIp) {
    const external = getExternalInfo(result, ip)
    if (!external?.country || external.status !== 'enriched') continue

    const key = countryAliases(normalizeCountry(external.country))
    const current = countries.get(key) ?? {
      country: external.country,
      countryCode: external.country_code,
      bytes: 0,
      packets: 0,
      ips: [],
    }

    current.bytes += traffic.bytes
    current.packets += traffic.packets
    if (!current.ips.includes(ip)) current.ips.push(ip)
    countries.set(key, current)
  }

  return countries
}

function flowBytesForCountry(flow: FlowEntry, matchedIps: string[]) {
  // Assigns the overall geolocated endpoint traffic to the country.
  let bytes = 0
  let packets = 0
  if (matchedIps.includes(flow.src_ip)) {
    bytes += flow.bytes_client_to_server
    packets += flow.packets_client_to_server
    if (!matchedIps.includes(flow.dst_ip)) {
      bytes += flow.bytes_server_to_client
      packets += flow.packets_server_to_client
    }
  }
  if (matchedIps.includes(flow.dst_ip)) {
    bytes += flow.bytes_server_to_client
    packets += flow.packets_server_to_client
    if (!matchedIps.includes(flow.src_ip)) {
      bytes += flow.bytes_client_to_server
      packets += flow.packets_client_to_server
    }
  }
  return { bytes, packets }
}

function flowsForCountry(result: AnalysisResult, traffic: CountryTraffic): CountryFlowEntry[] {
  // Incrocia gli IP del paese con i flow 5-tuple ricostruiti dal backend.
  const countryIps = new Set(traffic.ips)
  return (result.flows ?? [])
    .map((flow) => {
      const matchedIps = [flow.src_ip, flow.dst_ip].filter((ip) => countryIps.has(ip))
      const matchedTraffic = flowBytesForCountry(flow, matchedIps)
      return {
        flow,
        matchedIps,
        matchedBytes: matchedTraffic.bytes || flow.bytes_total,
        matchedPackets: matchedTraffic.packets || flow.packets_total,
      }
    })
    .filter((entry) => entry.matchedIps.length > 0)
    .sort((left, right) => right.matchedBytes - left.matchedBytes)
}

function colorForTraffic(bytes: number, maxBytes: number) {
  // Scala sequenziale dal verde chiaro al rosso, basata sul peso relativo dei byte.
  if (bytes <= 0 || maxBytes <= 0) return '#1e293b'
  const ratio = bytes / maxBytes
  if (ratio >= 0.75) return '#ef4444'
  if (ratio >= 0.5) return '#f97316'
  if (ratio >= 0.25) return '#eab308'
  return '#22c55e'
}

export default function WorldTrafficMap({ result }: WorldTrafficMapProps) {
  const [shapes, setShapes] = useState<CountryShape[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [hovered, setHovered] = useState<CountryTraffic | null>(null)
  const [selected, setSelected] = useState<SelectedCountry | null>(null)

  useEffect(() => {
    let active = true

    async function loadMap() {
      // La geometria e esterna e leggera: la carichiamo solo nel browser quando serve.
      try {
        setLoading(true)
        setError(null)
        const response = await fetch(WORLD_ATLAS_URL)
        if (!response.ok) throw new Error(`Error mappa ${response.status}`)
        const topology: WorldTopology = await response.json()
        if (active) setShapes(topologyToShapes(topology))
      } catch (err) {
        if (active) setError(err instanceof Error ? err.message : 'Impossibile caricare la mappa')
      } finally {
        if (active) setLoading(false)
      }
    }

    loadMap()

    return () => {
      active = false
    }
  }, [])

  const trafficByCountry = useMemo(() => aggregateTrafficByCountry(result), [result])
  const maxBytes = Math.max(...[...trafficByCountry.values()].map((item) => item.bytes), 0)
  const totalCountries = trafficByCountry.size
  const totalBytes = [...trafficByCountry.values()].reduce((sum, item) => sum + item.bytes, 0)

  return (
    <div className="card">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-slate-200">IP traffic map</h2>
          <p className="mt-0.5 text-xs text-slate-500">
            Countries colored by traffic toward enriched destination IPs
          </p>
        </div>
        <div className="flex gap-4 text-xs text-slate-500">
          <span>{totalCountries} paesi</span>
          <span>Totale: <strong className="text-brand-300">{formatBytes(totalBytes)}</strong></span>
        </div>
      </div>

      {trafficByCountry.size === 0 && (
        <div className="mb-4 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-xs text-amber-100">
          Press "Analyze with external tools" to retrieve countries for public IPs and color the map.
        </div>
      )}

      <div className="relative overflow-hidden rounded-lg border border-slate-700 bg-slate-950">
        {loading ? (
          <div className="flex h-[320px] items-center justify-center text-sm text-slate-500">
            Loading world map...
          </div>
        ) : error ? (
          <div className="flex h-[320px] items-center justify-center px-4 text-center text-sm text-red-200">
            {error}
          </div>
        ) : (
          <svg viewBox={`0 0 ${MAP_WIDTH} ${MAP_HEIGHT}`} className="h-[360px] w-full">
            <defs>
              {/* Gradiente sobrio per distinguere l'oceano senza introdurre rumore visivo. */}
              <linearGradient id="mapOcean" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#0f172a" />
                <stop offset="100%" stopColor="#020617" />
              </linearGradient>
            </defs>
            <rect width={MAP_WIDTH} height={MAP_HEIGHT} fill="url(#mapOcean)" />
            {shapes.map((shape) => {
              const traffic = trafficByCountry.get(countryAliases(normalizeCountry(shape.name)))
              const fill = traffic ? colorForTraffic(traffic.bytes, maxBytes) : '#1e293b'

              return (
                <path
                  key={shape.id}
                  d={shape.path}
                  fill={fill}
                  stroke="#334155"
                  strokeWidth={0.45}
                  vectorEffect="non-scaling-stroke"
                  role={traffic ? 'button' : undefined}
                  tabIndex={traffic ? 0 : undefined}
                  className={`transition-colors hover:fill-brand-400 ${traffic ? 'cursor-pointer' : ''}`}
                  onMouseEnter={() => setHovered(traffic ?? null)}
                  onMouseLeave={() => setHovered(null)}
                  onClick={() => {
                    // Click sul paese: apre il detailso dei flow collegati a quel paese.
                    if (traffic) {
                      setSelected({
                        traffic,
                        flows: flowsForCountry(result, traffic),
                      })
                    }
                  }}
                  onKeyDown={(event) => {
                    // Keyboard accessibility: Enter/Space open the same popup as click.
                    if (traffic && (event.key === 'Enter' || event.key === ' ')) {
                      event.preventDefault()
                      setSelected({
                        traffic,
                        flows: flowsForCountry(result, traffic),
                      })
                    }
                  }}
                >
                  <title>
                    {traffic
                      ? `${traffic.country}: ${formatBytes(traffic.bytes)} verso ${traffic.ips.length} IP`
                      : `${shape.name}: no geolocated traffic`}
                  </title>
                </path>
              )
            })}
          </svg>
        )}

        {hovered && (
          <div className="absolute left-3 top-3 max-w-xs rounded-lg border border-slate-600 bg-slate-800/95 p-3 text-xs shadow-xl">
            <p className="font-semibold text-white">
              {hovered.country}{hovered.countryCode ? ` (${hovered.countryCode})` : ''}
            </p>
            <p className="mt-1 text-slate-300">{formatBytes(hovered.bytes)} verso {hovered.ips.length} IP</p>
            <p className="text-slate-400">{formatCount(hovered.packets)} packets</p>
            <p className="mt-2 break-words font-mono text-[11px] text-slate-500">
              {hovered.ips.slice(0, 6).join(', ')}
              {hovered.ips.length > 6 ? `, +${hovered.ips.length - 6}` : ''}
            </p>
          </div>
        )}
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-3 text-xs text-slate-500">
        <span>Scala:</span>
        <span className="flex items-center gap-1"><span className="h-3 w-6 rounded bg-[#22c55e]" /> basso</span>
        <span className="flex items-center gap-1"><span className="h-3 w-6 rounded bg-[#eab308]" /> medio</span>
        <span className="flex items-center gap-1"><span className="h-3 w-6 rounded bg-[#f97316]" /> alto</span>
        <span className="flex items-center gap-1"><span className="h-3 w-6 rounded bg-[#ef4444]" /> massimo</span>
        <span className="text-slate-600">Clicca un paese colorato per vedere i flow.</span>
      </div>

      {selected && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 px-4">
          <div className="w-full max-w-5xl overflow-hidden rounded-xl border border-slate-700 bg-slate-900 shadow-2xl">
            <div className="flex items-start justify-between gap-4 border-b border-slate-700 px-5 py-4">
              <div>
                <h3 className="text-base font-semibold text-white">
                  Flow verso {selected.traffic.country}{selected.traffic.countryCode ? ` (${selected.traffic.countryCode})` : ''}
                </h3>
                <p className="mt-1 text-xs text-slate-500">
                  {formatBytes(selected.traffic.bytes)} · {formatCount(selected.traffic.packets)} packets · {selected.traffic.ips.length} IP geolocalizzati
                </p>
              </div>
              <button
                type="button"
                onClick={() => setSelected(null)}
                className="rounded-md p-2 text-slate-400 hover:bg-slate-800 hover:text-slate-100"
                aria-label="Chiudi flow paese"
              >
                <X size={18} />
              </button>
            </div>

            <div className="max-h-[70vh] overflow-y-auto p-5">
              <div className="mb-4 rounded-lg border border-slate-700 bg-slate-800/70 p-3">
                <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">IP del paese</p>
                <div className="flex flex-wrap gap-1.5">
                  {selected.traffic.ips.map((ip) => (
                    <span key={ip} className="rounded bg-slate-700 px-2 py-1 font-mono text-[11px] text-slate-200">{ip}</span>
                  ))}
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="min-w-full text-xs">
                  <thead className="text-left text-slate-500">
                    <tr>
                      <th className="pb-2 pr-3">Flow</th>
                      <th className="pb-2 pr-3">Endpoint</th>
                      <th className="pb-2 pr-3">Protocol</th>
                      <th className="pb-2 pr-3">Traffic paese</th>
                      <th className="pb-2 pr-3">Totale flow</th>
                      <th className="pb-2 pr-3">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-700/70">
                    {selected.flows.slice(0, 300).map((entry) => (
                      <tr key={entry.flow.flow_id}>
                        <td className="py-3 pr-3 align-top">
                          <div className="font-mono text-slate-100">{entry.flow.flow_id}</div>
                          <div className="mt-1 text-slate-500">{entry.flow.first_seen}</div>
                        </td>
                        <td className="py-3 pr-3 align-top font-mono text-slate-400">
                          <div>{entry.flow.src_ip}:{entry.flow.src_port ?? '-'}</div>
                          <div className="text-slate-600">→ {entry.flow.dst_ip}:{entry.flow.dst_port ?? '-'}</div>
                          <div className="mt-1 text-[11px] text-brand-300">
                            IP paese: {entry.matchedIps.join(', ')}
                          </div>
                        </td>
                        <td className="py-3 pr-3 align-top text-slate-300">{entry.flow.protocol}</td>
                        <td className="py-3 pr-3 align-top text-slate-300">
                          {formatBytes(entry.matchedBytes)}
                          <div className="text-slate-500">{formatCount(entry.matchedPackets)} pkt</div>
                        </td>
                        <td className="py-3 pr-3 align-top text-slate-400">
                          {formatBytes(entry.flow.bytes_total)}
                          <div className="text-slate-500">{formatCount(entry.flow.packets_total)} pkt</div>
                        </td>
                        <td className="py-3 pr-3 align-top text-slate-400">{entry.flow.state}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {selected.flows.length === 0 && (
                <p className="py-8 text-center text-sm text-slate-500">
                  No 5-tuple flow is linked to the geolocated IPs in this country.
                </p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
