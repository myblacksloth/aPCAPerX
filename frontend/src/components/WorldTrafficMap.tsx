/**
 * Mappa geografica del traffico verso IP pubblici.
 *
 * Il componente colora i paesi in base ai byte osservati verso IP di
 * destinazione per cui l'arricchimento esterno ha restituito un paese.
 * Le geometrie arrivano da world-atlas in formato TopoJSON e vengono
 * proiettate in SVG con una semplice proiezione equirettangolare.
 */
import { useEffect, useMemo, useState } from 'react'
import type { AnalysisResult, IPExternalInfo } from '../types/analysis'
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
  // Alcuni servizi GeoIP e Natural Earth usano nomi diversi per lo stesso paese.
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
  // Un poligono puo avere piu anelli: contorno esterno e buchi interni.
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
  // Cerca i dati esterni prima nella mappa globale, poi nelle top list arricchite.
  const fromMap = result.external_ip_info?.[ip]
  if (fromMap) return fromMap

  const fromTopDst = result.top_dst_ips.find((entry) => entry.ip === ip)?.external
  if (fromTopDst) return fromTopDst

  const fromTopSrc = result.top_src_ips.find((entry) => entry.ip === ip)?.external
  return fromTopSrc ?? null
}

function aggregateTrafficByCountry(result: AnalysisResult) {
  // Usa i byte delle top destinazioni e completa con i pacchetti dettagliati se disponibili.
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

  useEffect(() => {
    let active = true

    async function loadMap() {
      // La geometria e esterna e leggera: la carichiamo solo nel browser quando serve.
      try {
        setLoading(true)
        setError(null)
        const response = await fetch(WORLD_ATLAS_URL)
        if (!response.ok) throw new Error(`Errore mappa ${response.status}`)
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
          <h2 className="text-base font-semibold text-slate-200">Mappa traffico IP</h2>
          <p className="mt-0.5 text-xs text-slate-500">
            Paesi colorati in base al traffico verso gli IP di destinazione arricchiti
          </p>
        </div>
        <div className="flex gap-4 text-xs text-slate-500">
          <span>{totalCountries} paesi</span>
          <span>Totale: <strong className="text-brand-300">{formatBytes(totalBytes)}</strong></span>
        </div>
      </div>

      {trafficByCountry.size === 0 && (
        <div className="mb-4 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-xs text-amber-100">
          Premi "Analizza con tool esterni" per recuperare i paesi degli IP pubblici e colorare la mappa.
        </div>
      )}

      <div className="relative overflow-hidden rounded-lg border border-slate-700 bg-slate-950">
        {loading ? (
          <div className="flex h-[320px] items-center justify-center text-sm text-slate-500">
            Caricamento mappa mondiale...
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
                  className="transition-colors hover:fill-brand-400"
                  onMouseEnter={() => setHovered(traffic ?? null)}
                  onMouseLeave={() => setHovered(null)}
                >
                  <title>
                    {traffic
                      ? `${traffic.country}: ${formatBytes(traffic.bytes)} verso ${traffic.ips.length} IP`
                      : `${shape.name}: nessun traffico geolocalizzato`}
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
            <p className="text-slate-400">{formatCount(hovered.packets)} pacchetti</p>
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
      </div>
    </div>
  )
}
