/**
 * Pannello Security basato sulle informazioni gia raccolte sugli IP.
 *
 * Le segnalazioni sono euristiche: evidenziano connessioni potenzialmente
 * rischiose usando GeoIP, ASN, flag proxy/hosting, porte, protocolli e volume.
 * Non sostituiscono una threat intelligence con blacklist dedicate.
 */
import { AlertTriangle, ShieldAlert, ShieldCheck } from 'lucide-react'
import type { AnalysisResult, IPExternalInfo, IPServiceEntry } from '../types/analysis'
import { formatBytes, formatCount } from '../utils/format'

interface SecurityPanelProps {
  result: AnalysisResult
}

interface SecurityFinding {
  ip: string
  severity: 'high' | 'medium' | 'low'
  score: number
  title: string
  details: string[]
  bytes: number
  packets: number
  external: IPExternalInfo | null
}

const CLEAR_TEXT_SERVICES = new Set(['HTTP', 'FTP', 'FTP-DATA', 'Telnet', 'SMTP', 'POP3', 'IMAP'])
const REMOTE_ADMIN_SERVICES = new Set(['SSH', 'RDP', 'VNC', 'SMB', 'Telnet'])
const DATABASE_SERVICES = new Set(['MySQL', 'PostgreSQL', 'Redis', 'MongoDB', 'MSSQL', 'Oracle'])
const SUSPICIOUS_PORTS = new Set([23, 2323, 3389, 5900, 445, 135, 139, 1433, 1521, 3306, 5432, 6379, 27017])

function getExternalInfo(result: AnalysisResult, ip: string): IPExternalInfo | null {
  // Recupera i dati esterni dalla mappa globale o dalle top list arricchite.
  return (
    result.external_ip_info?.[ip]
    ?? result.top_dst_ips.find((entry) => entry.ip === ip)?.external
    ?? result.top_src_ips.find((entry) => entry.ip === ip)?.external
    ?? null
  )
}

function servicesForIp(result: AnalysisResult, ip: string): IPServiceEntry[] {
  // Riunisce i servizi osservati per l'IP nelle top sorgenti/destinazioni.
  const services = [
    ...(result.top_dst_ips.find((entry) => entry.ip === ip)?.services ?? []),
    ...(result.top_src_ips.find((entry) => entry.ip === ip)?.services ?? []),
  ]

  const seen = new Set<string>()
  return services.filter((service) => {
    const key = `${service.service}-${service.port ?? 'none'}-${service.protocol}-${service.direction}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

function trafficToDestinations(result: AnalysisResult) {
  // Calcola traffico verso IP destinazione usando le top destination e i pacchetti disponibili.
  const traffic = new Map<string, { bytes: number; packets: number }>()

  for (const entry of result.top_dst_ips) {
    traffic.set(entry.ip, { bytes: entry.bytes, packets: entry.count })
  }

  for (const packet of result.packets) {
    if (!packet.dst_ip || traffic.has(packet.dst_ip)) continue
    const current = traffic.get(packet.dst_ip) ?? { bytes: 0, packets: 0 }
    current.bytes += packet.length
    current.packets += 1
    traffic.set(packet.dst_ip, current)
  }

  return traffic
}

function severityFromScore(score: number): SecurityFinding['severity'] {
  // Soglie semplici per distinguere priorita operative.
  if (score >= 70) return 'high'
  if (score >= 35) return 'medium'
  return 'low'
}

function buildFinding(result: AnalysisResult, ip: string, bytes: number, packets: number, maxBytes: number): SecurityFinding | null {
  const external = getExternalInfo(result, ip)
  const services = servicesForIp(result, ip)
  const details: string[] = []
  let score = 0

  if (external?.proxy) {
    score += 35
    details.push('Il servizio GeoIP segnala proxy/VPN: possibile anonimizzazione o relay.')
  }

  if (external?.hosting) {
    score += 20
    details.push('IP associato a hosting/datacenter: destinazione comune per C2, scansioni o infrastrutture temporanee.')
  }

  if (external?.status === 'error') {
    score += 15
    details.push('I servizi esterni non hanno restituito dati affidabili per questo IP.')
  }

  const observedServices = services.map((service) => service.service)
  const observedPorts = services.map((service) => service.port).filter((port): port is number => port !== null)

  const clearText = observedServices.filter((service) => CLEAR_TEXT_SERVICES.has(service))
  if (clearText.length > 0) {
    score += 25
    details.push(`Traffico verso servizi non cifrati: ${[...new Set(clearText)].join(', ')}.`)
  }

  const remoteAdmin = observedServices.filter((service) => REMOTE_ADMIN_SERVICES.has(service))
  if (remoteAdmin.length > 0) {
    score += 30
    details.push(`Servizi di amministrazione remota osservati: ${[...new Set(remoteAdmin)].join(', ')}.`)
  }

  const databases = observedServices.filter((service) => DATABASE_SERVICES.has(service))
  if (databases.length > 0) {
    score += 30
    details.push(`Connessione verso servizi database: ${[...new Set(databases)].join(', ')}.`)
  }

  const suspiciousPorts = observedPorts.filter((port) => SUSPICIOUS_PORTS.has(port))
  if (suspiciousPorts.length > 0) {
    score += 20
    details.push(`Porte sensibili osservate: ${[...new Set(suspiciousPorts)].join(', ')}.`)
  }

  if (maxBytes > 0 && bytes / maxBytes >= 0.75 && bytes > 100_000) {
    score += 20
    details.push('Volume di traffico elevato rispetto alle altre destinazioni.')
  }

  if (external?.country && external.country_code && !['IT', 'EU'].includes(external.country_code)) {
    score += 5
    details.push(`Destinazione geolocalizzata fuori dal contesto locale: ${external.country} (${external.country_code}).`)
  }

  if (details.length === 0) return null

  const titleParts = [
    external?.as_name,
    external?.country_code,
    observedServices.slice(0, 2).join('/'),
  ].filter(Boolean)

  return {
    ip,
    severity: severityFromScore(score),
    score,
    title: titleParts.length > 0 ? titleParts.join(' - ') : 'Connessione da verificare',
    details,
    bytes,
    packets,
    external,
  }
}

function buildFindings(result: AnalysisResult) {
  // Produce i finding ordinati per rischio e volume.
  const traffic = trafficToDestinations(result)
  const maxBytes = Math.max(...[...traffic.values()].map((item) => item.bytes), 0)

  return [...traffic.entries()]
    .map(([ip, item]) => buildFinding(result, ip, item.bytes, item.packets, maxBytes))
    .filter((finding): finding is SecurityFinding => finding !== null)
    .sort((a, b) => b.score - a.score || b.bytes - a.bytes)
    .slice(0, 12)
}

function severityStyles(severity: SecurityFinding['severity']) {
  // Colori coerenti con il livello di priorita.
  if (severity === 'high') {
    return {
      icon: <ShieldAlert className="h-4 w-4 text-red-300" />,
      badge: 'border-red-500/30 bg-red-500/10 text-red-200',
      label: 'Alta',
    }
  }
  if (severity === 'medium') {
    return {
      icon: <AlertTriangle className="h-4 w-4 text-amber-300" />,
      badge: 'border-amber-500/30 bg-amber-500/10 text-amber-200',
      label: 'Media',
    }
  }
  return {
    icon: <ShieldCheck className="h-4 w-4 text-sky-300" />,
    badge: 'border-sky-500/30 bg-sky-500/10 text-sky-200',
    label: 'Bassa',
  }
}

export default function SecurityPanel({ result }: SecurityPanelProps) {
  const findings = buildFindings(result)
  const highCount = findings.filter((finding) => finding.severity === 'high').length
  const mediumCount = findings.filter((finding) => finding.severity === 'medium').length
  const enrichedCount = Object.values(result.external_ip_info ?? {}).filter((item) => item.status === 'enriched').length

  return (
    <div className="card">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-slate-200">Security</h2>
          <p className="mt-0.5 text-xs text-slate-500">
            Evidenze euristiche basate su IP, servizi, volume e arricchimento esterno
          </p>
        </div>
        <div className="flex gap-4 text-xs text-slate-500">
          <span><strong className="text-red-300">{highCount}</strong> alte</span>
          <span><strong className="text-amber-300">{mediumCount}</strong> medie</span>
          <span>{enrichedCount} IP arricchiti</span>
        </div>
      </div>

      {enrichedCount === 0 && (
        <div className="mb-4 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-xs text-amber-100">
          Premi "Analizza con tool esterni" per aumentare la precisione delle segnalazioni Security.
        </div>
      )}

      {findings.length === 0 ? (
        <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/10 px-4 py-4 text-sm text-emerald-100">
          Nessuna connessione rischiosa evidente con le informazioni disponibili.
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
          {findings.map((finding) => {
            const styles = severityStyles(finding.severity)
            return (
              <section key={finding.ip} className="rounded-lg border border-slate-700 bg-slate-900/60 p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      {styles.icon}
                      <p className="font-mono text-sm font-semibold text-white">{finding.ip}</p>
                    </div>
                    <p className="mt-1 text-xs text-slate-400">{finding.title}</p>
                  </div>
                  <span className={`rounded border px-2 py-1 text-xs font-semibold ${styles.badge}`}>
                    {styles.label} - score {finding.score}
                  </span>
                </div>

                <div className="mt-3 flex flex-wrap gap-3 text-xs text-slate-500">
                  <span>{formatBytes(finding.bytes)}</span>
                  <span>{formatCount(finding.packets)} pacchetti</span>
                  {finding.external?.country && (
                    <span>{finding.external.country}{finding.external.country_code ? ` (${finding.external.country_code})` : ''}</span>
                  )}
                  {finding.external?.asn && <span>AS{finding.external.asn}</span>}
                </div>

                <ul className="mt-3 space-y-1.5 text-xs text-slate-300">
                  {finding.details.map((detail) => (
                    <li key={detail} className="flex gap-2">
                      <span className="mt-1 h-1.5 w-1.5 flex-shrink-0 rounded-full bg-brand-400" />
                      <span>{detail}</span>
                    </li>
                  ))}
                </ul>
              </section>
            )
          })}
        </div>
      )}
    </div>
  )
}
