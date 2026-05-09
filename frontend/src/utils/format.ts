/**
 * Utility functions for formatting values in the interface.
 * Ogni funzione trasforma un valore numerico grezzo in una stringa
 * readable by the user.
 */

/**
 * Converte un valore in byte nella rappresentazione umana most appropriata.
 * Es: 1536 → "1.5 KB", 2097152 → "2.0 MB"
 */
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  // Computes the unit index using base-1024 logarithm
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  const value = bytes / Math.pow(1024, i)
  // One decimal is enough for readability
  return `${value.toFixed(1)} ${units[i]}`
}

/**
 * Formats a duration in seconds into a readable format.
 * Es: 0.453 → "0.453 s", 90 → "1m 30s", 3665 → "1h 01m"
 */
export function formatDuration(seconds: number): string {
  if (seconds < 1)  return `${seconds.toFixed(3)} s`
  if (seconds < 60) return `${seconds.toFixed(1)} s`

  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const s = Math.floor(seconds % 60)

  if (h > 0) return `${h}h ${String(m).padStart(2, '0')}m`
  return `${m}m ${String(s).padStart(2, '0')}s`
}

/**
 * Abbrevia un numero grande con suffissi K/M.
 * Es: 1200 → "1.2K", 3500000 → "3.5M"
 */
export function formatCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000)     return `${(n / 1_000).toFixed(1)}K`
  return String(n)
}

/**
 * Restituisce un colore esadecimale fisso per un nome di protocol.
 * I protocolli non in mappa ricevono un colore grigio neutro.
 */
export function protocolColor(protocol: string): string {
  const map: Record<string, string> = {
    HTTP:       '#22c55e',  // verde
    HTTPS:      '#6366f1',  // indigo
    DNS:        '#eab308',  // giallo
    TCP:        '#3b82f6',  // blu
    UDP:        '#06b6d4',  // ciano
    ICMP:       '#f97316',  // arancione
    ARP:        '#ec4899',  // rosa
    SSH:        '#8b5cf6',  // viola
    FTP:        '#f43f5e',  // rosso
    SMTP:       '#84cc16',  // lime
    'SMTP-TLS': '#84cc16',
    SMTPS:      '#84cc16',
    NTP:        '#a78bfa',  // lavanda
    DHCP:       '#fb923c',  // arancione chiaro
    SNMP:       '#38bdf8',  // azzurro
    RDP:        '#f472b6',  // fucsia
    MySQL:      '#4ade80',  // verde chiaro
    PostgreSQL: '#60a5fa',  // blu chiaro
    Redis:      '#ef4444',  // rosso vivo
    SMB:        '#d97706',  // ambra
    IPv6:       '#2dd4bf',  // teal
    Other:      '#64748b',  // grigio slate
  }
  return map[protocol] ?? '#64748b'
}

/**
 * Palette di 10 colori distinti per i grafici a torta e a barre.
 * Usata da Recharts quando si visualizzano most serie di data.
 */
export const CHART_COLORS = [
  '#6366f1', '#22c55e', '#f97316', '#06b6d4', '#eab308',
  '#ec4899', '#8b5cf6', '#3b82f6', '#f43f5e', '#14b8a6',
]
