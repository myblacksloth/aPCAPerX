/**
 * Vista TLS analysis.
 *
 * Mostra solo metadati osservabili nel handshake TLS. Il frontend non effettua
 * chiamate esterne e non promette decifratura: contenuti HTTP, payload e dati
 * applicativi cifrati restano non ispezionabili senza chiavi.
 */
import { useMemo, useState } from 'react'
import { AlertTriangle, Fingerprint, Filter, KeyRound, Lock, ShieldCheck } from 'lucide-react'
import type { AnalysisResult, TLSAnalysisResult, TLSEntry } from '../types/analysis'
import { formatCount } from '../utils/format'

interface TLSAnalysisViewProps {
  result: AnalysisResult
}

function emptyTls(): TLSAnalysisResult {
  // Fallback per report generati da backend precedenti alla sezione `tls`.
  return {
    stats: {
      total_connections: 0,
      with_sni: 0,
      with_certificate: 0,
      anomalous_connections: 0,
      expired_certificates: 0,
      legacy_tls: 0,
    },
    connections: [],
    top_sni: [],
    top_issuers: [],
    top_versions: [],
    limitations: [],
  }
}

function endpoint(ip: string | null, port: number | null) {
  // Formatta endpoint IP:porta mantenendo leggibile il valore mancante.
  return ip ? `${ip}${port ? `:${port}` : ''}` : 'n/d'
}

function anomalyBadge(entry: TLSEntry) {
  // Evidenzia le connessioni problematiche senza trasformare segnali euristici in certezze.
  if (entry.anomalies.length === 0) {
    return <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 text-[11px] text-emerald-100">OK</span>
  }
  const severe = entry.anomalies.some((item) => item.includes('scaduto') || item.includes('TLS vecchio'))
  return (
    <span className={`rounded border px-2 py-1 text-[11px] ${
      severe
        ? 'border-red-500/30 bg-red-500/10 text-red-100'
        : 'border-amber-500/30 bg-amber-500/10 text-amber-100'
    }`}>
      {entry.anomalies.length} alert
    </span>
  )
}

export default function TLSAnalysisView({ result }: TLSAnalysisViewProps) {
  const tls = result.tls ?? emptyTls()
  const [sniFilter, setSniFilter] = useState('')
  const [serverFilter, setServerFilter] = useState('')
  const [versionFilter, setVersionFilter] = useState('all')
  const [anomalyFilter, setAnomalyFilter] = useState('all')

  const versions = useMemo(
    () => ['all', ...new Set(tls.connections.map((entry) => entry.tls_version ?? 'UNKNOWN').sort())],
    [tls.connections],
  )

  const filtered = useMemo(() => {
    // Applica filtri GUI su SNI, server, versione e presenza anomalie.
    const sni = sniFilter.trim().toLowerCase()
    const server = serverFilter.trim().toLowerCase()
    return tls.connections.filter((entry) => {
      if (sni && !(entry.sni ?? '').toLowerCase().includes(sni)) return false
      if (server && !(entry.server_ip ?? '').toLowerCase().includes(server)) return false
      const version = entry.tls_version ?? 'UNKNOWN'
      if (versionFilter !== 'all' && version !== versionFilter) return false
      if (anomalyFilter === 'only' && entry.anomalies.length === 0) return false
      if (anomalyFilter === 'none' && entry.anomalies.length > 0) return false
      return true
    })
  }, [anomalyFilter, serverFilter, sniFilter, tls.connections, versionFilter])

  return (
    <div className="space-y-4">
      <div className="card">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-slate-200">TLS analysis</h2>
            <p className="mt-1 max-w-3xl text-xs text-slate-500">
              Metadati SSL/TLS osservabili dal PCAP: SNI, versione, cipher, ALPN, certificati, JA3 e anomalie. Nessuna decifratura del payload.
            </p>
          </div>
          <div className="flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-100">
            <ShieldCheck className="h-4 w-4" />
            Metadata only
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-6">
        {[
          ['Connessioni', tls.stats.total_connections, 'text-white'],
          ['Con SNI', tls.stats.with_sni, 'text-sky-300'],
          ['Con cert', tls.stats.with_certificate, 'text-emerald-300'],
          ['Anomalie', tls.stats.anomalous_connections, 'text-amber-300'],
          ['Cert scaduti', tls.stats.expired_certificates, 'text-red-300'],
          ['TLS legacy', tls.stats.legacy_tls, 'text-red-300'],
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
              <h3 className="text-sm font-semibold text-slate-200">Handshake e certificati</h3>
              <p className="mt-0.5 text-xs text-slate-500">{filtered.length} righe filtrate su {tls.connections.length}</p>
            </div>
          </div>

          <div className="mb-4 grid grid-cols-1 gap-2 lg:grid-cols-[1fr_1fr_150px_170px]">
            <div className="relative">
              <Filter className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
              <input
                value={sniFilter}
                onChange={(event) => setSniFilter(event.target.value)}
                placeholder="Filtra SNI..."
                className="w-full rounded-lg border border-slate-700 bg-slate-900 py-2 pl-9 pr-3 text-sm text-slate-100 placeholder-slate-600"
              />
            </div>
            <input
              value={serverFilter}
              onChange={(event) => setServerFilter(event.target.value)}
              placeholder="Filtra server IP..."
              className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder-slate-600"
            />
            <select value={versionFilter} onChange={(event) => setVersionFilter(event.target.value)} className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200">
              {versions.map((item) => <option key={item} value={item}>{item === 'all' ? 'Versione' : item}</option>)}
            </select>
            <select value={anomalyFilter} onChange={(event) => setAnomalyFilter(event.target.value)} className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200">
              <option value="all">Tutte</option>
              <option value="only">Solo anomalie</option>
              <option value="none">Senza anomalie</option>
            </select>
          </div>

          <div className="overflow-x-auto">
            <table className="min-w-full text-xs">
              <thead className="text-left text-slate-500">
                <tr>
                  <th className="pb-2 pr-3">SNI / Server</th>
                  <th className="pb-2 pr-3">TLS</th>
                  <th className="pb-2 pr-3">Certificato</th>
                  <th className="pb-2 pr-3">Fingerprint</th>
                  <th className="pb-2 pr-3">Anomalie</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/70">
                {filtered.slice(0, 300).map((entry) => (
                  <tr key={`${entry.packet_number}-${entry.client_ip}-${entry.server_ip}-${entry.server_port}`}>
                    <td className="py-3 pr-3 align-top">
                      <div className="font-mono text-slate-100">{entry.sni ?? 'SNI n/d'}</div>
                      <div className="mt-1 font-mono text-slate-500">{endpoint(entry.server_ip, entry.server_port)}</div>
                      <div className="mt-0.5 font-mono text-slate-600">client {endpoint(entry.client_ip, entry.client_port)}</div>
                      {entry.partial && <div className="mt-1 text-amber-200">record parziale</div>}
                    </td>
                    <td className="py-3 pr-3 align-top text-slate-400">
                      <div>{entry.tls_version ?? 'versione n/d'}</div>
                      <div className="mt-1 max-w-xs truncate font-mono text-slate-500">{entry.cipher_suite ?? 'cipher n/d'}</div>
                      <div className="mt-1 text-slate-500">ALPN: {entry.alpn.length ? entry.alpn.join(', ') : 'n/d'}</div>
                    </td>
                    <td className="py-3 pr-3 align-top text-slate-400">
                      <div className="max-w-sm truncate">Subject: {entry.cert_subject ?? 'n/d'}</div>
                      <div className="mt-1 max-w-sm truncate text-slate-500">Issuer: {entry.cert_issuer ?? 'n/d'}</div>
                      <div className="mt-1 text-slate-500">Validità: {entry.cert_not_before ?? 'n/d'} → {entry.cert_not_after ?? 'n/d'}</div>
                    </td>
                    <td className="py-3 pr-3 align-top text-slate-400">
                      <div className="max-w-xs truncate font-mono">SHA256 {entry.cert_sha256 ?? 'n/d'}</div>
                      <div className="mt-1 max-w-xs truncate font-mono text-slate-500">JA3 {entry.ja3 ?? 'n/d'}</div>
                      <div className="mt-1 max-w-xs truncate font-mono text-slate-500">JA3S {entry.ja3s ?? 'n/d'}</div>
                    </td>
                    <td className="py-3 pr-3 align-top">
                      {anomalyBadge(entry)}
                      {entry.anomalies.length > 0 && (
                        <div className="mt-2 flex max-w-xs flex-wrap gap-1">
                          {entry.anomalies.map((item) => (
                            <span key={item} className="rounded bg-slate-700/70 px-2 py-1 text-[11px] text-slate-200">{item}</span>
                          ))}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {filtered.length === 0 && (
              <p className="py-8 text-center text-sm text-slate-500">Nessuna connessione TLS corrisponde ai filtri.</p>
            )}
          </div>
        </section>

        <aside className="space-y-4">
          <div className="card">
            <div className="mb-3 flex items-center gap-2">
              <Lock className="h-4 w-4 text-brand-300" />
              <h3 className="text-sm font-semibold text-slate-200">SNI più frequenti</h3>
            </div>
            <div className="space-y-2">
              {tls.top_sni.slice(0, 10).map((item) => (
                <div key={item.value} className="flex items-center justify-between gap-3 rounded-lg bg-slate-900/70 px-3 py-2">
                  <span className="truncate font-mono text-xs text-slate-200">{item.value}</span>
                  <span className="text-xs text-slate-500">{formatCount(item.count)}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <div className="mb-3 flex items-center gap-2">
              <KeyRound className="h-4 w-4 text-brand-300" />
              <h3 className="text-sm font-semibold text-slate-200">Versioni TLS</h3>
            </div>
            <div className="space-y-2">
              {tls.top_versions.map((item) => (
                <div key={item.value} className="flex items-center justify-between gap-3 rounded-lg bg-slate-900/70 px-3 py-2">
                  <span className="text-xs text-slate-200">{item.value}</span>
                  <span className="text-xs text-slate-500">{formatCount(item.count)}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <div className="mb-3 flex items-center gap-2">
              <Fingerprint className="h-4 w-4 text-brand-300" />
              <h3 className="text-sm font-semibold text-slate-200">Issuer frequenti</h3>
            </div>
            <div className="space-y-2">
              {tls.top_issuers.slice(0, 10).map((item) => (
                <div key={item.value} className="rounded-lg bg-slate-900/70 px-3 py-2">
                  <div className="truncate text-xs text-slate-200">{item.value}</div>
                  <div className="mt-1 text-xs text-slate-500">{formatCount(item.count)} certificati</div>
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
              {tls.limitations.map((item) => <li key={item}>{item}</li>)}
            </ul>
          </div>
        </aside>
      </div>
    </div>
  )
}
