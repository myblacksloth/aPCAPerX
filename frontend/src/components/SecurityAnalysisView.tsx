/**
 * Tab Security avanzata.
 *
 * La vista esegue una seconda analisi opt-in sul traffico completo usando:
 * - metadati pacchetto gia estratti dal backend;
 * - arricchimento IP ottenuto in precedenza dall'utente;
 * - fonti esterne di threat intelligence chiamate solo dopo conferma esplicita.
 */
import { useMemo, useState } from 'react'
import { AlertTriangle, CheckCircle2, ExternalLink, Loader2, ShieldAlert, ShieldCheck, Siren } from 'lucide-react'
import type { AnalysisResult, SecurityAnalysisResponse, SecurityFinding } from '../types/analysis'
import { formatBytes, formatCount } from '../utils/format'

interface SecurityAnalysisViewProps {
  result: AnalysisResult
}

function enrichedIpCount(result: AnalysisResult): number {
  // Conta gli IP con dati esterni gia disponibili; la tab li usa come contesto.
  return Object.values(result.external_ip_info ?? {}).filter((item) => item.status === 'enriched').length
}

function buildSecurityPayload(result: AnalysisResult) {
  // Invia solo i metadati necessari alla correlazione Security, non raw hex o layer completi.
  return {
    packets: result.packets.map((packet) => ({
      number: packet.number,
      timestamp: packet.timestamp,
      src_ip: packet.src_ip,
      dst_ip: packet.dst_ip,
      protocol: packet.protocol,
      length: packet.length,
      src_port: packet.src_port,
      dst_port: packet.dst_port,
      info: packet.info,
    })),
    external_ip_info: result.external_ip_info ?? {},
    max_ips: 80,
  }
}

function severityStyle(severity: string) {
  // Palette di severita simile a una console SOC: critico rosso, medio ambra, informativo blu.
  switch (severity) {
    case 'critical':
      return {
        label: 'Critica',
        badge: 'border-red-400/40 bg-red-500/20 text-red-100',
        bar: 'bg-red-400',
        icon: <Siren className="h-4 w-4 text-red-300" />,
      }
    case 'high':
      return {
        label: 'Alta',
        badge: 'border-orange-400/40 bg-orange-500/20 text-orange-100',
        bar: 'bg-orange-400',
        icon: <ShieldAlert className="h-4 w-4 text-orange-300" />,
      }
    case 'medium':
      return {
        label: 'Media',
        badge: 'border-amber-400/40 bg-amber-500/20 text-amber-100',
        bar: 'bg-amber-400',
        icon: <AlertTriangle className="h-4 w-4 text-amber-300" />,
      }
    case 'low':
      return {
        label: 'Bassa',
        badge: 'border-sky-400/40 bg-sky-500/20 text-sky-100',
        bar: 'bg-sky-400',
        icon: <ShieldCheck className="h-4 w-4 text-sky-300" />,
      }
    default:
      return {
        label: 'Info',
        badge: 'border-slate-500/40 bg-slate-600/30 text-slate-100',
        bar: 'bg-slate-400',
        icon: <CheckCircle2 className="h-4 w-4 text-slate-300" />,
      }
  }
}

function scoreWidth(score: number): string {
  // Limita visivamente lo score tra 0 e 100 per evitare barre fuori layout.
  return `${Math.max(0, Math.min(score, 100))}%`
}

function FindingCard({ finding }: { finding: SecurityFinding }) {
  const style = severityStyle(finding.severity)

  return (
    <section className="rounded-lg border border-slate-700 bg-slate-900/70 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            {style.icon}
            <h3 className="text-sm font-semibold text-white">{finding.title}</h3>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            {finding.category}{finding.ip ? ` - ${finding.ip}` : ''}
          </p>
        </div>
        <span className={`rounded border px-2 py-1 text-xs font-semibold ${style.badge}`}>
          {style.label} - {finding.score}/100
        </span>
      </div>

      <p className="mt-3 text-sm text-slate-300">{finding.description}</p>

      <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-slate-700">
        <div className={`h-full ${style.bar}`} style={{ width: scoreWidth(finding.score) }} />
      </div>

      <div className="mt-3 grid grid-cols-1 gap-3 lg:grid-cols-2">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Evidenze</p>
          <ul className="mt-2 space-y-1.5 text-xs text-slate-300">
            {finding.evidence.slice(0, 6).map((item) => (
              <li key={item} className="flex gap-2">
                <span className="mt-1.5 h-1.5 w-1.5 flex-shrink-0 rounded-full bg-brand-400" />
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Azione consigliata</p>
          <p className="mt-2 text-xs text-slate-300">{finding.recommendation}</p>
          <div className="mt-3 flex flex-wrap gap-2">
            {finding.sources.map((source) => (
              <span key={source} className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300">
                {source}
              </span>
            ))}
            {finding.mitre.map((technique) => (
              <span key={technique} className="rounded border border-violet-500/30 bg-violet-500/10 px-2 py-1 text-[11px] text-violet-100">
                {technique}
              </span>
            ))}
          </div>
        </div>
      </div>
    </section>
  )
}

export default function SecurityAnalysisView({ result }: SecurityAnalysisViewProps) {
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [analysis, setAnalysis] = useState<SecurityAnalysisResponse | null>(null)
  const enriched = enrichedIpCount(result)
  const analysisActive = analysis !== null

  const topAssessments = useMemo(
    () => analysis?.ip_assessments.filter((item) => item.risk_score > 0).slice(0, 25) ?? [],
    [analysis],
  )

  const runAnalysis = async () => {
    // La chiamata reale parte solo da qui, dopo conferma esplicita nel popup.
    setConfirmOpen(false)
    setLoading(true)
    setError(null)

    try {
      const response = await fetch('/api/security-analysis', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(buildSecurityPayload(result)),
      })

      if (!response.ok) {
        const data = await response.json().catch(() => ({}))
        throw new Error(data.detail ?? `Errore ${response.status}: ${response.statusText}`)
      }

      const payload: SecurityAnalysisResponse = await response.json()
      setAnalysis(payload)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Errore sconosciuto durante l'analisi Security")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="card">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-slate-200">Security avanzata</h2>
            <p className="mt-1 max-w-3xl text-xs text-slate-500">
              Analisi professionale del traffico con scoring, threat intelligence, CVE, IOC, porte sensibili,
              anomalie di relazione e raccomandazioni operative.
            </p>
          </div>
          <button
            onClick={() => {
              // Dopo un'analisi riuscita il report resta attivo e non viene ricalcolato.
              if (!analysisActive) setConfirmOpen(true)
            }}
            disabled={loading || enriched === 0 || analysisActive}
            className={`flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold transition-colors ${
              analysisActive
                ? 'cursor-not-allowed border border-emerald-500/30 bg-emerald-500/15 text-emerald-100'
                : loading || enriched === 0
                ? 'cursor-not-allowed bg-slate-700 text-slate-400'
                : 'bg-red-500/90 text-white hover:bg-red-500'
            }`}
          >
            {analysisActive
              ? <CheckCircle2 className="h-4 w-4" />
              : loading
                ? <Loader2 className="h-4 w-4 animate-spin" />
                : <ShieldAlert className="h-4 w-4" />}
            {analysisActive ? 'Analisi attiva' : loading ? 'Analisi in corso...' : 'Analisi di sicurezza'}
          </button>
        </div>

        {enriched === 0 && (
          <div className="mt-4 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-100">
            Esegui prima "Analizza con tool esterni": la tab Security avanzata usa quei dati per evitare richieste inutili
            e aumentare la qualita della correlazione.
          </div>
        )}

        {error && (
          <div className="mt-4 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-100">
            {error}
          </div>
        )}

        {analysisActive && (
          <div className="mt-4 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-100">
            Analisi Security attiva: i risultati sono già stati recuperati e il comando è stato disabilitato.
          </div>
        )}
      </div>

      {analysis && (
        <>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-6">
            {[
              ['Critiche', analysis.summary.critical, 'text-red-300'],
              ['Alte', analysis.summary.high, 'text-orange-300'],
              ['Medie', analysis.summary.medium, 'text-amber-300'],
              ['Basse', analysis.summary.low, 'text-sky-300'],
              ['Finding', analysis.summary.total_findings, 'text-white'],
              ['IP pubblici', analysis.summary.analyzed_public_ips, 'text-slate-200'],
            ].map(([label, value, color]) => (
              <div key={label} className="rounded-lg border border-slate-700 bg-slate-800 p-4">
                <p className="text-xs text-slate-500">{label}</p>
                <p className={`mt-1 text-2xl font-bold ${color}`}>{value}</p>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1.3fr_0.7fr]">
            <div className="space-y-3">
              {analysis.findings.length === 0 ? (
                <div className="card border-emerald-500/20 bg-emerald-500/10 text-sm text-emerald-100">
                  Nessun finding rilevante con le fonti e i pacchetti disponibili.
                </div>
              ) : (
                analysis.findings.map((finding) => <FindingCard key={finding.id} finding={finding} />)
              )}
            </div>

            <aside className="space-y-4">
              <div className="card">
                <h3 className="text-sm font-semibold text-slate-200">Fonti usate</h3>
                <div className="mt-3 space-y-2">
                  {analysis.sources.map((source) => (
                    <div key={source.source} className="rounded-lg bg-slate-900/70 p-3">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-semibold text-slate-200">{source.source}</span>
                        <span className="rounded bg-slate-700 px-2 py-0.5 text-[11px] text-slate-300">{source.status}</span>
                      </div>
                      <p className="mt-1 text-xs text-slate-500">{source.detail}</p>
                    </div>
                  ))}
                </div>
              </div>

              <div className="card overflow-hidden">
                <h3 className="text-sm font-semibold text-slate-200">IP più rischiosi</h3>
                <div className="mt-3 overflow-x-auto">
                  <table className="min-w-full text-xs">
                    <thead className="text-left text-slate-500">
                      <tr>
                        <th className="pb-2 pr-3">IP</th>
                        <th className="pb-2 pr-3">Score</th>
                        <th className="pb-2 pr-3">Traffico</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-700/70">
                      {topAssessments.map((item) => (
                        <tr key={item.ip}>
                          <td className="py-2 pr-3 font-mono text-slate-200">
                            {item.ip}
                            <div className="mt-0.5 text-[11px] text-slate-500">{item.country ?? item.as_name ?? 'n/d'}</div>
                          </td>
                          <td className="py-2 pr-3 text-slate-200">{item.risk_score}</td>
                          <td className="py-2 pr-3 text-slate-400">
                            {formatCount(item.packets)} pkt
                            <div className="text-[11px] text-slate-500">{formatBytes(item.bytes_in + item.bytes_out)}</div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {analysis.errors.length > 0 && (
                <div className="card border-amber-500/20">
                  <h3 className="text-sm font-semibold text-amber-100">Errori non bloccanti</h3>
                  <ul className="mt-2 space-y-1 text-xs text-amber-100/80">
                    {analysis.errors.slice(0, 8).map((item) => <li key={item}>{item}</li>)}
                  </ul>
                </div>
              )}
            </aside>
          </div>
        </>
      )}

      {confirmOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 px-4">
          <div className="w-full max-w-lg rounded-xl border border-slate-700 bg-slate-900 p-5 shadow-2xl">
            <div className="flex items-start gap-3">
              <ShieldAlert className="mt-0.5 h-5 w-5 flex-shrink-0 text-red-300" />
              <div>
                <h3 className="text-base font-semibold text-white">Conferma uso di servizi esterni</h3>
                <p className="mt-2 text-sm text-slate-300">
                  L'analisi inviera indirizzi IP pubblici e metadati di traffico a servizi esterni di threat intelligence:
                  Shodan InternetDB, Feodo Tracker e URLhaus se configurato con Auth-Key sul backend.
                </p>
                <p className="mt-2 text-xs text-slate-500">
                  IP privati/locali non vengono interrogati. I dati sono usati solo per produrre finding, score e raccomandazioni.
                </p>
                <a
                  href="https://book.shodan.io/developer-apis/internetdb/"
                  target="_blank"
                  rel="noreferrer"
                  className="mt-3 inline-flex items-center gap-1 text-xs text-brand-300 hover:text-brand-200"
                >
                  Documentazione InternetDB <ExternalLink className="h-3 w-3" />
                </a>
              </div>
            </div>

            <div className="mt-5 flex justify-end gap-2">
              <button
                onClick={() => setConfirmOpen(false)}
                className="rounded-lg bg-slate-700 px-4 py-2 text-sm text-slate-200 hover:bg-slate-600"
              >
                Annulla
              </button>
              <button
                onClick={runAnalysis}
                className="rounded-lg bg-red-500 px-4 py-2 text-sm font-semibold text-white hover:bg-red-400"
              >
                Confermo e analizza
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
