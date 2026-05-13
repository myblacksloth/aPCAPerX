import { FormEvent, useMemo, useState } from 'react'
import { Save, Tags, Trash2, X } from 'lucide-react'

interface HostAliasesModalProps {
  ips: string[]
  aliases: Record<string, string>
  onClose: () => void
  onSave: (aliases: Record<string, string>) => void
}

export default function HostAliasesModal({ ips, aliases, onClose, onSave }: HostAliasesModalProps) {
  const [selectedIp, setSelectedIp] = useState(ips[0] ?? '')
  const [hostname, setHostname] = useState('')
  const [draftAliases, setDraftAliases] = useState<Record<string, string>>(aliases)

  const visibleIps = useMemo(() => ips.filter((ip) => !draftAliases[ip]), [draftAliases, ips])

  const saveOne = (event: FormEvent) => {
    // Store aliases in a local draft so users can review before persisting the report.
    event.preventDefault()
    const normalizedHostname = hostname.trim()
    if (!selectedIp || !normalizedHostname) return
    setDraftAliases((current) => ({ ...current, [selectedIp]: normalizedHostname }))
    setSelectedIp(visibleIps.find((ip) => ip !== selectedIp) ?? ips[0] ?? '')
    setHostname('')
  }

  const removeOne = (ip: string) => {
    // Removing the key restores the original IP display after the next save.
    setDraftAliases((current) => {
      const next = { ...current }
      delete next[ip]
      return next
    })
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 px-4">
      <section className="w-full max-w-2xl rounded-lg border border-slate-700 bg-slate-900 p-5 shadow-2xl">
        <div className="mb-4 flex items-start justify-between gap-3">
          <div className="flex items-center gap-2 text-white">
            <Tags className="h-5 w-5 text-brand-300" />
            <h2 className="text-base font-semibold">Hostname personalizzati</h2>
          </div>
          <button onClick={onClose} className="rounded-md border border-slate-700 p-1.5 text-slate-300 hover:border-slate-500" aria-label="Chiudi">
            <X className="h-4 w-4" />
          </button>
        </div>

        <form onSubmit={saveOne} className="grid gap-3 md:grid-cols-[1fr_1fr_auto]">
          <select
            value={selectedIp}
            onChange={(event) => setSelectedIp(event.target.value)}
            className="rounded-md border border-slate-600 bg-slate-950 px-3 py-2 text-sm text-slate-100"
          >
            {(visibleIps.length ? visibleIps : ips).map((ip) => (
              <option key={ip} value={ip}>{ip}</option>
            ))}
          </select>
          <input
            value={hostname}
            onChange={(event) => setHostname(event.target.value)}
            placeholder="Hostname, es. my_router"
            className="rounded-md border border-slate-600 bg-slate-950 px-3 py-2 text-sm text-slate-100"
          />
          <button className="inline-flex items-center justify-center gap-2 rounded-md bg-brand-500 px-3 py-2 text-sm font-semibold text-white">
            <Save className="h-4 w-4" />
            Aggiungi
          </button>
        </form>

        <div className="mt-4 max-h-72 space-y-2 overflow-y-auto">
          {Object.keys(draftAliases).length === 0 ? (
            <p className="rounded-md border border-slate-700 bg-slate-950 px-3 py-3 text-sm text-slate-400">
              Nessun hostname personalizzato definito.
            </p>
          ) : (
            Object.entries(draftAliases).sort(([left], [right]) => left.localeCompare(right, undefined, { numeric: true })).map(([ip, alias]) => (
              <div key={ip} className="flex items-center justify-between gap-3 rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm">
                <div className="min-w-0">
                  <div className="font-mono text-slate-400">{ip}</div>
                  <div className="truncate font-medium text-slate-100">{alias}</div>
                </div>
                <button onClick={() => removeOne(ip)} className="rounded-md border border-slate-700 p-2 text-slate-300 hover:border-red-400 hover:text-red-200" aria-label={`Rimuovi ${ip}`}>
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            ))
          )}
        </div>

        <div className="mt-5 flex justify-end gap-2">
          <button onClick={onClose} className="rounded-md border border-slate-600 px-3 py-2 text-sm text-slate-200 hover:border-slate-400">Annulla</button>
          <button onClick={() => onSave(draftAliases)} className="rounded-md bg-brand-500 px-3 py-2 text-sm font-semibold text-white">Salva nel report</button>
        </div>
      </section>
    </div>
  )
}
