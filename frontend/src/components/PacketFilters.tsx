/**
 * Wireshark-style filter panel.
 *
 * Provides both a text input for users who know the syntax and GUI controls
 * to quickly compose filters on the most common packet fields.
 */
import { useState } from 'react'
import { Filter, Plus, RotateCcw, X } from 'lucide-react'

interface PacketFiltersProps {
  filter: string
  filteredCount: number
  totalCount: number
  error: string | null
  onFilterChange: (filter: string) => void
}

type GuiField = 'ip.addr' | 'ip.src' | 'ip.dst' | 'protocol' | 'tcp.port' | 'udp.port' | 'frame.len' | 'info'
type GuiOperator = '==' | '!=' | 'contains' | '>' | '>=' | '<' | '<='

const EXAMPLES = [
  'ip.addr == 8.8.8.8',
  'dns or http',
  'tcp.port == 443 and ip.dst == 1.1.1.1',
  'frame.len > 1000',
  'info contains "Query"',
  'not arp',
]

export default function PacketFilters({
  filter,
  filteredCount,
  totalCount,
  error,
  onFilterChange,
}: PacketFiltersProps) {
  const [field, setField] = useState<GuiField>('ip.addr')
  const [operator, setOperator] = useState<GuiOperator>('==')
  const [value, setValue] = useState('')
  const [joiner, setJoiner] = useState<'and' | 'or'>('and')

  const addGuiFilter = () => {
    // Adds the GUI-built filter to the existing query.
    const cleanValue = value.trim()
    if (!cleanValue) return

    const quotedValue = /\s/.test(cleanValue) ? `"${cleanValue.replace(/"/g, '\\"')}"` : cleanValue
    const clause = `${field} ${operator} ${quotedValue}`
    onFilterChange(filter.trim() ? `${filter.trim()} ${joiner} ${clause}` : clause)
    setValue('')
  }

  return (
    <div className="card">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-brand-400" />
          <div>
            <h2 className="text-base font-semibold text-slate-200">Packet filters</h2>
            <p className="text-xs text-slate-500">Wireshark-style syntax applied to packet views</p>
          </div>
        </div>
        <div className="text-xs text-slate-500">
          {filteredCount.toLocaleString('it-IT')} / {totalCount.toLocaleString('it-IT')} packets
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-[1fr_auto]">
        <div>
          <input
            type="text"
            value={filter}
            onChange={(event) => onFilterChange(event.target.value)}
            placeholder='Example: ip.addr == 8.8.8.8 and dns'
            className={`w-full rounded-lg border bg-slate-900 px-3 py-2 font-mono text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:ring-1 ${
              error
                ? 'border-red-500/60 focus:border-red-500 focus:ring-red-500/30'
                : 'border-slate-700 focus:border-brand-500 focus:ring-brand-500/30'
            }`}
          />
          {error ? (
            <p className="mt-2 text-xs text-red-300">{error}</p>
          ) : (
            <p className="mt-2 text-xs text-slate-500">
              Use `and`, `or`, `not`, parentheses, and operators `==`, `!=`, `contains`, `&gt;`, `&gt;=`, `&lt;`, `&lt;=`.
            </p>
          )}
        </div>

        <button
          type="button"
          onClick={() => onFilterChange('')}
          disabled={!filter.trim()}
          className="flex items-center justify-center gap-2 rounded-lg bg-slate-700 px-4 py-2 text-sm text-slate-200 transition-colors hover:bg-slate-600 disabled:cursor-not-allowed disabled:opacity-40"
        >
          <RotateCcw className="h-4 w-4" />
          Reset
        </button>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-2 lg:grid-cols-[120px_180px_120px_1fr_auto]">
        <select
          value={joiner}
          onChange={(event) => setJoiner(event.target.value as 'and' | 'or')}
          className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200"
        >
          <option value="and">AND</option>
          <option value="or">OR</option>
        </select>

        <select
          value={field}
          onChange={(event) => setField(event.target.value as GuiField)}
          className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200"
        >
          <option value="ip.addr">Source or destination IP</option>
          <option value="ip.src">Source IP</option>
          <option value="ip.dst">Destination IP</option>
          <option value="protocol">Protocol</option>
          <option value="tcp.port">TCP port</option>
          <option value="udp.port">UDP port</option>
          <option value="frame.len">Frame length</option>
          <option value="info">Info</option>
        </select>

        <select
          value={operator}
          onChange={(event) => setOperator(event.target.value as GuiOperator)}
          className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200"
        >
          <option value="==">equals</option>
          <option value="!=">not equals</option>
          <option value="contains">contains</option>
          <option value=">">&gt;</option>
          <option value=">=">&gt;=</option>
          <option value="<">&lt;</option>
          <option value="<=">&lt;=</option>
        </select>

        <input
          type="text"
          value={value}
          onChange={(event) => setValue(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter') addGuiFilter()
          }}
          placeholder="Value"
          className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder-slate-600"
        />

        <button
          type="button"
          onClick={addGuiFilter}
          className="flex items-center justify-center gap-2 rounded-lg bg-brand-500 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-brand-600"
        >
          <Plus className="h-4 w-4" />
          Add
        </button>
      </div>

      <div className="mt-4 flex flex-wrap gap-2">
        {EXAMPLES.map((example) => (
          <button
            key={example}
            type="button"
            onClick={() => onFilterChange(example)}
            className="rounded-md border border-slate-700 bg-slate-900 px-2.5 py-1 text-xs font-mono text-slate-400 transition-colors hover:border-slate-600 hover:text-slate-200"
          >
            {example}
          </button>
        ))}
        {filter.trim() && (
          <button
            type="button"
            onClick={() => onFilterChange('')}
            className="flex items-center gap-1 rounded-md border border-red-500/30 bg-red-500/10 px-2.5 py-1 text-xs text-red-200"
          >
            <X className="h-3 w-3" />
            remove filter
          </button>
        )}
      </div>
    </div>
  )
}
