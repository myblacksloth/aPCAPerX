/**
 * Floating AI chat widget.
 *
 * The widget keeps its message history in component state, so closing the popup
 * only hides it and never clears the current conversation.
 */
import { useState } from 'react'
import { Bot, Loader2, MessageCircle, Send, X } from 'lucide-react'
import type { AIChatMessage, AIChatResponse, AnalysisResult } from '../types/analysis'

interface AIChatWidgetProps {
  result: AnalysisResult
}

export default function AIChatWidget({ result }: AIChatWidgetProps) {
  const [open, setOpen] = useState(false)
  const [messages, setMessages] = useState<AIChatMessage[]>([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [lastSelectionCount, setLastSelectionCount] = useState<number | null>(null)
  const [modelName, setModelName] = useState<string | null>(null)

  const sendQuestion = async () => {
    const question = input.trim()
    if (!question || loading) return

    const nextMessages: AIChatMessage[] = [...messages, { role: 'user', content: question }]
    setMessages(nextMessages)
    setInput('')
    setError(null)
    setLoading(true)

    try {
      const response = await fetch('/api/ai-chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          question,
          // Send packet metadata only. Raw bytes and layer trees stay in the browser.
          packets: result.packets.map(({ number, timestamp, src_ip, dst_ip, protocol, length, src_port, dst_port, info }) => ({
            number,
            timestamp,
            src_ip,
            dst_ip,
            protocol,
            length,
            src_port,
            dst_port,
            info,
          })),
          history: messages.slice(-8),
        }),
      })

      if (!response.ok) {
        const data = await response.json().catch(() => ({}))
        const detail = typeof data.detail === 'string' ? data.detail : null
        throw new Error(detail ?? `AI error ${response.status}: ${response.statusText}`)
      }

      const data: AIChatResponse = await response.json()
      setLastSelectionCount(data.selected_packet_count)
      setModelName(data.model)
      setMessages([...nextMessages, { role: 'assistant', content: data.answer }])
    } catch (err) {
      setError(err instanceof Error ? err.message : 'AI assistant is unavailable.')
      setMessages(nextMessages)
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="fixed bottom-14 right-5 z-50 flex h-14 w-14 items-center justify-center rounded-full border border-brand-300/40 bg-brand-500 text-white shadow-2xl shadow-brand-950/50 transition hover:bg-brand-400"
        aria-label="Open AI chat"
      >
        <MessageCircle className="h-6 w-6" />
      </button>

      {open && (
        <section className="fixed bottom-32 right-5 z-50 flex h-[560px] w-[min(420px,calc(100vw-2rem))] flex-col overflow-hidden rounded-xl border border-slate-700 bg-slate-900 shadow-2xl">
          <header className="flex items-center justify-between border-b border-slate-700 bg-slate-800 px-4 py-3">
            <div className="flex items-center gap-2">
              <Bot className="h-4 w-4 text-brand-300" />
              <div>
                <h2 className="text-sm font-semibold text-white">AI packet assistant</h2>
                <p className="text-[11px] text-slate-500">
                  {modelName ? `${modelName}` : 'Local lightweight model'}
                  {lastSelectionCount !== null ? ` · ${lastSelectionCount} selected packets` : ''}
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setOpen(false)}
              className="rounded-md p-1 text-slate-400 hover:bg-slate-700 hover:text-slate-100"
              aria-label="Close AI chat"
            >
              <X className="h-4 w-4" />
            </button>
          </header>

          <div className="flex-1 space-y-3 overflow-y-auto p-4">
            {messages.length === 0 && (
              <div className="rounded-lg border border-slate-700 bg-slate-950/40 p-3 text-sm text-slate-400">
                Ask about an IP, port, protocol, DNS query, HTTP host, TLS SNI, or suspicious flow.
                The backend will send only matching packets to the model.
              </div>
            )}

            {messages.map((message, index) => (
              <div
                key={`${message.role}-${index}`}
                className={`rounded-lg px-3 py-2 text-sm ${
                  message.role === 'user'
                    ? 'ml-8 bg-brand-500 text-white'
                    : 'mr-8 border border-slate-700 bg-slate-800 text-slate-200'
                }`}
              >
                <p className="whitespace-pre-wrap">{message.content}</p>
              </div>
            ))}

            {loading && (
              <div className="mr-8 flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-300">
                <Loader2 className="h-4 w-4 animate-spin text-brand-300" />
                Analyzing selected packets...
              </div>
            )}

            {error && (
              <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200">
                {error}
              </div>
            )}
          </div>

          <div className="border-t border-slate-700 p-3">
            <div className="flex items-end gap-2">
              <textarea
                value={input}
                onChange={(event) => setInput(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' && !event.shiftKey) {
                    event.preventDefault()
                    sendQuestion()
                  }
                }}
                placeholder="Ask about this PCAP..."
                className="max-h-28 min-h-11 flex-1 resize-none rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder-slate-600 outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500/30"
                disabled={loading}
              />
              <button
                type="button"
                onClick={sendQuestion}
                disabled={loading || !input.trim()}
                className="flex h-11 w-11 items-center justify-center rounded-lg bg-brand-500 text-white transition hover:bg-brand-400 disabled:cursor-not-allowed disabled:opacity-40"
                aria-label="Send question"
              >
                {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
              </button>
            </div>
          </div>
        </section>
      )}
    </>
  )
}
