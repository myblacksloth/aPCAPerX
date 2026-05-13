import type { AnalysisResult } from '../types/analysis'

function escapeRegExp(value: string): string {
  // Escape user-saved IP text before building a replacement regex.
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function replaceAliases(value: string, aliases: Record<string, string>): string {
  // Replace exact IP text wherever a UI string embeds it, such as "ip:port".
  return Object.entries(aliases).reduce((current, [ip, hostname]) => {
    if (!ip || !hostname) return current
    return current.replace(new RegExp(escapeRegExp(ip), 'g'), hostname)
  }, value)
}

function aliasValue(value: unknown, aliases: Record<string, string>, keyName = ''): unknown {
  // Recursively clone report data for display while preserving host_aliases itself.
  if (typeof value === 'string') return replaceAliases(value, aliases)
  if (Array.isArray(value)) return value.map((item) => aliasValue(item, aliases))
  if (value && typeof value === 'object') {
    const output: Record<string, unknown> = {}
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      if (keyName === 'host_aliases' || key === 'host_aliases') {
        output[key] = child
      } else {
        const aliasedKey = replaceAliases(key, aliases)
        output[aliasedKey] = aliasValue(child, aliases, key)
      }
    }
    return output
  }
  return value
}

export function applyHostAliases(result: AnalysisResult): AnalysisResult {
  // Build a presentation-only report; the original report remains IP-based for saving and editing aliases.
  const aliases = result.host_aliases ?? {}
  if (Object.keys(aliases).length === 0) return result
  return aliasValue(result, aliases) as AnalysisResult
}

export function collectAliasableIps(result: AnalysisResult): string[] {
  // Collect IPs from whole-report structures, especially backend flows that cover the full PCAP.
  const ips = new Set<string>()
  const add = (value?: string | null) => {
    if (value && /^\d{1,3}(\.\d{1,3}){3}$|:/.test(value)) ips.add(value)
  }

  result.top_src_ips.forEach((entry) => add(entry.ip))
  result.top_dst_ips.forEach((entry) => add(entry.ip))
  result.conversations.forEach((conversation) => {
    add(conversation.src_ip)
    add(conversation.dst_ip)
  })
  result.flows?.forEach((flow) => {
    add(flow.src_ip)
    add(flow.dst_ip)
  })
  result.follow_streams?.forEach((stream) => {
    add(stream.src_ip)
    add(stream.dst_ip)
  })
  result.packets.forEach((packet) => {
    add(packet.src_ip)
    add(packet.dst_ip)
  })
  result.dns?.queries.forEach((query) => {
    add(query.client)
    add(query.resolver)
    query.answer_ips.forEach(add)
  })
  result.http?.requests.forEach((request) => {
    add(request.client_ip)
    add(request.server_ip)
  })
  result.tls?.connections.forEach((connection) => {
    add(connection.client_ip)
    add(connection.server_ip)
  })

  return [...ips].sort((left, right) => left.localeCompare(right, undefined, { numeric: true }))
}
