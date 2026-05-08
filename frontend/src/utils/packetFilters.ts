/**
 * Parser e valutatore per filtri pacchetto in stile Wireshark.
 *
 * Il filtro viene applicato lato frontend sui pacchetti gia presenti nel report.
 * La sintassi supporta gli operatori piu utili per l'analisi rapida senza
 * tentare di replicare tutta la display-filter language di Wireshark.
 */
import type { PacketEntry } from '../types/analysis'

export interface FilterParseResult {
  /** Funzione pronta per valutare un pacchetto */
  predicate: (packet: PacketEntry) => boolean
  /** Errore leggibile da mostrare in UI, se il filtro non e valido */
  error: string | null
}

type TokenType = 'word' | 'string' | 'number' | 'op' | 'paren'

interface Token {
  type: TokenType
  value: string
}

type AstNode =
  | { type: 'condition'; field: string; operator: string | null; value: string | null }
  | { type: 'and' | 'or'; left: AstNode; right: AstNode }
  | { type: 'not'; child: AstNode }

const COMPARISON_OPERATORS = new Set(['==', '!=', '>', '>=', '<', '<=', 'contains'])
const PROTOCOL_ALIASES: Record<string, string[]> = {
  ip: ['IP', 'IPv4', 'IPv6'],
  tcp: ['TCP'],
  udp: ['UDP'],
  dns: ['DNS', 'MDNS'],
  http: ['HTTP', 'HTTP-Alt'],
  https: ['HTTPS', 'HTTPS-Alt'],
  tls: ['HTTPS', 'TLS'],
  arp: ['ARP'],
  icmp: ['ICMP'],
  ssh: ['SSH'],
}

function tokenize(input: string): Token[] {
  // Tokenizer minimale: riconosce parentesi, operatori, stringhe tra virgolette e parole.
  const tokens: Token[] = []
  let index = 0

  while (index < input.length) {
    const char = input[index]

    if (/\s/.test(char)) {
      index += 1
      continue
    }

    if (char === '(' || char === ')') {
      tokens.push({ type: 'paren', value: char })
      index += 1
      continue
    }

    const twoChars = input.slice(index, index + 2)
    if (['==', '!=', '>=', '<='].includes(twoChars)) {
      tokens.push({ type: 'op', value: twoChars })
      index += 2
      continue
    }

    if (['>', '<'].includes(char)) {
      tokens.push({ type: 'op', value: char })
      index += 1
      continue
    }

    if (char === '!') {
      tokens.push({ type: 'word', value: char })
      index += 1
      continue
    }

    if (char === '"' || char === "'") {
      const quote = char
      let value = ''
      index += 1
      while (index < input.length && input[index] !== quote) {
        value += input[index]
        index += 1
      }
      if (input[index] !== quote) throw new Error('Stringa non terminata')
      tokens.push({ type: 'string', value })
      index += 1
      continue
    }

    let value = ''
    while (index < input.length && !/\s|\(|\)/.test(input[index])) {
      if (['>', '<', '=', '!'].includes(input[index])) break
      value += input[index]
      index += 1
    }

    if (!value) throw new Error(`Token non valido vicino a "${input.slice(index)}"`)
    tokens.push({ type: /^\d+(\.\d+)?$/.test(value) ? 'number' : 'word', value })
  }

  return tokens
}

class Parser {
  private position = 0

  constructor(private tokens: Token[]) {}

  parse(): AstNode {
    // Punto di ingresso: parse completo con precedenza not > and > or.
    const node = this.parseOr()
    if (!this.isAtEnd()) throw new Error(`Token inatteso: ${this.peek()?.value}`)
    return node
  }

  private parseOr(): AstNode {
    let node = this.parseAnd()
    while (this.matchWord('or') || this.matchWord('||')) {
      node = { type: 'or', left: node, right: this.parseAnd() }
    }
    return node
  }

  private parseAnd(): AstNode {
    let node = this.parseNot()
    while (this.matchWord('and') || this.matchWord('&&')) {
      node = { type: 'and', left: node, right: this.parseNot() }
    }
    return node
  }

  private parseNot(): AstNode {
    if (this.matchWord('not') || this.matchWord('!')) {
      return { type: 'not', child: this.parseNot() }
    }
    return this.parsePrimary()
  }

  private parsePrimary(): AstNode {
    if (this.matchParen('(')) {
      const node = this.parseOr()
      if (!this.matchParen(')')) throw new Error('Parentesi chiusa mancante')
      return node
    }

    return this.parseCondition()
  }

  private parseCondition(): AstNode {
    const field = this.advance()
    if (!field || !['word', 'number'].includes(field.type)) {
      throw new Error('Filtro incompleto: campo mancante')
    }

    const next = this.peek()
    if (!next || !this.isOperator(next)) {
      return { type: 'condition', field: field.value, operator: null, value: null }
    }

    const operator = this.advance()?.value ?? null
    const value = this.advance()
    if (!value || !['word', 'string', 'number'].includes(value.type)) {
      throw new Error(`Valore mancante dopo ${operator}`)
    }

    return { type: 'condition', field: field.value, operator, value: value.value }
  }

  private isOperator(token: Token) {
    return token.type === 'op' || COMPARISON_OPERATORS.has(token.value.toLowerCase())
  }

  private matchWord(value: string) {
    const token = this.peek()
    if (token?.type === 'word' && token.value.toLowerCase() === value) {
      this.position += 1
      return true
    }
    return false
  }

  private matchParen(value: string) {
    const token = this.peek()
    if (token?.type === 'paren' && token.value === value) {
      this.position += 1
      return true
    }
    return false
  }

  private advance() {
    if (this.isAtEnd()) return null
    const token = this.tokens[this.position]
    this.position += 1
    return token
  }

  private peek() {
    return this.tokens[this.position]
  }

  private isAtEnd() {
    return this.position >= this.tokens.length
  }
}

function packetField(packet: PacketEntry, field: string): string | number | null {
  // Mappa i nomi in stile Wireshark sui campi disponibili nel report.
  const normalized = field.toLowerCase()
  switch (normalized) {
    case 'ip.addr':
    case 'ip':
      return `${packet.src_ip ?? ''} ${packet.dst_ip ?? ''}`.trim()
    case 'ip.src':
    case 'src':
    case 'src.ip':
      return packet.src_ip
    case 'ip.dst':
    case 'dst':
    case 'dst.ip':
      return packet.dst_ip
    case 'tcp.port':
    case 'udp.port':
    case 'port':
      return `${packet.src_port ?? ''} ${packet.dst_port ?? ''}`.trim()
    case 'tcp.srcport':
    case 'udp.srcport':
    case 'src.port':
      return packet.src_port
    case 'tcp.dstport':
    case 'udp.dstport':
    case 'dst.port':
      return packet.dst_port
    case 'frame.len':
    case 'len':
    case 'length':
      return packet.length
    case 'frame.number':
    case 'number':
    case 'no':
      return packet.number
    case 'frame.time':
    case 'time':
      return packet.timestamp
    case 'protocol':
    case 'proto':
      return packet.protocol
    case 'info':
      return packet.info
    default:
      return null
  }
}

function protocolMatches(packet: PacketEntry, value: string) {
  // Permette filtri brevi come "dns" oppure "tcp".
  const protocol = packet.protocol.toLowerCase()
  const aliases = PROTOCOL_ALIASES[value.toLowerCase()]
  if (aliases) return aliases.some((alias) => protocol.includes(alias.toLowerCase()))
  return protocol.includes(value.toLowerCase())
}

function valueMatches(rawField: string | number | null, operator: string | null, rawValue: string | null) {
  // Valuta confronto testuale o numerico in base al tipo del campo.
  if (rawField === null) return false
  if (!operator || rawValue === null) return String(rawField).toLowerCase().includes(String(rawValue ?? '').toLowerCase())

  const fieldText = String(rawField).toLowerCase()
  const valueText = rawValue.toLowerCase()
  const fieldNumber = typeof rawField === 'number' ? rawField : Number(rawField)
  const valueNumber = Number(rawValue)
  const canCompareNumbers = Number.isFinite(fieldNumber) && Number.isFinite(valueNumber)

  switch (operator.toLowerCase()) {
    case '==':
      return fieldText.split(/\s+/).includes(valueText) || fieldText === valueText
    case '!=':
      return !(fieldText.split(/\s+/).includes(valueText) || fieldText === valueText)
    case 'contains':
      return fieldText.includes(valueText)
    case '>':
      return canCompareNumbers && fieldNumber > valueNumber
    case '>=':
      return canCompareNumbers && fieldNumber >= valueNumber
    case '<':
      return canCompareNumbers && fieldNumber < valueNumber
    case '<=':
      return canCompareNumbers && fieldNumber <= valueNumber
    default:
      return false
  }
}

function evaluate(node: AstNode, packet: PacketEntry): boolean {
  // Valutatore ricorsivo dell'albero logico del filtro.
  switch (node.type) {
    case 'and':
      return evaluate(node.left, packet) && evaluate(node.right, packet)
    case 'or':
      return evaluate(node.left, packet) || evaluate(node.right, packet)
    case 'not':
      return !evaluate(node.child, packet)
    case 'condition': {
      const field = node.field.toLowerCase()
      if (!node.operator && !node.value) return protocolMatches(packet, field)
      return valueMatches(packetField(packet, field), node.operator, node.value)
    }
    default:
      return true
  }
}

export function parsePacketFilter(input: string): FilterParseResult {
  // Restituisce un predicato sempre valido: in caso di filtro vuoto passa tutto.
  const trimmed = input.trim()
  if (!trimmed) return { predicate: () => true, error: null }

  try {
    const tokens = tokenize(trimmed)
    const ast = new Parser(tokens).parse()
    return { predicate: (packet) => evaluate(ast, packet), error: null }
  } catch (err) {
    return {
      predicate: () => true,
      error: err instanceof Error ? err.message : 'Filtro non valido',
    }
  }
}
