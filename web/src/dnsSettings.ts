import { connectionChain } from './connectionDraft.ts'
import type { Connection, DNSConfig } from './types'

// Keep in sync with raw tunnel types accepted by internal/model/features.go.
const rawDNSTunnelTypes = [
  'wireguard', 'socks', 'http', 'shadowsocks', 'vmess', 'vless', 'trojan', 'tuic',
  'hysteria', 'hysteria2', 'ssh', 'naive', 'anytls',
]

// A named raw outbound must be a tunnel even when built-in Direct is allowed.
export function dnsTunnelError(connections: Connection[], id: string, failure: DNSConfig['failure']): string | undefined {
  const chain = connectionChain(connections, id)
  for (const member of chain) {
    const connection = connections.find(c => c.id === member)
    if (connection?.type !== 'singbox') continue
    const rawType = (connection.endpoint ?? connection.outbound)?.type
    const type = typeof rawType === 'string' ? rawType : ''
    if (!rawDNSTunnelTypes.includes(type)) {
      return `dns.connection: raw type ${JSON.stringify(type)} does not guarantee a tunnel`
    }
  }
  if (!connections.some(connection => connection.id === id)) {
    return `dns.connection: unknown connection ${JSON.stringify(id)}`
  }
  if (failure !== 'direct' && chain.includes('direct')) {
    return 'dns: strict forbids direct in the connection chain'
  }
}

// The picker permits explicit Direct fallback; automatic defaults can require a stricter policy.
export function dnsTunnelChoices<T extends { value: string }>(choices: T[], connections: Connection[], failure: DNSConfig['failure'] = 'direct'): T[] {
  return choices.filter(choice => !dnsTunnelError(connections, choice.value, failure))
}

// Keep existing resolver lists usable until the operator changes their order or contents.
export function dnsUpstreamsIncomplete(current: string[], saved: string[]): boolean {
  if (JSON.stringify(current) === JSON.stringify(saved)) return false
  const primary = current[0]?.trim()
  const secondary = current[1]?.trim()
  return !primary || (current.length > 1 && (!secondary || primary === secondary))
}

// Replace one priority slot while preserving the route, extra servers, and manual pins.
export function selectDNSResolver(dns: DNSConfig, slot: 0 | 1, endpoint: string, bootstrapIP?: string) {
  const upstreams = [...dns.upstreams]
  if (!upstreams.length && slot === 1) upstreams.push('')
  upstreams[slot] = endpoint
  dns.upstreams = upstreams
  if (bootstrapIP) {
    const host = new URL(endpoint).hostname
    dns.bootstrap = { [host]: bootstrapIP, ...dns.bootstrap }
  }
}
