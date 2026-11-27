import { connectionChain } from './connectionDraft.ts'
import type { Connection, DNSConfig } from './types'

// A direct outbound in the fallback chain does not guarantee a DNS tunnel.
export function dnsTunnelChoices<T extends { value: string }>(choices: T[], connections: Connection[]): T[] {
  const direct = new Set(connections.filter(c => c.type === 'singbox' && c.outbound?.type === 'direct').map(c => c.id))
  return choices.filter(choice => !connectionChain(connections, choice.value).some(id => direct.has(id)))
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
