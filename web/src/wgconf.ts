import { translit } from './locales/transliteration.ru'
import type { WireGuard } from './types'

// Export one peer, defaulting AllowedIPs to both address families.
export function wireGuardToConf(wg: WireGuard): string {
  const lines = ['[Interface]', `PrivateKey = ${wg.private_key}`, `Address = ${wg.address.join(', ')}`]
  if (wg.mtu) lines.push(`MTU = ${wg.mtu}`)
  lines.push('', '[Peer]', `PublicKey = ${wg.peer.public_key}`)
  if (wg.peer.preshared_key) lines.push(`PresharedKey = ${wg.peer.preshared_key}`)
  lines.push(`Endpoint = ${wg.peer.endpoint}`)
  lines.push(`AllowedIPs = ${(wg.peer.allowed_ips?.length ? wg.peer.allowed_ips : ['0.0.0.0/0', '::/0']).join(', ')}`)
  if (wg.peer.keepalive) lines.push(`PersistentKeepalive = ${wg.peer.keepalive}`)
  return lines.join('\n')
}



// Transliterate a display name into a connection ID of at most 32 characters.
export function slugify(s: string): string {
  return s
    .toLowerCase()
    .split('')
    .map((ch) => translit[ch] ?? ch)
    .join('')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 32)
}
