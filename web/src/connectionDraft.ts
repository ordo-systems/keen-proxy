import type { Connection, WireGuard } from './types'

// Bound UTF-8 import payloads and file reads to 2 MiB.
export const MAX_CONNECTION_FILE = 2 * 1024 * 1024
// Raw wizard input; protocol builders parse and validate individual fields.
export type ManualFields = Record<string, string>
type Profile = Record<string, unknown>
type Candidate = { value: unknown; kind?: 'outbound' | 'endpoint' }
const endpointTypes = new Set([
  'wireguard',
  'tailscale',
  'openvpn',
  'openconnect',
])
const forbiddenTypes = new Set([
  'direct',
  'block',
  'dns',
  'selector',
  'urltest',
])
const object = (value: unknown): value is Profile =>
  value !== null && typeof value === 'object' && !Array.isArray(value)

function required(fields: ManualFields, key: string): string {
  const value = fields[key] ?? ''
  if (!value.trim()) throw new Error(key)
  return value
}
function unsigned(value: string, key: string): number {
  if (!/^\d+$/.test(value)) throw new Error(key)
  return Number(value)
}
function serverFields(f: ManualFields): Profile {
  const port = unsigned(required(f, 'port'), 'port')
  if (port < 1 || port > 65535) throw new Error('port')
  return {
    type: f.protocol,
    server: required(f, 'server').trim(),
    server_port: port,
  }
}
function tlsFields(f: ManualFields): Profile {
  return { enabled: true, server_name: f.sni?.trim() || f.server!.trim() }
}
function realityFields(f: ManualFields): Profile {
  required(f, 'sni')
  const key = required(f, 'publicKey')
  if (!/^[\w-]{43}$/.test(key)) throw new Error('publicKey')
  if (f.shortId && !/^(?:[a-f\d]{2}){1,8}$/i.test(f.shortId))
    throw new Error('shortId')
  return { enabled: true, public_key: key, short_id: f.shortId || '' }
}
function vlessTLS(f: ManualFields): Profile {
  const tls = tlsFields(f)
  if (f.security === 'reality') tls.reality = realityFields(f)
  tls.utls = { enabled: true, fingerprint: f.fingerprint || 'chrome' }
  return tls
}
function vlessProfile(f: ManualFields): Profile {
  const uuid = required(f, 'uuid').trim()
  if (!/^[a-f\d]{8}(-[a-f\d]{4}){3}-[a-f\d]{12}$/i.test(uuid))
    throw new Error('uuid')
  const out = { ...serverFields(f), uuid } as Profile
  if (f.flow) out.flow = f.flow
  if (f.security !== 'none') out.tls = vlessTLS(f)
  return out
}
function shadowsocksProfile(f: ManualFields): Profile {
  return {
    ...serverFields(f),
    method: required(f, 'cipher'),
    password: required(f, 'password'),
  }
}
function passwordTLSProfile(f: ManualFields): Profile {
  return {
    ...serverFields(f),
    password: required(f, 'password'),
    tls: tlsFields(f),
  }
}
function socksProfile(f: ManualFields): Profile {
  const out = { ...serverFields(f), version: f.version || '5' } as Profile
  if (f.username) {
    out.username = f.username
    out.password = f.password || ''
  }
  return out
}
function manualWG(f: ManualFields): WireGuard {
  const wg: WireGuard = {
    private_key: required(f, 'privateKey').trim(),
    address: required(f, 'address')
      .split(/[,\s]+/)
      .filter(Boolean),
    peer: {
      public_key: required(f, 'peerKey').trim(),
      endpoint: required(f, 'endpoint').trim(),
    },
  }
  if (f.psk) wg.peer.preshared_key = f.psk.trim()
  if (f.mtu) wg.mtu = unsigned(f.mtu, 'mtu')
  if (f.keepalive) wg.peer.keepalive = unsigned(f.keepalive, 'keepalive')
  return wg
}
const protocolBuilders: Record<string, (fields: ManualFields) => Profile> = {
  vless: vlessProfile,
  shadowsocks: shadowsocksProfile,
  trojan: passwordTLSProfile,
  hysteria2: passwordTLSProfile,
  socks: socksProfile,
}
// Build one draft profile from manual inputs; engine validation is separate.
export function manualConnection(f: ManualFields): Connection {
  const base = {
    id: required(f, 'id').trim(),
    name: required(f, 'name').trim(),
  }
  if (f.protocol === 'wireguard')
    return { ...base, type: 'wireguard', wireguard: manualWG(f) }
  if (f.protocol === 'amneziawg') {
    const profile = required(f, 'amneziawg')
    boundedImport(profile)
    return { ...base, type: 'amneziawg', amneziawg: profile }
  }
  const build = protocolBuilders[f.protocol!]
  if (!build) throw new Error('protocol')
  return { ...base, type: 'singbox', outbound: build(f) }
}

const commaList = (value: string) =>
  value
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
type WGSetter = (wg: WireGuard, value: string) => void
const wgFields: Record<string, Record<string, WGSetter>> = {
  interface: {
    privatekey: (wg, value) => {
      wg.private_key = value
    },
    address: (wg, value) => {
      wg.address = commaList(value)
    },
    mtu: (wg, value) => {
      wg.mtu = unsigned(value, 'MTU')
    },
  },
  peer: {
    publickey: (wg, value) => {
      wg.peer.public_key = value
    },
    presharedkey: (wg, value) => {
      wg.peer.preshared_key = value
    },
    endpoint: (wg, value) => {
      wg.peer.endpoint = value
    },
    allowedips: (wg, value) => {
      wg.peer.allowed_ips = commaList(value)
    },
    persistentkeepalive: (wg, value) => {
      wg.peer.keepalive = unsigned(value, 'Keepalive')
    },
  },
}
interface WGParseState {
  section: string
  peers: number
}
function wgSection(state: WGParseState, name: string): void {
  state.section = name.toLowerCase()
  if (!wgFields[state.section]) throw new Error('Unsupported WireGuard section')
  if (state.section === 'peer' && ++state.peers > 1)
    throw new Error('Unsupported WireGuard section')
}
// wg-quick DNS is metadata: each comma-separated item is a zoneless IP or a search domain.
// Empty items are rejected. The value is not stored and cannot replace KeenProxy DNS.
function dnsMetadata(value: string): void {
  for (const raw of value.split(',')) {
    const item = raw.trim()
    if (!ipv4(item) && !ipv6(item) && !hostname(item))
      throw new Error('invalid DNS metadata')
  }
}

function ipv4(value: string): boolean {
  const parts = value.split('.')
  if (parts.length !== 4) return false
  for (const part of parts) {
    if (!/^(0|[1-9]\d{0,2})$/.test(part) || Number(part) > 255) return false
  }
  return true
}

function ipv6(value: string): boolean {
  // URL parses IPv6 without network access. Restrict its input first because
  // URL normalization would otherwise discard embedded tabs or line breaks.
  if (!/^[\da-f:.]+$/i.test(value)) return false
  try {
    new URL(`http://[${value}]/`)
    return true
  } catch {
    return false
  }
}

function hostname(value: string): boolean {
  if (value === '' || value.length > 253) return false
  if (value.endsWith('.')) value = value.slice(0, -1)
  if (/^[\d.]+$/.test(value)) return false
  return value.split('.').every((label) =>
    /^[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$/i.test(label),
  )
}

function wgAssignment(wg: WireGuard, section: string, line: string): void {
  const eq = line.indexOf('=')
  if (eq < 0) throw new Error('Invalid WireGuard line')
  const key = line.slice(0, eq).trim().toLowerCase()
  const value = line.slice(eq + 1).trim()
  if (section === 'interface' && key === 'dns') {
    dnsMetadata(value)
    return
  }
  const assign = wgFields[section]?.[key]
  if (!assign) throw new Error('Unsupported WireGuard setting: ' + key)
  assign(wg, value)
}
// Reject unsupported sections, fields, and multiple peers. DNS metadata is checked and discarded.
function parseWG(text: string): WireGuard {
  const wg: WireGuard = {
    private_key: '',
    address: [],
    peer: { endpoint: '', public_key: '' },
  }
  const state: WGParseState = { section: '', peers: 0 }
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*/, '').trim()
    if (!line) continue
    const match = line.match(/^\[(\w+)\]$/)
    if (match) wgSection(state, match[1]!)
    else wgAssignment(wg, state.section, line)
  }
  if (
    !wg.private_key ||
    !wg.address.length ||
    !wg.peer.endpoint ||
    !wg.peer.public_key
  )
    throw new Error('Incomplete WireGuard profile')
  return wg
}

// Extract connection profiles only; global routing and DNS settings are not imported.
function jsonCandidates(obj: Profile): Candidate[] {
  const candidates: Candidate[] = []
  for (const [plural, kind] of [
    ['outbounds', 'outbound'],
    ['endpoints', 'endpoint'],
  ] as const) {
    if (obj[plural] !== undefined) {
      if (!Array.isArray(obj[plural])) throw new Error(plural)
      for (const value of obj[plural]) candidates.push({ value, kind })
    }
    if (obj[kind] !== undefined) candidates.push({ value: obj[kind], kind })
  }
  if (!candidates.length && obj.type) candidates.push({ value: obj })
  return candidates
}
// Exclude built-in routing actions and move the imported tag into the display name.
function rawProfile({ value, kind }: Candidate): Connection[] {
  if (!object(value) || typeof value.type !== 'string')
    throw new Error('Missing connection type')
  if (forbiddenTypes.has(value.type)) return []
  const key = kind ?? (endpointTypes.has(value.type) ? 'endpoint' : 'outbound')
  const profile = structuredClone(value)
  delete profile.tag
  return [
    {
      id: '',
      name: typeof value.tag === 'string' ? value.tag : '',
      type: 'singbox',
      [key]: profile,
    },
  ]
}
function jsonProfiles(raw: string): Connection[] {
  const obj: unknown = JSON.parse(raw)
  if (!object(obj)) throw new Error('Expected JSON object')
  const result = jsonCandidates(obj).flatMap(rawProfile)
  if (!result.length) throw new Error('No importable connections')
  return result
}
function linkProfile(raw: string): Connection {
  if (
    !/^(vless|vmess|trojan|ss|hysteria2|hy2|tuic|anytls|socks5?|tt):\/\/\S+$/i.test(
      raw,
    )
  )
    throw new Error('Invalid connection link')
  if (raw.startsWith('tt://'))
    return { id: '', name: '', type: 'trusttunnel', trusttunnel: { link: raw } }
  return { id: '', name: '', type: 'link', link: raw }
}

// Detect AWG-only settings before any structured WireGuard parser can discard them.
function isAmneziaWGConf(text: string): boolean {
  return /^\s*(?:Jc|Jmin|Jmax|S[1-4]|H[1-4]|I[1-5]|HeaderProtectionKey|ContentPaddingAddition|RandomTrailers|DisableCookies|RekeyAfterTime|RekeyTimeout|RejectAfterTime|KeepaliveTimeout|MaxHandshakeAttempts)\s*=/im.test(text)
}
// Decode bounded wg-quick, JSON, or link input into unassigned draft candidates.
export function importConnections(
  text: string,
  filename: string,
): Connection[] {
  if (new TextEncoder().encode(text).byteLength > MAX_CONNECTION_FILE)
    throw new Error('File exceeds 2 MiB')
  const raw = text.replace(/^\uFEFF/, '').trim()
  if (!raw) throw new Error('Empty file')
  if (filename.toLowerCase().endsWith('.conf') || /^\[Interface\]/im.test(raw)) {
    if (isAmneziaWGConf(raw))
      return [{ id: '', name: '', type: 'amneziawg', amneziawg: text }]
    return [{ id: '', name: '', type: 'wireguard', wireguard: parseWG(raw) }]
  }
  return raw.startsWith('{') ? jsonProfiles(raw) : [linkProfile(raw)]
}

// Allow explicit direct fallback; reject cycles and missing connection references.
export function canFallback(
  list: Connection[],
  self: string,
  target: string,
): boolean {
  if (!target) return true
  if (target === 'direct') return true
  const seen = new Set([self])
  let current: string | undefined = target
  while (current && current !== 'direct') {
    if (seen.has(current)) return false
    seen.add(current)
    const c = list.find((c) => c.id === current)
    if (!c) return false
    current = c.fallback
  }
  return true
}
// Follow fallback IDs for display, stopping at a missing entry or repeated ID.
export function connectionChain(list: Connection[], id: string): string[] {
  const chain: string[] = [],
    seen = new Set<string>()
  let current: string | undefined = id
  while (current && !seen.has(current)) {
    chain.push(current)
    seen.add(current)
    current = list.find((c) => c.id === current)?.fallback
  }
  return chain
}

// Copy JSON profile data, including values held in Vue reactive proxies.
export function copyConnection(connection: Connection): Connection {
  return JSON.parse(JSON.stringify(connection)) as Connection
}

// Multiple exported tunnels require an explicit choice; never import the first silently.
export function selectAmneziaProfile(profiles: Connection[], chosen: number | null): Connection {
  const index = chosen === null && profiles.length === 1 ? 0 : chosen
  if (index === null || !Number.isInteger(index) || index < 0 || index >= profiles.length)
    throw new Error('amnezia_choose_profile')
  return copyConnection(profiles[index]!)
}

export const STALE_IMPORT = 'import_stale'
export const DRAFT_CHANGED = 'draft_changed'

function boundedImport(text: string): void {
  if (new TextEncoder().encode(text).byteLength > MAX_CONNECTION_FILE)
    throw new Error('File exceeds 2 MiB')
}

export type ClassifiedImport =
  | { kind: 'vpn'; uri: string }
  | { kind: 'profiles'; profiles: Connection[] }

// Classify wizard input without decoding vpn://. The backend owns that envelope.
export function classifyConnectionImport(text: string, filename: string, protocol: string): ClassifiedImport {
  boundedImport(text)
  const raw = text.replace(/^\uFEFF/, '').trim()
  if (!raw) throw new Error('Empty file')
  if (raw.startsWith('vpn://')) return { kind: 'vpn', uri: raw }
  if (protocol === 'amneziawg')
    return { kind: 'profiles', profiles: [{ id: '', name: '', type: 'amneziawg', amneziawg: text }] }
  return { kind: 'profiles', profiles: importConnections(text, filename) }
}

// Name a selected profile. An unselected multi-export must not inherit the first profile's name.
export function suggestedConnectionName(profiles: Connection[], chosen: number | null, filename = ''): string {
  const index = chosen === null && profiles.length === 1 ? 0 : chosen
  const selected = index !== null && Number.isInteger(index) ? profiles[index] : undefined
  if (selected?.name) return selected.name
  return filename.replace(/\.[^.]+$/, '')
}

const connectionErrors: Record<string, string> = {
  amnezia_invalid_profile: 'ui.amneziaInvalid',
  amnezia_service_profile: 'ui.amneziaService',
  amnezia_admin_profile: 'ui.amneziaAdmin',
  amnezia_unsupported_profile: 'ui.amneziaUnsupported',
  amnezia_format_version: 'ui.amneziaVersion',
  amnezia_choose_profile: 'ui.pickProfile',
  amnezia_demo_unavailable: 'ui.amneziaDemo',
  'File exceeds 2 MiB': 'ui.largeFile',
  'Empty file': 'ui.fileError',
  file: 'ui.fileError',
  'Unsupported WireGuard section': 'ui.unsupportedWG',
  'Incomplete WireGuard profile': 'ui.invalid',
  'Invalid WireGuard line': 'ui.invalid',
  'invalid DNS metadata': 'ui.invalid',
  'Invalid connection link': 'ui.invalid',
  [DRAFT_CHANGED]: 'ui.configChanged',
}

// Map stable import failures to translation keys. Never echo parser text; it can contain secrets.
export function connectionErrorKey(cause: unknown, fallback = 'ui.invalid'): string {
  const code = cause instanceof Error ? cause.message : ''
  if (code.startsWith('Unsupported WireGuard setting')) return 'ui.unsupportedWG'
  return connectionErrors[code] ?? fallback
}
