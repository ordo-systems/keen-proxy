import type { Config, Connection, Group } from './types'
import { connectionChain } from './connectionDraft.ts'

// Entry identity follows model.ParseEntry: comments, wildcards, trailing dots,
// IDNA and masked prefixes. Country and category identity follows Defaults.
export function entryIdentity(raw: string): string {
  let value = raw.trim()
  const comment = value.indexOf('#')
  if (comment >= 0) value = value.slice(0, comment).trim()
  if (!value) return raw.trim().toLowerCase()
  const prefix = maskedPrefix(value)
  if (prefix) return prefix
  let domain = value
  if (domain.startsWith('*')) domain = domain.slice(1)
  if (domain.startsWith('.')) domain = domain.slice(1)
  if (domain.endsWith('.')) domain = domain.slice(0, -1)
  try {
    const ascii = new URL(`http://${domain}`).hostname.toLowerCase()
    if (ascii.includes('.')) return ascii
  } catch {
    /* Keep a lowercase token when the value is not a domain. */
  }
  return value.toLowerCase()
}

export function geoIdentity(raw: string): string {
  return raw.trim().toUpperCase()
}

export function isGeo(group: Group): boolean {
  return group.countries !== undefined || group.categories !== undefined
}

export function valueOff(
  flags: string[] | undefined,
  raw: string,
  identity: (value: string) => string,
): boolean {
  const id = identity(raw)
  return (flags ?? []).some((flag) => identity(flag) === id)
}

export function entryOff(group: Group, entry: string): boolean {
  return valueOff(group.disabled_entries, entry, entryIdentity)
}

export function selectorOff(
  group: Group,
  kind: 'countries' | 'categories',
  value: string,
): boolean {
  const flags = kind === 'countries' ? group.disabled_countries : group.disabled_categories
  return valueOff(flags, value, geoIdentity)
}

// enabled=false stores the original value. Equivalent spellings collapse to one flag.
export function withFlag(
  flags: string[] | undefined,
  raw: string,
  enabled: boolean,
  identity: (value: string) => string,
): string[] | undefined {
  const id = identity(raw)
  const next = (flags ?? []).filter((flag) => identity(flag) !== id)
  if (!enabled) next.push(raw)
  return next.length ? next : undefined
}

export function setGroupEnabled(group: Group, enabled: boolean): void {
  if (enabled) delete group.disabled
  else group.disabled = true
}

export function setEntryEnabled(group: Group, entry: string, enabled: boolean): void {
  group.disabled_entries = withFlag(group.disabled_entries, entry, enabled, entryIdentity)
}

export function setSelectorEnabled(
  group: Group,
  kind: 'countries' | 'categories',
  value: string,
  enabled: boolean,
): void {
  const stored = geoIdentity(value)
  const key = kind === 'countries' ? 'disabled_countries' : 'disabled_categories'
  group[key] = withFlag(group[key], stored, enabled, geoIdentity)
}

// An explicit rename keeps the off flag on the new spelling.
export function migrateFlag(
  flags: string[] | undefined,
  from: string,
  to: string,
  identity: (value: string) => string,
): string[] | undefined {
  if (!flags?.length) return undefined
  const fromID = identity(from)
  const toID = identity(to)
  if (fromID === toID) return flags
  const next = flags.filter((flag) => identity(flag) !== fromID)
  if (next.length === flags.length) return flags
  if (!next.some((flag) => identity(flag) === toID)) next.push(to)
  return next
}

// Drop flags only for values the user removed. Flags for absent preset values stay.
export function dropRemoved(
  flags: string[] | undefined,
  before: string[],
  after: string[],
  identity: (value: string) => string,
): string[] | undefined {
  const kept = new Set(after.map(identity))
  const removed = new Set(before.filter((value) => !kept.has(identity(value))).map(identity))
  const next = (flags ?? []).filter((flag) => !removed.has(identity(flag)))
  return next.length ? next : undefined
}

function unionFlags(
  current: string[] | undefined,
  previous: string[] | undefined,
  identity: (value: string) => string,
): string[] | undefined {
  const next: string[] = []
  const seen = new Set<string>()
  for (const value of [...(current ?? []), ...(previous ?? [])]) {
    const id = identity(value)
    if (seen.has(id)) continue
    seen.add(id)
    next.push(value)
  }
  return next.length ? next : undefined
}

// A preset update may remove and later restore an entry. That is not a deletion of its switch.
export function retainPresetActivation(previous: Group | undefined, next: Group): Group {
  if (!previous?.preset || previous.preset.id !== next.preset?.id) return next
  const merged: Group = { ...next }
  if (previous.disabled) merged.disabled = true
  const entries = unionFlags(next.disabled_entries, previous.disabled_entries, entryIdentity)
  const countries = unionFlags(next.disabled_countries, previous.disabled_countries, geoIdentity)
  const categories = unionFlags(next.disabled_categories, previous.disabled_categories, geoIdentity)
  if (entries) merged.disabled_entries = entries
  else delete merged.disabled_entries
  if (countries) merged.disabled_countries = countries
  else delete merged.disabled_countries
  if (categories) merged.disabled_categories = categories
  else delete merged.disabled_categories
  return merged
}

export function ruleTotal(group: Group): number {
  return isGeo(group)
    ? (group.countries?.length ?? 0) + (group.categories?.length ?? 0)
    : group.entries.length
}

export function ruleActive(group: Group): number {
  if (group.disabled) return 0
  if (isGeo(group)) {
    const countries = (group.countries ?? []).filter((code) => !selectorOff(group, 'countries', code)).length
    const categories = (group.categories ?? []).filter((label) => !selectorOff(group, 'categories', label)).length
    return countries + categories
  }
  return group.entries.filter((entry) => !entryOff(group, entry)).length
}

// An inverted geo group with no active selectors is inactive, never match-all.
export function geoInactive(group: Group): boolean {
  return isGeo(group) && !group.disabled && ruleActive(group) === 0
}

export function activeChain(connections: Connection[], id: string): string[] {
  const active = connectionChain(connections, id).filter(
    (member) => member === 'direct' || connections.some((connection) => connection.id === member && !connection.disabled),
  )
  return active.length ? active : ['block']
}

// Trust live selection only while it belongs to the current enabled chain.
export function activeExit(config: Config, target: string, observed?: string): string {
  if (target === 'direct' || target === 'block') return target
  const chain = activeChain(config.connections ?? [], target)
  return observed && chain.includes(observed) ? observed : chain[0] ?? 'block'
}

export function entryMatches(entry: string, host: string): boolean {
  const rule = entryIdentity(entry)
  const name = entryIdentity(host)
  if (!rule || !name) return false
  if (rule.includes('/')) {
    const [network, suffix] = rule.split('/')
    const expected = addressParts(network!)
    const actual = addressParts(host.split('/')[0]!)
    if (!expected || !actual || expected.width !== actual.width) return false
    const shift = BigInt(expected.width - Number(suffix))
    return expected.value >> shift === actual.value >> shift
  }
  return name === rule || name.endsWith(`.${rule}`)
}

function geoHit(group: Group, country: string, categories: string[]): boolean {
  const countryHit = !!country && (group.countries ?? []).some(
    (code) => !selectorOff(group, 'countries', code) && geoIdentity(code) === geoIdentity(country),
  )
  const categoryHit = categories.some((label) =>
    (group.categories ?? []).some((item) => !selectorOff(group, 'categories', item) && geoIdentity(item) === geoIdentity(label)),
  )
  return countryHit || categoryHit
}

// Match compilation order: global blocks first, explicit entries before geo.
function rulePriority(group: Group): number {
  return (group.target === 'block' ? 0 : 2) + Number(isGeo(group))
}

function groupMatches(group: Group, host: string, country: string, categories: string[], address: string): boolean {
  if (group.disabled) return false
  if (!isGeo(group)) return group.entries.some((entry) => !entryOff(group, entry) && (entryMatches(entry, host) || entryMatches(entry, address)))
  if (geoInactive(group) || (!country && !categories.length)) return false
  const hit = geoHit(group, country, categories)
  return group.except ? !hit : hit
}

// Null means no active rule matched. Callers must not invent a disabled connection.
export function simulatedRoute(
  config: Config,
  host: string,
  country = '',
  categories: string[] = [],
  address = '',
): { outbound: string; rule: string } | null {
  const groups = [...(config.groups ?? [])].sort((a, b) => rulePriority(a) - rulePriority(b))
  for (const group of groups) {
    if (groupMatches(group, host, country, categories, address))
      return { outbound: activeExit(config, group.target), rule: group.name }
  }
  return null
}

function addressParts(raw: string): { value: bigint; width: number } | null {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(raw)) {
    const octets = raw.split('.').map(Number)
    if (octets.some((part) => part > 255)) return null
    return { value: octets.reduce((n, part) => n * 256n + BigInt(part), 0n), width: 32 }
  }
  if (!raw.includes(':') || raw.includes('%')) return null
  try {
    const host = new URL(`http://[${raw}]/`).hostname.slice(1, -1)
    const halves = host.split('::')
    const left = halves[0] ? halves[0].split(':') : []
    const right = halves[1] ? halves[1].split(':') : []
    const words = halves.length === 1 ? left : [...left, ...Array<string>(8 - left.length - right.length).fill('0'), ...right]
    return { value: words.reduce((n, word) => n * 65536n + BigInt(`0x${word}`), 0n), width: 128 }
  } catch {
    return null
  }
}

function maskedPrefix(raw: string): string | null {
  const [host, suffix] = raw.split('/')
  const address = addressParts(host!)
  if (!address) return null
  const bits = suffix === undefined ? address.width : Number(suffix)
  if (!Number.isInteger(bits) || bits < 0 || bits > address.width) return null
  const shift = BigInt(address.width - bits)
  const masked = (address.value >> shift) << shift
  if (address.width === 32) {
    const value = Number(masked)
    return `${value >>> 24}.${(value >>> 16) & 255}.${(value >>> 8) & 255}.${value & 255}/${bits}`
  }
  const words = Array.from({ length: 8 }, (_, index) => ((masked >> BigInt((7 - index) * 16)) & 65535n).toString(16))
  const canonical = new URL(`http://[${words.join(':')}]/`).hostname.slice(1, -1)
  return `${canonical}/${bits}`
}

