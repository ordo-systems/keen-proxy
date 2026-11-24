import dnsProfiles from '../../../internal/catalog/dns.json' with { type: 'json' }
import initial from './config.json' with { type: 'json' }
import { createTelemetry } from './telemetry.ts'
import { activeExit, canonicalEntry, entryIdentity, groupDisabledEntryKeys, isGeo, retainPresetActivation } from '../activation.ts'
import { connectionChain } from '../connectionDraft.ts'
import { maxMemoryLimitMiB, type Catalog, type Config, type DiagnosticReport, type DomainStatus, type GeoLookup, type GeoStatus, type JournalKind, type Status } from '../types.ts'

// Only synthetic examples are bundled; the demo never imports runtime configuration.
export const catalog: Catalog = {
  presets: [
    { id: 'sample-work', name: 'Example work sites', category: 'Other', domains: ['work.example.com', 'meet.example.com'], prefixes: [], description: 'Synthetic domains for exploring the preset preview.' },
  ],
  dns: dnsProfiles,
  filters: [{ id: 'sample-ads', name: 'Example advertising list', category: 'Other', url: 'https://lists.example.com/ads.txt', enabled: true, auto_update: false, source: 'Synthetic demo data', license: 'GPL-3.0-only' }],
  // Public metadata of the router's built-in sources (internal/geoip/sources.go); the demo downloads nothing.
  geoip: [
    { id: 'dbip', name: 'DB-IP IP to Country Lite', kind: 'country', homepage: 'https://db-ip.com/db/download/ip-to-country-lite', license: 'CC BY 4.0', attribution: 'IP Geolocation by DB-IP', attribution_url: 'https://db-ip.com/', updates: 'monthly', enabled: true, origin: 'download.db-ip.com' },
    { id: 'ip-location-db', name: 'ip-location-db user-country', kind: 'country', homepage: 'https://github.com/sapics/ip-location-db', license: 'PDDL 1.0', updates: 'daily', enabled: false, origin: 'GitHub release sapics/ip-location-db · user-country.mmdb' },
    { id: 'loyalsoldier', name: 'Loyalsoldier GeoIP (GeoLite2-based)', kind: 'country', homepage: 'https://github.com/Loyalsoldier/geoip', license: 'GeoLite2 data, MaxMind terms', attribution: 'Includes GeoLite2 data created by MaxMind', attribution_url: 'https://www.maxmind.com', updates: 'weekly', enabled: false, origin: 'GitHub latest release Loyalsoldier/geoip · Country-without-asn.mmdb' },
    { id: 'runetfreedom-ru', name: 'runetfreedom: blocked in Russia', kind: 'category', categories: ['RU-BLOCKED', 'RU-BLOCKED-COMMUNITY', 'RE-FILTER', 'RU-WHITELIST', 'PRIVATE'], homepage: 'https://github.com/runetfreedom/russia-blocked-geoip', license: 'GPL-3.0 repository; data from antifilter.download and re:filter', updates: '6h', enabled: false, origin: 'GitHub latest release runetfreedom/russia-blocked-geoip · Country-ru-only.mmdb' },
    { id: 'runetfreedom-services', name: 'runetfreedom: service networks', kind: 'category', categories: ['CLOUDFLARE', 'CLOUDFRONT', 'DDOS-GUARD', 'FACEBOOK', 'FASTLY', 'GOOGLE', 'NETFLIX', 'TELEGRAM', 'TWITTER', 'YANDEX'], homepage: 'https://github.com/runetfreedom/russia-blocked-geoip', license: 'GPL-3.0 repository', updates: '6h', enabled: false, origin: 'GitHub latest release runetfreedom/russia-blocked-geoip · Country-asn.mmdb' },
  ],
}

// Synthetic country answers shared by every demo database (documentation and well-known ranges).
const demoGeo: [string, number, string][] = [['77.88.0.0', 16, 'RU'], ['8.8.8.0', 24, 'US'], ['1.1.1.0', 24, 'AU'], ['185.199.108.0', 22, 'NL']]
// Synthetic labels of the same ranges for category databases.
const demoCategories: [string, number, string][] = [['77.88.0.0', 16, 'RU-WHITELIST'], ['8.8.8.0', 24, 'GOOGLE'], ['1.1.1.0', 24, 'CLOUDFLARE'], ['185.199.108.0', 22, 'RU-BLOCKED']]

function ipv4(ip: string): number | undefined {
  const m = ip.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (!m || m.slice(1).some(o => Number(o) > 255)) return undefined
  return m.slice(1).reduce((n, o) => n * 256 + Number(o), 0)
}

function demoCountry(ip: number, table = demoGeo): string {
  for (const [net, bits, cc] of table) {
    const size = 2 ** (32 - bits)
    if (Math.floor(ip / size) === Math.floor(ipv4(net)! / size)) return cc
  }
  return ''
}

// JSON copies accept Vue proxies and isolate saved state from editable drafts.
function copy<T>(value: T): T { return JSON.parse(JSON.stringify(value)) }

// Match Go's IPv4 ParseAddr and global-or-link-local unicast checks.
function isDNSBypassSource(value: unknown): boolean {
  if (typeof value !== 'string') return false
  const octets = value.split('.')
  if (octets.length !== 4 || octets.some(octet => !/^(?:0|[1-9]\d{0,2})$/.test(octet) || Number(octet) > 255)) return false
  const first = Number(octets[0])
  return first !== 127 && (first < 224 || first >= 240) && value !== '0.0.0.0' && value !== '255.255.255.255'
}

// This small validation subset protects the demo state; the real daemon is authoritative.
function validate(config: Config) {
  const ids = (config.connections ?? []).map(c => c.id)
  if (new Set(ids).size !== ids.length || ids.some(id => !id)) throw new Error('Connection IDs must be non-empty and unique')
  const targets = new Set([...ids, 'direct', 'block'])
  for (const group of config.groups ?? []) {
    if (!targets.has(group.target)) throw new Error('Unknown group target')
    for (const entry of group.entries ?? []) {
      if (canonicalEntry(entry).type === 'invalid') throw new Error(`Not a domain, IP, or subnet: ${entry}`)
    }
  }
  const limit = config.system?.memory_limit_mib
  if (limit != null && (typeof limit !== 'number' || !Number.isInteger(limit) || limit < 1 || limit > maxMemoryLimitMiB)) {
    throw new Error('memory limit must be a positive integer number of MiB')
  }
  const sources = config.dns.bypass_sources
  if (sources != null && !Array.isArray(sources)) throw new Error('dns.bypass_sources: expected a list of unicast IPv4 addresses')
  for (const [index, source] of sources?.entries() ?? []) {
    if (!isDNSBypassSource(source)) throw new Error(`dns.bypass_sources[${index}]: expected a unicast IPv4 address`)
  }
}

// Owns one browser session's synthetic applied state and previous configuration.
export function createDemo(now: () => number = () => Date.now()) {
  let saved = copy(initial as Config)
  let previous = copy(saved)
  const telemetry = createTelemetry(now, lookupGeo)

  function save(config: Config) {
    validate(config)
    telemetry.sync(saved)
    previous = copy(saved)
    saved = copy(config)
    if (!saved.dns.bypass_sources?.length) delete saved.dns.bypass_sources
    // Null is inherit. Persist omission, never zero.
    if (saved.system == null || saved.system.memory_limit_mib == null) {
      if (saved.system) delete saved.system.memory_limit_mib
      if (!saved.system || Object.keys(saved.system).length === 0) delete saved.system
    }
    telemetry.applied()
    return copy(saved)
  }

  // Databases "downloaded" by a demo update; enabled databases count as present.
  const fetched = new Set<string>()
  const kind = (id: string, own?: string) => (catalog.geoip.find(b => b.id === id)?.kind ?? (own === 'category' ? 'category' : 'country'))
  function geoip(): GeoStatus {
    return { demo: true, databases: saved.geoip.databases.map(db => {
      const present = db.enabled || fetched.has(db.id)
      return { id: db.id, name: catalog.geoip.find(b => b.id === db.id)?.name ?? (db.name || db.id), builtin: catalog.geoip.some(b => b.id === db.id), kind: kind(db.id, db.kind), enabled: db.enabled, local: !!db.file, loaded: db.enabled, present, built: present ? telemetry.started.slice(0, 10) : undefined, type: present ? 'Synthetic demo' : undefined, checked: present ? telemetry.started : undefined, updated: present ? telemetry.started : undefined }
    }) }
  }
  function updateGeo(id = ''): GeoStatus {
    if (id && !saved.geoip.databases.some(db => db.id === id)) throw new Error('Unknown database')
    for (const db of saved.geoip.databases) if (db.id === id || (!id && db.enabled)) fetched.add(db.id)
    return geoip()
  }
  function lookupGeo(ip: string, id = ''): GeoLookup {
    const n = ipv4(ip)
    if (n === undefined) throw new Error('The demo checks IPv4 addresses only')
    const results = saved.geoip.databases.filter(db => (id ? db.id === id : db.enabled)).map(db => {
      const ready = db.enabled || fetched.has(db.id)
      const k = kind(db.id, db.kind)
      const answer = demoCountry(n, k === 'category' ? demoCategories : demoGeo)
      return { id: db.id, name: catalog.geoip.find(b => b.id === db.id)?.name ?? (db.name || db.id), enabled: db.enabled, kind: k, country: ready ? answer || undefined : undefined, error: ready ? undefined : 'Not downloaded yet' }
    })
    if (id && !results.length) throw new Error('Unknown database')
    const hit = results.find(r => r.country && r.kind === 'country')
    const categories = [...new Set(results.filter(r => r.country && r.kind === 'category').map(r => r.country!))]
    return { ip: ip.trim(), country: hit?.country, database: hit?.id, categories, results }
  }

  telemetry.sync(saved)


  return {
    geoip, updateGeo, lookupGeo,
    config: () => copy(saved), previous: () => copy(previous), save, validate, preview,
    diagnostics: (connection: string) => diagnostics(saved, connection),
    domains: (names?: string[]) => domains(saved, names), status: () => status(saved, telemetry.started),
    stats(series = true) {
      telemetry.sync(saved)
      return telemetry.stats(saved, series)
    },
    journal(kind: JournalKind, params: Record<string, string | number | undefined> = {}) {
      telemetry.sync(saved)
      return telemetry.journal(kind, params)
    },
  }
}

// Preview updates a copy and leaves the session unchanged.
function preview(config: Config, id: string, target: string, index?: number) {
  const preset = catalog.presets.find(p => p.id === id)
  if (!preset) throw new Error('Unknown demo preset')
  const draft = copy(config)
  draft.groups ??= []
  const previous = index === undefined ? undefined : draft.groups[index]
  const old = previous?.entries ?? []
  const group = retainPresetActivation(previous, {
    name: preset.name,
    target,
    entries: [...preset.domains],
    preset: { id, version: 'demo', base: [...preset.domains], auto_update: false },
  })
  if (index === undefined) draft.groups.push(group)
  else draft.groups[index] = group
  validate(draft)
  return { config: draft, diff: { added: group.entries.filter(e => !old.includes(e)), removed: old.filter(e => !group.entries.includes(e)) } }
}

// A disabled profile is unavailable. Do not invent a network measurement for it.
function diagnostics(saved: Config, connection: string): DiagnosticReport {
  const profile = saved.connections?.find(c => c.id === connection)
  if (!profile) throw new Error('Unknown connection')
  if (profile.disabled) throw new Error('disabled')
  return { connection, demo: true, results: (['http', 'https', 'transfer'] as const).map((kind, i) => ({ kind, ok: true, checked: new Date().toISOString(), latency_ms: 42 + i * 17, bytes: kind === 'transfer' ? 65536 : undefined })) }
}

function routingNames(saved: Config): string[] {
  return (saved.groups ?? []).flatMap(group => {
    if (group.disabled || isGeo(group)) return []
    const off = groupDisabledEntryKeys(group)
    return off.size ? group.entries.filter(entry => !off.has(entryIdentity(entry))) : group.entries
  })
}

// Reserved example IPs represent every synthetic DNS answer.
function domains(saved: Config, names = routingNames(saved)): DomainStatus {
  const now = new Date().toISOString()
  return { demo: true, limited: false, conflicts: {}, written_at: now, application: 'synthetic', records: [...new Set(names)].map(name => ({ name, source: 'demo', checked_at: now, attempted_at: now, addresses: name.endsWith('.invalid') ? [] : [{ ip: '192.0.2.10', expires_at: new Date(Date.now() + 300000).toISOString() }], error: name.endsWith('.invalid') ? 'Synthetic NXDOMAIN' : undefined })) }
}

// Summarize enabled demo databases with the credits their licenses require.
function geoSummary(saved: Config, started: string): Status['geoip'] {
  const enabled = saved.geoip.databases.filter(db => db.enabled)
  const isCat = (id: string) => catalog.geoip.find(b => b.id === id)?.kind === 'category'
  const countries = enabled.filter(db => !isCat(db.id) && db.kind !== 'category')
  const attributions = enabled.flatMap(db => {
    const b = catalog.geoip.find(x => x.id === db.id)
    return b?.attribution ? [{ text: b.attribution, url: b.attribution_url ?? '' }] : []
  })
  return { loaded: countries.length > 0, type: 'Synthetic demo', built: started.slice(0, 10), active: countries.length, categories: enabled.length - countries.length, attributions, error: countries.length ? undefined : 'No enabled country databases' }
}

function failover(saved: Config): Status['failover'] {
  const connections = saved.connections ?? []
  const rows = connections.filter(connection => connection.fallback).map(connection => [connection.id, {
    active: activeExit(saved, connection.id),
    chain: connectionChain(connections, connection.id),
  }] as const)
  return rows.length ? Object.fromEntries(rows) : undefined
}

// Derive summary counts and health from the synthetic applied configuration.
function status(saved: Config, started: string): Status {
  const active = (saved.connections ?? []).filter(connection => !connection.disabled)
  return {
    started, mode: saved.intercept.mode, sources: 2, connections: saved.connections?.length ?? 0,
    groups: saved.groups?.length ?? 0, entries: (saved.groups ?? []).reduce((n, g) => n + g.entries.length, 0),
    clients: saved.clients?.length ?? 0, online_devices: 4, dns: '127.0.0.1:5353', firewall: true, restored: 0,
    geoip: geoSummary(saved, started), conn_countries: { fi: 'FI', nl: 'NL', de: 'DE' },
    failover: failover(saved),
    health: Object.fromEntries(active.map(connection => [connection.id, { ok: true, checked: new Date().toISOString(), since: started, latency_ms: 42 }])),
  }
}
