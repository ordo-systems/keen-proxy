import { firewallAudit } from './firewall.ts'
import type { Config, GeoLookup, JournalEntry, JournalKind, JournalPage, StatPoint, StatsSnapshot } from '../types'
import { activeExit, simulatedRoute } from '../activation.ts'

export const DEMO_TICK_MS = 3000
export const DEMO_JOURNAL_LIMIT = 120
const HISTORY = 60
const SEED_ROUTES = 12
const destinations = [
  { host: 'video.example.com', ip: '8.8.8.8' },
  { host: 'work.example.com', ip: '77.88.0.1' },
  { host: 'updates.example.com', ip: '185.199.108.1' },
]
const hosts = destinations.map(destination => destination.host)
const fields = {
  routes: ['outbound', 'client', 'network'],
  audit: ['actor', 'result', 'target'],
  system: ['level', 'source'],
} as const

type Query = Record<string, string | number | undefined>

function tags(config: Config) {
  return [...(config.connections ?? []).map(c => c.id), 'direct']
}


function idle(tag: string, frame: number, epoch: number, series: boolean) {
  const point = { t: epoch + frame * DEMO_TICK_MS, unique: 0, down: 0, up: 0 }
  return {
    tag, active: 0, unique: 0, down: 0, up: 0, down_total: 0, up_total: 0, peak_down: 0, peak_unique: 0, top: [],
    series: series ? Array.from({ length: HISTORY }, (_, i) => ({ ...point, t: epoch + (frame - HISTORY + 1 + i) * DEMO_TICK_MS })) : null,
  }
}

// Cumulative traffic counters use bytes, while sampled rates use bits per second.
function volume(frame: number, scale: number) {
  return scale * (3_000_000 + frame * 120_000 + Math.round(Math.sin(frame / 4 + scale) * 180_000)) * 3
}

function uploadVolume(downloadBytes: number) {
  return Math.floor(downloadBytes / 10)
}

function sample(frame: number, scale: number, epoch: number): StatPoint {
  const total = volume(frame, scale)
  const previous = volume(frame - 1, scale)
  const seconds = DEMO_TICK_MS / 1000
  const down = (total - previous) * 8 / seconds
  const up = (uploadVolume(total) - uploadVolume(previous)) * 8 / seconds
  return { t: epoch + frame * DEMO_TICK_MS, unique: Math.round(7 + scale + 3 * Math.sin(frame / 3 + scale)), down, up }
}

// Build a moving time window without replaying missed ticks or changing old points.
function snapshot(config: Config, frame: number, epoch: number, series: boolean): StatsSnapshot {
  const outbounds = tags(config).map(tag => {
    if (config.connections?.some(connection => connection.id === tag && connection.disabled)) return idle(tag, frame, epoch, series)
    const scale = 1 + [...tag].reduce((sum, char) => sum + char.charCodeAt(0), 0) % 4
    const current = sample(frame, scale, epoch)
    const total = volume(frame, scale)
    return {
      tag, active: current.unique + scale, unique: current.unique, down: current.down, up: current.up,
      down_total: total, up_total: uploadVolume(total), peak_down: 1_320_000 * scale, peak_unique: 10 + scale,
      series: series ? Array.from({ length: HISTORY }, (_, i) => sample(frame - HISTORY + 1 + i, scale, epoch)) : null,
      top: hosts.map((host, index) => {
        const share = [0.6, 0.25, 0.15][index]!
        return { host, down: Math.floor(total * share), up: Math.floor(total * share / 10), requests: Math.floor((frame + 1) * scale * share), last_seen: current.t }
      }),
    }
  })
  const cpu = Math.round(16 + 7 * Math.sin(frame / 4))
  const memory = Math.round(72 + 4 * Math.sin(frame / 12))
  const process = {
    cpu: Math.round((2.4 + Math.sin(frame / 4)) * 10) / 10,
    rss_bytes: Math.round(38 + 2 * Math.sin(frame / 12)) * 1024 ** 2,
  }
  return { system: { cpu, mem_pct: Math.round(memory / 256 * 100), mem_mb: 256, process }, outbounds }
}

function routeEntry(frame: number, epoch: number, config: Config, lookupGeo: (ip: string) => GeoLookup): JournalEntry {
  const candidates = tags(config)
  const destination = destinations[Math.floor(frame / candidates.length) % destinations.length]!
  const geo = lookupGeo(destination.ip)
  const routed = simulatedRoute(config, destination.host, geo.country, geo.categories, destination.ip)
  const preferred = candidates[frame % candidates.length] ?? 'direct'
  return {
    id: frame + 1, time: new Date(epoch + frame * DEMO_TICK_MS).toISOString(),
    host: destination.host, ip: destination.ip, client: '192.168.7.10',
    outbound: routed?.outbound ?? activeExit(config, preferred),
    rule: routed?.rule || 'Simulated traffic',
    network: 'tcp', destination_port: 443,
  }
}

function matches(entry: JournalEntry, keys: readonly (keyof JournalEntry)[], query: Query, search: string) {
  return keys.every(key => !query[key] || String(entry[key]) === String(query[key])) &&
    Object.values(entry).some(value => typeof value === 'string' && value.toLowerCase().includes(search))
}

function journalPage(records: JournalEntry[], kind: JournalKind, query: Query): JournalPage {
  const keys = fields[kind]
  const before = Number(query.before) || Infinity
  const limit = Math.min(DEMO_JOURNAL_LIMIT, Math.max(1, Math.floor(Number(query.limit) || 50)))
  const search = String(query.q ?? '').trim().toLowerCase()
  const found = records.filter(entry => entry.id < before && matches(entry, keys, query, search)).reverse()
  const facets = Object.fromEntries(keys.map(key => [key, [...new Set(records.map(entry => String(entry[key] ?? '')).filter(Boolean))].sort()]))
  return { entries: found.slice(0, limit).map(entry => ({ ...entry })), has_more: found.length > limit, facets }
}

// Share one session clock and a bounded journal between snapshots and subscriptions.
export function createTelemetry(now: () => number, lookupGeo: (ip: string) => GeoLookup) {
  const started = now()
  const epoch = started - (HISTORY - 1) * DEMO_TICK_MS
  let frame = HISTORY - 1 - SEED_ROUTES
  const time = new Date(started).toISOString()
  const records: Record<JournalKind, JournalEntry[]> = {
    routes: [],
    audit: [{ id: 1, time: new Date(started - 5 * 60000).toISOString(), actor: 'system', action: 'Demo session started', target: 'demo', result: 'info' }, ...firewallAudit(started)],
    system: [{ id: 1, time, level: 'INFO', source: 'demo', message: 'Browser demo: no router or network operations' }],
  }

  function sync(config: Config) {
    const next = HISTORY - 1 + Math.floor((now() - started) / DEMO_TICK_MS)
    if (next <= frame) return
    for (let i = Math.max(frame + 1, next - DEMO_JOURNAL_LIMIT + 1); i <= next; i++) {
      records.routes.push(routeEntry(i, epoch, config, lookupGeo))
    }
    frame = next
    records.routes = records.routes.slice(-DEMO_JOURNAL_LIMIT)
  }

  function applied() {
    const audit = records.audit
    audit.push({ id: audit.at(-1)!.id + 1, time: new Date(now()).toISOString(), actor: 'user', action: 'config.apply', target: 'demo', result: 'ok', details: 'Synthetic session only' })
    records.audit = audit.slice(-DEMO_JOURNAL_LIMIT)
  }

  return {
    started: time, sync, applied,
    stats: (config: Config, series: boolean) => snapshot(config, frame, epoch, series),
    journal: (kind: JournalKind, query: Query) => journalPage(records[kind], kind, query),
  }
}
