import assert from 'node:assert/strict'
import { register } from 'node:module'
import { beforeEach, test } from 'node:test'
import 'naive-ui'
import { api, setUnauthorizedHandler } from '../src/api.ts'
import type { Config, Session, Status } from '../src/types.ts'

register('./local-ts-resolver.mjs', import.meta.url)
// The store's startup imports need both the resolver and the document in place.
Object.defineProperty(globalThis, 'document', { configurable: true, value: { documentElement: {} } })
const { authed, store } = await import('../src/store.ts').finally(() => {
  Reflect.deleteProperty(globalThis, 'document')
})

function config(): Config {
  return {
    api: { listen: ':8080', token_file: 'panel.token' },
    lan: { interface: 'br0', wan: 'eth0' },
    dns: { listen: ':5353', upstreams: ['tls://dns.example'], fallback: '' },
    intercept: { mode: 'redirect', tcp_port: 12345, udp_port: 12346, fwmark: 1, route_table: 100 },
    geoip: { databases: [] },
    filters: { sources: [], exceptions: [] },
    connections: [], groups: [], networks: [], clients: [],
  }
}

function status(started: string): Status {
  return {
    started, mode: 'redirect', dns: ':5353', firewall: true, restored: 0,
    sources: 0, connections: 0, groups: 0, entries: 0, clients: 0, online_devices: 0,
    geoip: { loaded: false }, conn_countries: null,
  }
}

beforeEach(() => {
  store.setDraft(config())
  store.state.saved = JSON.stringify(store.state.config)
  store.state.status = null
  store.state.statusError = ''
})

test('Apply sends one snapshot and preserves edits made before the canonical reply', async (t) => {
  const reply = Promise.withResolvers<Response>()
  const put = t.mock.method(globalThis, 'fetch', (_url: RequestInfo | URL, _init?: RequestInit) => reply.promise)
  t.mock.method(api, 'status', async () => status('2026-11-27T09:00:00Z'))
  const draft = store.state.config!
  draft.lan.interface = 'br1'
  const sent = JSON.stringify(draft)
  const apply = store.apply()
  draft.dns.upstreams.push('tls://second.example')

  assert.strictEqual(store.apply(), apply)
  assert.equal(put.mock.callCount(), 1)
  const [path, init] = put.mock.calls[0].arguments
  assert.equal(path, '/api/config')
  assert.equal(init?.method, 'PUT')
  assert.equal(init?.body, sent)

  const canonical = config()
  canonical.lan.interface = 'br-canonical'
  reply.resolve(Response.json(canonical))
  await apply

  assert.deepEqual(store.applied.value, canonical)
  assert.strictEqual(store.state.config, draft)
  assert.deepEqual(draft.dns.upstreams, ['tls://dns.example', 'tls://second.example'])
  assert.equal(store.dirty.value, true)
  assert.equal(store.state.applying, false)
  store.discard()
  assert.deepEqual(store.state.config, canonical)
  assert.equal(store.dirty.value, false)
})

test('a status failure after PUT keeps the canonical save and the last status', async (t) => {
  const last = status('2026-11-27T08:00:00Z')
  const fresh = status('2026-11-27T10:00:00Z')
  const olderReply = Promise.withResolvers<Status>()
  const postSaveReply = Promise.withResolvers<Status>()
  const statuses = [Promise.resolve(last), olderReply.promise, postSaveReply.promise, Promise.resolve(fresh)]
  const readStatus = t.mock.method(api, 'status', () => statuses.shift()!)
  await store.refreshStatus()
  const olderPoll = store.refreshStatus()

  store.state.config!.lan.interface = 'br1'
  const canonical = config()
  canonical.lan.interface = 'br-canonical'
  t.mock.method(globalThis, 'fetch', async () => Response.json(canonical))
  await store.apply()
  assert.equal(readStatus.mock.callCount(), 3)
  assert.equal(store.state.applying, false)

  postSaveReply.reject(new Error('status temporarily unavailable'))
  olderReply.resolve(status('2026-11-27T08:30:00Z'))
  await olderPoll

  assert.deepEqual(store.state.config, canonical)
  assert.deepEqual(store.applied.value, canonical)
  assert.equal(store.dirty.value, false)
  assert.equal(store.state.error, '')
  assert.deepEqual(store.state.status, last)
  assert.equal(store.state.statusError, 'status temporarily unavailable')
  await store.refreshStatus()
  assert.deepEqual(store.state.status, fresh)
  assert.equal(store.state.statusError, '')
})

test('renewing an expired session after Apply preserves subsequent draft edits', async (t) => {
  const reply = Promise.withResolvers<Response>()
  const unauthorized = Promise.withResolvers<void>()
  let signedIn = false
  setUnauthorizedHandler(() => {
    authed.value = false
    unauthorized.resolve()
  })
  t.after(() => setUnauthorizedHandler(() => {}))
  const canonical = config()
  canonical.lan.interface = 'br1'
  t.mock.method(api, 'devices', async () => [])
  t.mock.method(api, 'session', async () => ({ trusted: false, ip: '192.0.2.1' }) as Session)
  t.mock.method(globalThis, 'fetch', async (url: string, init?: RequestInit) => {
    if (url === '/api/config' && init?.method === 'PUT') return reply.promise
    if (url === '/api/config' && signedIn) return Response.json(canonical)
    if (url === '/api/status') {
      return signedIn ? Response.json(status('2026-11-27T10:00:00Z')) : new Response(null, { status: 401 })
    }
    throw new Error(`Unexpected request ${init?.method} ${url}`)
  })
  const draft = store.state.config!
  draft.lan.interface = 'br1'
  const apply = store.apply()
  draft.lan.wan = 'eth1'
  reply.resolve(Response.json(canonical))
  await apply
  await unauthorized.promise
  assert.equal(authed.value, false)
  signedIn = true
  await store.loadSession(true)
  await store.load()
  assert.equal(authed.value, true)
  assert.equal(store.applied.value?.lan.wan, 'eth0')
  assert.equal(store.state.config?.lan.wan, 'eth1')
  assert.equal(store.dirty.value, true)
})

test('explicit logout discards edits and ignores a pending save reply after login', async (t) => {
  const reply = Promise.withResolvers<Response>()
  const fresh = config()
  fresh.lan.interface = 'br-other'
  t.mock.method(api, 'config', async () => fresh)
  t.mock.method(api, 'status', async () => status('2026-11-27T10:00:00Z'))
  t.mock.method(api, 'devices', async () => [])
  t.mock.method(globalThis, 'fetch', () => reply.promise)
  store.state.config!.lan.interface = 'br1'
  const apply = store.apply()
  store.state.config!.lan.wan = 'eth1'

  store.resetDraft()
  await store.load()
  const saved = config()
  saved.lan.interface = 'br1'
  reply.resolve(Response.json(saved))
  await apply

  assert.deepEqual(store.applied.value, fresh)
  assert.deepEqual(store.state.config, fresh)
  assert.equal(store.dirty.value, false)
})

test('a rejected PUT preserves both the saved baseline and unsaved changes', async (t) => {
  const reply = Promise.withResolvers<Response>()
  t.mock.method(globalThis, 'fetch', () => reply.promise)
  const draft = store.state.config!
  draft.lan.interface = 'br1'
  const apply = store.apply()
  draft.lan.wan = 'eth1'
  reply.resolve(Response.json({ error: 'reload failed' }, { status: 503 }))

  await assert.rejects(apply, { message: 'reload failed' })
  assert.deepEqual(store.applied.value, config())
  assert.strictEqual(store.state.config, draft)
  assert.deepEqual(draft.lan, { interface: 'br1', wan: 'eth1' })
  assert.equal(store.dirty.value, true)
  assert.equal(store.state.error, 'reload failed')
  assert.equal(store.state.applying, false)
})
