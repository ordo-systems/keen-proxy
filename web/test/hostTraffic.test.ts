import assert from 'node:assert/strict'
import { test } from 'node:test'
import { effectScope, nextTick, ref } from 'vue'
import type { HostStat } from '../src/types.ts'
import { HOST_PREVIEW, useHostTraffic } from '../src/useHostTraffic.ts'

const ranking = (prefix: string, n: number): HostStat[] =>
  Array.from({ length: n }, (_, i) => ({ host: `${prefix}${i}.example`, down: n - i, up: 0, requests: 1, last_seen: 0 }))

// Serves a filtered, ranked list like /api/stats/hosts and records every request.
function fakeServer(byTag: Record<string, HostStat[]>) {
  const calls: { tag: string; q: string; limit: number }[] = []
  let fail = false
  const fetchHosts = async (tag: string, q: string, limit: number) => {
    calls.push({ tag, q, limit })
    if (fail) throw new Error('Offline')
    const matched = (byTag[tag] ?? []).filter((h) => h.host.includes(q))
    return { hosts: matched.slice(0, limit), total: matched.length }
  }
  return { calls, fetchHosts, setFail: (v: boolean) => { fail = v } }
}

const settle = async () => {
  await nextTick()
  await new Promise((resolve) => setImmediate(resolve))
}

function mount(t: { after: (fn: () => void) => void }, server: ReturnType<typeof fakeServer>, initialTag = 'fi') {
  const scope = effectScope()
  t.after(() => scope.stop())
  const tag = ref(initialTag)
  const q = ref('')
  const traffic = scope.run(() => useHostTraffic(() => tag.value, () => q.value, server.fetchHosts))!
  return { tag, q, traffic }
}

test('fetches only the top hosts first and everything after Show all, including on polls', async (t) => {
  const server = fakeServer({ fi: ranking('h', 25) })
  const { traffic } = mount(t, server)
  await settle()
  assert.deepEqual(server.calls, [{ tag: 'fi', q: '', limit: HOST_PREVIEW }])
  assert.equal(traffic.hosts.value.length, 10)
  assert.equal(traffic.hosts.value[0]!.host, 'h0.example')
  assert.equal(traffic.total.value, 25)
  assert.equal(traffic.more.value, true)

  await traffic.showAll()
  assert.ok((server.calls.at(-1)?.limit ?? 0) >= 25)
  assert.equal(traffic.hosts.value.length, 25)
  assert.equal(traffic.more.value, false)

  await traffic.load()
  assert.equal(traffic.hosts.value.length, 25)
})

test('offers no Show all when the ranking fits the preview', async (t) => {
  const server = fakeServer({ fi: ranking('h', HOST_PREVIEW) })
  const { traffic } = mount(t, server)
  await settle()
  assert.equal(traffic.hosts.value.length, HOST_PREVIEW)
  assert.equal(traffic.more.value, false)
})

test('search keeps the chosen view and a tab switch returns to the preview', async (t) => {
  const server = fakeServer({ fi: [...ranking('video', 30), ...ranking('mail', 5)], de: ranking('de', 15) })
  const { tag, q, traffic } = mount(t, server)
  await settle()
  await traffic.showAll()
  assert.equal(traffic.hosts.value.length, 35)

  q.value = 'video'
  await settle()
  assert.equal(server.calls.at(-1)!.q, 'video')
  assert.equal(traffic.expanded.value, true)
  assert.equal(traffic.hosts.value.length, 30)
  assert.ok(traffic.hosts.value.every((h) => h.host.startsWith('video')))

  q.value = ''
  tag.value = 'de'
  await settle()
  assert.deepEqual(server.calls.at(-1), { tag: 'de', q: '', limit: HOST_PREVIEW })
  assert.equal(traffic.expanded.value, false)
  assert.equal(traffic.hosts.value.length, 10)
  assert.equal(traffic.more.value, true)
})

test('expanded search loads all newly matching hosts in one request', async (t) => {
  const server = fakeServer({ fi: [...ranking('video', 30), ...ranking('mail', 12)] })
  const { q, traffic } = mount(t, server)
  q.value = 'mail'
  await settle()
  await traffic.showAll()
  assert.equal(traffic.hosts.value.length, 12)

  const numberOfCalls = server.calls.length
  q.value = ''
  await settle()
  assert.equal(server.calls.length, numberOfCalls + 1)
  assert.equal(traffic.hosts.value.length, 42)
})

test('a failed Show all keeps the preview and the button', async (t) => {
  const server = fakeServer({ fi: ranking('h', 25) })
  const { traffic } = mount(t, server)
  await settle()
  server.setFail(true)
  await traffic.showAll()
  assert.equal(traffic.expanded.value, false)
  assert.equal(traffic.expanding.value, false)
  assert.equal(traffic.hosts.value.length, 10)
  assert.equal(traffic.more.value, true)
})

test('drops a response that arrives after the tab changed', async (t) => {
  const slow = Promise.withResolvers<{ hosts: HostStat[]; total: number }>()
  const server = fakeServer({ de: ranking('de', 3) })
  const fetchHosts = (tag: string, q: string, limit: number) =>
    tag === 'fi' ? slow.promise : server.fetchHosts(tag, q, limit)
  const scope = effectScope()
  t.after(() => scope.stop())
  const tag = ref('fi')
  const traffic = scope.run(() => useHostTraffic(() => tag.value, () => '', fetchHosts))!
  tag.value = 'de'
  await settle()
  slow.resolve({ hosts: ranking('fi', 10), total: 20 })
  await settle()
  assert.deepEqual(traffic.hosts.value.map((h) => h.host), ['de0.example', 'de1.example', 'de2.example'])
  assert.equal(traffic.more.value, false)
})

test('keeps the button visible while expanding and drops an older preview response', async (t) => {
  const preview = Promise.withResolvers<{ hosts: HostStat[]; total: number }>()
  const full = Promise.withResolvers<{ hosts: HostStat[]; total: number }>()
  const server = fakeServer({ fi: ranking('h', 25) })
  let delay = false
  const scope = effectScope()
  t.after(() => scope.stop())
  const traffic = scope.run(() => useHostTraffic(() => 'fi', () => '', (tag, q, limit) => {
    if (delay) return limit === HOST_PREVIEW ? preview.promise : full.promise
    return server.fetchHosts(tag, q, limit)
  }))
  assert.ok(traffic)
  await settle()
  delay = true
  const pendingPreview = traffic.load()
  const pendingExpansion = traffic.showAll()
  assert.equal(traffic.more.value, true)
  assert.equal(traffic.expanding.value, true)
  assert.equal(traffic.hosts.value.length, 10)
  full.resolve({ hosts: ranking('h', 25), total: 25 })
  await pendingExpansion
  preview.resolve({ hosts: ranking('h', 10), total: 25 })
  await pendingPreview
  assert.equal(traffic.hosts.value.length, 25)
  assert.equal(traffic.more.value, false)
  assert.equal(traffic.expanding.value, false)
})

test('refreshes rows even when a poll takes longer than the refresh interval', async (t) => {
  const first = Promise.withResolvers<{ hosts: HostStat[]; total: number }>()
  const second = Promise.withResolvers<{ hosts: HostStat[]; total: number }>()
  let requests = 0
  const scope = effectScope()
  t.after(() => scope.stop())
  const traffic = scope.run(() => useHostTraffic(() => 'fi', () => '', () =>
    ++requests === 1 ? first.promise : second.promise,
  ))
  assert.ok(traffic)

  void traffic.load()
  first.resolve({ hosts: ranking('first', 10), total: 15 })
  await settle()
  assert.equal(traffic.hosts.value[0]?.host, 'first0.example')
  assert.equal(requests, 1)

  const refresh = traffic.load()
  second.resolve({ hosts: ranking('second', 10), total: 15 })
  await refresh
  assert.equal(traffic.hosts.value[0]?.host, 'second0.example')
})
