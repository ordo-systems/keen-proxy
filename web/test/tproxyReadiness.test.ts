import assert from 'node:assert/strict'
import { test } from 'node:test'
import { effectScope, nextTick, ref } from 'vue'
import { api } from '../src/api.ts'
import type { TProxyReadiness } from '../src/types.ts'
import { useTProxyReadiness } from '../src/useTProxyReadiness.ts'

test('checks on visiting Network, and a fresh successful recheck restores the TPROXY choice', async (t) => {
  const scope = effectScope()
  t.after(() => scope.stop())
  const visible = ref(false)
  const first = Promise.withResolvers<TProxyReadiness>()
  const retry = Promise.withResolvers<TProxyReadiness>()
  const probe = t.mock.fn(() => retry.promise)
  probe.mock.mockImplementationOnce(() => first.promise)
  const readiness = scope.run(() => useTProxyReadiness(() => visible.value, probe))!

  await readiness.check()
  assert.equal(probe.mock.callCount(), 0)
  assert.equal(readiness.unavailable.value, false)

  visible.value = true
  await nextTick()
  assert.equal(readiness.checking.value, true)
  await readiness.check()
  assert.equal(probe.mock.callCount(), 1)
  first.resolve({ state: 'unavailable', reason: 'module_not_loaded', startup_blocked: true })
  await first.promise
  assert.equal(readiness.checking.value, false)
  assert.equal(readiness.unavailable.value, true)
  assert.equal(readiness.startupBlocked.value, true)
  assert.deepEqual(readiness.result.value, { state: 'unavailable', reason: 'module_not_loaded', startup_blocked: true })

  const pending = readiness.check()
  assert.equal(probe.mock.callCount(), 2)
  assert.equal(readiness.unavailable.value, true)
  retry.resolve({ state: 'ready' })
  await pending
  assert.equal(readiness.unavailable.value, false)
  assert.equal(readiness.startupBlocked.value, false)
  assert.equal(readiness.result.value?.state, 'ready')
})

test('an unknown probe or transport failure leaves TPROXY selectable', async (t) => {
  const scope = effectScope()
  t.after(() => scope.stop())
  const visible = ref(false)
  const first = Promise.withResolvers<TProxyReadiness>()
  const probe = t.mock.fn(async (): Promise<TProxyReadiness> => { throw new Error('Offline') })
  probe.mock.mockImplementationOnce(() => first.promise)
  const readiness = scope.run(() => useTProxyReadiness(() => visible.value, probe))!

  visible.value = true
  await nextTick()
  first.resolve({ state: 'unknown', reason: 'probe_failed', startup_blocked: true })
  await first.promise
  assert.equal(readiness.result.value?.state, 'unknown')
  assert.equal(readiness.unavailable.value, false)

  await readiness.check()
  assert.equal(readiness.checking.value, false)
  assert.equal(readiness.result.value?.state, 'failed')
  assert.equal(readiness.unavailable.value, false)
  assert.equal(readiness.startupBlocked.value, true)
})

test('recovery refreshes readiness after an older probe even when Network is hidden', async (t) => {
  const scope = effectScope()
  t.after(() => scope.stop())
  const visible = ref(true)
  const first = Promise.withResolvers<TProxyReadiness>()
  const fresh = Promise.withResolvers<TProxyReadiness>()
  const freshStarted = Promise.withResolvers<void>()
  const probe = t.mock.fn(() => {
    freshStarted.resolve()
    return fresh.promise
  })
  probe.mock.mockImplementationOnce(() => first.promise)
  const readiness = scope.run(() => useTProxyReadiness(() => visible.value, probe))!

  visible.value = false
  const refresh = readiness.check(true)
  assert.equal(probe.mock.callCount(), 1)
  first.resolve({ state: 'ready', startup_blocked: true })
  await freshStarted.promise
  assert.equal(probe.mock.callCount(), 2)
  assert.equal(readiness.startupBlocked.value, true)
  fresh.resolve({ state: 'ready' })
  await refresh
  assert.equal(readiness.startupBlocked.value, false)
})

test('saved recovery posts with the session and no draft or config write', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async (_url: string, _init: RequestInit) =>
    new Response(null, { status: 204 }),
  )
  assert.equal(await api.retryTProxy(), undefined)
  assert.deepEqual(fetch.mock.calls.map(({ arguments: [url, init] }) => [url, init.method, init.credentials, init.body]), [
    ['/api/diagnostics/tproxy/retry', 'POST', 'same-origin', undefined],
  ])
})

test('saved recovery reports activation errors from the router', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => Response.json({ error: 'TPROXY activation failed' }, { status: 422 }))
  await assert.rejects(api.retryTProxy(), { status: 422, message: 'TPROXY activation failed' })
})
