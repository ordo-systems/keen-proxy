import assert from 'node:assert/strict'
import { test } from 'node:test'
import { api, setUnauthorizedHandler } from '../src/api.ts'
import { api as demoAPI } from '../src/demo/api.ts'

test('downloads the ZIP with same-origin session credentials', async (t) => {
  const zip = new Uint8Array([80, 75, 3, 4, 0, 255])
  const fetch = t.mock.method(globalThis, 'fetch', async () =>
    new Response(zip, { headers: { 'Content-Type': 'application/zip' } }),
  )

  const archive = await api.diagnosticBundle()
  assert.deepEqual(new Uint8Array(await archive.arrayBuffer()), zip)
  assert.equal(fetch.mock.calls.length, 1)
  const [url, init] = fetch.mock.calls[0]!.arguments as unknown as [string, RequestInit]
  assert.equal(url, '/api/diagnostics/bundle')
  assert.equal(init.method, 'GET')
  assert.equal(init.credentials, 'same-origin')
  assert.equal(init.headers, undefined)
})

test('an expired archive session invokes the panel login handler', async (t) => {
  const signIn = t.mock.fn()
  setUnauthorizedHandler(signIn)
  t.after(() => setUnauthorizedHandler(() => {}))
  t.mock.method(globalThis, 'fetch', async () =>
    Response.json({ error: 'token login required' }, { status: 401 }),
  )

  await assert.rejects(api.diagnosticBundle(), { status: 401 })
  assert.equal(signIn.mock.callCount(), 1)
})

test('does not save a successful HTML response as a diagnostics ZIP', async (t) => {
  t.mock.method(globalThis, 'fetch', async () =>
    new Response('<html>Panel</html>', { headers: { 'Content-Type': 'text/html' } }),
  )

  await assert.rejects(api.diagnosticBundle(), /ZIP archive/)
})

test('rejects a diagnostics response without a content type', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => new Response(null))
  await assert.rejects(api.diagnosticBundle(), /ZIP archive/)
})

test('static demo never calls the router archive endpoint', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => assert.fail('unexpected fetch'))
  await assert.rejects(demoAPI.diagnosticBundle(), /router/)
  assert.equal(fetch.mock.callCount(), 0)
})

test('module confirmation sends a token only on the load request, without a browser session', async (t) => {
  const status = { guard: { state: 'registered' }, tproxy: { state: 'unknown' }, token_required: true }
  const fetch = t.mock.method(globalThis, 'fetch', async () => Response.json(status))

  assert.deepEqual(await api.loadKernelModule('guard', 'fixture-token'), status)
  assert.equal(fetch.mock.calls.length, 1)
  const [url, init] = fetch.mock.calls[0]!.arguments as unknown as [string, RequestInit]
  assert.equal(url, '/api/diagnostics/kernel-modules/guard/load')
  assert.equal(init.method, 'POST')
  assert.equal(init.credentials, 'omit')
  assert.equal(init.redirect, 'error')
  assert.equal(new Headers(init.headers).get('Authorization'), 'Bearer fixture-token')
})

test('startup loading uses a request-scoped bearer and returns kernel diagnostics', async (t) => {
  const before = { guard: { state: 'registered', can_autoload: true }, tproxy: { state: 'unknown' }, token_required: true }
  const after = { ...before, guard: { ...before.guard, autoload: true } }
  const fetch = t.mock.method(globalThis, 'fetch', async (_url: string, init: RequestInit) =>
    Response.json(init.method === 'PUT' ? after : before),
  )

  assert.deepEqual(await api.setKernelModuleAutoload('guard', true, 'fixture-token'), after)
  assert.deepEqual(await api.kernelModules(), before)
  assert.equal(fetch.mock.callCount(), 2)
  const [url, init] = fetch.mock.calls[0]!.arguments
  assert.equal(url, '/api/diagnostics/kernel-modules/guard/autoload')
  assert.equal(init.method, 'PUT')
  assert.equal(init.credentials, 'omit')
  assert.equal(init.redirect, 'error')
  assert.equal(new Headers(init.headers).get('Authorization'), 'Bearer fixture-token')
  assert.equal(new Headers(init.headers).get('Content-Type'), 'application/json')
  assert.equal(init.body, '{"enabled":true}')
  const [, probe] = fetch.mock.calls[1]!.arguments
  assert.equal(new Headers(probe.headers).get('Authorization'), null)
})

test('a signed-in session can disable startup loading without a bearer', async (t) => {
  const status = { guard: { state: 'unknown' }, tproxy: { state: 'not_found' }, token_required: false }
  const fetch = t.mock.method(globalThis, 'fetch', async () => Response.json(status))

  assert.deepEqual(await api.setKernelModuleAutoload('tproxy', false), status)
  assert.equal(fetch.mock.callCount(), 1)
  const [url, init] = fetch.mock.calls[0]!.arguments as unknown as [string, RequestInit]
  assert.equal(url, '/api/diagnostics/kernel-modules/tproxy/autoload')
  assert.equal(init.method, 'PUT')
  assert.equal(init.credentials, 'same-origin')
  assert.equal(new Headers(init.headers).get('Authorization'), null)
  assert.equal(init.body, '{"enabled":false}')
})

test('the static demo neither exposes nor modifies kernel module startup settings', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => assert.fail('unexpected fetch'))
  const unsupported = { guard: { state: 'unknown' }, tproxy: { state: 'unknown' }, token_required: true }

  assert.deepEqual(await demoAPI.kernelModules(), unsupported)
  await assert.rejects(demoAPI.setKernelModuleAutoload('guard', true, 'fixture-token'), /router/)
  assert.deepEqual(await demoAPI.kernelModules(), unsupported)
  assert.equal(fetch.mock.callCount(), 0)
})
