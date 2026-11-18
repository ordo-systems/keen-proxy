import assert from 'node:assert/strict'
import { test } from 'node:test'
import { api, setUnauthorizedHandler } from '../src/api.ts'
import { api as demoAPI } from '../src/demo/api.ts'

const invalid = {
  list: { entries: [] }, valid: false, duplicates: 0, omitted_issues: 0,
  issues: [{ kind: 'unsupported', location: 'rules[0]', message: 'Unsupported rule' }],
}

test('preview sends the original file with session credentials and returns invalid previews', async (t) => {
  const file = new File([new Uint8Array([83, 82, 83, 0, 255])], 'rules.srs', { type: 'application/x-srs' })
  const fetch = t.mock.method(globalThis, 'fetch', async () => Response.json(invalid))
  assert.equal(api.resourceExchangeAvailable, true)
  assert.deepEqual(await api.previewResources('srs', file), invalid)
  const [path, init] = fetch.mock.calls[0]!.arguments as unknown as [string, RequestInit]
  assert.equal(path, '/api/resources/preview?format=srs')
  assert.equal(init.method, 'POST')
  assert.equal(init.credentials, 'same-origin')
  assert.equal(new Headers(init.headers).get('Content-Type'), 'application/octet-stream')
  assert.equal(init.body, file)
})

test('export forwards only the resource list and returns bytes and losses without downloading', async (t) => {
  const payload = { data: 'U1JTAP8=', losses: ['Some entries were omitted'] }
  const fetch = t.mock.method(globalThis, 'fetch', async () => Response.json(payload))
  const list = { name: 'Example', entries: [{ type: 'ip_cidr' as const, value: '192.0.2.1/32', disabled: true }] }
  assert.deepEqual(await api.exportResources('srs', list), payload)
  const [path, init] = fetch.mock.calls[0]!.arguments as unknown as [string, RequestInit]
  assert.equal(path, '/api/resources/export?format=srs')
  assert.equal(init.method, 'POST')
  assert.equal(init.credentials, 'same-origin')
  assert.equal(new Headers(init.headers).get('Content-Type'), 'application/json')
  assert.deepEqual(JSON.parse(init.body as string), list)
})

test('backup import sends a large original YAML file or pasted text without a JSON envelope', async (t) => {
  const yaml = 'groups: []\n# ' + 'é'.repeat(1 << 20)
  const file = new File([yaml], 'backup.yaml', { type: 'text/plain' })
  const config = { groups: [], connections: [] }
  const fetch = t.mock.method(globalThis, 'fetch', async () => Response.json(config))
  assert.ok(file.size > 2 * 1024 * 1024)
  assert.deepEqual(await api.importYAML(file), config)
  assert.deepEqual(await api.importYAML('groups: []\n'), config)
  const calls = fetch.mock.calls.map(call => call.arguments as unknown as [string, RequestInit])
  for (const [path, init] of calls) {
    assert.equal(path, '/api/config/import')
    assert.equal(init.method, 'POST')
    assert.equal(init.credentials, 'same-origin')
    assert.equal(new Headers(init.headers).get('Content-Type'), 'application/yaml')
  }
  assert.equal(calls[0]![1].body, file)
  assert.equal(await (calls[1]![1].body as Blob).text(), 'groups: []\n')
})

test('transport errors keep their status and expired sessions use the shared login handler', async (t) => {
  const login = t.mock.fn()
  setUnauthorizedHandler(login)
  t.after(() => setUnauthorizedHandler(() => {}))
  t.mock.method(globalThis, 'fetch', async () => Response.json({ error: 'Sign in first' }, { status: 401 }))
  await assert.rejects(api.previewResources('txt', new Blob(['example.test'])), { status: 401, message: 'Sign in first' })
  await assert.rejects(api.exportResources('txt', { entries: [] }), { status: 401 })
  assert.equal(login.mock.callCount(), 2)
})

test('the static demo advertises no conversion and never sends a file or list', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => assert.fail('Unexpected fetch'))
  assert.equal(demoAPI.resourceExchangeAvailable, false)
  await assert.rejects(demoAPI.previewResources('txt', new Blob(['example.test'])), /Go backend/)
  await assert.rejects(demoAPI.exportResources('txt', { entries: [] }), /Go backend/)
  assert.equal(fetch.mock.callCount(), 0)
})
