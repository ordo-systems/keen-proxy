import assert from 'node:assert/strict'
import { test } from 'node:test'
import { effectScope, shallowRef } from 'vue'
import { useCurrentDomainAddresses } from '../src/domainAddresses.ts'
import type { DomainRecord } from '../src/types.ts'

test('draft DNS addresses expire without replacing the preview snapshot', (t) => {
  const start = Date.parse('2026-11-18T10:00:00Z')
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: start })
  const snapshot = shallowRef<DomainRecord[][]>([[{
    name: 'preview.example',
    checked_at: new Date(start).toISOString(), attempted_at: new Date(start).toISOString(), source: 'preview',
    addresses: [
      { ip: '192.0.2.1', expires_at: new Date(start + 1000).toISOString() },
      { ip: '192.0.2.2', expires_at: new Date(start + 2000).toISOString() },
    ],
  }]])
  const original = snapshot.value
  const scope = effectScope()
  t.after(() => scope.stop())
  const projection = scope.run(() => useCurrentDomainAddresses(() => snapshot.value))!
  const ips = () => projection.value[0]!.map(address => address.ip)
  assert.deepEqual(ips(), ['192.0.2.1', '192.0.2.2'])
  t.mock.timers.tick(1000)
  assert.equal(snapshot.value, original)
  assert.deepEqual(ips(), ['192.0.2.2'])
  t.mock.timers.tick(1000)
  assert.deepEqual(ips(), [])
})
