import assert from 'node:assert/strict'
import { test } from 'node:test'
import { dnsTunnelChoices, dnsUpstreamsIncomplete, selectDNSResolver } from '../src/dnsSettings.ts'
import type { Connection, DNSConfig } from '../src/types'

const primary = 'https://one.example/dns-query'
const secondary = 'tls://two.example:853'
const extra = '192.0.2.53'

test('an unchanged legacy list does not block an unrelated edit', () => {
  assert.equal(dnsUpstreamsIncomplete([], []), false)
  assert.equal(dnsUpstreamsIncomplete([primary], [primary]), false)
})

test('a changed list accepts one upstream and rejects a missing or duplicate priority server', () => {
  assert.equal(dnsUpstreamsIncomplete([extra], [primary, secondary]), false)
  assert.equal(dnsUpstreamsIncomplete([], [primary]), true)
  assert.equal(dnsUpstreamsIncomplete(['', secondary], []), true)
  assert.equal(dnsUpstreamsIncomplete([primary, ' '], []), true)
  assert.equal(dnsUpstreamsIncomplete([primary, primary], []), true)
  assert.equal(dnsUpstreamsIncomplete([primary, secondary], []), false)
})

test('editing a resolver preserves the other slots, route, and bootstrap entries', () => {
  const dns: DNSConfig = {
    listen: '127.0.0.1:5353', fallback: '127.0.0.1:53', upstreams: [primary, '192.0.2.54', extra],
    bootstrap: { 'one.example': '192.0.2.1' },
  }
  selectDNSResolver(dns, 1, secondary, '192.0.2.2')
  assert.deepEqual(dns.upstreams, [primary, secondary, extra])
  assert.deepEqual(dns.bootstrap, { 'one.example': '192.0.2.1', 'two.example': '192.0.2.2' })
  selectDNSResolver(dns, 0, primary, '192.0.2.99')
  assert.equal(dns.bootstrap?.['one.example'], '192.0.2.1')
  assert.equal(dns.route, undefined)
  assert.equal(dns.fallback, '127.0.0.1:53')
})

test('selecting the secondary first leaves an explicit empty primary slot', () => {
  const dns: DNSConfig = { listen: '127.0.0.1:5353', fallback: '', upstreams: [] }
  selectDNSResolver(dns, 1, extra)
  assert.deepEqual(dns.upstreams, ['', extra])
  selectDNSResolver(dns, 0, primary)
  assert.deepEqual(dns.upstreams, [primary, extra])
  assert.equal(dns.bootstrap, undefined)
})

test('DNS tunnel choices omit direct interfaces and tunnels that fall back to one', () => {
  const bound: Connection = { id: 'lan', name: 'LAN', type: 'singbox', outbound: { type: 'direct', bind_interface: 'eth0' } }
  const tunnel: Connection = { id: 'wg', name: 'WG', type: 'singbox', endpoint: { type: 'wireguard' } }
  const choices = [{ value: 'lan', label: 'LAN' }, { value: 'wg', label: 'WG' }]
  assert.deepEqual(dnsTunnelChoices(choices, [bound, tunnel]), [choices[1]])
  assert.deepEqual(dnsTunnelChoices(choices.slice(0, 1), [bound]), [])
  assert.deepEqual(dnsTunnelChoices(choices, [bound, { ...tunnel, fallback: bound.id }]), [])
})
