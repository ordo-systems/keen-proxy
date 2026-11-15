import { test } from 'node:test'
import assert from 'node:assert/strict'
import { protocolOf, serverOf } from '../src/conn.ts'
import type { Connection } from '../src/types.ts'

test('AWG summaries expose only protocol and endpoint, never profile secrets', () => {
  const connection: Connection = {
    id: 'awg',
    name: 'AWG',
    type: 'amneziawg',
    amneziawg: '[Interface]\nPrivateKey=private-secret\nHeaderProtectionKey=header-secret\nI1=<b 0xc0ffee><r 32>\n[Peer]\nPresharedKey=psk-secret\n  eNdPoInT = [2001:db8::1]:51820 # server\n',
  }
  assert.equal(protocolOf(connection), 'AmneziaWG')
  assert.deepEqual(serverOf(connection), { host: '[2001:db8::1]', port: '51820' })
  assert.equal(connection.amneziawg!.includes('private-secret'), true)
})

test('ordinary WireGuard summaries still use their structured peer', () => {
  const connection: Connection = {
    id: 'wg',
    name: 'WG',
    type: 'wireguard',
    wireguard: {
      private_key: 'private-secret',
      address: ['10.1.0.2/32'],
      peer: { endpoint: 'vpn.example.test:51820', public_key: 'peer-key' },
    },
  }
  assert.equal(protocolOf(connection), 'WireGuard')
  assert.deepEqual(serverOf(connection), { host: 'vpn.example.test', port: '51820' })
})

test('incomplete AWG drafts do not expose profile text as a server address', () => {
  for (const profile of [undefined, '', '[Interface]\nPrivateKey=private-secret', '[Peer]\nEndpoint = # not configured']) {
    assert.deepEqual(serverOf({ id: 'draft', name: 'Draft', type: 'amneziawg', amneziawg: profile }), { host: '', port: '' })
  }
})
