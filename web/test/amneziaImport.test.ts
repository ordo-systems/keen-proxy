import assert from 'node:assert/strict'
import { test } from 'node:test'
import * as draft from '../src/connectionDraft.ts'
import type { Connection } from '../src/types.ts'

const profiles: Connection[] = [
  { id: '', name: 'First', type: 'amneziawg', amneziawg: 'first-private-profile' },
  { id: '', name: 'Second', type: 'amneziawg', amneziawg: 'second-private-profile' },
]

test('multiple decoded profiles require explicit selection and keep the chosen credentials', () => {
  assert.throws(() => draft.selectAmneziaProfile(profiles, null), /amnezia_choose_profile/)
  const selected = draft.selectAmneziaProfile(profiles, 1)
  assert.equal(selected.amneziawg, 'second-private-profile')
  selected.amneziawg = 'edited'
  assert.equal(profiles[1]!.amneziawg, 'second-private-profile')
  for (const index of [-1, 2, 0.5, NaN]) {
    assert.throws(() => draft.selectAmneziaProfile(profiles, index), /amnezia_choose_profile/)
  }
})

test('a single autonomous export does not need a selector; empty exports cannot be saved', () => {
  assert.equal(draft.selectAmneziaProfile(profiles.slice(0, 1), null).amneziawg, 'first-private-profile')
  assert.throws(() => draft.selectAmneziaProfile([], null), /amnezia_choose_profile/)
})

test('an unselected multi-export does not inherit the first profile name or decode vpn://', () => {
  assert.equal(draft.suggestedConnectionName(profiles, null, 'export.vpn'), 'export')
  assert.equal(draft.suggestedConnectionName(profiles, 1, 'export.vpn'), 'Second')
  assert.equal(draft.suggestedConnectionName(profiles.slice(0, 1), null, 'export.vpn'), 'First')
  const classified = draft.classifyConnectionImport(' \uFEFFvpn://not-decoded-secret ', 'export.vpn', 'wireguard')
  assert.equal(classified.kind, 'vpn')
  if (classified.kind !== 'vpn') return
  assert.equal(classified.uri, 'vpn://not-decoded-secret')
  const raw = '[Interface]\nPrivateKey=secret\nFutureKey=1\n'
  const conf = draft.classifyConnectionImport(raw, 'a.conf', 'amneziawg')
  assert.equal(conf.kind, 'profiles')
  if (conf.kind === 'profiles') assert.equal(conf.profiles[0]!.amneziawg, raw)
  const wg = '[Interface]\nPrivateKey=a\nAddress=10.1.0.2/32\n[Peer]\nPublicKey=b\nEndpoint=vpn.example.test:51820\n'
  const parsed = draft.classifyConnectionImport(wg, 'a.conf', 'wireguard')
  assert.equal(parsed.kind, 'profiles')
  if (parsed.kind === 'profiles') assert.equal(parsed.profiles[0]!.type, 'wireguard')
})

test('import failures map to translation keys and never echo profile text', () => {
  assert.equal(draft.connectionErrorKey(new Error('private-secret leaked')), 'ui.invalid')
  assert.equal(draft.connectionErrorKey(new SyntaxError('Unexpected token private-secret')), 'ui.invalid')
  assert.equal(draft.connectionErrorKey(new Error('amnezia_demo_unavailable')), 'ui.amneziaDemo')
  assert.equal(draft.connectionErrorKey(new Error('Unsupported WireGuard setting: privatekey')), 'ui.unsupportedWG')
  assert.throws(
    () => draft.manualConnection({ protocol: 'amneziawg', id: 'a', name: 'A', amneziawg: 'x'.repeat(draft.MAX_CONNECTION_FILE + 1) }),
    /2 MiB/,
  )
})
