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
