import assert from 'node:assert/strict'
import { test } from 'node:test'
import { localPresetFits, mergeResourceEntries, planResourceImport, resourceList, snapshotResourceDraft, stageResourceImport } from '../src/resourceExchange.ts'
import { entryOff, ruleActive } from '../src/activation.ts'
import type { ResourcePreview } from '../src/resourceExchange.ts'

const domain = (value: string, disabled = false) => ({ type: 'domain_suffix' as const, value, disabled })
const ip = (value: string, disabled = false) => ({ type: 'ip_cidr' as const, value, disabled })

test('append preserves spelling, order and activation of existing resources', () => {
  const existing = { entries: ['*.Example.COM', '192.0.2.9 # host'], disabled_entries: ['.example.com'] }
  const next = mergeResourceEntries(existing, [domain('example.com'), ip('192.0.2.9/32'), domain('new.test', true)], 'append')
  assert.deepEqual(next.entries, [...existing.entries, 'new.test'])
  assert.deepEqual(next.disabled_entries, ['.example.com', 'new.test'])
  assert.deepEqual(next.added, ['new.test'])
  assert.deepEqual(next.removed, [])
  assert.equal(next.duplicates, 2)
  assert.deepEqual(next.effectiveDisabled, [true, false, true])
  assert.equal(next.activationConflicts, 1)
  assert.deepEqual(existing, { entries: ['*.Example.COM', '192.0.2.9 # host'], disabled_entries: ['.example.com'] })
})

test('replace removes only old resources and keeps switches on retained resources', () => {
  const existing = { entries: ['old.test', '*.keep.test', 'enabled.test'], disabled_entries: ['old.test', 'keep.test'] }
  const next = mergeResourceEntries(existing, [domain('keep.test'), domain('enabled.test', true), ip('2001:db8::/48', true)], 'replace')
  assert.deepEqual(next.entries, ['keep.test', 'enabled.test', '2001:db8::/48'])
  assert.deepEqual(next.disabled_entries, ['keep.test', '2001:db8::/48'])
  assert.deepEqual(next.added, ['2001:db8::/48'])
  assert.deepEqual(next.removed, ['old.test'])
  assert.equal(next.duplicates, 2)
  assert.deepEqual(next.effectiveDisabled, [true, false, true])
  assert.equal(next.activationConflicts, 2)
})


test('replace keeps dormant catalog flags for entries not in the current revision', () => {
  const result = mergeResourceEntries({ entries: ['old.test'], disabled_entries: ['future.test', 'old.test'] }, [domain('replacement.test')], 'replace')
  assert.deepEqual(result.disabled_entries, ['future.test'])
  assert.deepEqual(result.removed, ['old.test'])
})
test('empty replacement reports every removed resource and clears its switches', () => {
  const result = mergeResourceEntries({ entries: ['old.test'], disabled_entries: ['old.test'] }, [], 'replace')
  assert.deepEqual(result.entries, [])
  assert.deepEqual(result.removed, ['old.test'])
  assert.equal(result.disabled_entries, undefined)
})

test('both import modes and export keep numeric suffixes and IPv4/IPv6 prefixes independent', () => {
  const incoming = [domain('010.0.0.1', true), ip('10.0.0.1/32'), ip('::ffff:10.0.0.1/128', true)]
  for (const mode of ['append', 'replace'] as const) {
    const draft = {}
    const plan = planResourceImport(snapshotResourceDraft(draft, undefined),
      { valid: true, list: { entries: incoming }, duplicates: 0, issues: [], omitted_issues: 0 }, mode)
    const staged = stageResourceImport(plan, draft, undefined)
    assert.ok(staged)
    const group = { name: 'Numeric rules', target: 'direct', ...staged }
    assert.deepEqual(group.entries, ['010.0.0.1', '10.0.0.1/32', '::ffff:10.0.0.1/128'])
    assert.equal(entryOff(group, '*.010.0.0.1'), true)
    assert.equal(entryOff(group, '10.0.0.1'), false)
    assert.equal(entryOff(group, '::FFFF:a00:1'), true)
    assert.equal(ruleActive(group), 1)
    assert.deepEqual(resourceList(group.name, group).entries, incoming)
  }
})

test('preview reports every switch discrepancy, including hidden rows and dormant flags', () => {
  const group = { entries: ['active.test', 'off.test'], disabled_entries: ['off.test', 'dormant.test'] }
  const draft = { groups: [group] }
  const undisputed = Array.from({ length: 25 }, (_, index) => domain(`row-${index}.test`))
  const incoming = [...undisputed, domain('active.test', true), domain('off.test'), domain('dormant.test')]
  for (const mode of ['append', 'replace'] as const) {
    const plan = planResourceImport(snapshotResourceDraft(draft, group),
      { valid: true, list: { entries: incoming }, duplicates: 0, issues: [], omitted_issues: 0 }, mode)
    assert.equal(plan.changes?.activationConflicts, 3)
    assert.deepEqual(plan.changes?.effectiveDisabled.slice(25), [false, true, true])
    assert.equal(stageResourceImport(plan, draft, group), group)
    assert.deepEqual(resourceList('Example', group).entries.filter(entry =>
      ['active.test', 'off.test', 'dormant.test'].includes(entry.value)).map(entry => entry.disabled), [false, true, true])
    group.entries = ['active.test', 'off.test']
  }
})

const preview = (valid = true): ResourcePreview => ({
  valid, list: { name: 'Imported name', entries: [domain('new.test', true)] },
  duplicates: 0, issues: [], omitted_issues: 0,
})

test('staging preserves unrelated live edits, selector fields and catalog provenance', () => {
  const group = {
    name: 'Original', target: 'direct', entries: ['old.test'], categories: [] as string[],
    preset: { id: 'catalog', base: ['old.test'], auto_update: true },
  }
  const draft = { groups: [group], unrelated: 'original' }
  const plan = planResourceImport(snapshotResourceDraft(draft, group), preview(), 'replace')
  group.name = 'Renamed in the draft'
  group.target = 'block'
  group.preset.auto_update = false
  draft.unrelated = 'edited while previewing'
  draft.groups.unshift({ ...group, name: 'Other group', entries: ['other.test'] })

  assert.equal(stageResourceImport(plan, draft, group), group)
  assert.deepEqual(draft, {
    groups: [
      { name: 'Other group', target: 'block', entries: ['other.test'], categories: [], preset: group.preset },
      { name: 'Renamed in the draft', target: 'block', entries: ['new.test'], disabled_entries: ['new.test'],
        categories: [], preset: { id: 'catalog', base: ['old.test'], auto_update: false } },
    ],
    unrelated: 'edited while previewing',
  })
})

test('staging rejects changed entries, switches, a replaced destination, or a discarded draft', () => {
  const group = { entries: ['old.test'], disabled_entries: ['old.test'] }
  const draft = { groups: [group] }
  const plan = planResourceImport(snapshotResourceDraft(draft, group), preview(), 'append')
  assert.equal(stageResourceImport(plan, draft, { ...group }), undefined)
  assert.equal(stageResourceImport(plan, draft, undefined), undefined)
  group.entries.push('concurrent.test')
  assert.equal(stageResourceImport(plan, draft, group), undefined)
  assert.deepEqual(group.entries, ['old.test', 'concurrent.test'])
  group.entries.pop()
  group.disabled_entries.pop()
  assert.equal(stageResourceImport(plan, draft, group), undefined)
  group.disabled_entries.push('old.test')
  assert.equal(stageResourceImport(plan, { ...draft }, group), undefined)
  assert.deepEqual(group, { entries: ['old.test'], disabled_entries: ['old.test'] })
})

test('invalid previews never stage recognized rows, even for new destinations', () => {
  const draft = {}
  const snapshot = snapshotResourceDraft(draft, undefined)
  assert.equal(stageResourceImport(planResourceImport(snapshot, preview(false), 'append'), draft, undefined), undefined)
  const plan = planResourceImport(snapshot, preview(), 'append')
  assert.equal(stageResourceImport(plan, {}, undefined), undefined)
  assert.deepEqual(stageResourceImport(plan, draft, undefined), { entries: ['new.test'], disabled_entries: ['new.test'] })
})

test('preset budget replaces the old resource count and counts UTF-8 bytes and flags', () => {
  const full = { entries: Array<string>(1_024).fill('\u00e9'.repeat(512)) }
  const next = { entries: ['next.test'], disabled_entries: ['next.test'] }
  assert.equal(localPresetFits([full], next), false)
  assert.equal(localPresetFits([full], next, full), true)
  assert.equal(localPresetFits([], { ...full, disabled_entries: ['x'] }), false)
  assert.equal(localPresetFits(Array.from({ length: 64 }, () => ({ entries: [] })), next), false)
})

test('resource export strips routing comments but leaves validation to the backend', () => {
  const group = {
    name: 'Example', target: 'block', disabled: true,
    entries: [' *.Example.test. # comment', '192.0.2.1 # host', 'unvalidated.test/path'],
    disabled_entries: ['example.test'],
  }
  assert.deepEqual(resourceList(group.name, group), {
    name: 'Example',
    entries: [
      domain('*.Example.test.', true),
      ip('192.0.2.1'),
      domain('unvalidated.test/path'),
    ],
  })
})
