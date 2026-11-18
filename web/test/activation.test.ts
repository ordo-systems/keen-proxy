import { test } from 'node:test'
import assert from 'node:assert/strict'
import { reactive } from 'vue'
import {
  activeChain,
  activeExit,
  dropRemoved,
  canonicalEntry,
  entryIdentity,
  entryOff,
  geoInactive,
  groupDisabledEntryKeys,
  migrateFlag,
  retainPresetActivation,
  ruleActive,
  ruleTotal,
  setGroupEnabled,
  setEntryEnabled,
  setSelectorEnabled,
  simulatedRoute,
  withFlag,
} from '../src/activation.ts'
import type { Config, Group } from '../src/types.ts'

test('entry identity matches canonical domain and prefix spellings', () => {
  assert.deepEqual(canonicalEntry('*.Example.COM'), { type: 'domain_suffix', value: 'example.com' })
  assert.equal(entryIdentity('example.com # note'), 'domain_suffix:example.com')
  assert.equal(entryIdentity('192.0.2.1'), 'ip_cidr:192.0.2.1/32')
  assert.equal(entryIdentity('192.0.2.9/24'), 'ip_cidr:192.0.2.0/24')
  assert.equal(entryIdentity('*.example.com'), entryIdentity('example.com'))
  assert.equal(entryIdentity('2001:0DB8:0:0::1'), 'ip_cidr:2001:db8::1/128')
  assert.equal(entryIdentity('2001:db8::a/64'), 'ip_cidr:2001:db8::/64')
  assert.equal(entryIdentity('b\u00fccher.example.'), 'domain_suffix:xn--bcher-kva.example')
  assert.equal(entryIdentity('010.0.0.1'), 'domain_suffix:010.0.0.1')
  assert.equal(entryIdentity('10.0.0.1/32'), 'ip_cidr:10.0.0.1/32')
  assert.equal(entryIdentity('0xA.0.0.1'), 'domain_suffix:0xa.0.0.1')
  assert.equal(entryIdentity('*.10.0.0.1'), 'domain_suffix:10.0.0.1')
  assert.equal(entryIdentity('::FFFF:0a00:1'), 'ip_cidr:::ffff:10.0.0.1/128')
  assert.equal(entryIdentity('::ffff:10.0.0.1'), entryIdentity('::ffff:a00:1/128'))
  for (const invalid of ['10.0.0.1/032', '10.0.0.1/32/1', '10.0.0.1/ 32', '::ffff:010.0.0.1/128']) {
    assert.equal(canonicalEntry(invalid).type, 'invalid')
  }
})

test('bulk counts and row lookups share a reactive flag set without conflating numeric domains and IPs', () => {
  const values = Array.from({ length: 19_998 }, (_, index) => `row-${index}.test`)
  const group = reactive<Group>({
    name: 'bulk', target: 'direct', entries: [...values, '010.0.0.1', '10.0.0.1/32'],
    disabled_entries: [...values, '010.0.0.1'],
  })
  const initialFlags = groupDisabledEntryKeys(group)
  assert.equal(ruleActive(group), 1)
  assert.equal(entryOff(group, '*.010.0.0.1'), true)
  assert.equal(entryOff(group, '10.0.0.1'), false)
  assert.equal(groupDisabledEntryKeys(group), initialFlags)

  group.disabled_entries!.push('10.0.0.1')
  assert.notEqual(groupDisabledEntryKeys(group), initialFlags)
  assert.equal(ruleActive(group), 0)
  assert.equal(entryOff(group, '10.0.0.1/32'), true)
  group.disabled_entries = ['10.0.0.1']
  assert.equal(ruleActive(group), 19_999)
  group.entries.pop()
  assert.equal(ruleActive(group), 19_999)
  delete group.disabled_entries
  assert.equal(entryOff(group, '10.0.0.1'), false)
})

test('simulated routing keeps a numeric suffix distinct from the corresponding Internet address', () => {
  const suffix: Group = { name: 'numeric suffix', target: 'direct', entries: ['010.0.0.1'] }
  const prefix: Group = { name: 'network', target: 'direct', entries: ['10.0.0.1/32'] }
  const config = { connections: [], groups: [suffix, prefix] } as unknown as Config
  assert.equal(simulatedRoute(config, 'sub.010.0.0.1')?.rule, suffix.name)
  assert.equal(simulatedRoute(config, '10.0.0.1')?.rule, prefix.name)
  setEntryEnabled(suffix, '.010.0.0.1.', false)
  assert.equal(simulatedRoute(config, 'sub.010.0.0.1'), null)
  assert.equal(simulatedRoute(config, '10.0.0.1')?.rule, prefix.name)
})

test('explicit entry edits migrate flags and deletes remove only that flag', () => {
  const group: Group = { name: 'games', target: 'fi', entries: ['Example.COM', 'keep.example'] }
  setEntryEnabled(group, 'Example.COM', false)
  assert.equal(entryOff(group, 'example.com'), true)
  group.disabled_entries = migrateFlag(group.disabled_entries, 'Example.COM', 'other.example', entryIdentity)
  group.entries[0] = 'other.example'
  assert.equal(entryOff(group, 'other.example'), true)
  assert.equal(entryOff(group, 'Example.COM'), false)
  group.disabled_entries = dropRemoved(group.disabled_entries, ['other.example'], [], entryIdentity)
  assert.equal(group.disabled_entries, undefined)
  const kept = withFlag(['later.example', 'stay.example'], 'stay.example', false, entryIdentity)
  assert.deepEqual(dropRemoved(kept, ['stay.example'], ['stay.example'], entryIdentity), ['later.example', 'stay.example'])
})

test('preset merge keeps off switches, including a temporarily removed entry', () => {
  const previous: Group = {
    name: 'Work',
    target: 'fi',
    entries: ['old.example'],
    disabled: true,
    disabled_entries: ['old.example', 'later.example'],
    preset: { id: 'sample-work', version: '1', base: ['old.example'], auto_update: true },
  }
  const next: Group = {
    name: 'Example work sites',
    target: 'direct',
    entries: ['work.example.com', 'later.example'],
    preset: { id: 'sample-work', version: 'demo', base: ['work.example.com'], auto_update: false },
  }
  const merged = retainPresetActivation(previous, next)
  assert.equal(merged.disabled, true)
  assert.deepEqual(merged.disabled_entries, ['old.example', 'later.example'])
  assert.equal(merged.entries[1], 'later.example')
  assert.equal(entryOff(merged, 'later.example'), true)
  assert.equal(merged.preset?.auto_update, false)
})

test('disabled children stay counted as off without a parent rewrite, and empty except is inactive', () => {
  const group: Group = {
    name: 'countries',
    target: 'fi',
    entries: [],
    countries: ['RU', 'DE'],
    except: true,
    disabled_countries: ['DE'],
  }
  setSelectorEnabled(group, 'countries', 'ru', false)
  assert.equal(group.disabled, undefined)
  assert.equal(ruleActive(group), 0)
  assert.equal(geoInactive(group), true)
  group.disabled = true
  group.disabled_countries = ['DE']
  assert.equal(ruleActive(group), 0)
  assert.equal(group.disabled_countries?.[0], 'DE')
})

test('simulated routes skip off entries and do not turn an empty except group into match-all', () => {
  const config = {
    connections: [
      { id: 'fi', name: 'FI', type: 'link', disabled: true, fallback: 'nl' },
      { id: 'nl', name: 'NL', type: 'link', fallback: 'direct' },
    ],
    groups: [
      { name: 'via-fi', target: 'fi', entries: ['openai.com', 'chatgpt.com'], disabled_entries: ['chatgpt.com'] },
      { name: 'off-group', target: 'nl', entries: ['blocked.example'], disabled: true },
      { name: 'except-ru', target: 'fi', entries: [], countries: ['RU'], except: true, disabled_countries: ['RU'] },
    ],
  } as Config
  assert.equal(simulatedRoute(config, 'chatgpt.com'), null)
  assert.equal(simulatedRoute(config, 'blocked.example'), null)
  assert.deepEqual(simulatedRoute(config, 'openai.com'), { outbound: 'nl', rule: 'via-fi' })
  assert.equal(simulatedRoute(config, 'video.example.com', 'US'), null)
  assert.deepEqual(activeChain(config.connections!, 'fi'), ['nl', 'direct'])
  config.connections![1]!.disabled = true
  delete config.connections![1]!.fallback
  assert.deepEqual(activeChain(config.connections!, 'fi'), ['block'])
})

test('demo routing keeps global block and explicit-domain precedence over earlier country groups', () => {
  const config = {
    connections: [{ id: 'vpn', name: 'VPN', type: 'link' }],
    groups: [
      { name: 'country', target: 'vpn', entries: [], countries: ['FI'] },
      { name: 'specific', target: 'direct', entries: ['steam.test'] },
    ],
  } as Config
  assert.deepEqual(simulatedRoute(config, 'steam.test', 'FI'), { outbound: 'direct', rule: 'specific' })
  const blocked: Group = { name: 'global block', target: 'block', entries: ['steam.test'] }
  config.groups!.push(blocked)
  assert.deepEqual(simulatedRoute(config, 'steam.test', 'FI'), { outbound: 'block', rule: 'global block' })
  setGroupEnabled(blocked, false)
  assert.deepEqual(simulatedRoute(config, 'steam.test', 'FI'), { outbound: 'direct', rule: 'specific' })
  setEntryEnabled(config.groups![1]!, 'steam.test', false)
  assert.deepEqual(simulatedRoute(config, 'steam.test', 'FI'), { outbound: 'vpn', rule: 'country' })
})

test('country and category switches preserve union and except behavior', () => {
  const group: Group = {
    name: 'geo', target: 'direct', entries: [], countries: ['RU'], categories: ['TELEGRAM'],
  }
  const config = { connections: [], groups: [group] } as unknown as Config
  assert.equal(ruleTotal(group), 2)
  assert.equal(ruleActive(group), 2)
  assert.equal(simulatedRoute(config, 'site.test', 'RU')?.rule, 'geo')
  setSelectorEnabled(group, 'countries', ' ru ', false)
  assert.equal(simulatedRoute(config, 'site.test', 'RU'), null)
  assert.equal(simulatedRoute(config, 'site.test', 'US', [' telegram '])?.rule, 'geo')
  assert.equal(ruleActive(group), 1)
  setSelectorEnabled(group, 'categories', 'TELEGRAM', false)
  assert.equal(simulatedRoute(config, 'site.test', 'US', ['TELEGRAM']), null)
  assert.equal(ruleActive(group), 0)
  setSelectorEnabled(group, 'countries', 'RU', true)
  group.except = true
  assert.equal(simulatedRoute(config, 'site.test', 'RU'), null)
  assert.equal(simulatedRoute(config, 'site.test', 'US')?.rule, 'geo')
  setSelectorEnabled(group, 'countries', 'RU', false)
  assert.equal(simulatedRoute(config, 'site.test', 'US'), null)
})

test('address rule switches use masked IPv4 and IPv6 identities', () => {
  const group: Group = { name: 'addresses', target: 'direct', entries: ['192.0.2.0/24', '2001:db8::/64'] }
  const config = { connections: [], groups: [group] } as unknown as Config
  assert.equal(simulatedRoute(config, '192.0.2.200')?.rule, 'addresses')
  assert.equal(simulatedRoute(config, '2001:db8::beef')?.rule, 'addresses')
  assert.equal(simulatedRoute(config, '198.51.100.1'), null)
  assert.equal(simulatedRoute(config, '2001:db9::1'), null)
  setEntryEnabled(group, '192.0.2.99/24', false)
  setEntryEnabled(group, '2001:0db8:0:0::1/64', false)
  assert.equal(simulatedRoute(config, '192.0.2.200'), null)
  assert.equal(simulatedRoute(config, '2001:db8::beef'), null)
})

test('renaming preserves another disabled entry and deduplicates an already disabled destination', () => {
  const flags = ['old.example', 'next.example', 'other.example']
  assert.deepEqual(migrateFlag(flags, 'active.example', 'renamed.example', entryIdentity), flags)
  assert.deepEqual(migrateFlag(flags, 'OLD.EXAMPLE', 'next.example', entryIdentity), ['next.example', 'other.example'])
  assert.deepEqual(migrateFlag(flags, 'old.example', '*.OLD.example', entryIdentity), flags)
  assert.equal(migrateFlag(undefined, 'active.example', 'renamed.example', entryIdentity), undefined)
})

test('parent switches preserve child choices and rule totals across restore', () => {
  const group: Group = { name: 'rules', target: 'direct', entries: ['on.example', 'off.example'], disabled_entries: ['off.example'] }
  assert.equal(ruleTotal(group), 2)
  assert.equal(ruleActive(group), 1)
  setGroupEnabled(group, false)
  assert.equal(ruleActive(group), 0)
  setGroupEnabled(group, true)
  assert.equal(ruleActive(group), 1)
  assert.deepEqual(group.disabled_entries, ['off.example'])
  const geo: Group = { name: 'geo', target: 'direct', entries: [], countries: ['RU'], categories: ['GOOGLE'], disabled_categories: ['GOOGLE'] }
  assert.equal(ruleTotal(geo), 2)
  assert.equal(ruleActive(geo), 1)
})

test('replacing a preset does not inherit the old preset disabled rules', () => {
  const previous: Group = {
    name: 'old', target: 'direct', entries: ['shared.example'], disabled: true, disabled_entries: ['shared.example'],
    preset: { id: 'old', version: '1', base: ['shared.example'], auto_update: false },
  }
  const next: Group = {
    name: 'new', target: 'direct', entries: ['shared.example'],
    preset: { id: 'new', version: '1', base: ['shared.example'], auto_update: false },
  }
  const replacement = retainPresetActivation(previous, next)
  assert.equal(ruleActive(replacement), 1)
  assert.equal(entryOff(replacement, 'shared.example'), false)
  assert.equal(replacement.preset?.id, 'new')
})

test('disabled connection notices follow a live fallback without trusting stale or unrelated exits', () => {
  const config = {
    connections: [
      { id: 'a', type: 'link', disabled: true, fallback: 'b' },
      { id: 'b', type: 'link', fallback: 'c' },
      { id: 'c', type: 'link' },
    ],
  } as Config
  assert.equal(activeExit(config, 'a', 'c'), 'c')
  assert.equal(activeExit(config, 'a', 'a'), 'b')
  assert.equal(activeExit(config, 'a', 'direct'), 'b')
  config.connections![1]!.disabled = true
  assert.equal(activeExit(config, 'a', 'b'), 'c')
  config.connections![2]!.disabled = true
  assert.equal(activeExit(config, 'a', 'c'), 'block')
  assert.equal(activeExit(config, 'direct', 'c'), 'direct')
})

test('global country blocks override earlier explicit routing groups until switched off', () => {
  const config = {
    groups: [
      { name: 'specific', target: 'direct', entries: ['steam.test'] },
      { name: 'country-block', target: 'block', entries: [], countries: ['FI'] },
    ],
  } as Config
  assert.deepEqual(simulatedRoute(config, 'steam.test', 'FI'), { outbound: 'block', rule: 'country-block' })
  setSelectorEnabled(config.groups![1]!, 'countries', 'FI', false)
  assert.deepEqual(simulatedRoute(config, 'steam.test', 'FI'), { outbound: 'direct', rule: 'specific' })
})
