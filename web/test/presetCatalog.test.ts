import assert from 'node:assert/strict'
import { test } from 'node:test'
import { catalogCounts, filterCatalog } from '../src/presetCatalog.ts'
import type { Preset } from '../src/types.ts'

const claude: Preset = { id: 'claude', name: 'Claude', category: 'AI', description: 'Anthropic assistant', domains: ['claude.ai'], prefixes: [] }
const github: Preset = { id: 'github', name: 'GitHub', category: 'Development', description: 'Source hosting', domains: ['github.com'], prefixes: ['192.0.2.0/24'] }
const openai: Preset = { id: 'openai', name: 'OpenAI', category: 'AI', description: 'Chat and API', domains: ['chatgpt.com'], prefixes: [] }
const catalog = [claude, github, openai]

test('category counts describe the full catalog and preserve catalog order', () => {
  assert.deepEqual([...catalogCounts(catalog)], [['AI', 2], ['Development', 1]])
  assert.deepEqual(filterCatalog(catalog, 'AI', '').map(preset => preset.id), ['claude', 'openai'])
})

test('search is case-insensitive, accepts IP ranges, and stays scoped to the selected category', () => {
  assert.deepEqual(filterCatalog(catalog, '', '  CHATGPT.COM ').map(preset => preset.id), ['openai'])
  assert.deepEqual(filterCatalog(catalog, 'AI', 'Anthropic').map(preset => preset.id), ['claude'])
  assert.deepEqual(filterCatalog(catalog, 'AI', 'GitHub'), [])
  assert.deepEqual(filterCatalog(catalog, '', '192.0.2.0/24').map(preset => preset.id), ['github'])
})

test('a preset without IP ranges does not break search for other presets', () => {
  const withoutPrefixes: Preset = { ...claude, prefixes: null }
  assert.deepEqual(filterCatalog([withoutPrefixes, github], '', '192.0.2.0/24'), [github])
})
