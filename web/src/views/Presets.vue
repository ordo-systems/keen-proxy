<script setup lang="ts">
import {computed,onMounted,ref,shallowRef} from 'vue'
import {useI18n} from 'vue-i18n'
import { ChevronDown, Search } from '@lucide/vue'
import {NAlert,NButton,NInput,NSelect,NModal,NCheckbox,useMessage} from 'naive-ui'
import {api} from '../api'
import {store,selectableTargets} from '../store'
import {entryIdentity,setGroupEnabled} from '../activation'
import { localPresetFits, localPresetID, maxLocalPresets, validLocalPresetName } from '../resourceExchange'
import ResourceExchangePanel from '../components/ResourceExchangePanel.vue'
import { bundledPresetMatches, snapshotBundledPreset, stageBundledPreset } from '../presetDraft'
import { catalogCounts, filterCatalog } from '../presetCatalog'
import type { BundledPresetPlan } from '../presetDraft'
import type {Group,LocalPreset,Preset} from '../types'
const {t}=useI18n();const message=useMessage()
const catalog=ref<Preset[]>([]),q=ref(''),category=ref(''),target=ref('direct'),error=ref('')
const pendingPreview = ref<string>()
const myPresets = 'local'
const categoryOrder = new Map(['AI', 'Video', 'Games', 'Messengers', 'Work', 'Development', 'Russia', 'Smart home', 'Other']
  .map((value, index) => [value, index]))
const expanded = ref<string>()
const loadingCatalog = ref(true)
const preview = shallowRef<BundledPresetPlan>()
const previewStale = computed(() => !!preview.value && !bundledPresetMatches(preview.value.snapshot, store.state.config))
const applying = computed(() => store.state.applying)
const localName = ref('')
const localPresets = computed(() => store.state.config?.local_presets ?? [])
const validLocalName = computed(() => validLocalPresetName(localName.value))
function createLocal() {
  const config = store.state.config
  if (!config || applying.value || !validLocalName.value || localPresets.value.length >= maxLocalPresets) return
  const presets = config.local_presets ??= []
  presets.push({ id: localPresetID(presets), name: localName.value.trim(), entries: [] })
  localName.value = ''
}
function removeLocal(preset: LocalPreset) {
  const config = store.state.config
  if (!config || applying.value) return
  const next = localPresets.value.filter(item => item.id !== preset.id)
  if (next.length) config.local_presets = next
  else delete config.local_presets
}
function copyLocal(preset: LocalPreset) {
  const config = store.state.config
  if (!config || applying.value || !preset.entries.length) return
  const groups = config.groups ??= []
  groups.push({ name: preset.name, target: target.value, entries: [...preset.entries], disabled_entries: preset.disabled_entries?.slice() })
  message.success(t('resources.staged'))
}
function copyCatalogToLocal(preset: Preset) {
  const config = store.state.config
  if (!config || applying.value) return
  const seen = new Set<string>()
  const entries = [...(preset.domains ?? []), ...(preset.prefixes ?? [])].filter(entry => {
    const key = entryIdentity(entry)
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
  if (!localPresetFits(localPresets.value, { entries })) {
    message.warning(t('resources.presetBudget'))
    return
  }
  const presets = config.local_presets ??= []
  presets.push({ id: localPresetID(presets), name: [...preset.name].slice(0, 64).join(''), entries })
  message.success(t('resources.staged'))
}
const sections = computed(() => [
  { value: '', label: t('features.all'), count: catalog.value.length },
  ...Array.from(catalogCounts(catalog.value))
    .sort(([a], [b]) => (categoryOrder.get(a) ?? categoryOrder.size) - (categoryOrder.get(b) ?? categoryOrder.size))
    .map(([value, count]) => ({ value, label: t('features.categories.' + value), count })),
  { value: myPresets, label: t('resources.localPresets'), count: localPresets.value.length },
])
const currentSection = computed(() => sections.value.find(section => section.value === category.value)!)
const rows = computed(() => {
  const installed = new Map<string, Group>()
  for (const group of store.state.config?.groups ?? []) {
    if (group.preset && !installed.has(group.preset.id)) installed.set(group.preset.id, group)
  }
  return filterCatalog(catalog.value, category.value, q.value).map(preset => ({ preset, group: installed.get(preset.id) }))
})
const targets = computed(() => selectableTargets(target.value))
const targetNames = computed(() => new Map([
  ...(store.state.config?.connections ?? []).map(c => [c.id, c.name || c.id] as const),
  ['direct', t('target.direct')],
  ['block', t('target.block')],
]))

function selectSection(value: string) {
  category.value = value
  expanded.value = undefined
}

function toggleDetails(id: string) {
  expanded.value = expanded.value === id ? undefined : id
}
// Preview a preset against the current draft without writing configuration.
async function prepare(p: Preset) {
  const draft = store.state.config
  if (!draft || applying.value || pendingPreview.value) return
  const snapshot = snapshotBundledPreset(draft, p.id)
  pendingPreview.value = p.id
  error.value = ''
  try {
    const result = await api.previewPreset(draft, p.id, target.value, snapshot.index < 0 ? undefined : snapshot.index)
    preview.value = { snapshot, result }
  } catch (e) { error.value = (e as Error).message }
  finally { pendingPreview.value = undefined }
}
function accept() {
  const shown = preview.value
  if (!shown) return
  const next = stageBundledPreset(shown, store.state.config, applying.value)
  if (!next) return
  store.setDraft(next)
  preview.value = undefined
  message.success(t('features.draft'))
}
function remove(p: Preset) {
  const config = store.state.config
  if (config && !applying.value) config.groups = (config.groups ?? []).filter(g => g.preset?.id !== p.id)
}
onMounted(async () => {
  try { catalog.value = (await api.catalog()).presets }
  catch (e) { error.value = (e as Error).message }
  finally { loadingCatalog.value = false }
})
</script>
<template>
 <div class="page-head"><div><h1>{{t('nav.presets')}}</h1><p>{{t('features.presetsIntro')}}</p></div></div>
 <ResourceExchangePanel kind="presets" :bundled="catalog" />
 <NAlert v-if="error" type="error" closable @close="error=''">{{error}}</NAlert>
 <div class="catalog-layout">
  <nav class="catalog-sidebar" :aria-label="t('features.presetCategories')">
   <h2>{{ t('features.presetCategories') }}</h2>
   <button v-for="section in sections" :key="section.value" type="button"
     :class="{ 'local-section': section.value === myPresets }"
     :aria-current="section.value === category ? 'true' : undefined" @click="selectSection(section.value)">
    <span>{{ section.label }}</span><span class="section-count">{{ section.count }}</span>
   </button>
  </nav>
  <section class="catalog-content" aria-labelledby="preset-section-title">
   <NSelect class="mobile-categories" :value="category" :options="sections"
     :aria-label="t('features.presetCategories')" @update:value="selectSection" />
   <h2 id="preset-section-title">{{ currentSection.label }}</h2>
   <div class="tools" :class="{ 'local-tools': category === myPresets }">
    <NInput v-if="category !== myPresets" v-model:value="q" :placeholder="t('features.search')"
      :input-props="{ 'aria-label': t('features.search') }" clearable>
     <template #prefix><Search :size="16" aria-hidden="true" /></template>
    </NInput>
    <div class="route-picker">
     <span id="preset-new-route">{{ t('features.presetNewRoute') }}</span>
     <NSelect v-model:value="target" :disabled="!!pendingPreview" :options="targets" aria-labelledby="preset-new-route" />
    </div>
   </div>
   <template v-if="category === myPresets">
    <p class="muted">{{ t('resources.localHint') }}</p>
    <div class="actions local-create">
     <NInput v-model:value="localName" :maxlength="64" :placeholder="t('resources.newPreset')" :input-props="{ 'aria-label': t('resources.newPreset') }" />
     <NButton :disabled="applying || !validLocalName || localPresets.length >= maxLocalPresets" @click="createLocal">{{ t('common.add') }}</NButton>
    </div>
    <ul v-if="localPresets.length" class="local-list">
     <li v-for="preset in localPresets" :key="preset.id">
      <div><strong>{{ preset.name }}</strong><small>{{ t('resources.entries', { count: preset.entries.length }) }}</small></div>
      <div class="actions">
       <NButton :disabled="applying || !preset.entries.length" @click="copyLocal(preset)">{{ t('resources.usePreset') }}</NButton>
       <NButton :disabled="applying" @click="removeLocal(preset)">{{ t('common.delete') }}</NButton>
      </div>
     </li>
    </ul>
   </template>
   <p v-else-if="loadingCatalog" class="empty muted" role="status">{{ t('features.presetLoading') }}</p>
   <p v-else-if="!rows.length" class="empty muted" role="status">{{ t('features.presetNoMatches') }}</p>
   <table v-else class="preset-table" aria-labelledby="preset-section-title">
    <thead>
     <tr>
      <th scope="col">{{ t('features.presetColumn') }}</th>
      <th scope="col" class="metric">{{ t('features.domains') }}</th>
      <th scope="col" class="rule-status">{{ t('features.presetInRules') }}</th>
      <th scope="col" class="row-action"><span class="sr-only">{{ t('features.presetActions') }}</span></th>
     </tr>
    </thead>
    <tbody>
     <template v-for="{ preset, group } in rows" :key="preset.id">
      <tr>
       <td>
        <button type="button" class="preset-name" :aria-expanded="expanded === preset.id" @click="toggleDetails(preset.id)">
         <ChevronDown :size="14" aria-hidden="true" />{{ preset.name }}
        </button>
        <small>{{ preset.description }}</small>
        <small class="mobile-summary">
         {{ t('features.domains') }}: {{ preset.domains.length }} ·
         {{ !group ? t('features.presetNotAdded') : group.disabled ? t('resources.disabled') : (targetNames.get(group.target) ?? group.target) }}
        </small>
       </td>
       <td class="metric">{{ preset.domains.length }}</td>
       <td class="rule-status">
        <span v-if="group && !group.disabled" class="configured">{{ targetNames.get(group.target) ?? group.target }}</span>
        <span v-else class="muted">{{ group ? t('resources.disabled') : t('features.presetNotAdded') }}</span>
       </td>
       <td class="row-action">
        <NButton v-if="group" size="small" secondary type="primary" :aria-expanded="expanded === preset.id" @click="toggleDetails(preset.id)">
         {{ t('features.presetOpenRule') }}
        </NButton>
        <NButton v-else size="small" :disabled="applying || !!pendingPreview" :loading="pendingPreview === preset.id" @click="prepare(preset)">
         {{ t('features.presetPreviewAction') }}
        </NButton>
       </td>
      </tr>
      <tr v-if="expanded === preset.id" class="detail-row">
       <td colspan="4">
        <div class="preset-detail">
         <div v-if="group" class="preset-options">
          <NCheckbox :disabled="applying" :checked="!group.disabled" @update:checked="value => setGroupEnabled(group, value)">{{ t('features.enabled') }}</NCheckbox>
          <NCheckbox :disabled="applying" :checked="group.preset?.auto_update" @update:checked="value => { if (group.preset) group.preset.auto_update = value }">{{ t('features.presetAuto') }}</NCheckbox>
          <NSelect :disabled="applying" :value="group.target" :options="selectableTargets(group.target)" :aria-label="t('features.target')" @update:value="value => { group.target = value }" />
         </div>
         <h3>{{ t('features.composition') }}</h3>
         <pre>{{ preset.domains.join('\n') }}</pre>
         <template v-if="preset.prefixes.length">
          <h3>{{ t('features.presetPrefixes') }}</h3>
          <pre>{{ preset.prefixes.join('\n') }}</pre>
         </template>
         <div class="actions">
          <NButton v-if="group" :disabled="applying || !!pendingPreview" :loading="pendingPreview === preset.id" @click="prepare(preset)">{{ t('features.previewUpdate') }}</NButton>
          <NButton :disabled="applying || localPresets.length >= maxLocalPresets" @click="copyCatalogToLocal(preset)">{{ t('resources.copyToLocal') }}</NButton>
          <NButton v-if="group" :disabled="applying" @click="remove(preset)">{{ t('common.delete')}}</NButton>
         </div>
        </div>
       </td>
      </tr>
     </template>
    </tbody>
   </table>
   <p v-if="category !== myPresets" class="catalog-note muted">{{ t('features.presetSource') }}</p>
  </section>
 </div>
 <NModal :show="!!preview" preset="card" :title="t('features.preview')" style="width:min(680px,94vw)" @update:show="v=>{if(!v)preview=undefined}">
  <p>{{t('features.previewHint')}}</p><div v-if="preview"><b>+{{preview.result.diff.added.length}} / −{{preview.result.diff.removed.length}}</b><pre>{{preview.result.diff.added.map(s=>'+ '+s).concat(preview.result.diff.removed.map(s=>'− '+s)).join('\n')||t('features.noChanges')}}</pre></div>
  <NAlert v-if="previewStale" type="warning">{{ t('resources.presetPreviewStale') }}</NAlert>
  <NButton type="primary" :disabled="applying || previewStale" @click="accept">{{t('features.toDraft')}}</NButton>
 </NModal>
</template>
<style scoped>
.catalog-layout { display: grid; grid-template-columns: minmax(160px, 194px) minmax(0, 1fr); border: 1px solid var(--line); border-radius: 10px; background: var(--card); }
.catalog-sidebar { padding: 12px 8px; border-inline-end: 1px solid var(--line); }
.catalog-sidebar h2 { margin: 0 10px 6px; font-size: 13px; }
.catalog-sidebar button, .preset-name { color: inherit; font: inherit; background: none; border: 0; cursor: pointer; text-align: start; }
.catalog-sidebar button { width: 100%; min-height: 36px; display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 5px 9px; border-inline-start: 3px solid transparent; border-radius: 5px; }
.catalog-sidebar button:hover, .preset-name:hover { background: var(--sidebar-hover); }
.catalog-sidebar button[aria-current='true'] { background: var(--sidebar-active); border-inline-start-color: var(--accent); color: var(--accent); font-weight: 650; }
.catalog-sidebar .local-section { margin-top: 9px; border-top: 1px solid var(--line); }
.section-count { color: var(--muted); font-variant-numeric: tabular-nums; }
.catalog-content { min-width: 0; padding: 14px 16px; }
.catalog-content h2 { margin: 0 0 10px; font-size: 19px; }
.mobile-categories, .mobile-summary { display: none; }
.tools { display: grid; grid-template-columns: minmax(0, 1fr) minmax(210px, .65fr); gap: 8px; margin-bottom: 12px; }
.tools.local-tools { grid-template-columns: minmax(0, 330px); }
.route-picker { display: grid; grid-template-columns: auto minmax(0, 1fr); align-items: center; gap: 8px; }
.route-picker > span, .catalog-note { color: var(--muted); font-size: 12px; }
.preset-table { width: 100%; border-collapse: collapse; font-size: 13px; text-align: start; }
.preset-table th { text-align: start; font-size: 12px; color: var(--muted); background: var(--page); padding: 7px 8px; }
.preset-table td { padding: 6px 8px; border-bottom: 1px solid var(--line); overflow-wrap: anywhere; }
.preset-table .metric { text-align: end; width: 5.5rem; font-variant-numeric: tabular-nums; }
.preset-table .rule-status { width: 9rem; }
.preset-table .row-action { width: 1%; text-align: end; white-space: nowrap; }
.configured::before { display: inline-block; content: ''; width: 7px; height: 7px; margin-inline-end: 6px; border-radius: 50%; background: var(--ok); vertical-align: 1px; }
.preset-name { display: inline-flex; align-items: center; gap: 6px; padding: 3px 4px; border-radius: 4px; font-weight: 650; overflow-wrap: anywhere; }
.preset-name svg { flex-shrink: 0; }
.preset-name[aria-expanded='true'] svg { transform: rotate(180deg); }
small { display: block; color: var(--muted); font-size: 12px; }
.detail-row td { padding: 0; background: var(--page); }
.preset-detail { padding: 12px; }
.preset-detail h3 { margin: 10px 0 4px; font-size: 13px; }
.preset-options { display: grid; gap: 8px; max-width: 26rem; }
.catalog-note { margin: 12px 0 0; }
.empty { padding: 12px 0; }
.actions { display: flex; gap: 8px; flex-wrap: wrap; }
.local-create > .n-input { width: min(24rem, 100%); }
.local-list { list-style: none; margin: 12px 0 0; padding: 0; }
.local-list li { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 8px; border-bottom: 1px solid var(--line); padding: 10px 0; overflow-wrap: anywhere; }
p { margin: 0 0 8px; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; max-height: 230px; overflow: auto; font-size: 12px; }
.sr-only { position: absolute; width: 1px; height: 1px; clip-path: inset(50%); overflow: hidden; }
@media (max-width: 760px) {
  .catalog-layout { display: block; }
  .catalog-sidebar, .preset-table .metric, .preset-table .rule-status { display: none; }
  .mobile-categories, .mobile-summary { display: block; }
  .mobile-categories { margin-bottom: 12px; }
  .catalog-content { padding: 12px; }
  .tools { grid-template-columns: minmax(0, 1fr); }
  .preset-table .row-action .n-button, .preset-name { min-height: 44px; }
  .preset-options > .n-checkbox { min-height: 44px; padding: 10px 0; }
}
</style>
