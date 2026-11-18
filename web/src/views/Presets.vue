<script setup lang="ts">
import {computed,onMounted,ref,shallowRef} from 'vue'
import {useI18n} from 'vue-i18n'
import {NAlert,NButton,NCard,NInput,NSelect,NModal,NCheckbox,useMessage} from 'naive-ui'
import {api} from '../api'
import {store,selectableTargets} from '../store'
import {entryIdentity,setGroupEnabled} from '../activation'
import { localPresetFits, localPresetID, maxLocalPresets, validLocalPresetName } from '../resourceExchange'
import ResourceExchangePanel from '../components/ResourceExchangePanel.vue'
import { bundledPresetMatches, snapshotBundledPreset, stageBundledPreset } from '../presetDraft'
import type { BundledPresetPlan } from '../presetDraft'
import type {Group,LocalPreset,Preset} from '../types'
const {t}=useI18n();const message=useMessage()
const catalog=ref<Preset[]>([]),q=ref(''),category=ref(''),target=ref('direct'),error=ref(''),busy=ref(false)
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
const categories=computed(()=>[{label:t('features.all'),value:''},...Array.from(new Set(catalog.value.map(p=>p.category))).map(c=>({label:t('features.categories.'+c),value:c}))])
const rows=computed(()=>catalog.value.filter(p=>(!category.value||p.category===category.value)&&(!q.value||`${p.name} ${p.description} ${p.domains.join(' ')}`.toLowerCase().includes(q.value.toLowerCase()))))
function installed(p:Preset){return store.state.config?.groups?.find(g=>g.preset?.id===p.id)}
// Preview a preset against the current draft without writing configuration.
async function prepare(p: Preset) {
  const draft = store.state.config
  if (!draft || applying.value || busy.value) return
  const snapshot = snapshotBundledPreset(draft, p.id)
  busy.value = true
  error.value = ''
  try {
    const result = await api.previewPreset(draft, p.id, target.value, snapshot.index < 0 ? undefined : snapshot.index)
    preview.value = { snapshot, result }
  } catch (e) { error.value = (e as Error).message }
  finally { busy.value = false }
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
function editInstalled(p: Preset, edit: (group: Group) => void) {
  if (applying.value) return
  const group = installed(p)
  if (group) edit(group)
}
onMounted(async()=>{try{catalog.value=(await api.catalog()).presets}catch(e){error.value=(e as Error).message}})
</script>
<template>
 <div class="page-head"><div><h1>{{t('nav.presets')}}</h1><p>{{t('features.presetsIntro')}}</p></div></div>
 <ResourceExchangePanel kind="presets" :bundled="catalog" />
 <NAlert type="info" style="margin-bottom:12px">{{t('features.presetSource')}}</NAlert>
 <NAlert v-if="error" type="error" closable @close="error=''">{{error}}</NAlert>
 <div class="tools"><NInput v-model:value="q" :placeholder="t('features.search')" clearable/><NSelect v-model:value="category" :options="categories"/><NSelect v-model:value="target" :disabled="busy" :options="selectableTargets()" :placeholder="t('features.target')"/></div>
 <section class="local-presets" aria-labelledby="local-presets-title">
  <h2 id="local-presets-title">{{ t('resources.localPresets') }}</h2>
  <p>{{ t('resources.localHint') }}</p>
  <div class="actions">
   <NInput v-model:value="localName" :maxlength="64" :placeholder="t('resources.newPreset')" :input-props="{ 'aria-label': t('resources.newPreset') }" />
   <NButton :disabled="applying || !validLocalName || localPresets.length >= maxLocalPresets" @click="createLocal">{{ t('common.add') }}</NButton>
  </div>
  <div class="grid">
   <NCard v-for="preset in localPresets" :key="preset.id" size="small" :title="preset.name">
    <p>{{ t('resources.entries', { count: preset.entries.length }) }}</p>
    <div class="actions">
     <NButton :disabled="applying || !preset.entries.length" @click="copyLocal(preset)">{{ t('resources.usePreset') }}</NButton>
     <NButton :disabled="applying" @click="removeLocal(preset)">{{ t('common.delete') }}</NButton>
    </div>
   </NCard>
  </div>
 </section>
 <div class="grid">
 <NCard v-for="p in rows" :key="p.id" size="small" :title="p.name">
  <p>{{p.description}}</p><div class="muted">{{t('features.categories.'+p.category)}} · {{p.domains.length}} {{t('features.domains')}}</div>
  <details><summary>{{t('features.composition')}}</summary><pre>{{p.domains.join('\n')}}</pre></details>
  <template v-if="installed(p)">
   <div class="preset-options">
    <NCheckbox :disabled="applying" :checked="!installed(p)!.disabled" @update:checked="v=>editInstalled(p, g=>setGroupEnabled(g,v))">{{t('features.enabled')}}</NCheckbox>
    <NCheckbox :disabled="applying" :checked="installed(p)!.preset!.auto_update" @update:checked="v=>editInstalled(p, g=>{g.preset!.auto_update=v})">{{t('features.presetAuto')}}</NCheckbox>
   </div>
   <NSelect :disabled="applying" :value="installed(p)!.target" :options="selectableTargets(installed(p)!.target)" style="margin-top:8px" @update:value="v=>editInstalled(p, g=>{g.target=v})"/>
  </template>
  <div class="actions">
   <NButton :disabled="applying || busy" :loading="busy" @click="prepare(p)">{{installed(p)?t('features.previewUpdate'):t('features.install')}}</NButton>
   <NButton :disabled="applying || localPresets.length >= maxLocalPresets" @click="copyCatalogToLocal(p)">{{ t('resources.copyToLocal') }}</NButton>
   <NButton v-if="installed(p)" :disabled="applying" @click="remove(p)">{{t('common.delete')}}</NButton>
  </div>
 </NCard>
 </div>
 <NModal :show="!!preview" preset="card" :title="t('features.preview')" style="width:min(680px,94vw)" @update:show="v=>{if(!v)preview=undefined}">
  <p>{{t('features.previewHint')}}</p><div v-if="preview"><b>+{{preview.result.diff.added.length}} / −{{preview.result.diff.removed.length}}</b><pre>{{preview.result.diff.added.map(s=>'+ '+s).concat(preview.result.diff.removed.map(s=>'− '+s)).join('\n')||t('features.noChanges')}}</pre></div>
  <NAlert v-if="previewStale" type="warning">{{ t('resources.presetPreviewStale') }}</NAlert>
  <NButton type="primary" :disabled="applying || previewStale" @click="accept">{{t('features.toDraft')}}</NButton>
 </NModal>
</template>
<style scoped>
.tools{display:grid;grid-template-columns:2fr 1fr 1fr;gap:10px;margin:12px 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(320px,100%),1fr));gap:12px}.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}p{margin:0 0 8px}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:230px;overflow:auto;font-size:12px}summary{cursor:pointer;margin:8px 0}
.local-presets { margin-bottom: 20px; }
.local-presets .grid { margin-top: 12px; }
.local-presets .actions > .n-input { width: min(24rem, 100%); }
.preset-options {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  gap: 8px;
  margin-top: 8px;
}
@media (max-width: 600px) {
  .tools { grid-template-columns: 1fr; }
  .preset-options { gap: 0; }
  .preset-options > .n-checkbox {
    box-sizing: border-box;
    min-height: 44px;
    padding: 10px 0;
  }
}
</style>
