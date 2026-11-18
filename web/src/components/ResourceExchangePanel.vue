<script setup lang="ts">
import { computed, onBeforeUnmount, ref, shallowRef, watch } from 'vue'
import { NAlert, NButton, NModal, useMessage } from 'naive-ui'
import { useI18n } from 'vue-i18n'
import { isGeo } from '../activation'
import { api } from '../api'
import { saveDownload } from '../download'
import { groupKey } from '../groups'
import {
  localPresetFits, localPresetID, maxLocalPresets, planResourceImport, resourceDraftMatches,
  resourceList, snapshotResourceDraft, stageResourceImport, validLocalPresetName,
} from '../resourceExchange'
import type { ResourceExport, ResourceFormat, ResourceImportPlan, ResourceMode, ResourceSnapshot } from '../resourceExchange'
import { selectableTargets, store, targetLabel } from '../store'
import type { Group, LocalPreset, Preset } from '../types'

const props = defineProps<{ kind: 'groups' | 'presets'; bundled?: Preset[] }>()
const { t } = useI18n()
const message = useMessage()
const formats: Record<ResourceFormat, { extension: string; mime: string }> = {
  txt: { extension: 'txt', mime: 'text/plain;charset=utf-8' },
  csv: { extension: 'csv', mime: 'text/csv;charset=utf-8' },
  json: { extension: 'json', mime: 'application/json' },
  'sing-box-json': { extension: 'sing-box.json', mime: 'application/json' },
  srs: { extension: 'srs', mime: 'application/octet-stream' },
}
const rowLimit = 25
const issueLimit = 10
const action = ref<'import' | 'export' | null>(null)
const selected = ref('')
const format = ref<ResourceFormat | ''>('')
const mode = ref<ResourceMode | ''>('')
const name = ref('')
const route = ref('')
const file = shallowRef<File>()
const busy = ref(false)
const error = ref('')
const plan = shallowRef<ResourceImportPlan>()
const exported = shallowRef<{
  result: ResourceExport
  source: Group | LocalPreset | Preset
  name: string
  snapshot?: ResourceSnapshot
  format: ResourceFormat
}>()

const presets = computed(() => store.state.config?.local_presets ?? [])
const routes = computed(() => selectableTargets())
const options = computed<{ key: string; label: string; item: Group | LocalPreset | Preset }[]>(() => {
  if (props.kind === 'groups') {
    return (store.state.config?.groups ?? []).flatMap((group, index) => isGeo(group) ? [] : [{
      key: groupKey(group), label: `${index + 1}. ${group.name} — ${targetLabel(group.target)}`, item: group,
    }])
  }
  const local = presets.value.map((item, index) => ({
    key: `local:${item.id}`, label: t('resources.localOption', { index: index + 1, name: item.name }), item,
  }))
  if (action.value === 'import') return local
  return [...local, ...(props.bundled ?? []).map(item => ({
    key: `bundled:${item.id}`, label: t('resources.bundledOption', { name: item.name }), item,
  }))]
})
const source = computed(() => options.value.find(option => option.key === selected.value)?.item)
const destination = computed(() => source.value && !('domains' in source.value) ? source.value : undefined)
const creating = computed(() => action.value === 'import' && selected.value === 'new')
const canCreate = computed(() => props.kind === 'groups' || presets.value.length < maxLocalPresets)
const canImport = computed(() => !!file.value && !!mode.value && (creating.value
  ? canCreate.value && validLocalPresetName(name.value) && (props.kind === 'presets' || routes.value.some(target => target.value === route.value))
  : !!destination.value))
const canPrepare = computed(() => !busy.value && !!store.state.config && !!format.value &&
  (action.value === 'import' ? !store.state.applying && canImport.value : !!source.value))
const importStale = computed(() => !!plan.value &&
  !resourceDraftMatches(plan.value.snapshot, store.state.config, destination.value))
const overBudget = computed(() => !!plan.value?.changes && props.kind === 'presets' && !importStale.value &&
  !localPresetFits(presets.value, plan.value.changes, destination.value))
const canStage = computed(() => canPrepare.value && !!plan.value?.changes && !importStale.value && !overBudget.value)
const reviewedChanges = computed(() => importStale.value ? null : plan.value?.changes)
const ignoredName = computed(() => {
  const input = plan.value?.preview.list.name
  return input && input !== (creating.value ? name.value.trim() : destination.value?.name) ? input : ''
})
const exportStale = computed(() => {
  const ready = exported.value
  return !!ready && (ready.source !== source.value || ready.name !== source.value?.name ||
    (ready.snapshot && !resourceDraftMatches(ready.snapshot, store.state.config, destination.value)))
})

// A late response cannot restore a result after changing the form, closing or navigating away.
let request = 0
watch([action, selected, format, mode, name, route, file], () => {
  request++
  busy.value = false
  plan.value = undefined
  exported.value = undefined
  error.value = ''
}, { flush: 'sync' })
onBeforeUnmount(() => { request++ })

function open(next: 'import' | 'export') {
  selected.value = ''
  format.value = ''
  mode.value = ''
  name.value = ''
  route.value = ''
  file.value = undefined
  action.value = next
}

async function prepare() {
  const draft = store.state.config, selectedFormat = format.value
  if (!canPrepare.value || !draft || !selectedFormat) return
  const current = ++request
  busy.value = true
  error.value = ''
  plan.value = undefined
  exported.value = undefined
  try {
    if (action.value === 'import' && file.value && mode.value) {
      const snapshot = snapshotResourceDraft(draft, destination.value)
      const operation = mode.value
      const preview = await api.previewResources(selectedFormat, file.value)
      if (current === request) plan.value = planResourceImport(snapshot, preview, operation)
    } else if (source.value) {
      const item = source.value, sourceName = item.name
      const snapshot = 'domains' in item ? undefined : snapshotResourceDraft(draft, item)
      const resources = snapshot?.resources ?? ('domains' in item ? { entries: [...(item.domains ?? []), ...(item.prefixes ?? [])] } : item)
      const result = await api.exportResources(selectedFormat, resourceList(sourceName, resources))
      if (current === request) exported.value = { result, source: item, name: sourceName, snapshot, format: selectedFormat }
    }
  } catch (cause) {
    if (current === request) error.value = (cause as Error).message
  } finally {
    if (current === request) busy.value = false
  }
}

function stage() {
  const draft = store.state.config, current = destination.value
  if (!canStage.value || !draft || !plan.value) return
  const resources = stageResourceImport(plan.value, draft, current)
  if (!resources) return
  if (!current) {
    const label = name.value.trim()
    if (props.kind === 'groups') (draft.groups ??= []).push({ ...resources, name: label, target: route.value })
    else {
      const local = draft.local_presets ??= []
      local.push({ ...resources, name: label, id: localPresetID(local) })
    }
  }
  action.value = null
  message.success(t('resources.staged'))
}

function download() {
  const ready = exported.value
  if (!ready || exportStale.value) return
  const { extension, mime } = formats[ready.format]
  try {
    const bytes = Uint8Array.from(atob(ready.result.data), character => character.charCodeAt(0))
    saveDownload(new Blob([bytes], { type: mime }), `keenproxy-resources.${extension}`)
    action.value = null
  } catch {
    error.value = t('resources.downloadError')
  }
}
</script>

<template>
  <section class="exchange" :aria-label="t('resources.section')" data-testid="resource-exchange">
    <div class="exchange-actions">
      <NButton :disabled="!api.resourceExchangeAvailable || store.state.applying" data-testid="resource-import" @click="open('import')">
        {{ t('resources.import') }}
      </NButton>
      <NButton :disabled="!api.resourceExchangeAvailable" data-testid="resource-export" @click="open('export')">
        {{ t('resources.export') }}
      </NButton>
    </div>
    <p v-if="!api.resourceExchangeAvailable" class="muted">{{ t('resources.demoFileLimit') }}</p>
    <NModal :show="action !== null" preset="card" :title="t(action === 'export' ? 'resources.export' : 'resources.import')"
      style="width: min(660px, 94vw)" @update:show="shown => { if (!shown) action = null }">
      <form v-if="action" class="exchange-form" @submit.prevent="prepare">
        <label>
          {{ t(action === 'import' ? 'resources.target' : 'resources.source') }}
          <select v-model="selected" :disabled="busy" data-testid="resource-selection">
            <option value="" disabled>{{ t('resources.choose') }}</option>
            <option v-for="option in options" :key="option.key" :value="option.key">{{ option.label }}</option>
            <option v-if="action === 'import'" value="new" :disabled="!canCreate">
              {{ t(props.kind === 'groups' ? 'resources.newGroup' : 'resources.newPreset') }}
            </option>
          </select>
        </label>
        <p v-if="action === 'import' && !canCreate" class="muted">{{ t('resources.presetCountLimit') }}</p>
        <template v-if="creating">
          <label>
            {{ t('dialog.name') }}
            <input v-model="name" :disabled="busy" :placeholder="t('resources.nameLimit')" data-testid="resource-name">
          </label>
          <label v-if="props.kind === 'groups'">
            {{ t('groups.colTarget') }}
            <select v-model="route" :disabled="busy" data-testid="resource-route">
              <option value="" disabled>{{ t('resources.choose') }}</option>
              <option v-for="target in routes" :key="target.value" :value="target.value">{{ target.label }}</option>
            </select>
          </label>
        </template>
        <label>
          {{ t('resources.format') }}
          <select v-model="format" :disabled="busy" data-testid="resource-format">
            <option value="" disabled>{{ t('resources.choose') }}</option>
            <option v-for="(_, key) in formats" :key="key" :value="key">{{ t(`resources.formats.${key}`) }}</option>
          </select>
        </label>
        <template v-if="action === 'import'">
          <label>
            {{ t('resources.mode') }}
            <select v-model="mode" :disabled="busy" data-testid="resource-mode">
              <option value="" disabled>{{ t('resources.choose') }}</option>
              <option value="append">{{ t('resources.append') }}</option>
              <option value="replace">{{ t('resources.replace') }}</option>
            </select>
          </label>
          <label>
            {{ t('resources.file') }}
            <input type="file" :disabled="busy" data-testid="resource-file"
              @change="file = ($event.target as HTMLInputElement).files?.[0]">
          </label>
        </template>
        <p v-else>{{ t('resources.exportScope') }}</p>
        <div>
          <NButton attr-type="submit" :disabled="!canPrepare" :loading="busy" data-testid="resource-prepare">
            {{ t(action === 'import' ? 'features.preview' : 'resources.prepareExport') }}
          </NButton>
        </div>
      </form>
      <NAlert v-if="error" class="result" type="error" role="alert">{{ error }}</NAlert>
      <div v-if="plan" class="result" aria-live="polite" data-testid="resource-preview">
        <NAlert v-if="!plan.preview.valid" type="error">{{ t('resources.blocked') }}</NAlert>
        <NAlert v-if="importStale" type="warning">{{ t('resources.stale') }}</NAlert>
        <NAlert v-if="overBudget" type="warning">{{ t('resources.presetBudget') }}</NAlert>
        <NAlert v-if="ignoredName && plan.preview.valid && !importStale" type="warning">
          {{ t('resources.ignoredName', { name: ignoredName }) }}
        </NAlert>
        <NAlert v-if="reviewedChanges?.activationConflicts" type="warning" data-testid="resource-activation-conflicts">
          {{ t('resources.activationConflicts', { count: reviewedChanges.activationConflicts }) }}
        </NAlert>
        <p>
          {{ t('resources.entries', { count: plan.preview.list.entries.length }) }} ·
          {{ t('resources.fileDuplicates', { count: plan.preview.duplicates }) }}
          <template v-if="plan.changes"> · {{ t('resources.destinationDuplicates', { count: plan.changes.duplicates }) }}</template>
        </p>
        <ul v-if="plan.preview.list.entries.length" class="result-list">
          <li v-for="(entry, index) in plan.preview.list.entries.slice(0, rowLimit)" :key="index">
            {{ t(`resources.${entry.type}`) }} · <code>{{ entry.value }}</code>
            <template v-if="reviewedChanges">
              · {{ t(reviewedChanges.effectiveDisabled[index] ? 'resources.disabled' : 'resources.enabled') }}
              <template v-if="reviewedChanges.effectiveDisabled[index] !== !!entry.disabled">
                ({{ t(entry.disabled ? 'resources.fileDisabled' : 'resources.fileEnabled') }})
              </template>
            </template>
            <template v-else-if="entry.disabled"> · {{ t('resources.fileDisabled') }}</template>
          </li>
        </ul>
        <p v-if="plan.preview.list.entries.length > rowLimit" class="muted">
          {{ t('resources.omitted', { count: plan.preview.list.entries.length - rowLimit }) }}
        </p>
        <ul v-if="plan.preview.issues.length" class="result-list">
          <li v-for="(issue, index) in plan.preview.issues.slice(0, issueLimit)" :key="index">
            <strong>{{ t(`resources.${issue.kind}`) }} — {{ issue.location }}</strong>: {{ issue.message }}
          </li>
        </ul>
        <p v-if="plan.preview.omitted_issues || plan.preview.issues.length > issueLimit" class="muted">
          {{ t('resources.omittedIssues', { count: plan.preview.omitted_issues + Math.max(0, plan.preview.issues.length - issueLimit) }) }}
        </p>
        <div v-if="plan.changes && !importStale" class="diff">
          <div v-for="kind in (['added', 'removed'] as const)" :key="kind">
            <strong>{{ t(`resources.${kind}`, { count: plan.changes[kind].length }) }}</strong>
            <ul v-if="plan.changes[kind].length" class="result-list">
              <li v-for="(entry, index) in plan.changes[kind].slice(0, rowLimit)" :key="index"><code>{{ entry }}</code></li>
            </ul>
            <p v-if="plan.changes[kind].length > rowLimit" class="muted">
              {{ t('resources.omitted', { count: plan.changes[kind].length - rowLimit }) }}
            </p>
          </div>
        </div>
        <div v-if="plan.preview.valid">
          <NButton type="primary" :disabled="!canStage" data-testid="resource-stage" @click="stage">{{ t('features.toDraft') }}</NButton>
        </div>
      </div>
      <div v-if="exported" class="result" aria-live="polite" data-testid="resource-export-review">
        <NAlert v-if="exportStale" type="warning">{{ t('resources.exportStale') }}</NAlert>
        <template v-else>
          <NAlert v-if="'target' in exported.source && exported.source.disabled" type="warning">{{ t('resources.groupStateLoss') }}</NAlert>
          <NAlert v-if="exported.result.losses?.length" type="warning" :title="t('resources.exportLosses')">
            <ul class="result-list">
              <li v-for="loss in exported.result.losses" :key="loss">{{ loss }}</li>
            </ul>
          </NAlert>
          <NButton type="primary" data-testid="resource-download" @click="download">{{ t('resources.confirmExport') }}</NButton>
        </template>
      </div>
    </NModal>
  </section>
</template>

<style scoped>
.exchange { margin-bottom: 16px; }
.exchange-actions { display: flex; flex-wrap: wrap; gap: 8px; }
.exchange p { margin: 8px 0 0; }
.exchange-form, .result { display: grid; gap: 10px; }
.exchange-form label { display: grid; gap: 4px; }
.exchange-form input, .exchange-form select {
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 7px 9px;
  min-height: 36px;
  width: 100%;
  background: var(--card);
  color: var(--text);
  font: inherit;
}
.exchange-form :disabled { opacity: 0.65; }
.exchange-form p, .result p, .result-list { margin: 0; }
.result { margin-top: 12px; overflow-wrap: anywhere; }
.result-list { padding-inline-start: 1.4rem; max-height: 12rem; overflow: auto; }
.diff { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
</style>
