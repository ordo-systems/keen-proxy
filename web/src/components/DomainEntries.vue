<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { NButton, NInput, NModal, NAlert, NSwitch, useDialog } from 'naive-ui'
import { Plus, Pencil, Trash2, RefreshCw, ChevronRight, ChevronDown } from '@lucide/vue'
import type { Group, DomainStatus, DomainRecord } from '../types'
import { store } from '../store'
import { api } from '../api'
import { domainName } from '../domain'
import { useCurrentDomainAddresses } from '../domainAddresses'
import { canonicalEntry, dropRemoved, entryIdentity, entryOff, groupDisabledEntryKeys, migrateFlag, setEntryEnabled } from '../activation'

// Edit group entries in the shared draft and display live or isolated preview DNS records.
const props = defineProps<{ group: Group; status: DomainStatus | null; query: string; preview: boolean; refreshing: boolean }>()
const emit = defineEmits<{ refresh: [names: string[]] }>()
const { t, locale } = useI18n()
const dialog = useDialog()
const expanded = ref(new Set<string>())
const show = ref(false)
const editing = ref<number | null>(null)
const value = ref('')
const error = ref('')
const saving = ref(false)
const pageSize = 50
const page = ref(0)
const applying = computed(() => store.state.applying)
watch([() => props.group, () => props.query], () => { page.value = 0 })

const matchingIndexes = computed(() => {
  const query = props.query.toLowerCase()
  if (!query || props.group.name.toLowerCase().includes(query)) return
  const indexes: number[] = []
  props.group.entries.forEach((entry, index) => { if (entry.toLowerCase().includes(query)) indexes.push(index) })
  return indexes
})
const rowCount = computed(() => matchingIndexes.value?.length ?? props.group.entries.length)
const lastPage = computed(() => Math.max(0, Math.ceil(rowCount.value / pageSize) - 1))
watch(lastPage, last => { if (page.value > last) page.value = last })
const pageStart = computed(() => Math.min(page.value, lastPage.value) * pageSize)
const pageEnd = computed(() => Math.min(pageStart.value + pageSize, rowCount.value))
const visibleRows = computed(() => {
  const rows = []
  for (let position = pageStart.value; position < pageEnd.value; position++) {
    const index = matchingIndexes.value?.[position] ?? position
    const entry = props.group.entries[index]!
    const canonical = canonicalEntry(entry)
    rows.push({ entry, index, name: domainName(canonical),
      off: entryOff(props.group, canonical) })
  }
  return rows
})
const indexedRecords = computed(() => {
  const records = new Map<string, DomainRecord[]>()
  for (const row of visibleRows.value) if (row.name) records.set(row.name, [])
  if (records.size) {
    for (const record of props.status?.records ?? []) {
      for (let name = record.name; name;) {
        records.get(name)?.push(record)
        const dot = name.indexOf('.')
        if (dot < 0) break
        name = name.slice(dot + 1)
      }
    }
  }
  return visibleRows.value.map(row => row.name ? records.get(row.name) ?? [] : [])
})
const currentAddresses = useCurrentDomainAddresses(() => indexedRecords.value)
const rows = computed(() => visibleRows.value.map((row, index) => ({
  ...row,
  records: indexedRecords.value[index] ?? [],
  addresses: currentAddresses.value[index] ?? [],
})))
function date(v: string) { return !v || v.startsWith('0001') ? '—' : new Date(v).toLocaleString(locale.value) }
function toggle(s: string) { if (expanded.value.has(s)) expanded.value.delete(s); else expanded.value.add(s) }
function open(index: number | null) {
  if (applying.value) return
  editing.value = index
  value.value = index === null ? '' : props.group.entries[index]!
  error.value = ''
  show.value = true
}
function toggleEntry(entry: string, enabled: boolean) {
  if (!applying.value) setEntryEnabled(props.group, entry, enabled)
}
// Validate a copied configuration before updating entries and requesting a domain preview.
async function save() {
  const draft = store.state.config, group = props.group
  const groupIndex = draft?.groups?.indexOf(group) ?? -1
  if (!draft || groupIndex < 0 || applying.value || saving.value) return
  const original = group.entries, originalFlags = group.disabled_entries
  error.value = ''
  const lines = value.value.split('\n').map(s => s.split('#')[0]!.trim()).filter(Boolean)
  if (!lines.length || (editing.value !== null && lines.length !== 1)) { error.value = t('domains.oneOnly'); return }
  saving.value = true
  try {
    const cfg = JSON.parse(JSON.stringify(draft))
    const next = [...original]
    const previous = editing.value === null ? '' : original[editing.value]!
    if (editing.value === null) next.push(...lines.filter(s => !next.includes(s)))
    else next[editing.value] = lines[0]!
    const flags = editing.value === null ? props.group.disabled_entries : migrateFlag(props.group.disabled_entries, previous, lines[0]!, entryIdentity)
    cfg.groups[groupIndex].entries = next
    cfg.groups[groupIndex].disabled_entries = flags
    await api.validateConfig(cfg)
    if (applying.value || store.state.config !== draft || props.group !== group ||
      draft.groups?.[groupIndex] !== group || group.entries !== original || group.disabled_entries !== originalFlags) return
    group.entries = next
    group.disabled_entries = flags
    show.value = false
    const off = groupDisabledEntryKeys(group)
    const domains = lines.flatMap(line => {
      const canonical = canonicalEntry(line)
      return canonical.type === 'domain_suffix' && !off.has(entryIdentity(canonical)) ? [canonical.value] : []
    })
    if (domains.length && !group.preset && !group.disabled) emit('refresh', domains)
  } catch (e) { error.value = (e as Error).message || t('domains.saveError') }
  finally { saving.value = false }
}
function remove(index: number) {
  if (applying.value) return
  const draft = store.state.config, group = props.group
  const entry = group.entries[index]
  dialog.warning({ title: t('domains.remove'), content: entry, positiveText: t('common.delete'), negativeText: t('common.cancel'), onPositiveClick: () => {
    if (applying.value || store.state.config !== draft || !draft?.groups?.includes(group) || group.entries[index] !== entry) return
    const remaining = group.entries.filter((_, current) => current !== index)
    group.disabled_entries = dropRemoved(group.disabled_entries, group.entries, remaining, entryIdentity)
    group.entries = remaining
  } })
}
</script>

<template>
  <div class="domain-entries">
    <div class="entries-toolbar">
      <span class="hint">{{ t('domains.hint') }}</span>
      <NButton size="small" :disabled="applying" @click="open(null)"><template #icon><Plus :size="14" /></template>{{ t('domains.add') }}</NButton>
    </div>
    <div v-if="preview" class="hint preview">{{ t('domains.preview') }}</div>
    <p v-if="group.disabled" class="hint">{{ t('groups.parentOff') }}</p>
    <p v-if="!rows.length" class="hint">{{ t('domains.emptyGroup') }}</p>
    <div v-for="row in rows" :key="`${row.index}:${row.entry}`" class="entry" :class="{ off: row.off || group.disabled }">
      <div class="entry-line">
        <NSwitch size="small" :disabled="applying" :value="!row.off" :aria-label="t('groups.toggleEntry', { name: row.entry })" @update:value="(v: boolean) => toggleEntry(row.entry, v)" />
        <button class="entry-label" :aria-label="`${t('domains.details')}: ${row.entry}`" :aria-expanded="expanded.has(row.entry)" @click="toggle(row.entry)">
          <ChevronDown v-if="expanded.has(row.entry)" :size="14" /><ChevronRight v-else :size="14" />
          <span class="entry-type">{{ t(row.name ? 'domains.domain' : 'domains.address') }}</span>
          <strong>{{ row.entry }}</strong>
          <span class="ip-count">{{ group.disabled ? t('groups.parentOffShort') : row.off ? t('groups.entryOff') : row.name ? t('domains.ipCount', { n: row.addresses.length }) : t('groups.entryOn') }}</span>
        </button>
        <div class="entry-actions">
          <NButton v-if="row.name && !group.disabled && !row.off && !(group.preset && preview)" size="tiny" quaternary :loading="refreshing" :title="t('domains.refresh')" :aria-label="`${t('domains.refresh')}: ${row.entry}`" @click="emit('refresh', [row.name!])"><template #icon><RefreshCw :size="14" /></template></NButton>
          <NButton size="tiny" quaternary :disabled="applying" :title="t('common.edit')" :aria-label="`${t('common.edit')}: ${row.entry}`" @click="open(row.index)"><template #icon><Pencil :size="14" /></template></NButton>
          <NButton size="tiny" quaternary type="error" :disabled="applying" :title="t('common.delete')" :aria-label="`${t('common.delete')}: ${row.entry}`" @click="remove(row.index)"><template #icon><Trash2 :size="14" /></template></NButton>
        </div>
      </div>
      <div v-if="expanded.has(row.entry)" class="entry-detail">
        <template v-if="row.name">
          <div v-if="!row.records.length" class="hint">{{ t('domains.waiting') }}</div>
          <div v-for="r in row.records" :key="r.name">
            <div class="record-meta">{{ r.name }} · {{ t('domains.checked') }}: {{ date(r.checked_at) }} · {{ t('domains.source') }}: {{ t(r.source === 'observed' ? 'domains.observed' : 'domains.resolved') }}</div>
            <div v-if="r.error" class="dns-error">{{ t('domains.error') }}: {{ r.error }}</div>
          </div>
          <div v-if="row.records.some(r => r.limited)" class="hint">{{ t('domains.limited') }}</div>
          <div class="addresses">
            <span v-for="a in row.addresses" :key="`${a.name}:${a.ip}`" class="address" :title="`${a.name} · ${t('domains.expires')}: ${date(a.expires_at)}`">{{ a.ip }} <small>{{ t('domains.expires') }} {{ date(a.expires_at) }}</small><span v-if="status?.conflicts?.[a.ip]" class="dns-error">{{ t('domains.conflict') }}</span></span>
          </div>
          <div v-if="!row.addresses.length" class="hint">{{ t('domains.empty') }}</div>
        </template>
        <span v-else class="hint">{{ t('domains.noDNS') }}</span>
      </div>
    </div>
    <div v-if="lastPage > 0" class="entry-pages">
      <NButton size="tiny" :disabled="page === 0" @click="page--">{{ t('groups.previousEntries') }}</NButton>
      <span class="hint" aria-live="polite">{{ t('groups.entryPage', { first: pageStart + 1, last: pageEnd, count: rowCount }) }}</span>
      <NButton size="tiny" :disabled="page >= lastPage" @click="page++">{{ t('groups.nextEntries') }}</NButton>
    </div>
    <NModal v-model:show="show" preset="card" :title="t(editing === null ? 'domains.add' : 'domains.edit')" style="width: min(560px, 94vw)">
      <NInput v-model:value="value" type="textarea" :autosize="{ minRows: 4, maxRows: 12 }" :placeholder="t('domains.placeholder')" />
      <NAlert v-if="error" type="error" style="margin-top: 12px">{{ error }}</NAlert>
      <template #footer><div class="dialog-actions"><NButton @click="show = false">{{ t('common.cancel') }}</NButton><NButton type="primary" :loading="saving" :disabled="applying" @click="save">{{ t('common.save') }}</NButton></div></template>
    </NModal>
  </div>
</template>

<style scoped>
.domain-entries { padding: 10px 16px 14px; }
.entries-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 10px; }
.entry-pages { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-top: 8px; }
.entry { border-top: 1px solid var(--line, #ffffff12); }
.entry.off { color: var(--muted); }
.entry-line { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 9px 0; }
.entry-line > :deep(.n-switch) { flex-shrink: 0; }
.entry-label { display: flex; flex: 1; flex-wrap: wrap; align-items: center; gap: 8px; border: 0; padding: 0; background: none; color: inherit; cursor: pointer; text-align: left; min-width: 0; }
.entry-label strong { font: 600 13px ui-monospace, monospace; overflow-wrap: anywhere; }
.entry-type, .ip-count { font-size: 10px; border-radius: 3px; padding: 2px 5px; background: #739ee91a; color: var(--muted); white-space: nowrap; }
.entry-actions, .dialog-actions { display: flex; justify-content: flex-end; gap: 6px; flex-shrink: 0; }
.entry-detail { padding: 0 0 12px 22px; }
.record-meta, .hint { color: var(--muted); font-size: 12px; }
.preview { margin-bottom: 8px; color: #c39b49; }
.addresses { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
.address { padding: 4px 8px; background: #739ee915; border: 1px solid #739ee925; border-radius: 4px; font-family: ui-monospace, monospace; }
.address small { display: block; font: 10px system-ui; color: var(--muted); }
.dns-error { color: #e78484; font-size: 12px; }
@media(max-width: 720px) { .entries-toolbar { align-items: flex-start; flex-direction: column; } .entry-type { display: none; } .domain-entries { padding: 8px; } }
</style>
