<script setup lang="ts">
import { NButton, NSwitch } from 'naive-ui'
import { Trash2 } from '@lucide/vue'
import { useI18n } from 'vue-i18n'
import type { Group } from '../types'
import { countryName, flag } from '../countries'
import { dropRemoved, geoIdentity, selectorOff, setSelectorEnabled } from '../activation'

// Keep selected countries and categories visible. A switch does not delete the value.
const props = defineProps<{ group: Group }>()
const { t } = useI18n()

function reason(kind: 'countries' | 'categories', value: string) {
  if (props.group.disabled) return t('groups.parentOffShort')
  return selectorOff(props.group, kind, value) ? t('groups.entryOff') : t('groups.participates')
}

function removeCountry(code: string) {
  const next = (props.group.countries ?? []).filter((item) => geoIdentity(item) !== geoIdentity(code))
  props.group.disabled_countries = dropRemoved(props.group.disabled_countries, props.group.countries ?? [], next, geoIdentity)
  props.group.countries = next.length || !props.group.categories ? next : undefined
}

function removeCategory(label: string) {
  const next = (props.group.categories ?? []).filter((item) => geoIdentity(item) !== geoIdentity(label))
  props.group.disabled_categories = dropRemoved(props.group.disabled_categories, props.group.categories ?? [], next, geoIdentity)
  props.group.categories = next.length ? next : undefined
  if (!props.group.categories) props.group.countries ??= []
}
</script>

<template>
  <div class="selector-entries">
    <p v-if="group.disabled" class="hint">{{ t('groups.parentOff') }}</p>
    <div v-for="code in group.countries ?? []" :key="`c:${code}`" class="selector-row" :class="{ off: selectorOff(group, 'countries', code) || group.disabled }">
      <NSwitch size="small" :value="!selectorOff(group, 'countries', code)" :aria-label="t('groups.toggleCountry', { name: countryName(code) })" @update:value="(v: boolean) => setSelectorEnabled(group, 'countries', code, v)" />
      <span>{{ flag(code) }} {{ countryName(code) }} <small>{{ code }}</small></span>
      <small class="muted">{{ reason('countries', code) }}</small>
      <NButton size="tiny" quaternary type="error" :aria-label="`${t('groups.removeCountry')}: ${code}`" @click="removeCountry(code)"><template #icon><Trash2 :size="14" /></template></NButton>
    </div>
    <div v-for="label in group.categories ?? []" :key="`k:${label}`" class="selector-row" :class="{ off: selectorOff(group, 'categories', label) || group.disabled }">
      <NSwitch size="small" :value="!selectorOff(group, 'categories', label)" :aria-label="t('groups.toggleCountry', { name: label })" @update:value="(v: boolean) => setSelectorEnabled(group, 'categories', label, v)" />
      <span>{{ label }}</span>
      <small class="muted">{{ reason('categories', label) }}</small>
      <NButton size="tiny" quaternary type="error" :aria-label="`${t('common.delete')}: ${label}`" @click="removeCategory(label)"><template #icon><Trash2 :size="14" /></template></NButton>
    </div>
  </div>
</template>

<style scoped>
.selector-entries { padding: 8px 12px 12px; }
.hint, .muted { color: var(--muted); font-size: 12px; }
.selector-row { display: flex; align-items: center; gap: 10px; padding: 8px 0; border-top: 1px solid var(--line); }
.selector-row.off { color: var(--muted); }
.selector-row > span { min-width: 0; flex: 1; overflow-wrap: anywhere; }
.selector-row small { margin-left: 6px; }
</style>
