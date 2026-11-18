<script setup lang="ts">
import { ref, shallowRef } from 'vue'
import {useI18n} from 'vue-i18n'
import {NAlert,NButton,NInput} from 'naive-ui'
import {api} from '../api'
import {store} from '../store'
import type {Config} from '../types'
const {t}=useI18n()
const text = ref(''), preview = shallowRef<Config>(), error = ref(''), file = ref<HTMLInputElement>()
const selected = shallowRef<File>()
const maxBackupBytes = 3 * 1024 * 1024
const loading = ref(false)
let request = 0

function resetPreview() {
  request++
  preview.value = undefined
  error.value = ''
}
function read(event: Event) {
  const input = event.target as HTMLInputElement
  const next = input.files?.[0]
  if (!next) return
  input.value = ''
  resetPreview()
  selected.value = undefined
  text.value = ''
  if (next.size > maxBackupBytes) {
    error.value = t('features.tooLarge')
    return
  }
  selected.value = next
}
function edit(value: string) {
  selected.value = undefined
  text.value = value
  resetPreview()
}
// Parse and validate on the server into a preview without replacing the active draft.
async function prepare(load: () => Promise<Config>) {
  if (loading.value) return
  loading.value = true
  resetPreview()
  const pending = request
  try {
    const config = await load()
    if (pending === request) preview.value = config
  } catch (e) {
    if (pending === request) error.value = (e as Error).message
  } finally {
    loading.value = false
  }
}
function validate() {
  const yaml = selected.value ?? text.value
  if (typeof yaml === 'string' && !yaml.trim()) return
  return prepare(() => api.importYAML(yaml))
}
function previous() {
  return prepare(() => api.previousConfig())
}
// Adopt the preview as the shared draft; persistence still requires Apply.
function accept() {
  if (!preview.value || store.state.applying) return
  store.setDraft(preview.value)
  edit('')
}
</script>
<template>
 <NAlert type="warning">{{t('features.yamlSecrets')}}</NAlert><p>{{t('features.yamlHint')}}</p>
 <div class="actions"><a :href="api.configExportURL()" download="keenproxy-backup.yaml">{{t('features.exportYAML')}}</a><a :href="api.configExportURL(true)" download="keenproxy-support-redacted.yaml">{{t('features.exportSupport')}}</a><NButton :disabled="loading" @click="previous">{{t('features.previous')}}</NButton><NButton @click="file?.click()">{{t('features.importFile')}}</NButton><input ref="file" type="file" accept=".yaml,.yml" style="display:none" @change="read"/></div>
 <p v-if="selected">{{ selected.name }} <NButton size="tiny" @click="edit('')">{{ t('common.cancel') }}</NButton></p>
 <NInput :value="text" type="textarea" :placeholder="t('features.pasteYAML')" :rows="5" @update:value="edit"/>
 <div class="actions"><NButton :disabled="loading || (!selected && !text.trim())" @click="validate">{{t('features.validate')}}</NButton><NButton v-if="preview" type="primary" :disabled="store.state.applying" @click="accept">{{t('features.toDraft')}}</NButton></div>
 <NAlert v-if="preview" type="info">{{t('features.yamlPreview',{groups:preview.groups?.length??0,connections:preview.connections?.length??0})}}</NAlert><NAlert v-if="error" type="error">{{error}}</NAlert>
</template>
<style scoped>.actions{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin:12px 0}a{color:var(--accent)}</style>
