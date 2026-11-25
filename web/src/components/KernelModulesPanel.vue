<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { NAlert, NButton, NInput, NModal, useMessage } from 'naive-ui'
import { api } from '../api'
import { ApiError } from '../apiError'
import type { KernelModuleDiagnostics } from '../types'

const { t } = useI18n()
const message = useMessage()
const checks = [
  { feature: 'guard', module: 'xt_comment' },
  { feature: 'tproxy', module: 'xt_TPROXY' },
] as const
const guardFamilies = [{ key: 'ipv4', label: 'IPv4' }, { key: 'ipv6', label: 'IPv6' }] as const
const status = ref<KernelModuleDiagnostics>()
const selected = ref<(typeof checks)[number]>()
const open = ref(false)
const refreshing = ref(false)
const loading = ref(false)
const token = ref('')
const probeError = ref(false)
const loadError = ref('')
const loadDetail = ref('')
const showToken = computed(() => status.value?.token_required ?? false)
const canSubmit = computed(() =>
  selected.value != null && !!status.value?.[selected.value.feature].can_load &&
  !refreshing.value && !loading.value && (!showToken.value || !!token.value.trim()),
)

async function refresh() {
  if (refreshing.value || loading.value) return
  refreshing.value = true
  probeError.value = false
  try {
    status.value = await api.kernelModules()
  } catch {
    status.value = undefined
    probeError.value = true
  } finally {
    refreshing.value = false
  }
}

function confirm(check: (typeof checks)[number]) {
  selected.value = check
  token.value = ''
  loadError.value = ''
  loadDetail.value = ''
  open.value = true
}

function dismiss() {
  if (loading.value) return
  open.value = false
  token.value = ''
}

async function load() {
  if (!canSubmit.value || !selected.value) return
  const { feature, module } = selected.value
  loading.value = true
  loadError.value = ''
  loadDetail.value = ''
  try {
    if (showToken.value) await api.login(token.value)
    status.value = await api.loadKernelModule(feature)
    if (status.value[feature].state === 'registered') {
      message.success(t('kernelModules.loaded', { module }))
    } else {
      message.warning(t('kernelModules.loadUnverified', { module }))
    }
    open.value = false
  } catch (err) {
    loadError.value = err instanceof ApiError && err.status === 401
      ? 'kernelModules.invalidToken'
      : err instanceof ApiError && err.status === 403
        ? 'kernelModules.loadDenied'
        : 'kernelModules.loadFailed'
    if (err instanceof ApiError && (err.status === 409 || err.status === 422)) loadDetail.value = err.message
  } finally {
    token.value = ''
    loading.value = false
    if (loadError.value) await refresh()
  }
}

onMounted(refresh)
</script>

<template>
  <section class="kernel-panel" aria-labelledby="kernel-modules-heading">
    <header class="kernel-heading">
      <div>
        <h2 id="kernel-modules-heading">{{ t('kernelModules.title') }}</h2>
        <p class="muted">{{ t('kernelModules.intro') }}</p>
      </div>
      <NButton :loading="refreshing" :disabled="loading || open" @click="refresh">
        {{ t('kernelModules.checkAgain') }}
      </NButton>
    </header>
    <NAlert v-if="probeError" type="error">{{ t('kernelModules.probeFailed') }}</NAlert>
    <p v-else-if="!status" class="muted" role="status">{{ t('kernelModules.checking') }}</p>
    <div v-else aria-live="polite">
      <div v-for="check in checks" :key="check.feature" class="kernel-row">
        <div>
          <strong>{{ t(`kernelModules.${check.feature}`) }}</strong>
          <code>{{ check.module }}</code>
          <p>{{ t(check.feature === 'tproxy' && status.tproxy.state === 'registered'
            ? 'kernelModules.tproxyRegistered' : `kernelModules.states.${status[check.feature].state}`) }}</p>
          <p v-if="status[check.feature].state === 'unloaded' && !status[check.feature].can_load" class="muted">
            {{ t('kernelModules.cannotLoad') }}
          </p>
          <dl v-if="check.feature === 'guard' && status.guard.ipv4" class="guard-evidence">
            <div v-for="family in guardFamilies" :key="family.key">
              <dt>{{ family.label }}</dt>
              <dd>{{ t(`kernelModules.guardStates.${status.guard[family.key] ?? 'unknown'}`) }}</dd>
            </div>
          </dl>
        </div>
        <NButton v-if="status[check.feature].can_load" :disabled="refreshing || loading || open" @click="confirm(check)">
          {{ t('kernelModules.load') }}
        </NButton>
      </div>
    </div>
  </section>
  <NModal :show="open" preset="dialog" :title="t('kernelModules.confirm', { module: selected?.module })"
    :closable="!loading" :mask-closable="!loading" :close-on-esc="!loading" @update:show="!$event && dismiss()">
    <p>{{ t('kernelModules.confirmNote') }}</p>
    <p v-if="showToken" class="muted">{{ t('kernelModules.tokenNote') }}</p>
    <label v-if="showToken">
      {{ t('kernelModules.token') }}
      <NInput v-model:value="token" type="password" placeholder="" :input-props="{ autocomplete: 'off' }"
        :disabled="loading || refreshing" @keydown.enter="load" />
    </label>
    <NAlert v-if="loadError" type="error" class="module-error">
      {{ t(loadError) }}
      <details v-if="loadDetail">
        <summary>{{ t('kernelModules.errorDetail') }}</summary>
        {{ loadDetail }}
      </details>
    </NAlert>
    <template #action>
      <NButton :disabled="loading" @click="dismiss">{{ t('kernelModules.cancel') }}</NButton>
      <NButton type="primary" :loading="loading" :disabled="!canSubmit" @click="load">
        {{ t('kernelModules.load') }}
      </NButton>
    </template>
  </NModal>
</template>

<style scoped>
.kernel-panel {
  padding: 18px;
  margin-bottom: 24px;
  border: 1px solid var(--line);
  border-radius: 10px;
}
.kernel-heading, .kernel-row {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: flex-start;
  gap: 10px 20px;
}
.kernel-heading h2 { margin: 0 0 4px; font-size: 18px; }
.kernel-panel p { margin: 4px 0 0; }
.kernel-row { border-top: 1px solid var(--line); margin-top: 12px; padding-top: 12px; }
.kernel-row code { margin-inline-start: 8px; }
.guard-evidence { display: flex; flex-wrap: wrap; gap: 6px 18px; margin: 8px 0 0; }
.guard-evidence div { display: flex; gap: 6px; }
.guard-evidence dt { font-weight: 600; }
.guard-evidence dd { margin: 0; color: var(--muted); }
.module-error { margin-top: 12px; }
</style>
