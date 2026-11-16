<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { NAlert, NCard, NForm, NFormItem, NInputNumber } from 'naive-ui'
import { Cpu } from '@lucide/vue'
import { store } from '../store'
import { maxMemoryLimitMiB } from '../types'

const { t } = useI18n()

// Empty uses the daemon default (startup Go limit or 768 MiB); clear omits the override.
const memoryLimit = computed<number | null>({
  get() {
    const value = store.state.config?.system?.memory_limit_mib
    return typeof value === 'number' ? value : null
  },
  set(value) {
    const cfg = store.state.config
    if (!cfg) return
    if (value == null) {
      if (cfg.system) delete cfg.system.memory_limit_mib
      if (cfg.system && Object.keys(cfg.system).length === 0) delete cfg.system
      return
    }
    cfg.system ??= {}
    cfg.system.memory_limit_mib = value
  },
})
</script>

<template>
  <NCard size="small">
    <template #header><span class="hdr"><Cpu :size="16" /> {{ t('settings.system') }}</span></template>
    <p class="hint">{{ t('settings.memoryLimitHint') }}</p>
    <NAlert type="warning" :show-icon="false">{{ t('settings.memoryLimitWarn') }}</NAlert>
    <NForm label-placement="top" style="margin-top: 12px">
      <NFormItem :label="t('settings.memoryLimit')">
        <NInputNumber
          v-model:value="memoryLimit"
          :min="1"
          :max="maxMemoryLimitMiB"
          :precision="0"
          :step="1"
          :show-button="false"
          clearable
          :placeholder="t('settings.memoryLimitPlaceholder')"
          style="width: 220px"
        />
      </NFormItem>
    </NForm>
  </NCard>
</template>

<style scoped>
.hdr {
  display: inline-flex;
  align-items: center;
  gap: 8px;
}
.hint {
  font-size: 12px;
  color: var(--muted);
  margin: 0 0 12px;
  font-weight: normal;
}
</style>
