<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { NAlert, NButton, NSelect } from 'naive-ui'
import { useI18n } from 'vue-i18n'
import { api } from '../api'
import { routerInterfaceName } from '../routerInterface'
import type { RouterInterface } from '../types'

const props = defineProps<{ value: string | null; retained?: string; disabled?: boolean }>()
const emit = defineEmits<{
  'update:value': [value: string | null]
  choose: [device: RouterInterface]
}>()
const { t } = useI18n()
const devices = ref<RouterInterface[]>()
const loading = ref(true)
const failed = ref(false)

async function load() {
  loading.value = true
  failed.value = false
  try {
    devices.value = await api.interfaces()
  } catch {
    failed.value = true
  } finally {
    loading.value = false
  }
}
onMounted(load)

const selected = computed(() => devices.value?.find(device => device.name === props.value))
const options = computed(() => {
  const choices = (devices.value ?? []).map(device => {
    const label = routerInterfaceName(device)
    return { value: device.name, label: label === device.name ? label : `${label} (${device.name})` }
  })
  // A missing saved device is still a valid way to keep the existing binding.
  for (const value of [props.retained, props.value]) {
    if (value && !choices.some(option => option.value === value)) choices.unshift({ value, label: value })
  }
  return choices
})
function choose(value: string | null) {
  emit('update:value', value)
  const device = devices.value?.find(device => device.name === value)
  if (device) emit('choose', device)
}
</script>

<template>
  <div class="interface-field">
    <span>{{ t('ui.routerDevice') }}</span>
    <NSelect
      size="large"
      :value="value"
      :options="options"
      :aria-label="t('ui.routerDevice')"
      :placeholder="t('ui.routerPickDevice')"
      :loading="loading"
      :disabled="disabled || loading || !options.length"
      @update:value="choose"
    />
    <NAlert v-if="failed" type="error" :show-icon="false" role="alert">
      {{ t('ui.routerListFailed') }}
      <NButton size="small" :disabled="disabled" @click="load">{{ t('ui.routerRetry') }}</NButton>
    </NAlert>
    <span v-else-if="selected" class="muted" role="status">
      {{ t(selected.up ? 'ui.routerDeviceUp' : 'ui.routerDeviceDown') }}
    </span>
    <span v-else-if="devices && value" class="muted" role="status">{{ t('ui.routerDeviceMissing') }}</span>
    <span v-else-if="devices?.length === 0" class="muted" role="status">{{ t('ui.routerListEmpty') }}</span>
  </div>
</template>

<style scoped>
.interface-field {
  display: grid;
  gap: 8px;
  min-width: 0;
}
.interface-field > span:first-child {
  font-weight: 600;
}
</style>
