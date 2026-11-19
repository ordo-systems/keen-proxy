import { computed, ref, shallowRef, watch } from 'vue'
import type { TProxyReadiness } from './types'

// Probe when Network is shown, or refresh the result after an activation attempt.
export function useTProxyReadiness(visible: () => boolean, probe: () => Promise<TProxyReadiness>) {
  const result = shallowRef<TProxyReadiness | { state: 'failed' } | null>(null)
  const startupBlocked = ref(false)
  const checking = ref(false)
  const unavailable = computed(() => result.value?.state === 'unavailable')
  let pending: Promise<void> | undefined

  async function probeReadiness() {
    checking.value = true
    try {
      const outcome = await probe()
      startupBlocked.value = outcome.startup_blocked === true
      result.value = outcome
    } catch {
      // A request failure is not proof that the capability is missing.
      result.value = { state: 'failed' }
    } finally {
      checking.value = false
    }
  }

  async function check(afterRecovery = false) {
    if (!afterRecovery && (!visible() || checking.value)) return
    // An earlier probe may reflect the state before recovery.
    if (checking.value) await pending
    pending = probeReadiness()
    await pending
  }

  watch(visible, (shown) => { if (shown) void check() }, { immediate: true })
  return { result, startupBlocked, checking, unavailable, check }
}
