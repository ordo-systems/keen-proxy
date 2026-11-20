import { computed, ref, shallowRef, watch } from 'vue'
import type { HostStat } from './types'

export const HOST_PREVIEW = 10
// Matches the stats retention limit for one outbound.
const HOST_LIMIT = 3000

type FetchHosts = (tag: string, q: string, limit: number) => Promise<{ hosts: HostStat[]; total: number }>

// Ranks the selected connection's hosts: the busiest HOST_PREVIEW by default and
// every match after showAll. A tab switch returns to the preview; a search keeps
// the chosen view. Responses for an outdated tab, search, or view are dropped,
// and failed refreshes keep the previous rows.
export function useHostTraffic(tag: () => string, query: () => string, fetchHosts: FetchHosts) {
  const hosts = shallowRef<HostStat[]>([])
  const total = ref(0)
  const expanded = ref(false)
  const expanding = ref(false)
  const more = computed(() => !expanded.value && total.value > hosts.value.length)
  let pending: { tag: string; query: string; full: boolean } | undefined

  async function load(full = expanded.value) {
    const t = tag()
    const q = query()
    if (pending?.tag === t && pending.query === q && pending.full === full) return
    const request = { tag: t, query: q, full }
    pending = request
    expanding.value = full && !expanded.value
    try {
      const result = await fetchHosts(t, q, full ? HOST_LIMIT : HOST_PREVIEW)
      if (request !== pending || t !== tag() || q !== query()) return
      hosts.value = result.hosts
      total.value = result.total
      expanded.value = full
    } catch {
      // Keep the displayed rows and view if the request fails.
    } finally {
      if (request === pending) {
        pending = undefined
        expanding.value = false
      }
    }
  }

  watch(
    [tag, query],
    ([t], [previous]) => {
      if (t !== previous) {
        expanded.value = false
        hosts.value = []
        total.value = 0
      }
      void load()
    },
    { immediate: true },
  )
  return {
    hosts, total, expanded, expanding, more,
    load: () => expanding.value ? undefined : load(),
    showAll: () => load(true),
  }
}
