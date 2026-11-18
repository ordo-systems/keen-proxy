import { shallowRef, watchEffect } from 'vue'
import type { DomainAddress, DomainRecord } from './types'

// The record snapshot can be frozen for a draft preview; visible addresses still expire in real time.
export function useCurrentDomainAddresses(visible: () => readonly (readonly DomainRecord[])[]) {
  const addresses = shallowRef<(DomainAddress & { name: string })[][]>([])
  watchEffect((cleanup) => {
    const rows = visible()
    let timer: ReturnType<typeof setTimeout> | undefined
    function refresh() {
      const now = Date.now()
      let next = Infinity
      addresses.value = rows.map(records => {
        const active: (DomainAddress & { name: string })[] = []
        for (const record of records) {
          for (const address of record.addresses) {
            const expiry = Date.parse(address.expires_at)
            if (expiry > now) {
              next = Math.min(next, expiry)
              active.push({ ...address, name: record.name })
            }
          }
        }
        return active
      })
      if (next !== Infinity) timer = setTimeout(refresh, Math.min(next - now, 2_147_483_647))
    }
    refresh()
    cleanup(() => clearTimeout(timer))
  })
  return addresses
}
