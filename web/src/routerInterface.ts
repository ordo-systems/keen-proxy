import type { Connection, RouterInterface } from './types'
import { slugify } from './wgconf.ts'

// Only outbounds that the simple editor can reproduce without losing settings.
export function boundRouterInterface(connection: Connection): string | undefined {
  const { outbound } = connection
  if (connection.type !== 'singbox' || connection.endpoint || !outbound ||
      outbound.type !== 'direct' || Object.keys(outbound).length !== 2) return undefined
  const device = outbound.bind_interface
  return typeof device === 'string' && device.trim() ? device : undefined
}

// Retain the original ID verbatim so every existing routing reference remains valid.
export function editRouterInterface(connection: Connection, name: string, device: string | null): Connection {
  if (!device?.trim()) throw new Error('routerDevice')
  return {
    ...connection,
    name: name.trim() || connection.id,
    outbound: { ...connection.outbound, bind_interface: device },
  }
}

export function routerInterfaceName(device: RouterInterface): string {
  return device.label?.trim() || device.name
}

// Keep the generated ID usable without asking for another field in the wizard.
export function routerInterfaceID(name: string, device: string, connections: readonly Connection[]): string {
  const base = slugify(name) || slugify(device) || 'router-interface'
  const taken = new Set(['direct', 'block', ...connections.map((connection) => connection.id)])
  let id = base
  for (let i = 2; taken.has(id); i++) {
    const suffix = `-${i}`
    id = base.slice(0, 32 - suffix.length) + suffix
  }
  return id
}
