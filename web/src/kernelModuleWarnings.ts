import type { KernelFeature, KernelModuleDiagnostics, KernelModuleStatus } from './types'

function firmwareUnregistered(status: KernelModuleStatus): boolean {
  return status.state === 'unloaded' ||
    (status.state === 'loaded_unregistered' && status.firmware_present === true)
}

// Warn only when the applied feature needs a module and the probe has positive evidence.
export function kernelModuleWarnings(
  modules: KernelModuleDiagnostics | null,
  activeMode: string | undefined,
  managedUpdates: boolean,
): KernelFeature[] {
  if (!modules) return []
  const warnings: KernelFeature[] = []
  if (activeMode === 'tproxy' && firmwareUnregistered(modules.tproxy)) warnings.push('tproxy')
  const guard = modules.guard
  if (managedUpdates && (firmwareUnregistered(guard) ||
    (guard.firmware_present === true && (guard.ipv4 === 'unregistered' || guard.ipv6 === 'unregistered')))) {
    warnings.push('guard')
  }
  return warnings
}
