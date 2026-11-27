import type { InterceptMode, KernelFeature, KernelModuleDiagnostics, KernelModuleStatus } from './types'

function firmwareUnregistered(status: KernelModuleStatus): boolean {
  return status.state === 'unloaded' ||
    (status.state === 'loaded_unregistered' && status.firmware_present === true)
}

// Warn only when the applied feature needs a module and the probe has positive evidence.
export function kernelModuleWarnings(
  modules: KernelModuleDiagnostics | null,
  appliedMode: InterceptMode | undefined,
  managedUpdates: boolean,
): KernelFeature[] {
  if (!modules) return []
  const warnings: KernelFeature[] = []
  if (appliedMode === 'tproxy' && firmwareUnregistered(modules.tproxy)) warnings.push('tproxy')
  if (managedUpdates && firmwareUnregistered(modules.guard)) warnings.push('guard')
  return warnings
}
