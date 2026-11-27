import assert from 'node:assert/strict'
import test from 'node:test'
import { kernelModuleWarnings } from '../src/kernelModuleWarnings.ts'
import type { KernelModuleStatus } from '../src/types.ts'

const diagnostics = (tproxy: KernelModuleStatus, guard = tproxy) => ({ tproxy, guard, token_required: true })

test('reports missing kernel registration independently of permission to load', () => {
  const modules = diagnostics({ state: 'unloaded', can_load: false }, { state: 'loaded_unregistered', firmware_present: true })
  assert.deepEqual(kernelModuleWarnings(modules, 'tproxy', true), ['tproxy', 'guard'])
  assert.deepEqual(kernelModuleWarnings(modules, 'redirect', true), ['guard'])
  assert.deepEqual(kernelModuleWarnings(modules, 'tproxy', false), ['tproxy'])
  assert.deepEqual(kernelModuleWarnings(modules, undefined, false), [])
})

test('requires proof that an unregistered loaded module exists in the firmware', () => {
  for (const status of [
    { state: 'loaded_unregistered' },
    { state: 'unknown', firmware_present: true },
    { state: 'registered', firmware_present: true },
    { state: 'not_found' },
  ] satisfies KernelModuleStatus[]) {
    assert.deepEqual(kernelModuleWarnings(diagnostics(status), 'tproxy', true), [], status.state)
  }
  assert.deepEqual(kernelModuleWarnings(null, 'tproxy', true), [])
})
