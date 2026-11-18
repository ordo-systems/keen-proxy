import { canonicalEntry, disabledEntryKeys, entryIdentity } from './activation.ts'

export type ResourceFormat = 'txt' | 'csv' | 'json' | 'sing-box-json' | 'srs'
export type ResourceEntry = { type: 'domain_suffix' | 'ip_cidr'; value: string; disabled?: boolean }
export type ResourceList = { name?: string; entries: ResourceEntry[] }
export type ResourceIssue = { location: string; message: string; kind: 'error' | 'unsupported' }
export type ResourcePreview = {
  list: ResourceList
  issues: ResourceIssue[]
  omitted_issues: number
  duplicates: number
  valid: boolean
}
export type ResourceExport = { data: string; losses: string[] }
export type ResourceMode = 'append' | 'replace'
export type ResourceCollection = { entries: string[]; disabled_entries?: string[] }
export type ResourceMerge = ResourceCollection & {
  added: string[]
  removed: string[]
  duplicates: number
  effectiveDisabled: boolean[]
  activationConflicts: number
}

// Import changes resources only; a duplicate never changes a previously saved switch.
export function mergeResourceEntries(current: ResourceCollection, incoming: ResourceEntry[], mode: ResourceMode): ResourceMerge {
  const existingKeys = current.entries.map(entryIdentity)
  const existing = new Set(existingKeys)
  const previouslyOff = disabledEntryKeys(current)
  const seen = new Map<string, boolean>()
  const entries = mode === 'append' ? [...current.entries] : []
  const newFlags: string[] = []
  const added: string[] = []
  const effectiveDisabled: boolean[] = []
  let duplicates = 0, activationConflicts = 0
  for (const item of incoming) {
    // The preview's declared kind is authoritative; normalize the spelling within it.
    const key = entryIdentity({ ...canonicalEntry(item.value), type: item.type })
    const present = existing.has(key)
    const earlier = seen.get(key)
    if (present) duplicates++
    else if (earlier === undefined) added.push(item.value)
    const disabled = earlier ?? (previouslyOff.has(key) || (!present && !!item.disabled))
    effectiveDisabled.push(disabled)
    if (disabled !== !!item.disabled) activationConflicts++
    if (earlier !== undefined) continue
    seen.set(key, disabled)
    if (mode === 'replace' || !present) entries.push(item.value)
    if (disabled && !previouslyOff.has(key)) newFlags.push(item.value)
  }
  const removed: string[] = []
  if (mode === 'replace') {
    current.entries.forEach((entry, index) => {
      if (!seen.has(existingKeys[index]!)) removed.push(entry)
    })
  }
  const retainedFlags = removed.length
    ? current.disabled_entries?.filter(flag => {
      const key = entryIdentity(flag)
      return !existing.has(key) || seen.has(key)
    })
    : current.disabled_entries
  const disabled = [...(retainedFlags ?? []), ...newFlags]
  return { entries, disabled_entries: disabled.length ? disabled : undefined, added, removed, duplicates,
    effectiveDisabled, activationConflicts }
}

// A draft replacement (Apply or Discard) and a different destination both invalidate a preview.
export type ResourceSnapshot = { draft: object; destination: ResourceCollection | undefined; resources: ResourceCollection }
export type ResourceImportPlan = { snapshot: ResourceSnapshot; preview: ResourcePreview; changes: ResourceMerge | null }

export function snapshotResourceDraft(draft: object, destination: ResourceCollection | undefined): ResourceSnapshot {
  return {
    draft,
    destination,
    resources: { entries: destination?.entries.slice() ?? [], disabled_entries: destination?.disabled_entries?.slice() },
  }
}

function equalValues(left: string[] = [], right: string[] = []): boolean {
  return left.length === right.length && left.every((value, i) => value === right[i])
}

export function resourceDraftMatches(snapshot: ResourceSnapshot, draft: object | null, destination: ResourceCollection | undefined): boolean {
  return draft === snapshot.draft && destination === snapshot.destination &&
    equalValues(snapshot.resources.entries, destination?.entries) &&
    equalValues(snapshot.resources.disabled_entries, destination?.disabled_entries)
}

// Even an invalid preview can display recognized rows, but it cannot produce draft changes.
export function planResourceImport(snapshot: ResourceSnapshot, preview: ResourcePreview, mode: ResourceMode): ResourceImportPlan {
  return { snapshot, preview, changes: preview.valid ? mergeResourceEntries(snapshot.resources, preview.list.entries, mode) : null }
}

export function stageResourceImport(plan: ResourceImportPlan, draft: object,
  destination: ResourceCollection | undefined): ResourceCollection | undefined {
  if (!plan.changes || !resourceDraftMatches(plan.snapshot, draft, destination)) return
  const target = destination ?? { entries: [] }
  target.entries = plan.changes.entries
  if (plan.changes.disabled_entries) target.disabled_entries = plan.changes.disabled_entries
  else delete target.disabled_entries
  return target
}

export const maxLocalPresets = 64

export function validLocalPresetName(name: string): boolean {
  const length = [...name.trim()].length
  return length > 0 && length <= 64
}

// Mirror the model's storage budget before allowing an import or catalog copy into the draft.
export function localPresetFits(presets: ResourceCollection[], next: ResourceCollection, replacing?: ResourceCollection): boolean {
  if (!replacing && presets.length >= maxLocalPresets) return false
  const encoder = new TextEncoder()
  let count = 0, bytes = 0
  for (const preset of [...presets.filter(preset => preset !== replacing), next]) {
    for (const entries of [preset.entries, preset.disabled_entries ?? []]) {
      if (entries.length > 20_000) return false
      count += entries.length
      if (count > 40_000) return false
      for (const entry of entries) {
        const size = encoder.encode(entry).length
        if (size > 1_024 || (bytes += size) > 1 << 20) return false
      }
    }
  }
  return true
}

// Resource export carries human-readable entries and their local activation flags, not routing configuration.
export function resourceList(name: string, collection: ResourceCollection): ResourceList {
  const off = disabledEntryKeys(collection)
  return {
    name,
    entries: collection.entries.map(value => {
      const canonical = canonicalEntry(value)
      // Remove the routing list's inline comment, but let Go validate the actual value.
      const comment = value.indexOf('#')
      const raw = (comment < 0 ? value : value.slice(0, comment)).trim()
      return { type: canonical.type === 'ip_cidr' ? 'ip_cidr' : 'domain_suffix', value: raw,
        disabled: off.has(entryIdentity(canonical)) }
    }),
  }
}

// Browser crypto works in the panel's HTTP LAN context without randomUUID.
export function localPresetID(presets: { id: string }[]): string {
  let id: string
  do {
    id = 'custom-' + Array.from(crypto.getRandomValues(new Uint8Array(6)), byte => byte.toString(16).padStart(2, '0')).join('')
  } while (presets.some(preset => preset.id === id))
  return id
}
