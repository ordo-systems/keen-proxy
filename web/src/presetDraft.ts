import { retainPresetActivation } from './activation.ts'
import type { Config } from './types'

type PresetDraftSnapshot = { draft: Config; contents: string; id: string; index: number }
type PresetPreview = { config: Config; diff: { added: string[]; removed: string[] } }
export type BundledPresetPlan = { snapshot: PresetDraftSnapshot; result: PresetPreview }

export function snapshotBundledPreset(draft: Config, id: string): PresetDraftSnapshot {
  return { draft, id, contents: JSON.stringify(draft), index: draft.groups?.findIndex(group => group.preset?.id === id) ?? -1 }
}

export function bundledPresetMatches(snapshot: PresetDraftSnapshot, draft: Config | null): boolean {
  return snapshot.draft === draft && snapshot.contents === JSON.stringify(draft)
}

// The endpoint returns a full config, so do not adopt it after any draft edit or replacement.
export function stageBundledPreset(plan: BundledPresetPlan, draft: Config | null, applying: boolean): Config | undefined {
  if (applying || !draft || !bundledPresetMatches(plan.snapshot, draft)) return
  const { id, index } = plan.snapshot
  const { config } = plan.result
  const resultIndex = index < 0 ? (draft.groups?.length ?? 0) : index
  const next = config.groups?.[resultIndex]
  if (!next || next.preset?.id !== id) return
  const previous = index < 0 ? undefined : draft.groups?.[index]
  const groups = [...config.groups!]
  groups[resultIndex] = retainPresetActivation(previous, next)
  return { ...config, groups }
}
