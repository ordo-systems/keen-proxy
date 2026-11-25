import type { Preset } from './types.ts'

// Counts describe the full catalog, even while a search is active.
export function catalogCounts(catalog: readonly Preset[]): Map<string, number> {
  const counts = new Map<string, number>()
  for (const preset of catalog) counts.set(preset.category, (counts.get(preset.category) ?? 0) + 1)
  return counts
}

export function filterCatalog(catalog: readonly Preset[], category: string, query: string): Preset[] {
  const needle = query.trim().toLowerCase()
  const matches = (value: string) => value.toLowerCase().includes(needle)
  return catalog.filter(preset => (!category || preset.category === category) &&
    (!needle || matches(preset.name) || matches(preset.description) ||
      preset.domains.some(matches) || preset.prefixes.some(matches)))
}
