import { canonicalEntry, type CanonicalEntry } from './activation.ts'

// Keep UI lookup keys compatible with model.ParseEntry (comments, wildcard,
// trailing dot and IDNA). Addresses remain explicit rules, never DNS lookups.
export function domainName(entry: string | CanonicalEntry): string | null {
  const entryValue = typeof entry === 'string' ? canonicalEntry(entry) : entry
  return entryValue.type === 'domain_suffix' ? entryValue.value : null
}
