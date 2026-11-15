import release from './release.json' with { type: 'json' }
import { ApiError } from '../apiError.ts'
import type { UpdatePreferences, UpdateSelection, UpdateStatus } from '../types'

// Display form matches release tags and ui-demo ldflags: v + unprefixed JSON version.
export function demoVersion(version = release.version): string {
  return version.startsWith('v') ? version : `v${version}`
}

// Clearly simulated build label. It is not a commit and changes with the installed demo version.
export function demoRevision(version: string): string {
  return `sim${version.replace(/\D/g, '')}`
}

function previousDemoVersion(version: string): string {
  const match = /^v(\d+)\.(\d+)\.(\d+)$/.exec(version)
  if (!match) return version
  let major = Number(match[1])
  let minor = Number(match[2])
  let patch = Number(match[3])
  if (patch > 0) patch -= 1
  else if (minor > 0) minor -= 1
  else if (major > 0) major -= 1
  return `v${major}.${minor}.${patch}`
}

const planned = demoVersion()
const initialPrevious = previousDemoVersion(planned)
const installDelayMs = 3000

function scheduled(prefs: UpdatePreferences, current: string, clock: string) {
  return prefs.enabled && current !== planned && prefs.time === clock.slice(11, 16)
}

function selectedRelease(selection: UpdateSelection, status: UpdateStatus) {
  const target = selection.rollback ? status.previous : status.latest
  if (!target || target !== selection.target || status.job?.state === 'running') {
    throw new ApiError(409, 'The simulated update state changed')
  }
  return target
}

// Simulate the updater entirely in this page, including the daily clock check.
export function createDemoUpdates() {
  let current = planned
  let previous = initialPrevious
  let prefs: UpdatePreferences = { enabled: false, time: '04:00' }
  let job: UpdateStatus['job']
  let completeAt = 0
  let checkedAt = new Date().toISOString()

  function begin(target: string, now: number) {
    job = { state: 'running', target }
    completeAt = now + installDelayMs
  }

  function advance(now: number, clock: string) {
    if (job?.state === 'running') {
      if (now >= completeAt) {
        previous = current
        current = job.target
        job = { state: 'success', target: current }
      }
      return
    }
    if (scheduled(prefs, current, clock)) {
      begin(planned, now)
    }
  }

  function status(): UpdateStatus {
    const now = Date.now()
    const clock = new Date(now).toISOString()
    advance(now, clock)
    return {
      available: true, demo: true, current, previous,
      latest: current === planned ? undefined : planned,
      checked_at: checkedAt, prefs: { ...prefs }, job: job && { ...job }, router_time: clock,
    }
  }

  function install(selection: UpdateSelection): UpdateStatus {
    const target = selectedRelease(selection, status())
    if (selection.rollback) prefs.enabled = false
    begin(target, Date.now())
    return status()
  }

  function save(next: UpdatePreferences): UpdateStatus {
    if (!/^(?:[01]\d|2[0-3]):[0-5]\d$/.test(next.time)) {
      throw new ApiError(400, 'Expected time in HH:MM format')
    }
    prefs = { ...next }
    return status()
  }

  function check(): UpdateStatus {
    checkedAt = new Date().toISOString()
    return status()
  }

  return { status, check, install, save }
}
