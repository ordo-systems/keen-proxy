import assert from 'node:assert/strict'
import { resolveObjectURL } from 'node:buffer'
import { test } from 'node:test'
import { api, setUnauthorizedHandler } from '../src/demo/api.ts'
import release from '../src/demo/release.json' with { type: 'json' }
import { demoRevision, demoVersion } from '../src/demo/updates.ts'
import { manualConnection } from '../src/connectionDraft.ts'
import { routerInterfaceName } from '../src/routerInterface.ts'
import { snapshotBundledPreset, stageBundledPreset } from '../src/presetDraft.ts'
import type { Connection } from '../src/types.ts'

async function readConfigExport(redacted = false) {
  const url = api.configExportURL(redacted)
  try {
    const blob = resolveObjectURL(url)!
    const contents = await blob.text()
    if (!redacted) return JSON.parse(contents)
    const heading = '# SUPPORT ONLY — secrets removed; not a restorable backup\n'
    assert.equal(blob.type, 'application/yaml')
    assert.ok(contents.startsWith(heading))
    return JSON.parse(contents.slice(heading.length))
  } finally {
    URL.revokeObjectURL(url)
  }
}

test('demo API drives the UI without HTTP or EventSource operations', async () => {
  const original = globalThis.fetch
  globalThis.fetch = async () => { throw new Error('Unexpected network request') }
  try {
    setUnauthorizedHandler(() => assert.fail('Demo must not request login'))
    assert.equal((await api.session()).authed, true)
    assert.equal((await api.login('synthetic')).ok, true)
    assert.equal((await api.logout()).ok, true)
    assert.equal((await api.catalog()).presets[0]!.id, 'sample-work')
    assert.equal((await api.features()).demo, true)
    assert.equal((await api.refreshFilters()).demo, true)
    assert.equal((await api.updates()).demo, true)
    const config = await api.config()
    assert.equal((await api.checkDNS(config)).demo, true)
    assert.equal((await api.validateConfig(config)).ok, true)
    assert.equal((await api.devices()).length, 4)
    const status = await api.status()
    assert.equal(status.connections, 3)
    assert.equal(status.build?.version, demoVersion())
    assert.equal(status.build?.version, (await api.updates()).current)
    assert.equal(status.build?.revision, demoRevision(status.build?.version ?? ''))
    assert.doesNotMatch(status.build?.revision ?? '', /^[a-f0-9]{7}$/)
    await assert.rejects(api.importAmnezia('vpn://secret'), /amnezia_demo_unavailable/)
    assert.ok((await api.stats()).outbounds!.length)
    assert.equal((await api.hosts('fi', 'nonexistent')).total, 0)
    assert.equal((await api.hosts('fi', 'video', 1)).hosts.length, 1)
    assert.equal((await api.hosts('unknown')).total, 0)
    assert.equal((await api.diagnosticCheck('fi')).demo, true)
    assert.deepEqual(await api.tproxyReadiness(), { state: 'ready' })
    await assert.rejects(api.retryTProxy(), /router only/)
    assert.equal((await api.domains()).demo, true)
    assert.equal((await api.resolveDomains(['example.com'])).records.length, 1)
    assert.ok((await api.journal('routes', {})).entries.length > 1)
    const stream = api.journalStream('routes')
    assert.equal(stream.onmessage, null)
    stream.close()
    const snapshot = snapshotBundledPreset(config, 'sample-work')
    const pending = api.previewPreset(config, 'sample-work', 'nl')
    config.local_presets = [{ id: 'custom-pending', name: 'Added while previewing', entries: ['new.test'] }]
    const result = await pending
    const plan = { snapshot, result }
    assert.equal(stageBundledPreset(plan, config, false), undefined)
    assert.equal(config.local_presets[0]!.entries[0], 'new.test')
    delete config.local_presets
    assert.equal(stageBundledPreset(plan, config, true), undefined)
    assert.equal(stageBundledPreset(plan, structuredClone(config), false), undefined)
    const staged = stageBundledPreset(plan, config, false)
    assert.ok(staged)
    await api.saveConfig(staged)
    assert.deepEqual(await api.previousConfig(), config)
    assert.equal((await api.config()).groups!.length, config.groups!.length + 1)
    await api.saveConfig(config)
    await assert.rejects(api.importYAML('synthetic'), /browser demo/)
    const link = await api.parseLink('vless://example@vpn.example.com:8443?security=tls#Example')
    assert.equal(link.server, 'vpn.example.com')
    assert.equal(link.name, 'Example')
    assert.equal(link.protocol, 'vless')
    assert.equal(link.type, 'link')
    assert.equal(link.port, 8443)
    assert.equal(link.tls, true)
    const trustTunnel = await api.parseLink('tt://?EXPORTED_TLV')
    assert.equal(trustTunnel.type, 'link')
    assert.equal(trustTunnel.protocol, 'trusttunnel')
    assert.equal(trustTunnel.tls, true)
    assert.equal((await api.parseLink('vless://example@vpn.example.com:443?security=none')).tls, false)
    assert.equal((await api.parseLink('vless://vpn.example.com')).name, 'Demo connection')
    assert.equal((await api.parseLink('vless://vpn.example.com')).port, 443)
    for (const url of [api.configExportURL(), api.configExportURL(true), api.journalExportURL('system', '')]) {
      assert.ok(url.startsWith('blob:'))
      URL.revokeObjectURL(url)
    }
  } finally { globalThis.fetch = original }
})

test('demo validates then applies an interface profile without altering raw profiles', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('Unexpected network request') })
  const original = await api.config()
  t.after(async () => { await api.saveConfig(original) })
  const devices = await api.interfaces()
  assert.ok(devices.some(device => device.name === original.lan.interface && device.up))
  assert.ok(devices.some(device => device.name === original.lan.wan && device.label === 'Internet' && device.up))
  const labeled = devices.find(device => device.name === 'nwg0')!
  assert.equal(routerInterfaceName(labeled), 'Home WireGuard')
  const unlabeled = devices.find(device => device.name === 'wg0')!
  assert.deepEqual(unlabeled, { name: 'wg0', up: false })
  assert.equal(routerInterfaceName(unlabeled), 'wg0')

  const draft = structuredClone(original)
  const connection = manualConnection({
    protocol: 'router-interface', id: 'home-wg', name: routerInterfaceName(labeled), routerDevice: labeled.name,
  })
  const raw = {
    id: 'raw-options', name: 'Raw direct', type: 'singbox' as const,
    outbound: { type: 'direct', bind_interface: original.lan.wan, routing_mark: 7 },
  }
  draft.connections = [...(draft.connections ?? []), raw, connection]
  assert.equal((await api.validateConfig(draft)).ok, true)
  assert.deepEqual(await api.config(), original)
  await api.saveConfig(draft)
  assert.deepEqual((await api.config()).connections, draft.connections)
  assert.equal((await api.diagnosticCheck(connection.id)).demo, true)
})

test('demo DNS Check previews draft DNS but only uses applied connection profiles', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('Unexpected network request') })
  const original = await api.config()
  t.after(async () => { await api.saveConfig(original) })
  const draft = await api.config()
  draft.dns.upstreams = ['https://Draft-Resolver.example/dns-query']
  draft.dns.route = 'connection'
  draft.dns.connection = 'fi'
  draft.dns.failure = 'strict'
  const local = { ...draft, dns: { ...draft.dns, route: 'direct' as const, connection: undefined, failure: undefined, upstreams: ['udp://[fe80::53%25br0]:53'] } }
  assert.equal((await api.checkDNS(local)).route, 'simulated: direct')
  local.dns.upstreams = ['udp://[fe80::53%25br%ZZ]:53']
  await assert.rejects(api.checkDNS(local), /expected a DNS server address/)
  await assert.rejects(api.checkDNS(draft), /dns\.bootstrap: IP required for Draft-Resolver\.example/)
  draft.dns.bootstrap = { 'Draft-Resolver.example': '192.0.2.53' }
  draft.dns.upstreams = ['192.0.2.53']
  await assert.rejects(api.checkDNS(draft), /requires DoH or DoT/)
  draft.dns.upstreams = ['https://Draft-Resolver.example/dns-query']
  const wg = draft.connections!.find(connection => connection.id === 'fi')!.wireguard!
  const { endpoint, ...otherPeerFields } = wg.peer
  wg.peer = { ...otherPeerFields, endpoint }
  wg.mtu = 0
  assert.equal((await api.checkDNS(draft)).route, 'simulated: fi')
  assert.equal(wg.peer.allowed_ips, undefined)
  wg.peer.allowed_ips = []
  assert.equal((await api.checkDNS(draft)).route, 'simulated: fi')
  const internationalHost = 'dns.\u0440\u0444'
  draft.dns.upstreams = [`https://${internationalHost}/dns-query`]
  draft.dns.bootstrap = { [internationalHost]: '192.0.2.53' }
  assert.equal((await api.checkDNS(draft)).route, 'simulated: fi')

  const applyFirst = /^Error: Apply connection changes first$/
  draft.connections!.reverse()
  await assert.rejects(api.checkDNS(draft), applyFirst)
  draft.connections!.reverse()
  const otherTunnel = draft.connections!.find(connection => connection.id === 'de')!
  const savedLink = otherTunnel.link
  otherTunnel.link = otherTunnel.link!.replace('#DE', '#edited')
  await assert.rejects(api.checkDNS(draft), applyFirst)
  otherTunnel.link = savedLink
  for (const connection of draft.connections!) connection.disabled = true
  await assert.rejects(api.checkDNS(draft), applyFirst)
  draft.dns.route = 'direct'
  assert.equal((await api.checkDNS(draft)).route, 'simulated: direct')
  assert.deepEqual(await api.config(), original)

  await api.saveConfig({ ...draft, dns: original.dns })
  draft.dns.route = 'connection'
  assert.equal((await api.checkDNS(draft)).rcode, 2)
  draft.dns.failure = 'direct'
  assert.equal((await api.checkDNS(draft)).route, 'simulated: direct')
  assert.deepEqual((await api.config()).dns, original.dns)
})

test('demo rejects Apply when an existing DNS tunnel gains an interface fallback', async (t) => {
  const original = await api.config()
  t.after(async () => { await api.saveConfig(original) })
  const config = await api.config()
  config.dns.route = 'connection'
  config.dns.connection = 'fi'
  const saved = await api.saveConfig(config)
  const draft = await api.config()
  const connections = draft.connections!
  connections.find(connection => connection.id === 'fi')!.fallback = 'nl'
  connections.find(connection => connection.id === 'nl')!.fallback = 'home-wg'
  connections.push(manualConnection({
    protocol: 'router-interface', id: 'home-wg', name: 'Home WireGuard', routerDevice: 'nwg0',
  }))
  const error = /dns\.connection: raw type "direct" does not guarantee a tunnel/
  await assert.rejects(api.checkDNS(draft), error)
  await assert.rejects(api.validateConfig(draft), error)
  await assert.rejects(api.saveConfig(draft), error)
  assert.deepEqual(await api.config(), saved)
})

test('demo rejects raw selectors in DNS chains and allows built-in Direct only with direct failure policy', async (t) => {
  const original = await api.config()
  t.after(async () => { await api.saveConfig(original) })
  const draft = await api.config()
  draft.dns.route = 'connection'
  draft.dns.connection = 'fi'
  const tunnel = draft.connections!.find(connection => connection.id === 'fi')!
  draft.connections!.push({
    id: 'selector', name: 'Selector', type: 'singbox',
    outbound: { type: 'selector', outbounds: ['direct'] },
  })
  tunnel.fallback = 'selector'
  draft.dns.failure = 'direct'
  const rawError = /dns\.connection: raw type "selector" does not guarantee a tunnel/
  await assert.rejects(api.checkDNS(draft), rawError)
  await assert.rejects(api.validateConfig(draft), rawError)
  await assert.rejects(api.saveConfig(draft), rawError)

  tunnel.fallback = 'direct'
  for (const failure of [undefined, 'strict'] as const) {
    draft.dns.failure = failure
    const strictError = /dns: strict forbids direct in the connection chain/
    await assert.rejects(api.checkDNS(draft), strictError)
    await assert.rejects(api.validateConfig(draft), strictError)
    await assert.rejects(api.saveConfig(draft), strictError)
  }
  draft.dns.connection = undefined
  const missingError = /dns\.connection: unknown connection ""/
  await assert.rejects(api.checkDNS(draft), missingError)
  await assert.rejects(api.saveConfig(draft), missingError)
  draft.dns.connection = 'fi'
  assert.deepEqual(await api.config(), original)

  draft.dns.failure = 'direct'
  await assert.rejects(api.checkDNS(draft), /Apply connection changes first/)
  assert.equal((await api.validateConfig(draft)).ok, true)
  await api.saveConfig(draft)
  assert.equal((await api.checkDNS(draft)).rcode, 0)
  assert.equal((await api.config()).dns.failure, 'direct')
})

test('demo Apply validates explicit DNS source bypasses without changing the saved config on failure', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('Unexpected network request') })
  const original = await api.config()
  t.after(async () => { await api.saveConfig(original) })
  const draft = await api.config()
  const sources = ['192.168.7.40', '192.0.2.53', '169.254.1.2']
  draft.dns.bypass_sources = sources
  assert.deepEqual(await api.config(), original)
  assert.deepEqual((await api.saveConfig(draft)).dns.bypass_sources, sources)
  assert.deepEqual(await api.previousConfig(), original)
  for (const redacted of [false, true]) {
    const exported = await readConfigExport(redacted)
    assert.deepEqual(exported.dns.bypass_sources, redacted ? undefined : sources)
  }

  for (const invalid of ['', 'resolver.local', '192.0.2.53/32', '::ffff:192.0.2.53',
    '192.0.2.053', '192.0.2.256', ' 192.0.2.53', '0.0.0.0', '127.0.0.1', '224.0.0.1', '255.255.255.255']) {
    const error = /dns\.bypass_sources\[3\]: expected a unicast IPv4 address/
    draft.dns.bypass_sources = [...sources, invalid]
    await assert.rejects(api.validateConfig(draft), error, invalid)
    await assert.rejects(api.saveConfig(draft), error, invalid)
    assert.deepEqual((await api.config()).dns.bypass_sources, sources)
    assert.deepEqual(await api.previousConfig(), original)
  }

  draft.dns.bypass_sources = []
  assert.equal(Object.hasOwn((await api.saveConfig(draft)).dns, 'bypass_sources'), false)
  assert.equal(Object.hasOwn((await api.config()).dns, 'bypass_sources'), false)
  assert.deepEqual((await api.previousConfig()).dns.bypass_sources, sources)
})

test('demo applies local presets without creating routes or exposing them in support exports', async (t) => {
  const original = await api.config()
  t.after(async () => { await api.saveConfig(original) })
  const draft = await api.config()
  draft.local_presets = [{ id: 'private-list', name: 'Internal list', entries: ['lab.example'], disabled_entries: ['lab.example'] }]
  assert.deepEqual(await api.config(), original)
  const applied = await api.saveConfig(draft)
  assert.deepEqual(applied.local_presets, draft.local_presets)
  assert.deepEqual(applied.groups, original.groups)
  for (const redacted of [false, true]) {
    const contents = await readConfigExport(redacted)
    assert.deepEqual(contents.local_presets, redacted ? undefined : draft.local_presets)
  }
})

test('demo support YAML removes protocol payloads and other sensitive fields without altering the backup', async (t) => {
  const original = await api.config()
  t.after(async () => { await api.saveConfig(original) })
  const draft = await api.config()
  const profiles = [
    { id: 'awg-fixture', name: 'AWG fixture', type: 'amneziawg', disabled: true, fallback: 'fi',
      amneziawg: '[Interface]\nPrivateKey = synthetic-awg-private\nHeaderProtectionKey = synthetic-awg-header\n[Peer]\nPresharedKey = synthetic-awg-peer\n' },
    { id: 'wg-fixture', name: 'WG fixture', type: 'wireguard', wireguard: {
      private_key: 'synthetic-wg-private', address: ['192.0.2.2/32'],
      peer: { endpoint: 'wg-fixture.example:51820', public_key: 'synthetic-wg-public', preshared_key: 'synthetic-wg-peer' },
    } },
    { id: 'link-fixture', name: 'Link fixture', type: 'link', link: 'trojan://synthetic-link-password@link-fixture.example:443' },
    { id: 'outbound-fixture', name: 'Outbound fixture', type: 'singbox',
      outbound: { type: 'socks', password: 'synthetic-outbound-password', extra: { secret: 'synthetic-outbound-nested' } } },
    { id: 'endpoint-fixture', name: 'Endpoint fixture', type: 'singbox',
      endpoint: { type: 'wireguard', private_key: 'synthetic-endpoint-private' } },
    { id: 'legacy-fixture', name: 'Legacy fixture', type: 'link', link: 'tt://?synthetic-link-token',
      trusttunnel: { link: 'tt://?synthetic-legacy-token' } },
  ] satisfies (Connection & { trusttunnel?: { link: string } })[]
  draft.connections!.push(...profiles)
  draft.dns.upstreams = ['https://resolver.example/synthetic-dns-token']
  draft.dns.bootstrap = { 'resolver.example': '192.0.2.53' }
  draft.dns.bypass_sources = ['192.0.2.54']
  draft.geoip.url = 'https://geo.example/synthetic-legacy-geo-token'
  draft.geoip.databases.push({ id: 'geo-fixture', url: 'https://geo.example/synthetic-geo-token', enabled: true })
  draft.failover = { url: 'https://health.example/synthetic-health-token', interval: 15, down_after: 60, up_after: 120 }
  draft.filters!.sources.push({ id: 'filter-fixture', name: 'Filter fixture',
    url: 'https://filter.example/synthetic-filter-token', enabled: true, auto_update: false })
  draft.groups![0]!.disabled_entries = ['private-disabled.example']
  draft.local_presets = [{ id: 'secret-preset', name: 'Private list', entries: ['private-preset.example'] }]
  const applied = await api.saveConfig(draft)

  const support = await readConfigExport(true)
  assert.equal(support.redacted, true)
  assert.deepEqual(support.connections, applied.connections!.map(({ id, name, type, disabled, fallback }) => ({
    id, name, type, link: 'REDACTED',
    ...(disabled === undefined ? {} : { disabled }),
    ...(fallback === undefined ? {} : { fallback }),
  })))
  assert.deepEqual(support.dns.upstreams, ['REDACTED'])
  assert.equal(Object.hasOwn(support.dns, 'bypass_sources'), false)
  assert.equal(support.geoip.url, 'REDACTED')
  assert.deepEqual(support.geoip.databases, applied.geoip.databases.map(db => db.url ? { ...db, url: 'REDACTED' } : db))
  assert.deepEqual(support.failover, { ...applied.failover, url: 'REDACTED' })
  assert.deepEqual(support.filters.sources, [
    { ...applied.filters!.sources[0], url: 'REDACTED' },
  ])
  assert.equal(Object.hasOwn(support.groups[0], 'disabled_entries'), false)
  assert.deepEqual(support.groups[0].entries, applied.groups![0]!.entries)
  assert.equal(Object.hasOwn(support, 'local_presets'), false)
  assert.deepEqual(await readConfigExport(), applied)
  assert.deepEqual(await api.config(), applied)
})

test('demo updates, rolls back, and saves a schedule without fetching', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: new Date('2026-11-07T02:00:00Z') })
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('Unexpected network request') })
  const before = await api.checkUpdates()
  assert.equal(before.available, true)
  assert.equal(before.demo, true)
  assert.equal(before.latest, undefined)
  assert.equal(before.current, `v${release.version}`)
  assert.ok(before.previous)
  assert.notEqual(before.previous, before.current)
  assert.equal(before.prefs.enabled, false)
  assert.equal((await api.status()).build?.version, before.current)
  assert.equal((await api.status()).build?.revision, demoRevision(before.current))
  await assert.rejects(api.saveUpdatePreferences({ enabled: true, time: '25:00' }))
  await assert.rejects(api.installUpdate({ rollback: false, target: before.current }))
  await assert.rejects(api.installUpdate({ rollback: true, target: 'v99.0.0' }))
  assert.equal((await api.installUpdate({ rollback: true, target: before.previous })).job?.state, 'running')
  await assert.rejects(api.installUpdate({ rollback: false, target: before.current }))
  t.mock.timers.tick(3000)
  const rolledBack = await api.updates()
  assert.equal(rolledBack.current, before.previous)
  assert.equal(rolledBack.previous, before.current)
  assert.equal(rolledBack.latest, before.current)
  assert.equal(rolledBack.job?.state, 'success')
  assert.equal(rolledBack.prefs.enabled, false)
  assert.equal((await api.status()).build?.version, rolledBack.current)
  assert.equal((await api.status()).build?.revision, demoRevision(rolledBack.current))
  assert.notEqual((await api.status()).build?.revision, demoRevision(before.current))
  assert.equal((await api.installUpdate({ rollback: false, target: rolledBack.latest! })).job?.state, 'running')
  t.mock.timers.tick(3000)
  const upgraded = await api.updates()
  assert.equal(upgraded.current, before.current)
  assert.equal(upgraded.latest, undefined)
  assert.equal((await api.status()).build?.version, upgraded.current)
  await api.installUpdate({ rollback: true, target: before.previous })
  t.mock.timers.tick(3000)
  await api.saveUpdatePreferences({ enabled: true, time: new Date(Date.now()).toISOString().slice(11, 16) })
  assert.equal((await api.updates()).job?.state, 'running')
  t.mock.timers.tick(3000)
  assert.equal((await api.updates()).current, before.current)
})

test('demo journal streams new records and stops after close', async (t) => {
  t.mock.timers.enable({ apis: ['setInterval', 'Date'], now: Date.now() })
  const previous = (await api.journal('routes', {})).entries[0]!
  const stream = api.journalStream('routes')
  t.after(() => stream.close())
  const seen: number[] = []
  stream.onmessage = (event) => seen.push(JSON.parse(event.data).id)
  t.mock.timers.tick(3000)
  assert.equal(seen.length, 1)
  assert.ok(seen[0]! > previous.id)
  stream.close()
  t.mock.timers.tick(6000)
  assert.equal(seen.length, 1)
})
