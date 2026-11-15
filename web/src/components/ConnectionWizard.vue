<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { onBeforeRouteLeave } from 'vue-router'
import {
  NButton,
  NInput,
  NSelect,
  NAlert,
  useDialog,
  useMessage,
} from 'naive-ui'
import {
  ArrowLeft,
  Check,
  Upload,
  LockKeyhole,
  Server,
  Shield,
  Network,
  FileText,
} from '@lucide/vue'
import { useI18n } from 'vue-i18n'
import { store } from '../store'
import { api } from '../api'
import type { Connection } from '../types'
import {
  classifyConnectionImport,
  connectionErrorKey,
  DRAFT_CHANGED,
  importConnections,
  manualConnection,
  selectAmneziaProfile,
  STALE_IMPORT,
  suggestedConnectionName,
  MAX_CONNECTION_FILE,
  type ManualFields,
} from '../connectionDraft'
import { slugify } from '../wgconf'
import { protocolOf, serverOf } from '../conn'
// Owns unsaved input; only a validated selected profile is added to the shared draft.
const emit = defineEmits<{ close: []; saved: [id: string] }>()
const { t } = useI18n(),
  dialog = useDialog(),
  message = useMessage()
const step = ref(0),
  protocol = ref('vless'),
  method = ref('manual'),
  busy = ref(false),
  error = ref(''),
  fieldError = ref(''),
  advanced = ref(false)
const fields = reactive<ManualFields>({
  id: '',
  name: '',
  protocol: 'vless',
  server: '',
  port: '443',
  uuid: '',
  security: 'reality',
  sni: '',
  publicKey: '',
  shortId: '',
  flow: 'xtls-rprx-vision',
  fingerprint: 'chrome',
  password: '',
  cipher: 'aes-128-gcm',
  username: '',
  version: '5',
  privateKey: '',
  address: '',
  peerKey: '',
  endpoint: '',
  psk: '',
  mtu: '',
  keepalive: '',
  amneziawg: '',
})
const link = ref(''),
  filename = ref(''),
  fileText = ref(''),
  candidates = ref<Connection[]>([]),
  chosen = ref<number | null>(null),
  validated = ref<Connection | null>(null),
  fileInput = ref<HTMLInputElement | null>(null),
  saved = ref(false)
let fileSequence = 0
let alive = true
const protocols = [
  { id: 'wireguard', name: 'WireGuard', hint: '.conf', icon: Network },
  { id: 'amneziawg', name: 'AmneziaWG', hint: '.conf / vpn://', icon: Network },
  { id: 'vless', name: 'VLESS', hint: 'TLS / REALITY', icon: Shield },
  { id: 'shadowsocks', name: 'Shadowsocks', hint: 'AEAD', icon: LockKeyhole },
  { id: 'trojan', name: 'Trojan', hint: 'TLS', icon: LockKeyhole },
  { id: 'hysteria2', name: 'Hysteria2', hint: 'QUIC', icon: Network },
  { id: 'socks', name: 'SOCKS', hint: '5 / 4a', icon: Server },
]
const methods = computed(() =>
  protocol.value === 'raw'
    ? [
        { value: 'file', label: t('ui.byFile') },
        { value: 'json', label: 'JSON' },
      ]
    : protocol.value === 'amneziawg'
      ? [
          { value: 'file', label: t('ui.byFile') },
          { value: 'manual', label: t('ui.awgPaste') },
        ]
    : protocol.value === 'wireguard'
      ? [
          { value: 'conf', label: t('ui.pasteConf') },
          { value: 'file', label: t('ui.byFile') },
          { value: 'manual', label: t('ui.manual') },
        ]
      : [
          { value: 'link', label: t('ui.byLink') },
          { value: 'file', label: t('ui.byFile') },
          { value: 'manual', label: t('ui.manual') },
        ],
)
function selectProtocol(value: string) {
  const changed = protocol.value !== value
  protocol.value = value
  fields.protocol = value
  if (!methods.value.some((m) => m.value === method.value))
    method.value = methods.value[0]!.value
  if (changed) resetImport(true)
  error.value = ''
  validated.value = null
}
let importedName = ''
let previousName = ''
function applyImportedName(name: string) {
  if (!name || (fields.name && fields.name !== importedName)) return
  importedName = name
  fields.name = name
}
function clearImportedName() {
  if (!importedName || fields.name !== importedName) return
  importedName = ''
  fields.name = ''
}
watch(
  () => fields.name,
  (v) => {
    if (v !== importedName) importedName = ''
    if (!fields.id || fields.id === slugify(previousName))
      fields.id = slugify(v)
    previousName = v
  },
)
watch(method, () => {
  candidates.value = []
  chosen.value = null
  filename.value = ''
})
watch(chosen, (index) => {
  if (index === null) return
  applyImportedName(suggestedConnectionName(candidates.value, index, filename.value))
})
watch(
  [fields, link, fileText, chosen, method, protocol],
  () => {
    if (step.value > 1) step.value = 1
    validated.value = null
    fieldError.value = ''
    error.value = ''
  },
  { deep: true },
)
watch(() => fields.amneziawg, () => {
  candidates.value = []
  chosen.value = null
})
const dirty = computed(
  () =>
    !!fields.name ||
    !!link.value ||
    !!fileText.value ||
    !!fields.server ||
    !!fields.privateKey ||
    !!fields.amneziawg,
)
function askLeave(): Promise<boolean> {
  if (saved.value || !dirty.value) return Promise.resolve(true)
  return new Promise((resolve) =>
    dialog.warning({
      title: t('ui.leaveTitle'),
      content: t('ui.leaveText'),
      positiveText: t('ui.leave'),
      negativeText: t('ui.stay'),
      onPositiveClick: () => resolve(true),
      onNegativeClick: () => resolve(false),
      onClose: () => resolve(false),
      onMaskClick: () => resolve(false),
    }),
  )
}
async function close() {
  if (await askLeave()) {
    fileSequence++
    emit('close')
  }
}
onBeforeRouteLeave(async () => await askLeave())
const beforeUnload = (event: BeforeUnloadEvent) => {
  if (dirty.value && !saved.value) {
    event.preventDefault()
    event.returnValue = ''
  }
}
onMounted(() => window.addEventListener('beforeunload', beforeUnload))
onUnmounted(() => {
  alive = false
  fileSequence++
  window.removeEventListener('beforeunload', beforeUnload)
})
function resetFileInput() {
  if (fileInput.value) fileInput.value.value = ''
}
function resetImport(clearText = false) {
  candidates.value = []
  chosen.value = null
  filename.value = ''
  if (clearText) fileText.value = ''
  clearImportedName()
}
function keepError(message: string, seq: number) {
  error.value = message
  void nextTick(() => {
    if (alive && seq === fileSequence) error.value = message
  })
}
// Bound file size and ignore reads superseded by another file or closing the wizard.
async function readFile(file?: File) {
  if (!file) return
  const seq = ++fileSequence
  candidates.value = []
  chosen.value = null
  filename.value = ''
  error.value = ''
  if (file.size > MAX_CONNECTION_FILE) {
    fileText.value = ''
    clearImportedName()
    keepError(t('ui.largeFile'), seq)
    resetFileInput()
    return
  }
  try {
    const text = await file.text()
    if (!alive || seq !== fileSequence) return
    const classified = classifyConnectionImport(text, file.name, protocol.value)
    const profiles = classified.kind === 'vpn'
      ? (await api.importAmnezia(classified.uri)).profiles
      : classified.profiles
    if (!alive || seq !== fileSequence) return
    if (!profiles.length) throw new Error('amnezia_unsupported_profile')
    fileText.value = text
    filename.value = file.name
    candidates.value = profiles
    chosen.value = profiles.length === 1 ? 0 : null
    applyImportedName(suggestedConnectionName(profiles, chosen.value, file.name))
  } catch (cause) {
    if (!alive || seq !== fileSequence) return
    candidates.value = []
    chosen.value = null
    filename.value = ''
    fileText.value = ''
    clearImportedName()
    keepError(t(connectionErrorKey(cause, 'ui.fileError')), seq)
  }
  if (seq === fileSequence) resetFileInput()
}
function drop(event: DragEvent) {
  event.preventDefault()
  void readFile(event.dataTransfer?.files[0])
}
// Field metadata controls localized labels and concealed credential inputs.
interface FormField {
  key: string
  label: string
  secret?: boolean
}
const inputFields = computed<FormField[]>(() => {
  const common: FormField[] = [
    { key: 'name', label: t('dialog.name') },
    { key: 'id', label: t('dialog.id') },
  ]
  if (method.value !== 'manual') return common
  if (protocol.value === 'amneziawg') return common
  if (protocol.value === 'wireguard')
    return [
      ...common,
      { key: 'privateKey', label: t('ui.privateKey'), secret: true },
      { key: 'address', label: t('ui.address') },
      { key: 'endpoint', label: t('ui.endpoint') },
      { key: 'peerKey', label: t('ui.peerKey') },
    ]
  const main = [
    ...common,
    { key: 'server', label: t('ui.server') },
    { key: 'port', label: t('ui.port') },
  ]
  if (protocol.value === 'vless')
    main.push({
      key: 'uuid',
      label: 'UUID',
      secret: true,
    } as (typeof main)[number])
  if (['trojan', 'hysteria2', 'shadowsocks'].includes(protocol.value))
    main.push({
      key: 'password',
      label: t('ui.password'),
      secret: true,
    } as (typeof main)[number])
  if (protocol.value === 'socks')
    main.push({ key: 'username', label: t('ui.username') }, {
      key: 'password',
      label: t('ui.password'),
      secret: true,
    } as (typeof main)[number])
  return main as { key: string; label: string; secret?: boolean }[]
})
const hasTLS = computed(
  () =>
    method.value === 'manual' &&
    ['vless', 'trojan', 'hysteria2'].includes(protocol.value),
)
const advancedFields = computed<FormField[]>(() =>
  protocol.value === 'wireguard'
    ? [
        { key: 'psk', label: 'Preshared key', secret: true },
        { key: 'mtu', label: 'MTU' },
        { key: 'keepalive', label: 'Keepalive' },
      ]
    : protocol.value === 'vless'
      ? [
          { key: 'flow', label: 'Flow' },
          { key: 'fingerprint', label: 'Fingerprint' },
        ]
      : [],
)
const profileOptions = computed(() =>
  candidates.value.map((c, i) => ({
    label: `${c.name || protocolOf(c)} · ${serverOf(c).host || i + 1}`,
    value: i,
  })),
)
function validateIdentity(c: Connection) {
  if (!/^[a-z0-9][a-z0-9_-]*$/.test(c.id)) throw new Error('id')
  if (
    ['direct', 'block'].includes(c.id) ||
    (store.state.config?.connections ?? []).some((x) => x.id === c.id)
  )
    throw new Error('duplicate')
}
// Decode previews only; credentials enter the shared draft after explicit review.
async function pastedAmnezia(): Promise<Connection> {
  const uri = fields.amneziawg!.trim()
  const classified = classifyConnectionImport(uri, 'profile.vpn', protocol.value)
  if (classified.kind !== 'vpn') throw new Error('amnezia_invalid_profile')
  const seq = ++fileSequence
  const { profiles } = await api.importAmnezia(classified.uri)
  if (!alive || seq !== fileSequence || fields.amneziawg!.trim() !== uri) throw new Error(STALE_IMPORT)
  if (!profiles.length) throw new Error('amnezia_unsupported_profile')
  candidates.value = profiles
  const selected = selectAmneziaProfile(profiles, chosen.value)
  applyImportedName(suggestedConnectionName(profiles, chosen.value))
  return selected
}

function report(cause: unknown, fallback = 'ui.invalid') {
  const key = cause instanceof Error ? cause.message : ''
  fieldError.value = key
  error.value = key === 'duplicate' ? t('ui.duplicate') : t(connectionErrorKey(cause, fallback))
}

// Validate the candidate in a copied full config without saving or starting the engine.
async function build(): Promise<Connection> {
  let candidate: Connection
  if (method.value === 'manual' && protocol.value === 'amneziawg' && fields.amneziawg?.trim().startsWith('vpn://'))
    candidate = await pastedAmnezia()
  else if (method.value === 'manual') candidate = manualConnection(fields)
  else if (method.value === 'link') {
    await api.parseLink(link.value.trim())
    candidate = importConnections(link.value, 'profile.txt')[0]!
  } else if (method.value === 'conf') {
    candidate = importConnections(fileText.value, 'profile.conf')[0]!
  } else if (method.value === 'json') {
    const parsed = importConnections(fileText.value, 'profile.json')
    if (parsed.length !== 1) throw new Error('file')
    candidate = parsed[0]!
  } else {
    candidate = selectAmneziaProfile(candidates.value, chosen.value)
  }
  candidate = {
    ...candidate,
    id: fields.id!.trim(),
    name: fields.name!.trim() || fields.id!.trim(),
  }
  validateIdentity(candidate)
  const config = store.state.config
  if (!config) throw new Error(DRAFT_CHANGED)
  const seq = fileSequence
  const cfg = JSON.parse(JSON.stringify(config))
  cfg.connections ??= []
  cfg.connections.push(candidate)
  await api.validateConfig(cfg)
  if (!alive) throw new Error(STALE_IMPORT)
  if (seq !== fileSequence || store.state.config !== config) throw new Error(DRAFT_CHANGED)
  return candidate
}
async function validate() {
  if (busy.value) return
  busy.value = true
  error.value = ''
  fieldError.value = ''
  try {
    const c = await build()
    if (!alive) return
    validated.value = c
    step.value = 2
  } catch (e) {
    if (!alive || (e as Error).message === STALE_IMPORT) return
    if ((e as Error).message === DRAFT_CHANGED) {
      validated.value = null
      step.value = 1
      error.value = t('ui.configChanged')
      return
    }
    report(e)
  } finally {
    busy.value = false
  }
}
// Revalidate against the current draft before adding the profile; Apply remains separate.
async function save() {
  if (busy.value || saved.value) return
  if (!validated.value) {
    error.value = t('ui.configChanged')
    step.value = 1
    return
  }
  busy.value = true
  try {
    const c = await build()
    if (!alive) return
    store.state.config!.connections!.push(c)
    saved.value = true
    message.info(t('ui.afterApply'))
    emit('saved', c.id)
  } catch (cause) {
    if (!alive || (cause as Error).message === STALE_IMPORT) return
    if ((cause as Error).message === DRAFT_CHANGED) {
      validated.value = null
      step.value = 1
      error.value = t('ui.configChanged')
      return
    }
    report(cause)
  } finally {
    busy.value = false
  }
}
</script>
<template>
  <div class="wizard">
    <NButton text :disabled="busy" @click="close"
      ><template #icon><ArrowLeft :size="18" /></template
      >{{ t('nav.connections') }}</NButton
    >
    <div class="page-head">
      <div>
        <h1>{{ t('ui.newConnection') }}</h1>
        <p>{{ t('ui.afterApply') }}</p>
      </div>
    </div>
    <ol class="steps">
      <li
        v-for="(label, i) in [
          t('ui.typeMethod'),
          t('ui.parameters'),
          t('ui.review'),
        ]"
        :key="i"
        :class="{ active: step === i, complete: step > i }"
      >
        <span
          ><Check v-if="step > i" :size="18" /><template v-else>{{
            i + 1
          }}</template></span
        >{{ label }}
      </li>
    </ol>
    <NAlert v-if="error" type="error" style="margin-bottom: 20px" role="alert"
      >{{ error
      }}<span
        v-if="fieldError && inputFields.some((f) => f.key === fieldError)"
      >
        · {{ inputFields.find((f) => f.key === fieldError)?.label }}</span
      ></NAlert
    >
    <div v-if="step === 0" class="split-view">
      <section>
        <h2>{{ t('ui.typeMethod') }}</h2>
        <div class="protocols">
          <button
            v-for="p in protocols"
            :key="p.id"
            :class="{ selected: protocol === p.id }"
            :aria-pressed="protocol === p.id"
            @click="selectProtocol(p.id)"
          >
            <component :is="p.icon" :size="28" /><span
              ><b>{{ p.name }}</b
              ><small>{{ p.hint }}</small></span
            >
          </button>
        </div>
        <NButton text style="margin-top: 24px" @click="selectProtocol('raw')">{{
          t('ui.moreProtocols')
        }}</NButton>
      </section>
      <aside class="detail-pane">
        <h2>
          {{ t('ui.method') }}
          {{
            protocol === 'raw'
              ? 'sing-box'
              : protocols.find((p) => p.id === protocol)?.name
          }}
        </h2>
        <label v-for="m in methods" :key="m.value" class="method"
          ><input
            v-model="method"
            type="radio"
            :value="m.value"
            name="connection-method"
          />{{ m.label }}</label
        ><NButton type="primary" size="large" @click="step = 1">{{
          t('ui.next')
        }}</NButton>
        <p class="muted">{{ t('ui.afterApply') }}</p>
      </aside>
    </div>
    <div v-else-if="step === 1" class="split-view">
      <section>
        <h2>
          {{
            protocol === 'raw'
              ? 'sing-box'
              : protocols.find((p) => p.id === protocol)?.name
          }}
          · {{ methods.find((m) => m.value === method)?.label }}
        </h2>
        <div
          v-if="method === 'file'"
          class="dropzone"
          @dragover.prevent
          @drop="drop"
        >
          <Upload :size="32" /><b>{{ filename || t('ui.selectFile') }}</b>
          <p>{{ t('ui.fileHint') }}</p>
          <NButton @click="fileInput?.click()">{{
            filename ? t('ui.replaceFile') : t('ui.byFile')
          }}</NButton
          ><input
            ref="fileInput"
            type="file"
            accept=".conf,.txt,.json,.vpn"
            hidden
            @change="readFile(($event.target as HTMLInputElement).files?.[0])"
          />
        </div>
        <NSelect
          v-if="candidates.length > 1 && (method === 'file' || (method === 'manual' && protocol === 'amneziawg'))"
          v-model:value="chosen"
          :options="profileOptions"
          :placeholder="t('ui.pickProfile')"
          :aria-label="t('ui.pickProfile')"
          style="margin: 16px 0"
        />
        <label v-if="method === 'link'" class="field"
          ><span>{{ t('ui.byLink') }}</span
          ><NInput
            v-model:value="link"
            type="password"
            show-password-on="click"
            :input-props="{ autocomplete: 'off', spellcheck: false }"
            placeholder="vless://…"
        /></label>
        <label v-if="method === 'json'" class="field"
          ><span>sing-box JSON</span
          ><NInput
            v-model:value="fileText"
            type="textarea"
            :autosize="{ minRows: 6, maxRows: 12 }"
            :input-props="{ autocomplete: 'off', spellcheck: false }"
        /></label>
        <label v-if="method === 'conf' || (method === 'manual' && protocol === 'amneziawg')" class="field">
          <span>{{ protocol === 'amneziawg' ? t('ui.awgImport') : t('ui.pasteConf') }}</span>
          <NInput
            v-if="protocol === 'amneziawg'"
            v-model:value="fields.amneziawg"
            type="textarea"
            :autosize="{ minRows: 10, maxRows: 18 }"
            :input-props="{ autocomplete: 'off', spellcheck: false }"
          />
          <NInput
            v-else
            v-model:value="fileText"
            type="textarea"
            :autosize="{ minRows: 10, maxRows: 18 }"
            :input-props="{ autocomplete: 'off', spellcheck: false }"
          />
        </label>
        <p v-if="protocol === 'amneziawg'" class="muted">{{ t('ui.awgHint') }}</p>
        <p v-if="protocol === 'wireguard' || protocol === 'amneziawg'" class="muted">{{ t('ui.confPolicy') }}</p>
        <div class="form-grid">
          <label v-for="f in inputFields" :key="f.key" class="field"
            ><span>{{ f.label }}</span
            ><NInput
              v-model:value="fields[f.key]"
              :type="f.secret ? 'password' : 'text'"
              :show-password-on="f.secret ? 'click' : undefined"
              :status="fieldError === f.key ? 'error' : undefined"
              :input-props="{ autocomplete: 'off', spellcheck: false }"
          /></label>
          <label
            v-if="method === 'manual' && protocol === 'vless'"
            class="field"
            ><span>{{ t('ui.security') }}</span
            ><NSelect
              v-model:value="fields.security"
              :options="[
                { value: 'reality', label: 'REALITY' },
                { value: 'tls', label: 'TLS' },
                { value: 'none', label: 'None' },
              ]"
          /></label>
          <label
            v-if="
              hasTLS && (protocol !== 'vless' || fields.security !== 'none')
            "
            class="field"
            ><span>SNI</span><NInput v-model:value="fields.sni"
          /></label>
          <template
            v-if="
              method === 'manual' &&
              protocol === 'vless' &&
              fields.security === 'reality'
            "
            ><label class="field"
              ><span>{{ t('ui.publicKey') }}</span
              ><NInput
                v-model:value="fields.publicKey"
                :status="
                  fieldError === 'publicKey' ? 'error' : undefined
                " /></label
            ><label class="field"
              ><span>Short ID</span
              ><NInput v-model:value="fields.shortId" /></label
          ></template>
          <label
            v-if="method === 'manual' && protocol === 'shadowsocks'"
            class="field"
            ><span>{{ t('ui.cipher') }}</span
            ><NSelect
              v-model:value="fields.cipher"
              :options="
                [
                  'aes-128-gcm',
                  'aes-256-gcm',
                  'chacha20-ietf-poly1305',
                  '2022-blake3-aes-128-gcm',
                  '2022-blake3-aes-256-gcm',
                  '2022-blake3-chacha20-poly1305',
                ].map((value) => ({ value, label: value }))
              "
          /></label>
          <label
            v-if="method === 'manual' && protocol === 'socks'"
            class="field"
            ><span>SOCKS</span
            ><NSelect
              v-model:value="fields.version"
              :options="
                ['5', '4', '4a'].map((value) => ({ value, label: value }))
              "
          /></label>
        </div>
        <template v-if="advancedFields.length && method === 'manual'"
          ><NButton text @click="advanced = !advanced">{{
            t('ui.advanced')
          }}</NButton>
          <div v-if="advanced" class="form-grid">
            <label v-for="f in advancedFields" :key="f.key" class="field"
              ><span>{{ f.label }}</span
              ><NInput
                v-model:value="fields[f.key]"
                :type="f.secret ? 'password' : 'text'"
                show-password-on="click"
            /></label></div
        ></template>
        <p v-if="protocol === 'socks'" class="muted">{{ t('ui.socksNote') }}</p>
      </section>
      <aside class="detail-pane">
        <h2>{{ t('ui.fields') }}</h2>
        <p class="muted">{{ t('ui.protected') }}</p>
        <p>{{ t('ui.connectivityLater') }}</p>
        <p v-if="method === 'file' || method === 'json'" class="muted">
          {{ t('ui.importOnly') }}
        </p>
      </aside>
      <div class="wizard-actions">
        <NButton :disabled="busy" @click="step = 0">{{ t('ui.back') }}</NButton
        ><NButton
          type="primary"
          :loading="busy"
          :disabled="!fields.id || busy"
          @click="validate"
          >{{ t('ui.formatCheck') }}</NButton
        >
      </div>
    </div>
    <div v-else-if="validated" class="split-view">
      <section>
        <h2>{{ t('ui.review') }}</h2>
        <div v-if="filename" class="data-row">
          <FileText :size="24" /><b>{{ filename }}</b
          ><span>{{ t('ui.fileParsed') }}</span>
        </div>
        <div class="data-row">
          <span>{{ t('dialog.name') }}</span
          ><b>{{ validated.name }}</b>
        </div>
        <div class="data-row">
          <span>{{ t('ui.typeMethod') }}</span
          ><b>{{ protocolOf(validated) }}</b>
        </div>
        <div v-if="serverOf(validated).host || serverOf(validated).port" class="data-row">
          <span>{{ t('ui.server') }}</span
          ><b>{{ [serverOf(validated).host, serverOf(validated).port].filter(Boolean).join(':') }}</b>
        </div>
        <div v-if="validated.wireguard" class="data-row">
          <span>{{ t('ui.address') }}</span
          ><b>{{ validated.wireguard.address.join(', ') }}</b>
        </div>
        <div class="data-row">
          <LockKeyhole :size="20" /><span>{{ t('ui.protected') }}</span>
        </div>
      </section>
      <aside class="detail-pane">
        <p class="pill ok">{{ t('ui.formatOK') }}</p>
        <p class="muted">{{ t('ui.connectivityLater') }}</p>
        <p v-if="validated.type === 'amneziawg'" class="muted">{{ t('ui.confPolicy') }}</p>
        <p v-if="method === 'file' || method === 'json'">
          {{ t('ui.importOnly') }}
        </p>
        <NButton type="primary" size="large" :loading="busy" :disabled="busy" @click="save">{{
          t('ui.saveDraft')
        }}</NButton>
      </aside>
      <div class="wizard-actions">
        <NButton :disabled="busy" @click="step = 1">{{ t('ui.back') }}</NButton>
      </div>
    </div>
  </div>
</template>
<style scoped>
.wizard {
  max-width: 1400px;
}
.page-head {
  margin-top: 12px;
}
.steps {
  display: flex;
  list-style: none;
  padding: 0 0 20px;
  margin: 20px 0;
  border-bottom: 1px solid var(--line);
  gap: 40px;
}
.steps li {
  display: flex;
  align-items: center;
  gap: 12px;
  flex: 1;
  color: var(--muted);
}
.steps li span {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  border: 1px solid var(--line);
  border-radius: 50%;
  flex: none;
}
.steps li.active {
  color: var(--accent);
  font-weight: 650;
}
.steps li.active span {
  background: var(--accent);
  color: var(--page);
}
.steps li.complete {
  color: var(--accent);
}
h2 {
  font-size: 24px;
  margin: 0 0 16px;
}
.protocols {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}
.protocols button {
  display: flex;
  align-items: center;
  gap: 22px;
  padding: 24px;
  min-height: 112px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: transparent;
  color: var(--text);
  text-align: left;
  cursor: pointer;
}
.protocols button.selected {
  border: 2px solid var(--accent);
  background: color-mix(in srgb, var(--accent) 9%, transparent);
}
.protocols b {
  font-size: 22px;
}
.protocols small {
  display: block;
  color: var(--muted);
  margin-top: 6px;
}
.method {
  display: flex;
  gap: 16px;
  padding: 18px 0;
  border-bottom: 1px solid var(--line);
  margin-bottom: 12px;
  cursor: pointer;
}
.method input {
  accent-color: var(--accent);
  width: 20px;
  height: 20px;
}
.detail-pane > .n-button {
  margin-top: 28px;
}
.field {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin-bottom: 16px;
  min-width: 0;
}
.field > span {
  color: var(--muted);
}
.form-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 0 24px;
  margin-top: 20px;
}
.wizard-actions {
  grid-column: 1/-1;
  display: flex;
  justify-content: space-between;
  padding-top: 20px;
  border-top: 1px solid var(--line);
  gap: 16px;
}
.dropzone {
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  gap: 12px;
  border: 1px dashed var(--line);
  border-radius: 8px;
  padding: 28px 20px;
}
.dropzone p {
  margin: 0;
  color: var(--muted);
}
.dropzone b {
  overflow-wrap: anywhere;
  max-width: 100%;
}
@media (max-width: 720px) {
  .steps {
    gap: 8px;
    margin: 20px 0;
    padding-bottom: 20px;
  }
  .steps li {
    font-size: 12px;
    gap: 6px;
    align-items: flex-start;
    flex-direction: column;
  }
  .steps li span {
    width: 28px;
    height: 28px;
  }
  .protocols {
    gap: 10px;
  }
  .protocols button {
    padding: 16px 12px;
    gap: 12px;
    min-height: 105px;
    flex-wrap: wrap;
  }
  .protocols b {
    font-size: 18px;
  }
  .form-grid {
    grid-template-columns: 1fr;
  }
  .wizard-actions {
    position: sticky;
    bottom: 0;
    background: var(--page);
    padding: 14px 0;
  }
  .wizard-actions .n-button {
    min-height: 44px;
  }
}
</style>
