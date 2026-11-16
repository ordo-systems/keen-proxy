<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue'
import { NModal, NCard, NTabs, NTabPane, NInput, NButton, NForm, NFormItem, NAlert, NSpace, useMessage } from 'naive-ui'
import { useI18n } from 'vue-i18n'
import { api } from '../api'
import { store } from '../store'
import type { Config, Connection, LinkPreview } from '../types'
import { slugify, wireGuardToConf } from '../wgconf'
import { connectionErrorKey, DRAFT_CHANGED, editedConnection, importConnections, manualConnection } from '../connectionDraft'

// Edit a local form copy so cancellation leaves the shared draft unchanged.
const props = defineProps<{ show: boolean; edit?: Connection | null }>()
const emit = defineEmits<{ (e: 'update:show', v: boolean): void }>()
const message = useMessage()
const { t } = useI18n()

const tab = ref<'link' | 'wireguard' | 'amneziawg' | 'singbox'>('link')
const name = ref('')
const id = ref('')
const idTouched = ref(false)
const link = ref('')
const wgText = ref('')
const awgText = ref('')
const busy = ref(false)
const sbText = ref('')
const preview = ref<LinkPreview | null>(null)
const previewError = ref('')
const error = ref('')
const revealed = ref(false)
const fallback = ref<string | null>(null)
const isEdit = computed(() => !!props.edit)

let saveGeneration = 0
let committed = false
onUnmounted(() => { saveGeneration++ })
watch(() => props.show, (open) => {
  if (!open) {
    saveGeneration++
    return
  }
  committed = false
  error.value = ''
  revealed.value = false
  preview.value = null
  previewError.value = ''
  const c = props.edit
  name.value = c?.name ?? ''
  id.value = c?.id ?? ''
  idTouched.value = !!c
  fallback.value = c?.fallback ?? null
  link.value = c?.link ?? ''
  wgText.value = c?.wireguard ? wireGuardToConf(c.wireguard) : ''
  awgText.value = c?.amneziawg ?? ''
  sbText.value = c?.outbound || c?.endpoint
    ? JSON.stringify({ [c.outbound ? 'outbound' : 'endpoint']: c.outbound ?? c.endpoint }, null, 2)
    : ''
  tab.value = c?.type === 'amneziawg' ? 'amneziawg' : c?.type === 'wireguard' ? 'wireguard' : c?.type === 'singbox' ? 'singbox' : 'link'
  if (link.value) checkLink()
})

watch(name, (v) => {
  if (!idTouched.value) id.value = slugify(v)
})

let seq = 0
// Ignore older preview responses after a newer request has started.
async function checkLink() {
  const my = ++seq
  preview.value = null
  previewError.value = ''
  if (!link.value.trim()) return
  try {
    const p = await api.parseLink(link.value)
    if (my !== seq) return
    preview.value = p
    if (!name.value && p.name) name.value = p.name
  } catch (e) {
    if (my === seq) previewError.value = (e as Error).message
  }
}

function build(): Connection {
  const base: Pick<Connection, 'id' | 'name' | 'fallback'> = { id: id.value.trim(), name: name.value.trim() || id.value.trim() }
  if (fallback.value) base.fallback = fallback.value
  if (tab.value === 'link') {
    const l = link.value.trim()
    return { ...base, type: 'link', link: l }
  }
  if (tab.value === 'amneziawg')
    return { ...manualConnection({ protocol: 'amneziawg', id: base.id, name: base.name, amneziawg: awgText.value }), ...base }
  if (tab.value === 'wireguard')
    return { ...importConnections(wgText.value, 'profile.conf')[0]!, ...base }
  const obj = JSON.parse(sbText.value || '{}')
  if (obj.outbound) return { ...base, type: 'singbox', outbound: obj.outbound }
  if (obj.endpoint) return { ...base, type: 'singbox', endpoint: obj.endpoint }
  // Infer endpoint versus outbound for an unwrapped raw profile.
  const endpointTypes = ['wireguard', 'tailscale', 'openvpn', 'openconnect']
  return endpointTypes.includes(obj.type) ? { ...base, type: 'singbox', endpoint: obj } : { ...base, type: 'singbox', outbound: obj }
}

// Validate a copied draft before replacing or appending the profile. Apply stays separate.
async function save() {
  if (busy.value || committed) return
  busy.value = true
  error.value = ''
  const generation = ++saveGeneration
  const edit = props.edit
  const config = store.state.config
  // Auto-detected AWG is parsed from wgText; compare that input after validation.
  const text = awgText.value
  const wgSnap = wgText.value
  const idSnap = id.value
  const nameSnap = name.value
  const tabSnap = tab.value
  try {
    const conn = editedConnection(edit, build())
    if (tab.value === 'amneziawg' && awgText.value.trim().startsWith('vpn://')) {
      error.value = t('ui.awgWizardOnly')
      return
    }
    if (!/^[a-z0-9][a-z0-9_-]*$/.test(conn.id)) {
      error.value = t('dialog.errId')
      return
    }
    if (conn.id === 'direct' || conn.id === 'block') {
      error.value = t('dialog.errReserved')
      return
    }
    if (!config) throw new Error(DRAFT_CHANGED)
    const list = config.connections ?? []
    if (list.some((c) => c.id === conn.id && c !== edit)) {
      error.value = t('dialog.errDup', { id: conn.id })
      return
    }
    if (conn.type === 'amneziawg') {
      const cfg = JSON.parse(JSON.stringify(config)) as Config
      const index = edit ? list.indexOf(edit) : -1
      cfg.connections ??= []
      if (edit && index < 0) throw new Error(DRAFT_CHANGED)
      if (index >= 0) cfg.connections.splice(index, 1, conn)
      else cfg.connections.push(conn)
      if (edit && edit.id !== conn.id) renameTarget(edit.id, conn.id, cfg)
      await api.validateConfig(cfg)
      if (
        generation !== saveGeneration || !props.show || props.edit !== edit ||
        store.state.config !== config || awgText.value !== text || wgText.value !== wgSnap ||
        id.value !== idSnap || name.value !== nameSnap || tab.value !== tabSnap
      ) throw new Error(DRAFT_CHANGED)
    }
    if (store.state.config !== config || !props.show || props.edit !== edit) throw new Error(DRAFT_CHANGED)
    const live = config.connections ?? []
    if (edit) {
      const i = live.indexOf(edit)
      if (i < 0) throw new Error(DRAFT_CHANGED)
      if (edit.id !== conn.id) renameTarget(edit.id, conn.id)
      live.splice(i, 1, conn)
    } else live.push(conn)
    committed = true
    message.info(t('dialog.added'))
    emit('update:show', false)
  } catch (e) {
    if (props.show) error.value = t(connectionErrorKey(e))
  } finally {
    busy.value = false
  }
}

// Rewrite routing, fallback, and DNS references within the shared draft.
function renameTarget(from: string, to: string, cfg = store.state.config!) {
  for (const g of cfg.groups ?? []) if (g.target === from) g.target = to
  for (const n of cfg.networks ?? []) if (n.target === from) n.target = to
  for (const c of cfg.clients ?? []) if (c.target === from) c.target = to
  for (const c of cfg.connections ?? []) if (c.fallback === from) c.fallback = to
  if (cfg.dns.connection === from) cfg.dns.connection = to
}
</script>

<template>
  <NModal :show="show" @update:show="emit('update:show', $event)">
    <NCard :title="isEdit ? t('dialog.editTitle') : t('conn.new')" style="width: min(720px, 96vw)" closable @close="emit('update:show', false)">
      <NForm label-placement="top">
        <NSpace :wrap="false" style="width: 100%">
          <NFormItem :label="t('dialog.name')" style="flex: 1">
            <NInput v-model:value="name" :placeholder="t('dialog.namePlaceholder')" />
          </NFormItem>
          <NFormItem :label="t('dialog.id')" style="width: 220px">
            <NInput v-model:value="id" placeholder="fi" @input="idTouched = true" />
          </NFormItem>
        </NSpace>
      </NForm>

      <NButton v-if="isEdit" block @click="revealed=!revealed">{{revealed?t('ui.hide'):t('ui.reveal')}}</NButton>
      <p v-if="isEdit&&!revealed" class="hint">{{t('ui.secret')}}</p>
      <NTabs v-if="!isEdit||revealed" v-model:value="tab" type="segment" animated>
        <NTabPane name="link" :tab="t('conn.link')">
          <NInput
            v-model:value="link"
            type="textarea"
            :autosize="{ minRows: 3, maxRows: 6 }"
            placeholder="vless://… vmess://… trojan://… ss://… hysteria2://… tuic://… anytls://… socks5://… tt://?…"
            class="mono"
            @blur="checkLink"
          />
          <div class="hint">{{ t('dialog.linkHint') }}</div>
          <NAlert v-if="previewError" type="error" :show-icon="false" style="margin-top: 10px">{{ previewError }}</NAlert>
          <div v-if="preview" class="preview">
            <span class="pill ok">{{ preview.protocol }}</span>
            <span class="mono">{{ preview.server }}<template v-if="preview.port">:{{ preview.port }}</template></span>
            <span v-if="preview.tls" class="pill dim">TLS</span>
            <span v-if="preview.addresses" class="mono muted">{{ preview.addresses.join(', ') }}</span>
          </div>
          <div v-if="!preview && link" style="margin-top: 10px">
            <NButton size="small" @click="checkLink">{{ t('dialog.checkLink') }}</NButton>
          </div>
        </NTabPane>
        <NTabPane name="wireguard" tab="WireGuard (.conf)">
          <NInput
            v-model:value="wgText"
            type="textarea"
            :autosize="{ minRows: 10, maxRows: 16 }"
            class="mono"
            placeholder="[Interface]&#10;PrivateKey = …&#10;Address = 10.13.13.2/32&#10;&#10;[Peer]&#10;PublicKey = …&#10;Endpoint = 203.0.113.10:51820&#10;AllowedIPs = 0.0.0.0/0"
          />
          <div class="hint">{{ t('dialog.wgHint') }}</div>
          <div class="hint">{{ t('ui.confPolicy') }}</div>
        </NTabPane>
        <NTabPane name="amneziawg" tab="AmneziaWG (.conf)">
          <NInput
            v-model:value="awgText"
            type="textarea"
            :autosize="{ minRows: 10, maxRows: 16 }"
            :input-props="{ autocomplete: 'off', spellcheck: false }"
            class="mono"
            :placeholder="t('ui.awgProfile')"
          />
          <div class="hint">{{ t('ui.awgHint') }}</div>
          <div class="hint">{{ t('ui.confPolicy') }}</div>
        </NTabPane>
        <NTabPane name="singbox" tab="sing-box JSON">
          <NInput
            v-model:value="sbText"
            type="textarea"
            :autosize="{ minRows: 10, maxRows: 18 }"
            class="mono"
            placeholder='{"type": "shadowtls", "server": "…", "server_port": 443, …}'
          />
          <div class="hint">{{ t('dialog.sbHint') }}</div>
        </NTabPane>
      </NTabs>

      <NAlert v-if="error" type="error" :show-icon="false" style="margin-top: 12px">{{ error }}</NAlert>
      <template #footer>
        <NSpace justify="end">
          <NButton :disabled="busy" @click="emit('update:show', false)">{{ t('common.cancel') }}</NButton>
          <NButton type="primary" :disabled="!id || busy" :loading="busy" @click="save">{{ isEdit ? t('common.save') : t('common.add') }}</NButton>
        </NSpace>
      </template>
    </NCard>
  </NModal>
</template>

<style scoped>
.hint {
  font-size: 12px;
  color: var(--muted);
  margin-top: 8px;
}
.preview {
  display: flex;
  gap: 10px;
  align-items: center;
  flex-wrap: wrap;
  margin-top: 10px;
}
</style>
