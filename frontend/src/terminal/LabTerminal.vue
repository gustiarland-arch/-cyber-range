<script setup>
// Terminal ke container lab melalui terminal gateway terisolasi. Tidak pernah membuka shell host.
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import { Power, RotateCw } from 'lucide-vue-next'
import { api } from '@/services/api'
import CrButton from '@/components/ui/CrButton.vue'

const props = defineProps({ labId: { type: [Number, String], required: true }, nodeKey: { type: String, required: true }, label: String })
const emit = defineEmits(['closed', 'opened'])
const el = ref(null)
const state = ref('connecting') // connecting | open | closed | error
const reason = ref('')
const session = ref(null)
let term = null, fit = null, ws = null, ro = null

function wsUrl(path) { return `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}${path}` }

async function connect() {
  state.value = 'connecting'; reason.value = ''
  term?.reset()
  try {
    session.value = await api(`/terminal/labs/${props.labId}/sessions`, { method: 'POST', body: { node_key: props.nodeKey } })
  } catch (e) { state.value = 'error'; reason.value = e.message; return }
  ws = new WebSocket(wsUrl(session.value.ws_path))
  ws.binaryType = 'arraybuffer'
  ws.onopen = () => ws.send(JSON.stringify({ ticket: session.value.ticket, cols: term.cols, rows: term.rows }))
  ws.onmessage = (ev) => {
    if (typeof ev.data === 'string') {
      const m = JSON.parse(ev.data)
      if (m.t === 'ready') { state.value = 'open'; emit('opened', m); term.focus() }
      else if (m.t === 'error') { state.value = 'error'; reason.value = m.message }
      else if (m.t === 'closed') { state.value = 'closed'; reason.value = m.reason }
      return
    }
    term.write(new Uint8Array(ev.data))
  }
  ws.onclose = () => { if (state.value === 'open' || state.value === 'connecting') { state.value = 'closed'; reason.value ||= 'koneksi terputus' } emit('closed', reason.value) }
}

async function disconnect() {
  if (session.value) await api(`/terminal/sessions/${session.value.id}/close`, { method: 'POST' }).catch(() => {})
  ws?.close()
}

onMounted(() => {
  term = new Terminal({ fontFamily: 'JetBrains Mono Variable, ui-monospace, monospace', fontSize: 13, cursorBlink: true, convertEol: false,
    theme: { background: '#080f1c', foreground: '#c9d6e8', cursor: '#22d3ee', selectionBackground: '#258bff55' }, scrollback: 3000 })
  fit = new FitAddon(); term.loadAddon(fit); term.open(el.value); fit.fit()
  term.onData((d) => { if (ws?.readyState === 1 && state.value === 'open') ws.send(JSON.stringify({ t: 'i', d })) })
  term.onResize(({ cols, rows }) => { if (ws?.readyState === 1) ws.send(JSON.stringify({ t: 'r', c: cols, r: rows })) })
  ro = new ResizeObserver(() => { try { fit.fit() } catch { /* hidden */ } }); ro.observe(el.value)
  connect()
})
onBeforeUnmount(() => { ro?.disconnect(); disconnect(); term?.dispose() })
defineExpose({ disconnect })
</script>
<template>
  <div class="flex h-full min-h-0 flex-col" data-test="lab-terminal" :data-state="state">
    <div class="flex items-center gap-2 border-b border-ink-700/60 px-3 py-1.5 text-xs">
      <span :class="['size-2 rounded-full', state === 'open' ? 'bg-ok' : state === 'connecting' ? 'bg-warn animate-pulse' : 'bg-sev-critical']" />
      <span class="font-mono text-ink-200">{{ label || nodeKey }}</span>
      <span class="text-ink-500">{{ state === 'open' ? `sesi #${session?.id} · container ${session?.container}` : state === 'connecting' ? 'menghubungkan…' : reason }}</span>
      <span class="ml-auto text-[10px] text-ink-500" v-if="session?.limits">maks {{ session.limits.max_seconds / 60 }} mnt · idle {{ session.limits.idle_seconds / 60 }} mnt · terekam untuk audit</span>
      <CrButton v-if="state === 'open'" size="sm" variant="ghost" data-test="terminal-close" @click="disconnect"><Power class="size-3.5" /> Tutup</CrButton>
      <CrButton v-else-if="state !== 'connecting'" size="sm" variant="ghost" data-test="terminal-reconnect" @click="connect"><RotateCw class="size-3.5" /> Hubungkan ulang</CrButton>
    </div>
    <div ref="el" class="min-h-0 flex-1 bg-ink-950 p-1.5" />
  </div>
</template>
