<script setup>
import { computed, markRaw, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { onBeforeRouteLeave, useRoute, useRouter } from 'vue-router'
import { VueFlow, useVueFlow, MarkerType } from '@vue-flow/core'
import { Background } from '@vue-flow/background'
import { Controls } from '@vue-flow/controls'
import { MiniMap } from '@vue-flow/minimap'
import '@vue-flow/core/dist/style.css'
import '@vue-flow/core/dist/theme-default.css'
import '@vue-flow/controls/dist/style.css'
import '@vue-flow/minimap/dist/style.css'
import { ArrowLeft, Boxes, CheckCircle2, Download, Eye, Maximize, Redo2, Save, ShieldCheck, SquareDashed, Undo2 } from 'lucide-vue-next'
import { api, download } from '@/services/api'
import { useUiStore } from '@/stores/ui'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrModal from '@/components/ui/CrModal.vue'
import CrState from '@/components/ui/CrState.vue'
import DeviceNode from '@/network-editor/DeviceNode.vue'
import ZoneNode from '@/network-editor/ZoneNode.vue'
import PropertiesPanel from '@/network-editor/PropertiesPanel.vue'
import { DEVICES, ZONE_COLORS, clone, newKey, zoneAt } from '@/network-editor/catalog'
import { useHistory } from '@/network-editor/useHistory'

const route = useRoute()
const router = useRouter()
const ui = useUiStore()
const FLOW_ID = 'topology-editor'
const { screenToFlowCoordinate, fitView, getSelectedNodes, getSelectedEdges, setCenter, findNode } = useVueFlow(FLOW_ID)
const nodeTypes = { device: markRaw(DeviceNode), zone: markRaw(ZoneNode) }

const net = ref(null)         // server state (summary + version)
const doc = ref(null)         // editable draft
const saved = ref('')         // JSON of last saved doc
const issues = ref([])
const meta = ref({ node_types: [], zone_kinds: [], link_kinds: [] })
const err = ref(null)
const saving = ref(false)
const selection = ref(null)   // { kind: 'node'|'link'|'zone', key }
const menu = ref(null)        // context menu {x, y, items}
const leaveTo = ref(null)
const history = useHistory()
const editable = computed(() => !!net.value?.can_edit)
const dirty = computed(() => doc.value && JSON.stringify(doc.value) !== saved.value)

async function load() {
  err.value = null
  try {
    const [m, n] = await Promise.all([api('/networks/meta'), api(`/networks/${route.params.id}`)])
    meta.value = m
    applyServer(n)
    await nextTick()
    setTimeout(() => fitView({ padding: 0.15 }), 50)
  } catch (e) { err.value = e }
}
function applyServer(n) {
  net.value = n
  doc.value = clone(n.topology)
  saved.value = JSON.stringify(doc.value)
  issues.value = n.issues
  history.reset(doc.value)
}
onMounted(load)

// ---- history + live validation (debounced)
let hTimer, vTimer
watch(doc, () => {
  clearTimeout(hTimer); clearTimeout(vTimer)
  hTimer = setTimeout(() => history.commit(doc.value), 300)
  vTimer = setTimeout(revalidate, 700)
}, { deep: true })
async function revalidate() {
  if (!doc.value) return
  try { issues.value = await api('/networks/validate', { method: 'POST', body: doc.value }) }
  catch (e) { if (e.code === 'validation_error') issues.value = (e.details || []).map((d) => ({ severity: 'error', code: 'schema', message: `${d.loc.slice(1).join('.')}: ${d.msg}` })) }
}
function undo() { const s = history.undo(); if (s) { doc.value = s; clearTimeout(hTimer) } }
function redo() { const s = history.redo(); if (s) { doc.value = s; clearTimeout(hTimer) } }

// ---- derived flow elements (single source of truth: doc)
const severityByNode = computed(() => {
  const m = {}
  for (const i of issues.value) if (i.ref?.node) m[i.ref.node] = m[i.ref.node] === 'error' ? 'error' : i.severity
  return m
})
const flowNodes = computed(() => {
  if (!doc.value) return []
  const zones = doc.value.zones.map((z) => ({
    id: `zone:${z.key}`, type: 'zone', position: { ...z.position }, zIndex: -1, draggable: editable.value,
    selectable: true, style: { width: `${z.size.w}px`, height: `${z.size.h}px` },
    selected: selection.value?.kind === 'zone' && selection.value.key === z.key,
    data: { zone: z, editable: editable.value, onResize },
  }))
  const nodes = doc.value.nodes.map((n) => ({
    id: n.key, type: 'device', position: { ...n.position }, draggable: editable.value, connectable: editable.value,
    selected: selection.value?.kind === 'node' && selection.value.key === n.key,
    data: { node: n, severity: severityByNode.value[n.key] },
  }))
  return [...zones, ...nodes]
})
const flowEdges = computed(() => (doc.value?.links || []).map((l) => {
  const sel = selection.value?.kind === 'link' && selection.value.key === l.key
  const bad = issues.value.some((i) => i.ref?.link === l.key && i.severity === 'error')
  return {
    id: l.key, source: l.source, target: l.target, label: l.label || (l.bandwidth_mbps ? (l.bandwidth_mbps >= 1000 ? `${l.bandwidth_mbps / 1000} Gb/s` : `${l.bandwidth_mbps} Mb/s`) : ''),
    selected: sel, animated: l.kind === 'vpn' || l.kind === 'wireless', updatable: false,
    style: { stroke: bad ? '#f43f5e' : sel ? '#22d3ee' : '#3a5478', strokeWidth: sel ? 2.5 : 1.75, strokeDasharray: l.kind === 'vpn' ? '6 4' : undefined },
    labelStyle: { fill: '#9bb0cc', fontSize: 10, fontFamily: 'JetBrains Mono Variable' }, labelBgStyle: { fill: '#08111f' },
    markerEnd: MarkerType.ArrowClosed,
  }
}))

// ---- interactions
const findDocNode = (k) => doc.value.nodes.find((n) => n.key === k)
const findZone = (k) => doc.value.zones.find((z) => z.key === k)
let zoneDragLast = null
function onNodeDragStart({ node }) { if (node.type === 'zone') zoneDragLast = { ...node.position } }
function onNodeDrag({ node }) {
  if (node.type !== 'zone' || !zoneDragLast) return
  const key = node.id.slice(5)
  const dx = node.position.x - zoneDragLast.x, dy = node.position.y - zoneDragLast.y
  zoneDragLast = { ...node.position }
  const z = findZone(key)
  z.position = { x: node.position.x, y: node.position.y }
  for (const n of doc.value.nodes) if (n.zone === key) n.position = { x: n.position.x + dx, y: n.position.y + dy }
}
function onNodeDragStop({ nodes }) {
  zoneDragLast = null
  for (const fn of nodes) {
    if (fn.type === 'zone') { findZone(fn.id.slice(5)).position = { x: Math.round(fn.position.x), y: Math.round(fn.position.y) }; continue }
    const n = findDocNode(fn.id)
    if (!n) continue
    n.position = { x: Math.round(fn.position.x), y: Math.round(fn.position.y) }
    const z = zoneAt(doc.value, n.position.x + 75, n.position.y + 24)
    if (z !== n.zone) { n.zone = z; ui.toast(`${n.label} → ${z ? findZone(z).name : 'tanpa zona'}`) }
  }
}
function onResize(id, p) {
  const z = findZone(id.slice(5))
  z.size = { w: Math.round(Math.max(120, p.width)), h: Math.round(Math.max(90, p.height)) }
  z.position = { x: Math.round(p.x), y: Math.round(p.y) }
}
function onConnect({ source, target }) {
  if (!editable.value || source === target) return
  if (doc.value.links.some((l) => (l.source === source && l.target === target) || (l.source === target && l.target === source)))
    return ui.toast('Perangkat ini sudah terhubung')
  const key = newKey('l', new Set(doc.value.links.map((l) => l.key)))
  doc.value.links.push({ key, source, target, label: null, kind: 'ethernet', bandwidth_mbps: 1000 })
  selection.value = { kind: 'link', key }
}
function selectFromFlow(fn) { selection.value = fn.type === 'zone' ? { kind: 'zone', key: fn.id.slice(5) } : { kind: 'node', key: fn.id } }

function addDevice(type, pos) {
  const key = newKey(type.slice(0, 3), new Set(doc.value.nodes.map((n) => n.key)))
  const count = doc.value.nodes.filter((n) => n.type === type).length + 1
  const position = { x: Math.round(pos.x - 75), y: Math.round(pos.y - 24) }
  const zone = zoneAt(doc.value, pos.x, pos.y)
  const sub = doc.value.subnets.find((s) => s.zone && s.zone === zone)
  doc.value.nodes.push({
    key, type, label: `${DEVICES[type].label} ${count}`, hostname: null, os: null, zone, group: null, properties: {}, position, elevation: null,
    interfaces: ['internet', 'switch'].includes(type) ? [] : [{ name: 'eth0', subnet: sub?.key || null, ip: null }],
  })
  selection.value = { kind: 'node', key }
}
function addZone(pos) {
  const key = newKey('z', new Set(doc.value.zones.map((z) => z.key)))
  const center = pos || screenToFlowCoordinate({ x: window.innerWidth / 2, y: window.innerHeight / 2 })
  doc.value.zones.push({ key, name: `Zone ${doc.value.zones.length + 1}`, kind: 'internal', color: ZONE_COLORS.internal,
    position: { x: Math.round(center.x - 200), y: Math.round(center.y - 130) }, size: { w: 400, h: 260 } })
  selection.value = { kind: 'zone', key }
}
function onDragStartPalette(e, type) { e.dataTransfer.setData('application/cr-device', type); e.dataTransfer.effectAllowed = 'copy' }
function onDrop(e) {
  const type = e.dataTransfer.getData('application/cr-device')
  if (!type || !editable.value) return
  addDevice(type, screenToFlowCoordinate({ x: e.clientX, y: e.clientY }))
}

function deleteKeys({ nodes = [], links = [], zones = [] }) {
  const ns = new Set(nodes), zs = new Set(zones)
  doc.value.links = doc.value.links.filter((l) => !links.includes(l.key) && !ns.has(l.source) && !ns.has(l.target))
  doc.value.nodes = doc.value.nodes.filter((n) => !ns.has(n.key))
  if (zs.size) {
    doc.value.zones = doc.value.zones.filter((z) => !zs.has(z.key))
    for (const n of doc.value.nodes) if (zs.has(n.zone)) n.zone = null
    for (const s of doc.value.subnets) if (zs.has(s.zone)) s.zone = null
  }
  selection.value = null
}
function deleteSelection() {
  const sn = getSelectedNodes.value, se = getSelectedEdges.value
  const target = {
    nodes: sn.filter((n) => n.type === 'device').map((n) => n.id), zones: sn.filter((n) => n.type === 'zone').map((n) => n.id.slice(5)), links: se.map((e) => e.id),
  }
  const s = selection.value
  if (s) target[{ node: 'nodes', link: 'links', zone: 'zones' }[s.kind]].push(s.key)
  if (target.nodes.length + target.links.length + target.zones.length) deleteKeys(target)
}
function duplicateNode(key) {
  const src = findDocNode(key)
  const copy = clone(src)
  copy.key = newKey(src.type.slice(0, 3), new Set(doc.value.nodes.map((n) => n.key)))
  copy.label = `${src.label} copy`
  copy.position = { x: src.position.x + 40, y: src.position.y + 40 }
  copy.interfaces = copy.interfaces.map((i) => ({ ...i, ip: null }))
  doc.value.nodes.push(copy)
  selection.value = { kind: 'node', key: copy.key }
}
function openMenu(ev, items) { ev.preventDefault(); menu.value = { x: ev.clientX, y: ev.clientY, items } }
function onNodeMenu({ event, node }) {
  if (!editable.value) return
  selectFromFlow(node)
  if (node.type === 'zone') return openMenu(event, [{ label: 'Hapus zona', danger: true, run: () => deleteKeys({ zones: [node.id.slice(5)] }) }])
  openMenu(event, [
    { label: 'Duplicate', run: () => duplicateNode(node.id) },
    { label: 'Putuskan semua link', run: () => { doc.value.links = doc.value.links.filter((l) => l.source !== node.id && l.target !== node.id) } },
    { label: 'Hapus perangkat', danger: true, run: () => deleteKeys({ nodes: [node.id] }) },
  ])
}
function onEdgeMenu({ event, edge }) {
  if (!editable.value) return
  selection.value = { kind: 'link', key: edge.id }
  openMenu(event, [{ label: 'Hapus koneksi', danger: true, run: () => deleteKeys({ links: [edge.id] }) }])
}
function onPaneMenu(event) {
  if (!editable.value) return
  const pos = screenToFlowCoordinate({ x: event.clientX, y: event.clientY })
  openMenu(event, [
    ...Object.entries(DEVICES).map(([t, d]) => ({ label: `Add ${d.label.toLowerCase()} here`, run: () => addDevice(t, pos) })),
    { label: 'Tambah zona di sini', run: () => addZone(pos) },
  ])
}
function focusRef(ref) {
  if (ref.node) { selection.value = { kind: 'node', key: ref.node }; const n = findNode(ref.node); if (n) setCenter(n.position.x + 75, n.position.y + 24, { zoom: 1.2, duration: 400 }) }
  else if (ref.link) selection.value = { kind: 'link', key: ref.link }
  else if (ref.zone) selection.value = { kind: 'zone', key: ref.zone }
  else selection.value = null
}

// ---- save / export
async function save() {
  if (!editable.value || saving.value) return
  saving.value = true
  try {
    const n = await api(`/networks/${net.value.id}/topology`, { method: 'PUT', body: { expected_version: net.value.version, topology: doc.value } })
    net.value = n; saved.value = JSON.stringify(doc.value); issues.value = n.issues
    ui.success(`Disimpan v${n.version} · ${n.validation_status}`)
  } catch (e) {
    if (e.code === 'version_conflict') ui.error('Orang lain menyimpan versi yang lebih baru. Ekspor draf Anda, lalu muat ulang.')
    else if (e.code === 'invalid_topology') { issues.value = e.details; ui.error('Perbaiki error struktur sebelum menyimpan') }
    else ui.error(e)
  } finally { saving.value = false }
}
async function exportAs(fmt) {
  if (dirty.value) ui.toast('Mengekspor versi terakhir yang disimpan (simpan dulu untuk menyertakan perubahan draf)')
  try { await download(`/networks/${net.value.id}/export`, { format: fmt }, `${net.value.name}.${fmt}`) } catch (e) { ui.error(e) }
}

function onKey(e) {
  const typing = ['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName)
  const mod = e.ctrlKey || e.metaKey
  if (mod && e.key.toLowerCase() === 's') { e.preventDefault(); save() }
  else if (typing) return
  else if (mod && e.key.toLowerCase() === 'z' && !e.shiftKey) { e.preventDefault(); undo() }
  else if (mod && (e.key.toLowerCase() === 'y' || (e.key.toLowerCase() === 'z' && e.shiftKey))) { e.preventDefault(); redo() }
  else if ((e.key === 'Delete' || e.key === 'Backspace') && editable.value) { e.preventDefault(); deleteSelection() }
  else if (e.key === 'Escape') { selection.value = null; menu.value = null }
}
const beforeUnload = (e) => { if (dirty.value) { e.preventDefault(); e.returnValue = '' } }
const closeMenu = () => { menu.value = null }
onMounted(() => { window.addEventListener('keydown', onKey); window.addEventListener('beforeunload', beforeUnload); window.addEventListener('click', closeMenu) })
onBeforeUnmount(() => { window.removeEventListener('keydown', onKey); window.removeEventListener('beforeunload', beforeUnload); window.removeEventListener('click', closeMenu) })
onBeforeRouteLeave((to) => { if (dirty.value && !leaveTo.value) { leaveTo.value = to.fullPath; return false } })
function discardAndLeave() { const t = leaveTo.value; saved.value = JSON.stringify(doc.value); router.push(t).finally(() => { leaveTo.value = null }) }

const errCount = computed(() => issues.value.filter((i) => i.severity === 'error').length)
const warnCount = computed(() => issues.value.length - errCount.value)
</script>

<template>
  <div v-if="err" class="panel"><CrState :kind="err.status === 404 ? 'empty' : 'error'" :title="err.status === 404 ? 'Jaringan tidak ditemukan' : undefined" :message="err.message" @retry="load" /></div>
  <div v-else-if="!doc" class="panel"><CrState kind="loading" /></div>
  <div v-else class="-m-5 flex h-[calc(100%+2.5rem)] flex-col lg:-m-6 lg:h-[calc(100%+3rem)]">
    <!-- toolbar -->
    <div class="flex flex-wrap items-center gap-2 border-b border-ink-800 bg-ink-900/80 px-3 py-2">
      <RouterLink :to="{ name: 'networks' }" class="rounded p-1.5 text-ink-400 hover:bg-ink-800 hover:text-ink-100" aria-label="Kembali ke daftar jaringan"><ArrowLeft class="size-4" /></RouterLink>
      <div class="mr-2 min-w-0">
        <div class="truncate text-sm font-semibold text-ink-100">{{ doc.name }}</div>
        <div class="flex items-center gap-1.5 font-mono text-[10px] text-ink-500">v{{ net.version }} · {{ net.owner }} · {{ net.visibility }}
          <CrBadge v-if="!editable" tone="warn"><Eye class="size-3" /> hanya-baca</CrBadge>
          <CrBadge v-if="dirty" tone="accent">belum disimpan</CrBadge></div>
      </div>
      <div class="flex items-center gap-1">
        <CrButton size="sm" variant="ghost" :disabled="!history.canUndo.value || !editable" title="Undo (Ctrl+Z)" aria-label="Undo" @click="undo"><Undo2 class="size-4" /></CrButton>
        <CrButton size="sm" variant="ghost" :disabled="!history.canRedo.value || !editable" title="Ulangi (Ctrl+Shift+Z)" aria-label="Ulangi" @click="redo"><Redo2 class="size-4" /></CrButton>
        <CrButton size="sm" variant="ghost" title="Sesuaikan tampilan" aria-label="Sesuaikan tampilan" @click="fitView({ padding: 0.15, duration: 300 })"><Maximize class="size-4" /></CrButton>
        <CrButton v-if="editable" size="sm" variant="ghost" @click="addZone()"><SquareDashed class="size-4" /> Zona</CrButton>
      </div>
      <button class="ml-1 flex items-center gap-1.5 rounded border border-ink-700 px-2 py-1 font-mono text-[11px]" title="Hasil validasi" @click="selection = null">
        <ShieldCheck v-if="errCount" class="size-3.5 text-sev-critical" /><CheckCircle2 v-else class="size-3.5 text-ok" />
        <span :class="errCount ? 'text-sev-critical' : 'text-ok'">{{ errCount }} error</span><span class="text-warn">{{ warnCount }} peringatan</span>
      </button>
      <div class="ml-auto flex items-center gap-1.5">
        <CrButton size="sm" @click="exportAs('json')"><Download class="size-3.5" /> JSON</CrButton>
        <CrButton size="sm" @click="exportAs('yaml')"><Download class="size-3.5" /> YAML</CrButton>
        <RouterLink :to="{ name: 'network-3d', params: { id: net.id } }" class="inline-flex h-8 items-center gap-1.5 rounded-md border border-ink-600 bg-ink-800 px-2.5 text-xs text-ink-100 hover:bg-ink-700"><Boxes class="size-3.5" /> Tampilan 3D</RouterLink>
        <span v-if="editable && !dirty" class="hidden text-[11px] text-ink-500 md:inline" data-test="save-hint">Tersimpan · ubah topologi untuk mengaktifkan Simpan</span>
        <CrButton v-if="editable" size="sm" variant="primary" :loading="saving" :disabled="!dirty" :title="dirty ? 'Simpan (Ctrl+S)' : 'Belum ada perubahan untuk disimpan. Ubah topologi dulu (tambah perangkat, sambungkan, edit properti).'" @click="save"><Save class="size-3.5" /> Simpan</CrButton>
      </div>
    </div>

    <div class="flex min-h-0 flex-1">
      <!-- palette -->
      <aside v-if="editable" class="w-44 shrink-0 overflow-y-auto border-r border-ink-800 bg-ink-900/90 p-2" aria-label="Palet perangkat">
        <div class="panel-title mb-2 px-1">Perangkat</div>
        <div v-for="(d, t) in DEVICES" :key="t" draggable="true" :data-device="t"
          class="mb-1 flex cursor-grab items-center gap-2 rounded-md border border-ink-700 bg-ink-850 px-2 py-1.5 text-xs text-ink-200 hover:border-accent-500/50 active:cursor-grabbing"
          title="Seret ke kanvas, atau klik dua kali untuk menambah" @dragstart="onDragStartPalette($event, t)"
          @dblclick="addDevice(t, screenToFlowCoordinate({ x: 600, y: 360 }))">
          <component :is="d.icon" class="size-4" :style="{ color: d.color }" /> {{ d.label }}
        </div>
        <p class="mt-3 px-1 text-[10px] leading-relaxed text-ink-500">Seret handle untuk menghubungkan. Klik kanan untuk opsi lain. Del menghapus, Ctrl+Z undo, Ctrl+S simpan.</p>
      </aside>

      <!-- canvas -->
      <div class="relative min-w-0 flex-1" @drop.prevent="onDrop" @dragover.prevent>
        <VueFlow :id="FLOW_ID" :nodes="flowNodes" :edges="flowEdges" :node-types="nodeTypes" :min-zoom="0.15" :max-zoom="2.5"
          :delete-key-code="null" :nodes-connectable="editable" :elevate-nodes-on-select="false" :snap-to-grid="true" :snap-grid="[10, 10]"
          class="cr-flow" fit-view-on-init
          @node-drag-start="onNodeDragStart" @node-drag="onNodeDrag" @node-drag-stop="onNodeDragStop" @connect="onConnect"
          @node-click="({ node }) => selectFromFlow(node)" @edge-click="({ edge }) => (selection = { kind: 'link', key: edge.id })"
          @pane-click="selection = null" @node-context-menu="onNodeMenu" @edge-context-menu="onEdgeMenu" @pane-context-menu="onPaneMenu">
          <Background pattern-color="#162a45" :gap="20" />
          <MiniMap pannable zoomable :node-color="(n) => n.type === 'zone' ? n.data.zone.color + '40' : DEVICES[n.data.node.type]?.color" mask-color="rgba(5,10,20,.7)" />
          <Controls :show-interactive="false" />
        </VueFlow>
        <div v-if="!doc.nodes.length && !doc.zones.length" class="pointer-events-none absolute inset-0 grid place-items-center">
          <div class="text-center text-sm text-ink-500">{{ editable ? 'Seret perangkat dari palet, atau klik kanan kanvas.' : 'Topologi ini kosong.' }}</div>
        </div>
        <ul v-if="menu" class="panel fixed z-50 min-w-48 p-1 text-sm shadow-2xl" :style="{ left: menu.x + 'px', top: menu.y + 'px' }" role="menu" @click.stop>
          <li v-for="m in menu.items" :key="m.label"><button role="menuitem" :class="['w-full rounded px-3 py-1.5 text-left hover:bg-ink-800', m.danger ? 'text-sev-critical' : 'text-ink-200']" @click="m.run(); menu = null">{{ m.label }}</button></li>
        </ul>
      </div>

      <PropertiesPanel :doc="doc" :selection="selection" :issues="issues" :editable="editable" :meta="meta" @focus="focusRef" @delete-selection="deleteSelection" />
    </div>
  </div>

  <CrModal :open="!!leaveTo" title="Perubahan belum disimpan" @close="leaveTo = null">
    <p class="text-sm">Topologi ini memiliki perubahan yang belum disimpan. Tinggalkan dan buang perubahan?</p>
    <template #footer><CrButton @click="leaveTo = null">Tetap di sini</CrButton><CrButton variant="danger" @click="discardAndLeave">Buang perubahan</CrButton></template>
  </CrModal>
</template>

<style>
.cr-flow { background: transparent; }
.cr-flow .vue-flow__minimap { background: #08111f; border: 1px solid #162a45; border-radius: 8px; }
.cr-flow .vue-flow__controls { box-shadow: none; border: 1px solid #162a45; border-radius: 8px; overflow: hidden; }
.cr-flow .vue-flow__controls-button { background: #0b1626; border-color: #162a45; fill: #9bb0cc; }
.cr-flow .vue-flow__controls-button:hover { background: #162a45; }
.cr-flow .vue-flow__node-zone, .cr-flow .vue-flow__node-device { padding: 0; border: 0; background: transparent; box-shadow: none !important; border-radius: 0; width: auto; }
.cr-flow .vue-flow__node-zone { width: 100%; }
.cr-flow .vue-flow__edge-textbg { fill: #08111f; }
</style>
