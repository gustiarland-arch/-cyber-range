<script setup>
// Right-hand inspector. Mutates the draft document in place; the editor records history.
import { computed } from 'vue'
import { AlertTriangle, Plus, Trash2, XCircle } from 'lucide-vue-next'
import { DEVICES, ZONE_COLORS, newKey } from './catalog'
import CrButton from '@/components/ui/CrButton.vue'

const props = defineProps({ doc: Object, selection: Object, issues: Array, editable: Boolean, meta: Object })
const emit = defineEmits(['focus', 'delete-selection'])

const node = computed(() => props.selection?.kind === 'node' ? props.doc.nodes.find((n) => n.key === props.selection.key) : null)
const link = computed(() => props.selection?.kind === 'link' ? props.doc.links.find((l) => l.key === props.selection.key) : null)
const zone = computed(() => props.selection?.kind === 'zone' ? props.doc.zones.find((z) => z.key === props.selection.key) : null)
const scopedIssues = computed(() => {
  const s = props.selection
  if (!s) return props.issues
  return props.issues.filter((i) => i.ref && i.ref[s.kind] === s.key)
})
const services = computed({
  get: () => node.value?.properties?.services || [],
  set: (v) => { node.value.properties = { ...(node.value.properties || {}), services: v } },
})
function addInterface() {
  const n = node.value
  const name = `eth${n.interfaces.length}`
  n.interfaces.push({ name, subnet: props.doc.subnets[0]?.key || null, ip: null })
}
function addService() { services.value = [...services.value, { port: 80, proto: 'tcp', name: '' }] }
function addSubnet() {
  const taken = new Set(props.doc.subnets.map((s) => s.key))
  props.doc.subnets.push({ key: newKey('s', taken), name: `Subnet ${props.doc.subnets.length + 1}`, cidr: `10.${props.doc.subnets.length + 100}.0.0/24`, gateway: null, vlan: null, zone: null })
}
function removeSubnet(key) {
  props.doc.subnets.splice(props.doc.subnets.findIndex((s) => s.key === key), 1)
  for (const n of props.doc.nodes) for (const i of n.interfaces) if (i.subnet === key) i.subnet = null
}
const nullIfEmpty = (v) => (v === '' ? null : v)
</script>

<template>
  <aside class="flex w-80 shrink-0 flex-col overflow-hidden border-l border-ink-800 bg-ink-900/90" aria-label="Properti">
    <div class="panel-header"><h2 class="panel-title">Properti {{ node ? 'perangkat' : link ? 'koneksi' : zone ? 'zona' : 'jaringan' }}</h2>
      <CrButton v-if="editable && selection" size="sm" variant="danger" @click="emit('delete-selection')"><Trash2 class="size-3.5" /></CrButton>
    </div>
    <fieldset :disabled="!editable" class="min-h-0 flex-1 space-y-3 overflow-y-auto p-4 text-sm">
      <!-- NODE -->
      <template v-if="node">
        <div><label class="field-label" for="p-label">Label</label><input id="p-label" v-model="node.label" class="input" maxlength="128" /></div>
        <div class="grid grid-cols-2 gap-2">
          <div><label class="field-label" for="p-type">Tipe</label>
            <select id="p-type" v-model="node.type" class="input"><option v-for="(d, t) in DEVICES" :key="t" :value="t">{{ d.label }}</option></select></div>
          <div><label class="field-label" for="p-zone">Zona</label>
            <select id="p-zone" :value="node.zone || ''" class="input" @change="node.zone = nullIfEmpty($event.target.value)"><option value="">—</option><option v-for="z in doc.zones" :key="z.key" :value="z.key">{{ z.name }}</option></select></div>
        </div>
        <div class="grid grid-cols-2 gap-2">
          <div><label class="field-label" for="p-host">Hostname</label><input id="p-host" :value="node.hostname" class="input font-mono" @input="node.hostname = nullIfEmpty($event.target.value)" /></div>
          <div><label class="field-label" for="p-os">OS / image</label><input id="p-os" :value="node.os" class="input" @input="node.os = nullIfEmpty($event.target.value)" /></div>
        </div>
        <div><label class="field-label" for="p-group">Grup</label><input id="p-group" :value="node.group" class="input" placeholder="mis. web-tier" @input="node.group = nullIfEmpty($event.target.value)" /></div>
        <div>
          <div class="mb-1 flex items-center justify-between"><span class="field-label !mb-0">Interfaces / IP</span>
            <button v-if="editable" class="text-xs text-accent-400 hover:underline" @click="addInterface"><Plus class="inline size-3" /> add</button></div>
          <div v-for="(itf, i) in node.interfaces" :key="i" class="mb-1.5 grid grid-cols-[56px_1fr_1fr_20px] items-center gap-1">
            <input v-model="itf.name" class="input !px-1.5 font-mono text-xs" aria-label="Nama interface" />
            <select :value="itf.subnet || ''" class="input !px-1 text-xs" aria-label="Subnet" @change="itf.subnet = nullIfEmpty($event.target.value)">
              <option value="">tanpa subnet</option><option v-for="s in doc.subnets" :key="s.key" :value="s.key">{{ s.name }} {{ s.cidr }}</option></select>
            <input :value="itf.ip" class="input !px-1.5 font-mono text-xs" placeholder="10.0.0.10" aria-label="Alamat IP" @input="itf.ip = nullIfEmpty($event.target.value)" />
            <button v-if="editable" class="text-ink-500 hover:text-sev-critical" aria-label="Hapus interface" @click="node.interfaces.splice(i, 1)"><XCircle class="size-4" /></button>
          </div>
          <p v-if="!node.interfaces.length" class="text-xs text-ink-500">Tidak ada interface.</p>
        </div>
        <div>
          <div class="mb-1 flex items-center justify-between"><span class="field-label !mb-0">Port / layanan</span>
            <button v-if="editable" class="text-xs text-accent-400 hover:underline" @click="addService"><Plus class="inline size-3" /> add</button></div>
          <div v-for="(svc, i) in services" :key="i" class="mb-1.5 grid grid-cols-[64px_60px_1fr_20px] items-center gap-1">
            <input v-model.number="svc.port" type="number" min="1" max="65535" class="input !px-1.5 font-mono text-xs" aria-label="Port" @change="services = [...services]" />
            <select v-model="svc.proto" class="input !px-1 text-xs" aria-label="Protokol" @change="services = [...services]"><option>tcp</option><option>udp</option></select>
            <input v-model="svc.name" class="input !px-1.5 text-xs" placeholder="service" aria-label="Nama layanan" @change="services = [...services]" />
            <button v-if="editable" class="text-ink-500 hover:text-sev-critical" aria-label="Hapus layanan" @click="services = services.filter((_, j) => j !== i)"><XCircle class="size-4" /></button>
          </div>
        </div>
        <div><label class="field-label" for="p-notes">Catatan</label>
          <textarea id="p-notes" :value="node.properties?.notes || ''" rows="2" class="input" @input="node.properties = { ...(node.properties || {}), notes: $event.target.value }" /></div>
        <div class="font-mono text-[10px] text-ink-500">key {{ node.key }}</div>
      </template>

      <!-- LINK -->
      <template v-else-if="link">
        <p class="font-mono text-xs text-ink-300">{{ doc.nodes.find((n) => n.key === link.source)?.label }} ⇄ {{ doc.nodes.find((n) => n.key === link.target)?.label }}</p>
        <div><label class="field-label" for="l-label">Label</label><input id="l-label" :value="link.label" class="input" @input="link.label = nullIfEmpty($event.target.value)" /></div>
        <div class="grid grid-cols-2 gap-2">
          <div><label class="field-label" for="l-kind">Medium</label><select id="l-kind" v-model="link.kind" class="input"><option v-for="k in meta.link_kinds" :key="k">{{ k }}</option></select></div>
          <div><label class="field-label" for="l-bw">Bandwidth (Mbps)</label><input id="l-bw" :value="link.bandwidth_mbps" type="number" min="1" class="input font-mono" @input="link.bandwidth_mbps = $event.target.value ? Number($event.target.value) : null" /></div>
        </div>
      </template>

      <!-- ZONE -->
      <template v-else-if="zone">
        <div><label class="field-label" for="z-name">Nama</label><input id="z-name" v-model="zone.name" class="input" /></div>
        <div class="grid grid-cols-2 gap-2">
          <div><label class="field-label" for="z-kind">Jenis</label>
            <select id="z-kind" v-model="zone.kind" class="input" @change="zone.color = ZONE_COLORS[zone.kind]"><option v-for="k in meta.zone_kinds" :key="k">{{ k }}</option></select></div>
          <div><label class="field-label" for="z-color">Warna</label><input id="z-color" v-model="zone.color" type="color" class="input h-9 !p-1" /></div>
        </div>
        <p class="text-xs text-ink-500">Seret perangkat ke dalam zona untuk menetapkannya. Memindahkan zona ikut memindahkan perangkatnya.</p>
      </template>

      <!-- NETWORK -->
      <template v-else>
        <div><label class="field-label" for="n-name">Nama jaringan</label><input id="n-name" v-model="doc.name" class="input" maxlength="128" /></div>
        <div><label class="field-label" for="n-desc">Deskripsi</label><textarea id="n-desc" v-model="doc.description" rows="2" class="input" /></div>
        <div>
          <div class="mb-1 flex items-center justify-between"><span class="field-label !mb-0">Subnets</span>
            <button v-if="editable" class="text-xs text-accent-400 hover:underline" @click="addSubnet"><Plus class="inline size-3" /> tambah subnet</button></div>
          <div v-for="s in doc.subnets" :key="s.key" class="mb-2 space-y-1 rounded-md border border-ink-700 p-2" :data-subnet="s.key">
            <div class="flex gap-1"><input v-model="s.name" class="input !py-1 text-xs" aria-label="Nama subnet" />
              <button v-if="editable" class="text-ink-500 hover:text-sev-critical" aria-label="Hapus subnet" @click="removeSubnet(s.key)"><Trash2 class="size-4" /></button></div>
            <div class="grid grid-cols-2 gap-1">
              <input v-model="s.cidr" class="input !py-1 font-mono text-xs" placeholder="10.0.0.0/24" aria-label="CIDR" />
              <input :value="s.gateway" class="input !py-1 font-mono text-xs" placeholder="gateway" aria-label="Gateway" @input="s.gateway = nullIfEmpty($event.target.value)" />
              <input :value="s.vlan" type="number" min="1" max="4094" class="input !py-1 font-mono text-xs" placeholder="VLAN" aria-label="VLAN" @input="s.vlan = $event.target.value ? Number($event.target.value) : null" />
              <select :value="s.zone || ''" class="input !py-1 text-xs" aria-label="Zona" @change="s.zone = nullIfEmpty($event.target.value)"><option value="">tanpa zona</option><option v-for="z in doc.zones" :key="z.key" :value="z.key">{{ z.name }}</option></select>
            </div>
          </div>
          <p v-if="!doc.subnets.length" class="text-xs text-ink-500">Belum ada subnet.</p>
        </div>
      </template>
    </fieldset>

    <div class="max-h-[38%] overflow-y-auto border-t border-ink-800 p-3" aria-label="Validasi">
      <div class="panel-title mb-2">Validasi {{ selection ? '(selection)' : '' }}</div>
      <p v-if="!scopedIssues.length" class="text-xs text-ok">Tidak ada masalah.</p>
      <button v-for="(i, idx) in scopedIssues" :key="idx" class="mb-1 flex w-full items-start gap-1.5 rounded px-1.5 py-1 text-left text-xs hover:bg-ink-800" @click="i.ref && emit('focus', i.ref)">
        <XCircle v-if="i.severity === 'error'" class="mt-0.5 size-3.5 shrink-0 text-sev-critical" /><AlertTriangle v-else class="mt-0.5 size-3.5 shrink-0 text-warn" />
        <span class="text-ink-300">{{ $tr(i.message) }}</span>
      </button>
    </div>
  </aside>
</template>
