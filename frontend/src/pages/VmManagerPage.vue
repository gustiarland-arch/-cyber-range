<script setup>
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { CheckCircle2, Cpu, XCircle } from 'lucide-vue-next'
import { api } from '@/services/api'
import { useAuthStore } from '@/stores/auth'
import CrButton from '@/components/ui/CrButton.vue'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrPanel from '@/components/ui/CrPanel.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'

const router = useRouter()
const data = ref(null)
const err = ref(null)
const auth = useAuthStore()
const probing = ref(false)
async function load(probe = false) {
  probing.value = probe
  try { data.value = await api('/labs/vms', { query: probe ? { probe: true } : {} }); err.value = null } catch (e) { err.value = e } finally { probing.value = false }
}
onMounted(() => load())
</script>

<template>
  <PageHeader section="Cyber Range Lab" title="Manajer Virtual Machine" subtitle="Node bertipe VM di seluruh lab Anda dan bagaimana host lab dapat merealisasikannya." />
  <CrState v-if="err" kind="error" :message="err.message" @retry="load()" />
  <CrState v-else-if="!data" kind="loading" />
  <template v-else>
    <div class="mb-4 grid gap-3 md:grid-cols-3">
      <div class="panel flex items-start gap-3 p-4">
        <component :is="data.capability.kvm_device ? CheckCircle2 : XCircle" :class="['mt-0.5 size-5', data.capability.kvm_device ? 'text-ok' : 'text-ink-500']" />
        <div><div class="text-sm font-semibold text-ink-100">Perangkat KVM</div><div class="text-xs text-ink-400">{{ data.capability.kvm_device ? '/dev/kvm tersedia di host ini' : '/dev/kvm tidak ada di host ini (KVM butuh host Linux dengan virtualisasi)' }}</div></div>
      </div>
      <div class="panel flex items-start gap-3 p-4">
        <component :is="data.capability.proxmox_configured ? CheckCircle2 : XCircle" :class="['mt-0.5 size-5', data.capability.proxmox_configured ? 'text-ok' : 'text-ink-500']" />
        <div><div class="text-sm font-semibold text-ink-100">Proxmox API</div><div class="text-xs text-ink-400">{{ data.capability.proxmox_configured ? 'Endpoint sudah dikonfigurasi' : 'Endpoint Proxmox belum dikonfigurasi (CR_PROXMOX_URL)' }}</div></div>
      </div>
      <div class="panel flex items-start gap-3 p-4">
        <Cpu class="mt-0.5 size-5 text-accent-400" />
        <div><div class="text-sm font-semibold text-ink-100">Mode aktif</div>
          <div class="text-xs text-ink-400" data-test="vm-mode">{{ data.capability.supported ? `VM penuh melalui ${data.capability.provider}` : 'Mode kompatibel: node VM berjalan sebagai container yang di-hardening' }}</div>
          <div v-if="data.capability.supported" class="mt-1 text-xs text-ink-400">Template: <span class="font-mono">{{ data.capability.templates.join(', ') || 'belum ada' }}</span></div>
          <CrButton v-if="data.capability.supported && auth.can('lab.manage')" size="sm" class="mt-2" :loading="probing" data-test="vm-probe" @click="load(true)">Uji koneksi</CrButton>
          <div v-if="data.capability.probe" :class="['mt-1 text-xs', data.capability.probe.ok ? 'text-ok' : 'text-sev-critical']" data-test="vm-probe-result">
            {{ data.capability.probe.ok ? `Terhubung (${data.capability.probe.hypervisor || 'Proxmox'} ${data.capability.probe.version || ''})` : data.capability.probe.error }}</div></div>
      </div>
    </div>
    <p class="mb-4 text-xs text-ink-500"><span class="mr-1 rounded border border-sev-medium/40 px-1.5 py-0.5 font-semibold text-sev-medium" data-test="vm-experimental">EKSPERIMENTAL</span>VM penuh (libvirt/Proxmox) belum diuji menyeluruh di luar komputer pengembang. {{ data.capability.note }} Panduan memasang Windows sungguhan lewat libvirt/KVM: berkas <span class="font-mono">VM-WINDOWS.md</span> di folder aplikasi.</p>
    <CrPanel title="Node VM" :padded="false">
      <CrState v-if="!data.vms.length" kind="empty" message="Tidak ada lab yang berisi node bertipe VM. Tambahkan di editor topologi lalu buat lab darinya." />
      <table v-else class="data-table">
        <thead><tr><th>Node</th><th>Lab</th><th>Mode</th><th>Image</th><th>Sumber daya</th><th>Kondisi</th></tr></thead>
        <tbody>
          <tr v-for="v in data.vms" :key="`${v.lab_id}-${v.node_key}`" class="cursor-pointer" @click="router.push({ name: 'lab-detail', params: { id: v.lab_id } })">
            <td class="text-ink-100">{{ v.label }}</td><td class="text-xs">{{ v.lab }}</td>
            <td><CrBadge :tone="v.mode.includes('compatible') ? 'warn' : 'ok'">{{ v.mode === 'vm' ? `VM (${v.provider || 'belum dibuat'})` : v.mode.includes('compatible') ? 'container (mode kompatibel)' : v.mode }}</CrBadge>
              <div v-if="v.name" class="font-mono text-[10px] text-ink-500">{{ v.name }}</div></td>
            <td class="font-mono text-xs">{{ v.image }}</td><td class="font-mono text-xs">{{ v.cpus }} vCPU · {{ v.memory_mb }} MB</td>
            <td><CrBadge :tone="v.status === 'running' ? 'ok' : 'neutral'">{{ $st(v.status) }}</CrBadge></td>
          </tr>
        </tbody>
      </table>
    </CrPanel>
  </template>
</template>
