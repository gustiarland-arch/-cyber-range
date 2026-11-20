<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { Download, HardDrive, Server } from 'lucide-vue-next'
import { api, download } from '@/services/api'
import { useUiStore } from '@/stores/ui'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrPanel from '@/components/ui/CrPanel.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'

const route = useRoute()
const ui = useUiStore()
const opts = ref(null)
const err = ref(null)
const source = ref('')
const format = ref('docker')
const prev = ref(null)
const prevErr = ref(null)
const busy = ref(false)
const pkgs = reactive({}) // VM name -> selected server package keys (vagrant only)
const winDc = ref(false) // office lab: domain controller as a Windows Server (Evaluation) VM
const winDcOn = computed(() => format.value === 'vagrant' && winDc.value)
const winPcs = ref([]) // employee PCs that run Windows 11 (Evaluation) and join the Windows domain
const kitQuery = () => ({ source: source.value, format: format.value, packages: pkgQuery.value,
  ...(winDcOn.value ? { windows_dc: 'true', ...(winPcs.value.length ? { windows_pcs: winPcs.value } : {}) } : {}) })
function toggleWinPc(node) {
  if (winPcs.value.includes(node)) winPcs.value = winPcs.value.filter((x) => x !== node)
  else { delete pkgs[node]; winPcs.value = [...winPcs.value, node] } // a Windows PC takes no Ubuntu packages
}
const MAX_PKGS = 4
const pkgQuery = computed(() => format.value !== 'vagrant' ? [] : Object.entries(pkgs).filter(([, v]) => v.length).map(([k, v]) => `${k}=${v.join(',')}`))
const pkgTitle = (k) => opts.value?.server_packages.find((p) => p.key === k)?.title || k
function togglePkg(node, key) {
  const cur = pkgs[node] || []
  if (cur.includes(key)) pkgs[node] = cur.filter((x) => x !== key)
  else if (cur.length < MAX_PKGS) pkgs[node] = [...cur, key]
  else ui.error({ message: `Maksimal ${MAX_PKGS} paket per VM` })
}

const STEPS = {
  docker: ['Pasang Docker Desktop (Windows/macOS) atau Docker Engine + Compose v2 (Linux).', 'Ekstrak ZIP, lalu klik dua kali mulai.bat (Windows) atau jalankan sh mulai.sh.', 'Masuk ke node: docker compose exec <node> sh. Selesai: berhenti.bat.'],
  vagrant: ['Pasang Vagrant 2.4+ dan VirtualBox 7 (atau libvirt + vagrant-libvirt di Linux).', 'Ekstrak ZIP, lalu klik dua kali mulai.bat (Windows) atau jalankan sh mulai.sh. Pertama kali butuh internet untuk mengunduh box.', 'Masuk ke VM: vagrant ssh <node>. Matikan: berhenti.bat, hapus semua: hapus.bat.'],
}

async function load() {
  try {
    opts.value = await api('/lab-kits/options'); err.value = null
    if (route.query.network) source.value = `network:${route.query.network}`
    else if (route.query.template) source.value = `template:${route.query.template}`
    else source.value = `template:${opts.value.templates[0]?.key}`
    if (route.query.format === 'vagrant') format.value = 'vagrant'
  } catch (e) { err.value = e }
}
onMounted(load)

let seq = 0
async function loadPreview(keep = false) {
  if (!source.value) return
  const my = ++seq
  if (!keep) prev.value = null
  prevErr.value = null
  try {
    const r = await api('/lab-kits/preview', { query: kitQuery() })
    if (my === seq) prev.value = r
  } catch (e) { if (my === seq) prevErr.value = e }
}
watch(source, () => { for (const k of Object.keys(pkgs)) delete pkgs[k]; winDc.value = false; winPcs.value = [] })
watch(winDc, (on) => { if (!on && winPcs.value.length) winPcs.value = []; else loadPreview(true) })
watch(winPcs, () => loadPreview(true))
watch([source, format], () => loadPreview(false))
// changing packages keeps the table (and an open package picker) on screen while the preview refreshes
watch(pkgQuery, (a, b) => { if (a.join('|') !== b.join('|')) loadPreview(true) })

const ramGb = computed(() => prev.value ? Math.max(0.1, prev.value.totals.memory_mb / 1024).toFixed(1) : '')
const heavy = computed(() => prev.value && format.value === 'vagrant' && prev.value.totals.memory_mb >= 4096)

async function get() {
  busy.value = true
  try {
    const name = (prev.value?.title || 'lab').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')
    await download('/lab-kits/download', kitQuery(), `cyber-range-kit-${name}-${format.value}${winDcOn.value ? '-windows' : ''}.zip`)
    ui.success('Lab Kit diunduh. Ikuti README.md di dalam ZIP.')
  } catch (e) { ui.error(e) } finally { busy.value = false }
}
</script>

<template>
  <PageHeader section="Cyber Range Lab" title="Lab Kit (jalankan di komputer sendiri)"
    subtitle="Unduh lab sebagai ZIP lalu jalankan di laptop Anda dengan Docker atau sebagai VM sungguhan dengan Vagrant. Cocok untuk memindahkan lab ke komputer atau VM lain di luar aplikasi ini." />
  <CrState v-if="err" kind="error" :message="err.message" @retry="load" />
  <CrState v-else-if="!opts" kind="loading" />
  <template v-else>
    <div class="grid gap-4 xl:grid-cols-3">
      <CrPanel title="1. Pilih lab" class="xl:col-span-1">
        <label class="field-label" for="kit-source">Sumber</label>
        <select id="kit-source" v-model="source" class="input w-full" data-test="kit-source">
          <optgroup label="Template bawaan">
            <option v-for="t in opts.templates" :key="t.key" :value="`template:${t.key}`">{{ t.title }} · {{ t.nodes }} node</option>
          </optgroup>
          <optgroup v-if="opts.networks.length" label="Topologi jaringan">
            <option v-for="n in opts.networks" :key="n.id" :value="`network:${n.id}`">{{ n.name }} (v{{ n.version }}){{ n.mine ? '' : ' · dibagikan' }}</option>
          </optgroup>
        </select>
        <div class="mt-4 field-label">Format</div>
        <div class="grid gap-2">
          <label v-for="f in opts.formats" :key="f.key" :class="['panel flex cursor-pointer gap-3 p-3', format === f.key ? 'ring-1 ring-accent-400' : '']" :data-format="f.key">
            <input v-model="format" type="radio" name="kit-format" :value="f.key" class="mt-1" />
            <div>
              <div class="flex items-center gap-1 text-sm font-semibold text-ink-100"><component :is="f.key === 'docker' ? HardDrive : Server" class="size-4" /> {{ f.title }}</div>
              <div class="text-xs text-ink-400">{{ f.key === 'docker' ? 'Ringan. Setiap node menjadi container, tanpa akses internet.' : 'Setiap node menjadi VM sungguhan (Ubuntu). Lebih berat, terasa seperti server asli.' }}</div>
              <div class="mt-1 text-[11px] text-ink-500">Butuh: {{ f.needs }}</div>
            </div>
          </label>
        </div>
        <p v-if="format === 'vagrant'" class="mt-2 text-xs text-ink-400" data-test="kit-pkg-hint">Di tabel sebelah kanan, pilih <b>Paket server</b> per VM (web, database, FTP, mail, DNS, Samba, SSH). Paket dipasang otomatis saat <span class="font-mono">vagrant up</span> pertama, sebelum internet lab diblokir.</p>
        <p v-if="format === 'vagrant'" class="mt-2 text-[11px] text-ink-500">Box yang diizinkan: <span class="font-mono">{{ opts.boxes.join(', ') }}</span></p>
      </CrPanel>

      <CrPanel title="2. Isi kit" class="xl:col-span-2" :padded="false">
        <CrState v-if="prevErr" kind="error" :message="prevErr.message" @retry="loadPreview(false)" />
        <CrState v-else-if="!prev" kind="loading" />
        <div v-else data-test="kit-preview">
          <div class="flex flex-wrap items-center gap-2 border-b border-ink-800 p-3 text-sm">
            <span class="font-semibold text-ink-100">{{ prev.title }}</span>
            <CrBadge tone="accent">{{ prev.totals.nodes }} node</CrBadge><CrBadge>{{ prev.totals.networks }} subnet</CrBadge>
            <CrBadge>{{ prev.totals.cpus }} CPU</CrBadge><CrBadge :tone="heavy ? 'warn' : 'neutral'" data-test="kit-ram">± {{ ramGb }} GB RAM</CrBadge>
            <CrBadge tone="ai">DEMO</CrBadge>
          </div>
          <label v-if="prev.windows_dc?.available" class="flex cursor-pointer items-start gap-3 border-b border-ink-800 p-3 text-sm" data-test="kit-windows-dc">
            <input v-model="winDc" type="checkbox" class="mt-1 accent-cyan-400" />
            <span><b class="text-ink-100">Domain controller Windows Server (Evaluation)</b>
              <span class="block text-xs text-ink-400">Active Directory asli di <span class="font-mono">dc01</span> dengan Event Log dan Sysmon Windows. Portal tetap Ubuntu; setiap PC karyawan bisa dipilih Ubuntu atau Windows 11 di tabel di bawah. Hanya VirtualBox; DC butuh {{ prev.windows_dc.memory_mb / 1024 }} GB RAM dan box sekitar 6 sampai 8 GB (<span class="font-mono">{{ prev.windows_dc.box }}</span>, lisensi evaluasi Microsoft 180 hari). Telemetri dikirim ke SIEM aplikasi dengan <span class="font-mono">kirim-ke-siem</span>.</span></span>
          </label>
          <p v-if="winDcOn && prev.windows_pc?.available" class="border-b border-ink-800 p-3 text-xs text-ink-400" data-test="kit-windows-pc-note">
            Centang <b class="text-ink-200">Windows 11</b> pada PC karyawan untuk memakai Windows 11 Enterprise (Evaluation, <span class="font-mono">{{ prev.windows_pc.box }}</span>, 90 hari).
            PC itu otomatis join ke domain dan karyawan simulasinya bekerja dengan akun domain asli. Butuh {{ prev.windows_pc.memory_mb / 1024 }} GB RAM per PC dan box sekitar 7 GB sekali unduh.
            <span v-if="winPcs.length" class="text-ink-200">Dipilih: {{ winPcs.join(', ') }}.</span>
          </p>
          <p v-if="heavy" class="border-b border-ink-800 bg-warn/10 p-3 text-xs text-warn">Lab ini butuh RAM cukup besar sebagai VM. Anda bisa menyalakan sebagian saja, misalnya <span class="font-mono">vagrant up {{ prev.nodes.slice(0, 2).map((n) => n.name).join(' ') }}</span>, atau pilih format Docker.</p>
          <table class="data-table">
            <thead><tr><th>Node</th><th>Berjalan sebagai</th><th>Alamat</th><th v-if="format === 'vagrant'">{{ winDcOn ? 'Sistem operasi dan paket' : 'Paket server' }}</th></tr></thead>
            <tbody>
              <tr v-for="n in prev.nodes" :key="n.name" :data-node="n.name">
                <td><div class="font-mono text-xs text-ink-100">{{ n.name }}</div><div class="text-xs text-ink-500">{{ n.label }}</div></td>
                <td class="font-mono text-xs">{{ n.runs_as }}</td>
                <td class="font-mono text-xs text-ink-300">{{ n.addresses }}</td>
                <td v-if="format === 'vagrant'" class="min-w-44">
                  <label v-if="winDcOn && n.office === 'ws'" class="mb-1 flex cursor-pointer items-center gap-2 text-xs" :data-test="`kit-winpc-${n.name}`">
                    <input type="checkbox" class="accent-cyan-400" :checked="winPcs.includes(n.name)" @change="toggleWinPc(n.name)" />
                    <span :class="winPcs.includes(n.name) ? 'text-ink-100' : 'text-ink-400'">Windows 11</span>
                  </label>
                  <span v-if="n.os === 'windows' && n.office === 'dc'" class="text-xs text-ink-500">AD DS, DNS, share (otomatis)</span>
                  <span v-else-if="n.os === 'windows'" class="text-xs text-ink-500">Join domain, karyawan simulasi, Sysmon (otomatis)</span>
                  <details v-else class="text-xs" :data-test="`kit-pkg-${n.name}`">
                    <summary class="cursor-pointer select-none text-accent-300">{{ (pkgs[n.name] || []).length ? `${pkgs[n.name].length} paket` : '+ Tambah paket' }}</summary>
                    <div class="mt-1 grid gap-1 rounded border border-ink-800 bg-ink-900 p-2">
                      <label v-for="sp in opts.server_packages" :key="sp.key" class="flex cursor-pointer items-start gap-2" :title="`apt: ${sp.apt.join(' ')} · port ${sp.ports}`">
                        <input type="checkbox" class="mt-0.5" :value="sp.key" :checked="(pkgs[n.name] || []).includes(sp.key)" :data-pkg="sp.key" @change="togglePkg(n.name, sp.key)" />
                        <span>{{ sp.title }}</span>
                      </label>
                    </div>
                  </details>
                  <div v-if="(pkgs[n.name] || []).length" class="mt-1 flex flex-wrap gap-1">
                    <CrBadge v-for="k in pkgs[n.name]" :key="k" tone="accent">{{ pkgTitle(k) }}</CrBadge>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
          <p v-if="prev.skipped.length" class="p-3 text-xs text-ink-500">Tidak dijalankan: {{ prev.skipped.map(s => s.label).join(', ') }} (internet disimulasikan, switch diwakili subnet).</p>
        </div>
      </CrPanel>
    </div>

    <CrPanel title="3. Unduh dan jalankan" class="mt-4">
      <ol class="mb-3 list-decimal space-y-1 pl-5 text-sm text-ink-300" data-test="kit-steps">
        <li v-for="s in STEPS[format]" :key="s">{{ s }}</li>
        <li v-if="winDcOn" data-test="kit-windows-steps">Untuk telemetri: di SIEM &amp; Analisis Log → Sumber log, tambah sumber jenis json, simpan file konfigurasinya sebagai <span class="font-mono">cr-shipper.env</span> di folder kit, lalu klik dua kali <span class="font-mono">kirim-ke-siem.bat</span>.</li>
      </ol>
      <ul class="mb-4 space-y-1 text-xs text-ink-500">
        <li>• Kit hanya berisi rancangan lab: tidak ada password, token, alamat server, atau flag CTF.</li>
        <li>• Jaringan lab terisolasi dan tidak punya akses internet. Jangan sambungkan ke jaringan produksi.</li>
        <li v-if="format === 'vagrant' && pkgQuery.length">• Paket server memakai konfigurasi bawaan Ubuntu, tanpa akun atau password tambahan.</li>
        <li v-if="winDcOn && winPcs.length">• <span class="font-mono">vagrant up</span> membuat domain controller lebih dulu, lalu PC Windows 11 join ke domain. Jalankan semua sekaligus atau DC lebih dulu.</li>
        <li v-if="winDcOn">• Password karyawan DEMO dibuat dari seed acak di komputer Anda saat <span class="font-mono">vagrant up</span> pertama, tidak ada di ZIP. Windows diunduh langsung dari box evaluasi, tidak ikut di ZIP.</li>
        <li>• Hasil di lab lokal tidak dinilai server. Flag CTF tetap dikirim lewat halaman CTF.</li>
      </ul>
      <CrButton variant="primary" :loading="busy" :disabled="!prev" data-test="kit-download" @click="get"><Download class="size-4" /> Unduh Lab Kit ({{ format === 'docker' ? 'Docker Compose' : 'Vagrant' }})</CrButton>
    </CrPanel>
  </template>
</template>
