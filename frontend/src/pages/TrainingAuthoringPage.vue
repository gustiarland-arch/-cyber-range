<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Eye, EyeOff, Paperclip, Plus, Trash2 } from 'lucide-vue-next'
import { api } from '@/services/api'
import { useUiStore } from '@/stores/ui'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrModal from '@/components/ui/CrModal.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import { fmtBytes } from '@/components/malware/mw'
import { CAT_LABEL, KIND_LABEL } from '@/components/training/tr'

const route = useRoute()
const router = useRouter()
const ui = useUiStore()
const tab = computed({ get: () => route.query.tab || 'challenges', set: (t) => router.replace({ query: { tab: t } }) })
const meta = ref(null)
const rows = ref(null)
const err = ref(null)
const PATH = { challenges: '/training/challenges', missions: '/training/missions' }
async function load() { rows.value = null; try { rows.value = await api(PATH[tab.value]); err.value = null } catch (e) { err.value = e } }
watch(tab, load)
onMounted(async () => { meta.value = await api('/training/meta').catch(() => null); load() })
async function publish(kind, r) {
  try { await api(`/training/${kind}/${r.id}/publish`, { method: 'POST', body: { is_published: !r.is_published } }); load() } catch (e) { ui.error(e) }
}
async function remove(kind, r) {
  try { await api(`/training/${kind}/${r.id}`, { method: 'DELETE' }); ui.success('Deleted'); load() } catch (e) { ui.error(e) }
}
const toDelete = ref(null)

// ---------------- challenge editor
const ch = ref(null)
const blankCh = () => ({ id: null, slug: '', title: '', category: 'misc', difficulty: 'beginner', points: 100, description: '', flag_format: 'CR{...}', flag: '', case_sensitive: false, lab_template: '', hints: [], attachments: [], flag_set: false })
async function editCh(r) {
  if (!r) { ch.value = blankCh(); return }
  try { const d = await api(`/training/challenges/${r.id}/authoring`); ch.value = { ...d, flag: '' } } catch (e) { ui.error(e) }
}
const saving = ref(false)
async function saveCh() {
  saving.value = true
  const c = ch.value
  const body = { slug: c.slug, title: c.title, category: c.category, difficulty: c.difficulty, points: Number(c.points), description: c.description,
    flag_format: c.flag_format, flag: c.flag || null, case_sensitive: c.case_sensitive, lab_template: c.lab_template || null,
    hints: c.hints.map((h) => ({ text: h.text, cost: Number(h.cost) })) }
  try {
    const r = await api(c.id ? `/training/challenges/${c.id}` : '/training/challenges', { method: c.id ? 'PUT' : 'POST', body })
    ui.success(c.id ? 'Challenge disimpan' : 'Challenge dibuat sebagai draf — tambahkan file, lalu terbitkan')
    await editCh({ id: r.id }); load()
  } catch (e) { ui.error(e) } finally { saving.value = false }
}
async function attach(e) {
  const f = e.target.files?.[0]
  if (!f) return
  const fd = new FormData(); fd.append('file', f)
  try { await api(`/training/challenges/${ch.value.id}/attachments`, { method: 'POST', form: fd }); await editCh({ id: ch.value.id }) } catch (er) { ui.error(er) }
  e.target.value = ''
}
async function detach(a) {
  try { await api(`/training/challenges/${ch.value.id}/attachments/${encodeURIComponent(a.name)}`, { method: 'DELETE' }); await editCh({ id: ch.value.id }) } catch (e) { ui.error(e) }
}

// ---------------- mission editor
const mi = ref(null)
async function editMi(r) {
  if (!r) { mi.value = { id: null, slug: '', title: '', briefing: '', difficulty: 'beginner', lab_template: '', objectives: [{ title: '', kind: 'answer', points: 25, hint: '', answer: '' }] }; return }
  try { const d = await api(`/training/missions/${r.id}/authoring`); mi.value = { ...d, lab_template: d.lab_template || '', objectives: d.objectives.map((o) => ({ ...o, answer: '' })) } } catch (e) { ui.error(e) }
}
async function saveMi() {
  const m = mi.value
  const objectives = m.objectives.map((o) => {
    const x = { title: o.title, kind: o.kind, points: Number(o.points), hint: o.hint || '' }
    if (o.kind === 'answer' && o.answer) x.answer = o.answer
    if (o.kind === 'challenge') x.slug = o.slug
    if (o.kind === 'vuln_finding') x.code = o.code
    if (o.kind === 'assessment') x.scenario = o.scenario
    if (o.kind === 'sensor') x.slug = o.slug || 'any'
    return x
  })
  try {
    const r = await api(m.id ? `/training/missions/${m.id}` : '/training/missions', { method: m.id ? 'PUT' : 'POST', body: { slug: m.slug, title: m.title, briefing: m.briefing, difficulty: m.difficulty, lab_template: m.lab_template || null, objectives } })
    ui.success('Misi disimpan'); await editMi({ id: r.id }); load()
  } catch (e) { ui.error(e) }
}
const KIND = { challenges: 'challenges', missions: 'missions' }
function open(r) { if (tab.value === 'challenges') editCh(r); else editMi(r) }
</script>

<template>
  <PageHeader section="Latihan: CTF & Misi" title="Penyusunan Latihan" subtitle="Buat draf, lampirkan file lalu terbitkan. Flag dan jawaban bersifat write-only: di-hash saat disimpan dan tidak pernah ditampilkan lagi.">
    <CrButton variant="primary" data-test="new-item" @click="open(null)"><Plus class="size-4" /> Baru {{ tab.slice(0, -1) }}</CrButton>
  </PageHeader>
  <nav class="mb-4 flex gap-1 border-b border-ink-700" role="tablist">
    <button v-for="[k, l] in [['challenges', 'CTF challenges'], ['missions', 'Misi']]" :key="k" role="tab" :aria-selected="tab === k" :data-tab="k"
      :class="['-mb-px border-b-2 px-3 py-2 text-sm', tab === k ? 'border-accent-400 text-ink-100' : 'border-transparent text-ink-400 hover:text-ink-200']" @click="tab = k">{{ l }}</button>
  </nav>
  <div class="panel">
    <CrState v-if="err" kind="error" :message="err.message" @retry="load" />
    <CrState v-else-if="!rows" kind="loading" />
    <CrState v-else-if="!rows.length" kind="empty" title="Belum ada isi" />
    <table v-else class="w-full text-sm">
      <thead class="text-left text-xs text-ink-500"><tr><th class="px-3 py-2">Judul</th><th>Detail</th><th>Status</th><th class="px-3 text-right">Aksi</th></tr></thead>
      <tbody class="divide-y divide-ink-800">
        <tr v-for="r in rows" :key="r.id" :data-row="r.slug">
          <td class="px-3 py-2"><button class="text-left text-ink-100 hover:text-accent-200" @click="open(r)">{{ r.title }}</button><div class="font-mono text-[11px] text-ink-500">{{ r.slug }}</div></td>
          <td class="text-xs text-ink-400">
            <template v-if="tab === 'challenges'">{{ CAT_LABEL[r.category] }} · {{ r.points }} poin · {{ r.solves }} solves</template>
            <template v-else>{{ r.difficulty }} · {{ r.objectives }} objectives · {{ r.points }} poin</template>
          </td>
          <td><CrBadge :tone="r.is_published ? 'ok' : 'warn'">{{ r.is_published ? 'published' : 'draft' }}</CrBadge> <CrBadge v-if="r.is_builtin">builtin</CrBadge></td>
          <td class="px-3 text-right">
            <CrButton size="sm" variant="ghost" :data-publish="r.slug" @click="publish(KIND[tab], r)"><component :is="r.is_published ? EyeOff : Eye" class="size-3.5" /> {{ r.is_published ? 'Unpublish' : 'Publish' }}</CrButton>
            <CrButton v-if="!r.is_builtin" size="sm" variant="ghost" @click="toDelete = { kind: KIND[tab], r }"><Trash2 class="size-3.5" /></CrButton>
          </td>
        </tr>
      </tbody>
    </table>
  </div>

  <!-- challenge -->
  <CrModal :open="!!ch" :title="ch?.id ? `Edit challenge` : 'Challenge baru'" width="max-w-3xl" @close="ch = null">
    <form v-if="ch" id="chform" class="grid gap-3 md:grid-cols-2" @submit.prevent="saveCh">
      <p v-if="ch.is_builtin" class="col-span-2 rounded border border-warn/40 p-2 text-xs text-warn">Challenge bawaan dikelola oleh platform; hanya status publikasi yang dapat diubah.</p>
      <label class="text-xs text-ink-400">Judul<input v-model="ch.title" class="input mt-1 w-full" required minlength="3" data-field="title" /></label>
      <label class="text-xs text-ink-400">Slug<input v-model="ch.slug" class="input mt-1 w-full font-mono" required pattern="[a-z0-9][a-z0-9\-]{1,62}[a-z0-9]" data-field="slug" /></label>
      <label class="text-xs text-ink-400">Kategori<select v-model="ch.category" class="input mt-1 w-full"><option v-for="c in meta?.categories || []" :key="c" :value="c">{{ CAT_LABEL[c] }}</option></select></label>
      <label class="text-xs text-ink-400">Tingkat kesulitan<select v-model="ch.difficulty" class="input mt-1 w-full"><option v-for="l in meta?.levels || []" :key="l">{{ l }}</option></select></label>
      <label class="text-xs text-ink-400">Poin<input v-model="ch.points" type="number" min="10" max="2000" class="input mt-1 w-full" /></label>
      <label class="text-xs text-ink-400">Template lab latihan<select v-model="ch.lab_template" class="input mt-1 w-full"><option value="">none</option><option v-for="t in meta?.lab_templates || []" :key="t.key" :value="t.key">{{ t.title }}</option></select></label>
      <label class="col-span-2 text-xs text-ink-400">Deskripsi (Markdown)<textarea v-model="ch.description" rows="6" class="input mt-1 w-full font-mono text-xs" required minlength="10" data-field="description" /></label>
      <label class="text-xs text-ink-400">Flag {{ ch.flag_set ? '(set — leave empty to keep)' : '' }}<input v-model="ch.flag" type="password" autocomplete="new-password" class="input mt-1 w-full font-mono" :required="!ch.id" data-field="flag" /></label>
      <label class="text-xs text-ink-400">Format flag yang ditampilkan ke peserta<input v-model="ch.flag_format" class="input mt-1 w-full font-mono" /></label>
      <label class="col-span-2 flex items-center gap-2 text-xs text-ink-300"><input v-model="ch.case_sensitive" type="checkbox" class="accent-cyan-400" /> Flag peka huruf besar/kecil</label>
      <div class="col-span-2">
        <div class="mb-1 flex items-center justify-between text-xs text-ink-400">Hints <CrButton size="sm" variant="ghost" type="button" @click="ch.hints.push({ text: '', cost: 10 })"><Plus class="size-3.5" /> Hint</CrButton></div>
        <div v-for="(h, i) in ch.hints" :key="i" class="mb-1 flex gap-2"><input v-model="h.text" class="input flex-1" placeholder="Teks hint" required minlength="3" /><input v-model="h.cost" type="number" min="0" class="input w-20" aria-label="Biaya" />
          <CrButton size="sm" variant="ghost" type="button" @click="ch.hints.splice(i, 1)"><Trash2 class="size-3.5" /></CrButton></div>
      </div>
      <div v-if="ch.id && !ch.is_builtin" class="col-span-2">
        <div class="mb-1 flex items-center justify-between text-xs text-ink-400">File
          <label class="flex cursor-pointer items-center gap-1 text-accent-300 hover:underline"><Paperclip class="size-3.5" /> Lampirkan<input type="file" class="hidden" aria-label="Lampirkan file" @change="attach" /></label></div>
        <p v-for="a in ch.attachments" :key="a.name" class="flex items-center gap-2 text-xs"><span class="font-mono">{{ a.name }}</span><span class="text-ink-500">{{ fmtBytes(a.size) }}</span>
          <button type="button" class="ml-auto text-bad" @click="detach(a)">remove</button></p>
      </div>
    </form>
    <template #footer><CrButton @click="ch = null">Tutup</CrButton><CrButton v-if="!ch?.is_builtin" type="submit" form="chform" variant="primary" :loading="saving" data-test="save-challenge">Simpan</CrButton></template>
  </CrModal>


  <!-- mission -->
  <CrModal :open="!!mi" :title="mi?.id ? 'Ubah misi' : 'Misi baru'" width="max-w-3xl" @close="mi = null">
    <form v-if="mi" id="miform" class="grid gap-3 md:grid-cols-2" @submit.prevent="saveMi">
      <p v-if="mi.is_builtin" class="col-span-2 rounded border border-warn/40 p-2 text-xs text-warn">Misi bawaan: hanya-baca kecuali publikasi.</p>
      <label class="text-xs text-ink-400">Judul<input v-model="mi.title" class="input mt-1 w-full" required minlength="3" /></label>
      <label class="text-xs text-ink-400">Slug<input v-model="mi.slug" class="input mt-1 w-full font-mono" required /></label>
      <label class="text-xs text-ink-400">Tingkat kesulitan<select v-model="mi.difficulty" class="input mt-1 w-full"><option v-for="l in meta?.levels || []" :key="l">{{ l }}</option></select></label>
      <label class="text-xs text-ink-400">Template lab<select v-model="mi.lab_template" class="input mt-1 w-full"><option value="">none</option><option v-for="t in meta?.lab_templates || []" :key="t.key" :value="t.key">{{ t.title }}</option></select></label>
      <label class="col-span-2 text-xs text-ink-400">Briefing (Markdown)<textarea v-model="mi.briefing" rows="4" class="input mt-1 w-full" required minlength="10" /></label>
      <div class="col-span-2">
        <div class="mb-1 flex items-center justify-between text-xs text-ink-400">Tujuan <CrButton size="sm" variant="ghost" type="button" @click="mi.objectives.push({ title: '', kind: 'answer', points: 25, hint: '', answer: '' })"><Plus class="size-3.5" /> Tujuan</CrButton></div>
        <div v-for="(o, i) in mi.objectives" :key="i" class="mb-2 grid gap-2 rounded border border-ink-700 p-2 md:grid-cols-6">
          <input v-model="o.title" class="input md:col-span-3" placeholder="Tujuan" required minlength="3" />
          <select v-model="o.kind" class="input md:col-span-2"><option v-for="k in meta?.objective_kinds || []" :key="k" :value="k">{{ KIND_LABEL[k] }}</option></select>
          <input v-model="o.points" type="number" min="0" class="input" aria-label="Poin" />
          <input v-if="o.kind === 'answer'" v-model="o.answer" type="password" autocomplete="new-password" class="input font-mono md:col-span-3" :placeholder="o.answer_set ? 'jawaban sudah diatur — kosongkan untuk mempertahankan' : 'jawaban yang diharapkan'" />
          <select v-if="o.kind === 'sensor'" v-model="o.slug" class="input md:col-span-3" aria-label="Jenis sensor"><option value="any">Zeek atau Suricata</option><option value="zeek">Zeek</option><option value="suricata">Suricata</option></select>
          <input v-if="o.kind === 'challenge'" v-model="o.slug" class="input font-mono md:col-span-3" placeholder="challenge slug" />
          <input v-if="o.kind === 'vuln_finding'" v-model="o.code" class="input font-mono md:col-span-3" placeholder="kode kerentanan, mis. CR-VA-005" />
          <input v-if="o.kind === 'assessment'" v-model="o.scenario" class="input font-mono md:col-span-3" placeholder="kode skenario, mis. RT-WEB-01" />
          <input v-model="o.hint" class="input md:col-span-2" placeholder="hint (opsional)" />
          <CrButton size="sm" variant="ghost" type="button" @click="mi.objectives.splice(i, 1)"><Trash2 class="size-3.5" /></CrButton>
        </div>
      </div>
    </form>
    <template #footer><CrButton @click="mi = null">Tutup</CrButton><CrButton v-if="!mi?.is_builtin" type="submit" form="miform" variant="primary">Simpan misi</CrButton></template>
  </CrModal>

  <CrModal :open="!!toDelete" title="Hapus?" @close="toDelete = null">
    <p class="text-sm text-ink-300">Hapus <b>{{ toDelete?.r.title }}</b>? Item yang sudah punya riwayat skor tidak dapat dihapus; batalkan publikasinya.</p>
    <template #footer><CrButton @click="toDelete = null">Batal</CrButton><CrButton variant="danger" @click="remove(toDelete.kind, toDelete.r); toDelete = null">Hapus</CrButton></template>
  </CrModal>
</template>
