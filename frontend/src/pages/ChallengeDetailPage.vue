<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ArrowLeft, CheckCircle2, Download, Flag, Lightbulb, Lock, PackageOpen, Server, XCircle } from 'lucide-vue-next'
import { api, download } from '@/services/api'
import { ago } from '@/services/format'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrModal from '@/components/ui/CrModal.vue'
import CrPanel from '@/components/ui/CrPanel.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import { kitLink } from '@/services/labkit'
import { fmtBytes } from '@/components/malware/mw'
import { CAT_LABEL, DIFF_TONE, launchPracticeLab, renderMarkdown } from '@/components/training/tr'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const ui = useUiStore()
const c = ref(null)
const err = ref(null)
const flag = ref('')
const result = ref(null)
const busy = ref(false)
const confirmHint = ref(null)
const canPlay = computed(() => auth.can('training.participate'))
async function load() { try { c.value = await api(`/training/challenges/${route.params.id}`); err.value = null } catch (e) { err.value = e } }
async function submit() {
  busy.value = true
  try {
    result.value = await api(`/training/challenges/${c.value.id}/submit`, { method: 'POST', body: { flag: flag.value } })
    if (result.value.correct) { flag.value = ''; load() }
  } catch (e) { ui.error(e) } finally { busy.value = false }
}
const ruleSrc = ref('')
const ruleReport = ref(null)
async function submitRule() {
  busy.value = true
  try {
    const r = await api(`/training/challenges/${c.value.id}/submit-rule`, { method: 'POST', body: { source: ruleSrc.value } })
    ruleReport.value = r
    if (r.correct && r.scored) { ui.success(`Rule lulus! +${r.points} poin`); load() }
  } catch (e) { ui.error(e) } finally { busy.value = false }
}
const DIFF_ID = { beginner: 'pemula', intermediate: 'menengah', advanced: 'mahir' }
async function unlock(h) {
  try { await api(`/training/challenges/${c.value.id}/hints/${h.id}/unlock`, { method: 'POST' }); confirmHint.value = null; load() } catch (e) { ui.error(e) }
}
async function dl(a) { try { await download(`/training/challenges/${c.value.id}/attachments/${encodeURIComponent(a.name)}`, null, a.name) } catch (e) { ui.error(e) } }
const launching = ref(false)
async function practice() {
  launching.value = true
  try { const r = await launchPracticeLab('challenge', c.value.id); ui.success('Lab latihan dibuat dan sedang di-deploy'); router.push({ name: 'lab-detail', params: { id: r.lab_id } }) } catch (e) { ui.error(e) } finally { launching.value = false }
}
onMounted(load)
</script>

<template>
  <RouterLink :to="{ name: 'ctf' }" class="mb-3 inline-flex items-center gap-1 text-xs text-ink-400 hover:text-ink-200"><ArrowLeft class="size-3.5" /> Semua challenge</RouterLink>
  <CrState v-if="err" kind="error" :message="err.message" @retry="load" />
  <CrState v-else-if="!c" kind="loading" />
  <template v-else>
    <PageHeader section="CTF Challenges" :title="c.title" :subtitle="`${CAT_LABEL[c.category] || c.category} · ${DIFF_ID[c.difficulty] || c.difficulty} · ${c.points} poin · ${c.solves} solves`">
      <CrButton v-if="c.lab_template && auth.can('lab.operate') && canPlay" :loading="launching" data-test="practice-lab" @click="practice"><Server class="size-4" /> Jalankan lab latihan</CrButton>
      <CrButton v-if="c.lab_template && auth.can('lab.kit.download')" data-test="kit-link" @click="router.push(kitLink(c.lab_template))"><PackageOpen class="size-4" /> Unduh Lab Kit</CrButton>
    </PageHeader>
    <div class="grid gap-4 lg:grid-cols-3">
      <div class="space-y-4 lg:col-span-2">
        <CrPanel title="Ringkas">
          <!-- eslint-disable-next-line vue/no-v-html -- renderMarkdown escapes all input -->
          <div class="text-sm text-ink-300" data-test="challenge-description" v-html="renderMarkdown(c.description)" />
          <p class="mt-2 text-xs text-ink-500">Format flag: <code class="font-mono text-accent-200">{{ c.flag_format }}</code></p>
        </CrPanel>
        <CrPanel v-if="c.attachments.length" title="File">
          <ul class="divide-y divide-ink-800">
            <li v-for="a in c.attachments" :key="a.name" class="flex items-center gap-3 py-2 text-sm">
              <span class="font-mono text-ink-100">{{ a.name }}</span><span class="text-xs text-ink-500">{{ fmtBytes(a.size) }}</span>
              <span class="hidden truncate font-mono text-[10px] text-ink-600 md:inline" :title="a.sha256">sha256 {{ a.sha256.slice(0, 16) }}…</span>
              <CrButton size="sm" class="ml-auto" :data-download="a.name" @click="dl(a)"><Download class="size-3.5" /> Unduh</CrButton>
            </li>
          </ul>
          <p class="mt-2 text-[11px] text-ink-500">Artefak pelatihan yang dibuat untuk latihan ini. Bukan telemetri dan tidak dimasukkan ke SIEM.</p>
        </CrPanel>
        <CrPanel v-if="c.kind !== 'flag'" :title="c.kind === 'sigma' ? 'Tulis rule Sigma' : 'Tulis rule YARA'" data-test="rule-panel">
          <div v-if="c.solved" class="mb-2 flex items-center gap-2 text-sm text-ok" data-test="solved-banner"><CheckCircle2 class="size-4" /> Lulus dengan {{ c.my_points }} poin {{ ago(c.solved_at) }}</div>
          <p class="mb-2 text-xs text-ink-400">Rule Anda dinilai otomatis terhadap data di lampiran <b>dan</b> beberapa data tersembunyi. Lulus bila semua yang berbahaya terdeteksi dan tidak ada false positive.</p>
          <template v-if="canPlay && !evClosed">
            <textarea v-model="ruleSrc" class="input h-56 w-full font-mono text-xs" spellcheck="false" maxlength="20000" data-test="rule-source"
              :placeholder="c.kind === 'sigma' ? 'title: ...\nlogsource:\n  category: webserver\ndetection:\n  ...' : 'rule Nama_Rule {\n  strings:\n    $a = &quot;...&quot;\n  condition:\n    $a\n}'" aria-label="Rule" />
            <div class="mt-2 flex justify-end"><CrButton variant="primary" :loading="busy" :disabled="!ruleSrc.trim()" data-test="submit-rule" @click="submitRule"><CheckCircle2 class="size-4" /> Nilai rule</CrButton></div>
          </template>
          <div v-if="ruleReport" class="mt-3 rounded border border-ink-700 p-3 text-sm" data-test="rule-report">
            <p v-if="!ruleReport.report.ok" class="flex items-start gap-1 text-bad"><XCircle class="mt-0.5 size-4 shrink-0" /> Rule belum bisa dipakai: {{ $tr(ruleReport.report.error) }}</p>
            <template v-else-if="c.kind === 'sigma'">
              <p :class="ruleReport.correct ? 'text-ok' : 'text-warn'" class="font-medium">{{ ruleReport.correct ? 'Lulus! Semua serangan terdeteksi tanpa false positive.' : 'Belum lulus.' }}</p>
              <ul class="mt-1 list-disc pl-5 text-xs text-ink-300">
                <li>Terdeteksi: {{ ruleReport.report.detected }} dari {{ ruleReport.report.malicious_total }} event berbahaya (termasuk yang tersembunyi)</li>
                <li>False positive: {{ ruleReport.report.false_positives }}</li>
                <li v-if="ruleReport.report.missed_visible.length">Event berbahaya di lampiran yang terlewat: id {{ ruleReport.report.missed_visible.join(', ') }}</li>
                <li v-if="ruleReport.report.false_positive_visible.length">Event normal di lampiran yang ikut terdeteksi: id {{ ruleReport.report.false_positive_visible.join(', ') }}</li>
                <li>Uji data tersembunyi: {{ ruleReport.report.hidden_passed ? 'lulus' : 'belum lulus (rule terlalu sempit atau terlalu umum)' }}</li>
              </ul>
            </template>
            <template v-else>
              <p :class="ruleReport.correct ? 'text-ok' : 'text-warn'" class="font-medium">{{ ruleReport.correct ? 'Lulus! Rule cocok hanya dengan dropper.' : 'Belum lulus.' }}</p>
              <ul class="mt-1 space-y-0.5 text-xs">
                <li v-for="s in ruleReport.report.samples" :key="s.name" :class="s.ok ? 'text-ok' : 'text-bad'">
                  {{ s.ok ? '✓' : '✗' }} <span class="font-mono">{{ s.name }}</span>: {{ s.matched ? 'cocok' : 'tidak cocok' }} (seharusnya {{ s.should_match ? 'cocok' : 'tidak cocok' }})</li>
                <li :class="ruleReport.report.hidden_passed ? 'text-ok' : 'text-bad'">{{ ruleReport.report.hidden_passed ? '✓' : '✗' }} {{ ruleReport.report.hidden_total }} sampel tersembunyi</li>
              </ul>
            </template>
          </div>
        </CrPanel>
        <CrPanel v-else title="Kirim flag">
          <div v-if="c.solved" class="flex items-center gap-2 text-sm text-ok" data-test="solved-banner"><CheckCircle2 class="size-4" /> Terpecahkan dengan {{ c.my_points }} poin {{ ago(c.solved_at) }}</div>
          <form v-else-if="canPlay" class="flex flex-wrap gap-2" @submit.prevent="submit">
            <input v-model="flag" class="input flex-1 font-mono" :placeholder="c.flag_format" aria-label="Flag" maxlength="512" autocomplete="off" spellcheck="false" />
            <CrButton type="submit" variant="primary" :loading="busy" :disabled="!flag.trim()" data-test="submit-flag"><Flag class="size-4" /> Kirim</CrButton>
          </form>
          <p v-else class="text-sm text-ink-400">Meninjau sebagai instruktur: mengirim memerlukan <code>training.participate</code>.</p>
          <div v-if="result && !c.solved" class="mt-3 text-sm" data-test="flag-result">
            <p v-if="result.correct && result.scored === false" class="text-warn">Benar, tetapi tidak dinilai: {{ result.reason }}</p>
            <p v-else-if="!result.correct" class="flex items-center gap-1 text-bad"><XCircle class="size-4" /> Flag salah · {{ result.remaining_attempts }} percobaan tersisa dalam jendela ini</p>
          </div>
          <p v-if="c.is_author" class="mt-2 text-xs text-warn">Anda menyusun challenge ini; solve Anda tidak dinilai.</p>
        </CrPanel>
      </div>
      <div class="space-y-4">
        <CrPanel title="Penilaian">
          <dl class="grid grid-cols-2 gap-y-1 text-sm">
            <dt class="text-ink-500">Nilai dasar</dt><dd class="text-right font-mono">{{ c.points }}</dd>
            <dt class="text-ink-500">Penalti hint</dt><dd class="text-right font-mono text-warn">−{{ c.hint_penalty }}</dd>
            <dt class="text-ink-500">Anda dapat memperoleh</dt><dd class="text-right font-mono text-accent-200" data-test="potential">{{ c.solved ? c.my_points : c.potential_points }}</dd>
            <dt class="text-ink-500">Tingkat kesulitan</dt><dd class="text-right"><CrBadge :tone="DIFF_TONE[c.difficulty]">{{ DIFF_ID[c.difficulty] || c.difficulty }}</CrBadge></dd>
          </dl>
        </CrPanel>
        <CrPanel title="Hints">
          <CrState v-if="!c.hints.length" kind="empty" title="Tidak ada hint" />
          <ol v-else class="space-y-2">
            <li v-for="h in c.hints" :key="h.id" class="rounded border border-ink-700 p-2 text-sm" :data-hint="h.position">
              <p v-if="h.unlocked" class="flex gap-2 text-ink-200"><Lightbulb class="mt-0.5 size-4 shrink-0 text-warn" /><!-- eslint-disable-next-line vue/no-v-html --><span v-html="renderMarkdown(h.text)" /></p>
              <div v-else class="flex items-center gap-2 text-ink-400"><Lock class="size-4" /> Hint {{ h.position }}
                <CrButton v-if="canPlay" size="sm" class="ml-auto" @click="confirmHint = h">Buka (−{{ h.cost }})</CrButton></div>
            </li>
          </ol>
        </CrPanel>
      </div>
    </div>
    <CrModal :open="!!confirmHint" title="Buka hint?" @close="confirmHint = null">
      <p class="text-sm text-ink-300">Membuka hint {{ confirmHint?.position }} mengurangi poin yang dapat Anda peroleh untuk challenge ini sebesar <b>{{ confirmHint?.cost }}</b>
        (tidak pernah di bawah 10% nilainya). Tindakan ini tidak dapat dibatalkan.</p>
      <template #footer><CrButton @click="confirmHint = null">Batal</CrButton><CrButton variant="primary" data-test="confirm-hint" @click="unlock(confirmHint)">Buka</CrButton></template>
    </CrModal>
  </template>
</template>
