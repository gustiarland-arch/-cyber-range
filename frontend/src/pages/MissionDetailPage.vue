<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ArrowLeft, CheckCircle2, Circle, PackageOpen, RefreshCw, Server } from 'lucide-vue-next'
import { api } from '@/services/api'
import { ago } from '@/services/format'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrPanel from '@/components/ui/CrPanel.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import { kitLink } from '@/services/labkit'
import { DIFF_LABEL, DIFF_TONE, KIND_LABEL, launchPracticeLab, renderMarkdown } from '@/components/training/tr'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const ui = useUiStore()
const m = ref(null)
const err = ref(null)
const answers = reactive({})
const feedback = reactive({})
const checking = ref(false)
const lastCheck = ref({})
const canPlay = computed(() => auth.can('training.participate'))
const LINKS = { challenge: 'ctf', vuln_finding: 'vulnerabilities', assessment: 'attack-simulation' }
async function load() { try { m.value = await api(`/training/missions/${route.params.id}`); err.value = null } catch (e) { err.value = e } }
async function check() {
  checking.value = true
  try {
    const r = await api(`/training/missions/${m.value.id}/check`, { method: 'POST' })
    lastCheck.value = Object.fromEntries(r.results.map((x) => [x.id, x]))
    const n = r.results.filter((x) => x.new).length
    ui.success(n ? `${n} objective(s) newly verified` : 'Checked: no new tujuan tercapai')
    load()
  } catch (e) { ui.error(e) } finally { checking.value = false }
}
async function answer(o) {
  try {
    const r = await api(`/training/missions/${m.value.id}/objectives/${o.id}/answer`, { method: 'POST', body: { answer: answers[o.id] || '' } })
    feedback[o.id] = r
    if (r.correct) load()
  } catch (e) { ui.error(e) }
}
const launching = ref(false)
async function practice() {
  launching.value = true
  try { const r = await launchPracticeLab('mission', m.value.id); ui.success('Lab latihan dibuat dan sedang di-deploy'); router.push({ name: 'lab-detail', params: { id: r.lab_id } }) } catch (e) { ui.error(e) } finally { launching.value = false }
}
const done = computed(() => m.value?.objectives.filter((o) => o.met).length || 0)
onMounted(load)
</script>

<template>
  <RouterLink :to="{ name: 'missions' }" class="mb-3 inline-flex items-center gap-1 text-xs text-ink-400 hover:text-ink-200"><ArrowLeft class="size-3.5" /> Semua misi</RouterLink>
  <CrState v-if="err" kind="error" :message="err.message" @retry="load" />
  <CrState v-else-if="!m" kind="loading" />
  <template v-else>
    <PageHeader section="Pusat Misi" :title="m.title" :subtitle="`${done}/${m.objectives.length} tujuan tercapai`">
      <CrButton v-if="m.lab_template && canPlay && auth.can('lab.operate')" :loading="launching" data-test="practice-lab" @click="practice"><Server class="size-4" /> Jalankan lab misi</CrButton>
      <CrButton v-if="m.lab_template && auth.can('lab.kit.download')" data-test="kit-link" @click="router.push(kitLink(m.lab_template))"><PackageOpen class="size-4" /> Unduh Lab Kit</CrButton>
      <CrButton v-if="canPlay" variant="primary" :loading="checking" data-test="check-mission" @click="check"><RefreshCw class="size-4" /> Verifikasi tujuan</CrButton>
    </PageHeader>
    <div class="grid gap-4 lg:grid-cols-3">
      <CrPanel title="Briefing">
        <template #actions><CrBadge :tone="DIFF_TONE[m.difficulty]">{{ DIFF_LABEL[m.difficulty] || m.difficulty }}</CrBadge></template>
        <!-- eslint-disable-next-line vue/no-v-html -- renderMarkdown escapes all input -->
        <div class="text-sm text-ink-300" v-html="renderMarkdown(m.briefing)" />
        <p v-if="m.is_author" class="mt-2 text-xs text-warn">Anda menyusun misi ini; tujuan yang Anda capai tidak dinilai.</p>
      </CrPanel>
      <CrPanel title="Tujuan" class="lg:col-span-2">
        <ol class="space-y-3">
          <li v-for="o in m.objectives" :key="o.id" :data-objective="o.position" :class="['rounded border p-3', o.met ? 'border-ok/40 bg-ok/5' : 'border-ink-700']">
            <div class="flex items-start gap-2">
              <CheckCircle2 v-if="o.met" class="mt-0.5 size-4 shrink-0 text-ok" /><Circle v-else class="mt-0.5 size-4 shrink-0 text-ink-600" />
              <div class="flex-1">
                <p class="text-sm font-medium text-ink-100">{{ o.title }}</p>
                <p class="mt-0.5 flex flex-wrap items-center gap-2 text-xs text-ink-500"><CrBadge>{{ KIND_LABEL[o.kind] }}</CrBadge> {{ o.points }} pts
                  <RouterLink v-if="LINKS[o.kind] && !o.met" :to="{ name: LINKS[o.kind] }" class="text-accent-300 hover:underline">buka →</RouterLink></p>
                <p v-if="o.met" class="mt-1 text-xs text-ok" data-test="evidence">{{ o.evidence }} · {{ ago(o.met_at) }}</p>
                <p v-else-if="lastCheck[o.id] && o.kind !== 'answer'" class="mt-1 text-xs text-ink-400">Not yet: {{ lastCheck[o.id].evidence }}</p>
                <p v-if="o.hint && !o.met" class="mt-1 text-xs text-ink-400">Hint: {{ o.hint }}</p>
                <form v-if="o.kind === 'answer' && !o.met && canPlay" class="mt-2 flex gap-2" @submit.prevent="answer(o)">
                  <input v-model="answers[o.id]" class="input flex-1 font-mono" maxlength="512" placeholder="Jawaban Anda" :aria-label="`Answer for objective ${o.position}`" />
                  <CrButton type="submit" :disabled="!answers[o.id]">Kirim</CrButton>
                </form>
                <p v-if="feedback[o.id] && !feedback[o.id].correct" class="mt-1 text-xs text-bad" data-test="answer-wrong">Jawaban salah.</p>
                <p v-if="feedback[o.id]?.correct && feedback[o.id].scored === false" class="mt-1 text-xs text-warn">{{ feedback[o.id].reason }}</p>
              </div>
            </div>
          </li>
        </ol>
      </CrPanel>
    </div>
  </template>
</template>
