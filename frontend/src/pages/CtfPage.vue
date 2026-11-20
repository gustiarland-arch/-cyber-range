<script setup>
import { useRoute } from 'vue-router'
import { computed, onMounted, ref } from 'vue'
import { CheckCircle2, Flag, PencilRuler, Server } from 'lucide-vue-next'
import { api } from '@/services/api'
import { useAuthStore } from '@/stores/auth'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import MyProgress from '@/components/training/MyProgress.vue'
import { CAT_LABEL, DIFF_LABEL, DIFF_TONE } from '@/components/training/tr'

const auth = useAuthStore()
const list = ref(null)
const err = ref(null)
const cat = ref('')
const show = ref('all')
const diff = ref(['beginner', 'intermediate', 'advanced'].includes(useRoute().query.difficulty) ? useRoute().query.difficulty : '')
async function load() {
  try { list.value = await api('/training/challenges'); err.value = null } catch (e) { err.value = e }
}
const cats = computed(() => [...new Set((list.value || []).map((c) => c.category))])
const shown = computed(() => (list.value || []).filter((c) => (!cat.value || c.category === cat.value) && (!diff.value || c.difficulty === diff.value) && (show.value === 'all' || (show.value === 'solved') === c.solved)))
const total = computed(() => (list.value || []).filter((c) => c.is_published).reduce((a, c) => a + c.points, 0))
onMounted(load)
</script>

<template>
  <PageHeader section="Latihan: CTF & Misi" title="CTF Challenges" subtitle="Tantangan latihan bertingkat dari pemula sampai mahir. Jawab dengan flag CR{...} atau tulis rule yang dinilai otomatis.">
    <RouterLink v-if="auth.can('training.manage')" :to="{ name: 'training-authoring', query: { tab: 'challenges' } }"><CrButton><PencilRuler class="size-4" /> Susun challenge</CrButton></RouterLink>
  </PageHeader>
  <MyProgress v-if="auth.can('training.participate')" />
  <div class="panel mb-4 flex flex-wrap items-center gap-2 p-3">
    <button :class="['rounded border px-2 py-1 text-xs', !cat ? 'border-accent-500/50 bg-accent-500/10 text-accent-200' : 'border-ink-700 text-ink-300']" @click="cat = ''">Semua kategori</button>
    <button v-for="c in cats" :key="c" :data-cat="c" :class="['rounded border px-2 py-1 text-xs', cat === c ? 'border-accent-500/50 bg-accent-500/10 text-accent-200' : 'border-ink-700 text-ink-300']" @click="cat = c">{{ CAT_LABEL[c] || c }}</button>
    <select v-model="diff" class="input ml-auto w-36" aria-label="Tingkat" data-test="difficulty-filter"><option value="">semua tingkat</option><option value="beginner">pemula</option><option value="intermediate">menengah</option><option value="advanced">mahir</option></select>
    <select v-model="show" class="input w-36" aria-label="Tampilkan"><option value="all">semua</option><option value="open">belum terpecahkan</option><option value="solved">terpecahkan</option></select>
    <span class="text-xs text-ink-500">{{ total }} poin tersedia</span>
  </div>
  <CrState v-if="err" kind="error" :message="err.message" @retry="load" />
  <CrState v-else-if="!list" kind="loading" />
  <CrState v-else-if="!shown.length" kind="empty" title="Belum ada challenge" message="Tidak ada challenge terbit yang cocok dengan filter ini." />
  <div v-else class="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
    <RouterLink v-for="c in shown" :key="c.id" :to="{ name: 'ctf-challenge', params: { id: c.id } }" :data-challenge="c.slug"
      :class="['panel block p-4 transition hover:border-accent-500/40', c.solved ? 'border-ok/40' : '']">
      <div class="mb-2 flex items-center gap-2">
        <Flag class="size-4 text-accent-300" />
        <span class="flex-1 truncate font-semibold text-ink-100">{{ c.title }}</span>
        <span class="font-mono text-sm text-accent-200">{{ c.points }}</span>
      </div>
      <div class="flex flex-wrap items-center gap-1.5 text-xs">
        <CrBadge>{{ CAT_LABEL[c.category] || c.category }}</CrBadge>
        <CrBadge :tone="DIFF_TONE[c.difficulty]">{{ DIFF_LABEL[c.difficulty] || c.difficulty }}</CrBadge>
        <CrBadge v-if="c.kind && c.kind !== 'flag'" tone="accent">rule {{ c.kind === 'sigma' ? 'Sigma' : 'YARA' }}</CrBadge>
        <CrBadge v-if="c.lab_template" tone="accent"><Server class="mr-1 inline size-3" />lab</CrBadge>
        <CrBadge v-if="!c.is_published" tone="warn">draft</CrBadge>
        <span class="ml-auto text-ink-500">{{ c.solves }} solve</span>
      </div>
      <div v-if="c.solved" class="mt-2 flex items-center gap-1 text-xs text-ok" data-test="solved"><CheckCircle2 class="size-3.5" /> Terpecahkan · {{ c.my_points }} poin</div>
    </RouterLink>
  </div>
</template>
