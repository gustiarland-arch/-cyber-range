<script setup>
import { onMounted, ref } from 'vue'
import { PencilRuler, Server, Target } from 'lucide-vue-next'
import { api } from '@/services/api'
import { useAuthStore } from '@/stores/auth'
import CrBadge from '@/components/ui/CrBadge.vue'
import CrButton from '@/components/ui/CrButton.vue'
import CrState from '@/components/ui/CrState.vue'
import PageHeader from '@/components/ui/PageHeader.vue'
import MyProgress from '@/components/training/MyProgress.vue'
import { DIFF_LABEL, DIFF_TONE } from '@/components/training/tr'

const auth = useAuthStore()
const list = ref(null)
const err = ref(null)
async function load() { try { list.value = await api('/training/missions'); err.value = null } catch (e) { err.value = e } }
onMounted(load)
</script>

<template>
  <PageHeader section="Pelatihan & Evaluasi" title="Pusat Misi" subtitle="Misi multi-langkah. Tujuan diverifikasi platform terhadap pelajaran, solve, scan lab dan assessment terotorisasi milik Anda sendiri.">
    <RouterLink v-if="auth.can('training.manage')" :to="{ name: 'training-authoring', query: { tab: 'missions' } }"><CrButton><PencilRuler class="size-4" /> Susun misi</CrButton></RouterLink>
  </PageHeader>
  <MyProgress v-if="auth.can('training.participate')" />
  <CrState v-if="err" kind="error" :message="err.message" @retry="load" />
  <CrState v-else-if="!list" kind="loading" />
  <CrState v-else-if="!list.length" kind="empty" title="Belum ada misi" message="Belum ada misi yang diterbitkan." />
  <div v-else class="grid gap-3 md:grid-cols-2">
    <RouterLink v-for="m in list" :key="m.id" :to="{ name: 'mission', params: { id: m.id } }" :data-mission="m.slug" class="panel block p-4 transition hover:border-accent-500/40">
      <div class="mb-2 flex items-center gap-2"><Target class="size-4 text-accent-300" /><span class="flex-1 font-semibold text-ink-100">{{ m.title }}</span>
        <span class="font-mono text-sm text-accent-200">{{ m.points }} poin</span></div>
      <div class="mb-2 flex flex-wrap gap-1.5 text-xs"><CrBadge :tone="DIFF_TONE[m.difficulty]">{{ DIFF_LABEL[m.difficulty] || m.difficulty }}</CrBadge>
        <CrBadge v-if="m.lab_template" tone="accent"><Server class="mr-1 inline size-3" />lab</CrBadge><CrBadge v-if="!m.is_published" tone="warn">draft</CrBadge>
        <CrBadge v-if="m.objectives && m.met === m.objectives" tone="ok">completed</CrBadge></div>
      <div class="h-1.5 overflow-hidden rounded bg-ink-800"><div class="h-full bg-ok" :style="{ width: `${m.objectives ? (100 * m.met) / m.objectives : 0}%` }" /></div>
      <p class="mt-1 text-right text-[11px] text-ink-500" data-test="mission-progress">{{ m.met }}/{{ m.objectives }} objectives</p>
    </RouterLink>
  </div>
</template>
