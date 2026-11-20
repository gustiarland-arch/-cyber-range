<script setup>
import { onMounted, ref } from 'vue'
import { Flag, Target, Trophy } from 'lucide-vue-next'
import { api } from '@/services/api'
import CrKpi from '@/components/ui/CrKpi.vue'

const me = ref(null)
defineExpose({ reload: load })
async function load() { me.value = await api('/training/me').catch(() => me.value) }
onMounted(load)
</script>
<template>
  <div v-if="me" class="mb-4 grid gap-3 sm:grid-cols-3" data-test="my-progress">
    <CrKpi label="Poin saya" :value="me.points" :icon="Trophy" />
    <CrKpi label="Challenge terselesaikan" :value="me.solves" :icon="Flag" tone="ok" />
    <CrKpi label="Misi selesai" :value="me.missions_completed" :icon="Target" :hint="`${me.objectives_met} tujuan tercapai`" />
  </div>
</template>
