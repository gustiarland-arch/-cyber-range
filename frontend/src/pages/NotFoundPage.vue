<script setup>
import CrState from '@/components/ui/CrState.vue'
</script>
<template>
  <div class="panel"><CrState kind="empty" title="Halaman tidak ditemukan" message="Rute ini tidak ada."><RouterLink :to="{ name: 'overview' }" class="text-sm text-accent-400 hover:underline">Kembali ke overview</RouterLink></CrState></div>
</template>
