<script setup>
import CrBadge from '@/components/ui/CrBadge.vue'
import { SEV_TONE, sevName } from '@/services/soc'
defineProps({ sev: { type: Number, required: true } })
</script>
<template><CrBadge :tone="SEV_TONE[sev]">{{ sevName(sev) }}</CrBadge></template>
