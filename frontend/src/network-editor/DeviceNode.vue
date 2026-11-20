<script setup>
import { computed } from 'vue'
import { Handle, Position } from '@vue-flow/core'
import { DEVICES, primaryIp } from './catalog'

const props = defineProps({ data: Object, selected: Boolean })
const dev = computed(() => DEVICES[props.data.node.type] || DEVICES.server)
const ip = computed(() => primaryIp(props.data.node))
</script>
<template>
  <div :class="['relative flex w-[150px] items-center gap-2 rounded-lg border bg-ink-900/95 px-2.5 py-2 shadow-lg transition',
    selected ? 'border-accent-400 shadow-glow' : 'border-ink-600 hover:border-ink-500',
    data.severity === 'error' ? 'ring-2 ring-sev-critical/70' : data.severity === 'warning' ? 'ring-1 ring-warn/60' : '']"
    :data-node-key="data.node.key">
    <Handle type="target" :position="Position.Left" class="!size-2.5 !border-ink-900 !bg-ink-400" />
    <div class="grid size-8 shrink-0 place-items-center rounded-md" :style="{ background: dev.color + '22', color: dev.color }">
      <component :is="dev.icon" class="size-4" />
    </div>
    <div class="min-w-0 leading-tight">
      <div class="truncate text-xs font-semibold text-ink-100">{{ data.node.label }}</div>
      <div class="truncate font-mono text-[10px] text-ink-400">{{ ip || dev.label }}</div>
    </div>
    <Handle type="source" :position="Position.Right" class="!size-2.5 !border-ink-900 !bg-accent-400" />
  </div>
</template>
