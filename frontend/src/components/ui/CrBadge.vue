<script setup>
defineProps({ tone: { type: String, default: 'neutral' } })
const tones = {
  neutral: 'border-ink-600 bg-ink-800 text-ink-300',
  accent: 'border-accent-500/40 bg-accent-500/10 text-accent-300',
  ok: 'border-ok/40 bg-ok/10 text-ok',
  warn: 'border-warn/40 bg-warn/10 text-warn',
  bad: 'border-bad/40 bg-bad/10 text-bad',
  critical: 'border-sev-critical/40 bg-sev-critical/10 text-sev-critical',
  high: 'border-sev-high/40 bg-sev-high/10 text-sev-high',
  medium: 'border-sev-medium/40 bg-sev-medium/10 text-sev-medium',
  low: 'border-sev-low/40 bg-sev-low/10 text-sev-low',
  ai: 'border-ai-400/40 bg-ai-400/10 text-ai-300',
}
</script>
<template>
  <span :class="['inline-flex items-center gap-1 whitespace-nowrap rounded border px-1.5 py-0.5 font-mono text-[11px] leading-none', tones[tone] || tones.neutral]"><slot /></span>
</template>
