<script setup>
import CrSpinner from './CrSpinner.vue'
const props = defineProps({
  variant: { type: String, default: 'secondary' }, // primary | secondary | ghost | danger
  size: { type: String, default: 'md' },
  loading: Boolean,
  disabled: Boolean,
  type: { type: String, default: 'button' },
})
const variants = {
  primary: 'bg-accent-500 text-ink-950 hover:bg-accent-400 shadow-glow',
  secondary: 'border border-ink-600 bg-ink-800 text-ink-100 hover:border-ink-500 hover:bg-ink-700',
  ghost: 'text-ink-300 hover:bg-ink-800 hover:text-ink-100',
  danger: 'border border-sev-critical/50 bg-sev-critical/10 text-sev-critical hover:bg-sev-critical/20',
}
const sizes = { sm: 'h-8 px-2.5 text-xs gap-1.5', md: 'h-9 px-3.5 text-sm gap-2', lg: 'h-11 px-5 text-sm gap-2' }
</script>
<template>
  <button :type="type" :disabled="disabled || loading"
    :class="['inline-flex select-none items-center justify-center rounded-md font-medium transition disabled:cursor-not-allowed disabled:opacity-50', variants[props.variant], sizes[props.size]]">
    <CrSpinner v-if="loading" class="size-4" />
    <slot />
  </button>
</template>
