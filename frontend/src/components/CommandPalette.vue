<script setup>
import { computed, nextTick, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { CornerDownLeft, Search } from 'lucide-vue-next'
import { NAV } from '@/services/navigation'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'

const ui = useUiStore()
const auth = useAuthStore()
const router = useRouter()
const q = ref('')
const sel = ref(0)
const input = ref(null)

const entries = computed(() => {
  const nav = NAV.flatMap((g) => g.items.map((i) => ({ ...i, section: g.section })))
    .filter((i) => i.to && auth.can(i.perm))
    .map((i) => ({ label: i.label, hint: i.section, icon: i.icon, run: () => router.push({ name: i.to }) }))
  const all = nav
  const s = q.value.trim().toLowerCase()
  return s ? all.filter((e) => `${e.label} ${e.hint}`.toLowerCase().includes(s)) : all
})

watch(() => ui.paletteOpen, async (o) => { if (o) { q.value = ''; sel.value = 0; await nextTick(); input.value?.focus() } })
watch(q, () => { sel.value = 0 })

function key(e) {
  if (e.key === 'ArrowDown') { e.preventDefault(); sel.value = Math.min(sel.value + 1, entries.value.length - 1) }
  else if (e.key === 'ArrowUp') { e.preventDefault(); sel.value = Math.max(sel.value - 1, 0) }
  else if (e.key === 'Enter') { e.preventDefault(); choose(entries.value[sel.value]) }
  else if (e.key === 'Escape') ui.paletteOpen = false
}
function choose(e) { if (!e) return; ui.paletteOpen = false; e.run() }
</script>
<template>
  <Teleport to="body">
    <div v-if="ui.paletteOpen" class="fixed inset-0 z-50 flex items-start justify-center bg-ink-950/70 p-4 pt-[14vh] backdrop-blur-sm" @mousedown.self="ui.paletteOpen = false">
      <div class="panel w-full max-w-xl overflow-hidden shadow-2xl" role="dialog" aria-label="Palet perintah">
        <div class="flex items-center gap-2 border-b border-ink-700 px-3">
          <Search class="size-4 text-ink-500" />
          <input ref="input" v-model="q" class="h-12 flex-1 bg-transparent text-sm text-ink-100 outline-none placeholder:text-ink-500" placeholder="Lompat ke modul atau jalankan aksi…" @keydown="key" />
        </div>
        <ul class="max-h-80 overflow-y-auto p-1" role="listbox">
          <li v-for="(e, i) in entries" :key="e.label" role="option" :aria-selected="i === sel"
            :class="['flex cursor-pointer items-center gap-3 rounded px-3 py-2 text-sm', i === sel ? 'bg-accent-500/10 text-accent-200' : 'text-ink-300']"
            @mouseenter="sel = i" @click="choose(e)">
            <component :is="e.icon" class="size-4" /><span class="flex-1">{{ e.label }}</span>
            <span class="text-[11px] text-ink-500">{{ e.hint }}</span>
            <CornerDownLeft v-if="i === sel" class="size-3.5 text-ink-500" />
          </li>
          <li v-if="!entries.length" class="px-3 py-6 text-center text-sm text-ink-500">Tidak ada yang cocok</li>
        </ul>
      </div>
    </div>
  </Teleport>
</template>
