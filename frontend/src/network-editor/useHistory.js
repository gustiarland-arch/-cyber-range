import { computed, ref } from 'vue'

/** Snapshot-based undo/redo for a JSON document. */
export function useHistory(limit = 100) {
  const past = ref([])
  const future = ref([])
  let current = null

  function reset(snapshot) { past.value = []; future.value = []; current = JSON.stringify(snapshot) }
  /** Record the state *after* a change. No-op when nothing changed. */
  function commit(snapshot) {
    const s = JSON.stringify(snapshot)
    if (s === current) return false
    if (current !== null) past.value.push(current)
    if (past.value.length > limit) past.value.shift()
    future.value = []
    current = s
    return true
  }
  function undo() {
    if (!past.value.length) return null
    future.value.push(current)
    current = past.value.pop()
    return JSON.parse(current)
  }
  function redo() {
    if (!future.value.length) return null
    past.value.push(current)
    current = future.value.pop()
    return JSON.parse(current)
  }
  return { reset, commit, undo, redo, canUndo: computed(() => past.value.length > 0), canRedo: computed(() => future.value.length > 0) }
}
