<script setup>
// Monaco code editor (lazy-loaded). Only the core editor is bundled: no language services that execute code.
import { onBeforeUnmount, onMounted, ref, shallowRef, watch } from 'vue'

const props = defineProps({ modelValue: { type: String, default: '' }, language: { type: String, default: 'plaintext' }, readonly: Boolean, height: { type: String, default: '22rem' }, label: String })
const emit = defineEmits(['update:modelValue'])
const el = ref(null)
const editor = shallowRef(null)
const failed = ref(false)
let registered = false

function registerYara(monaco) {
  if (registered) return
  registered = true
  monaco.languages.register({ id: 'yara' })
  monaco.languages.setMonarchTokensProvider('yara', {
    keywords: ['rule', 'private', 'global', 'meta', 'strings', 'condition', 'import', 'and', 'or', 'not', 'any', 'all', 'of', 'them', 'for', 'in', 'at',
      'filesize', 'entrypoint', 'true', 'false', 'nocase', 'wide', 'ascii', 'fullword', 'xor', 'base64', 'base64wide', 'private', 'matches', 'contains',
      'icontains', 'startswith', 'endswith', 'iequals', 'defined', 'none'],
    tokenizer: {
      root: [
        [/\/\/.*$/, 'comment'], [/\/\*/, 'comment', '@comment'],
        [/"([^"\\]|\\.)*"/, 'string'], [/\{[0-9a-fA-F?\s[\]\-|()~]+\}/, 'number.hex'],
        [/\/(?:[^/\\\n]|\\.)+\/[is]*/, 'regexp'],
        [/[$#@!][A-Za-z0-9_*]*/, 'variable'],
        [/\b(u?int(8|16|32)(be)?)\b/, 'type'],
        [/0x[0-9a-fA-F]+|\d+(KB|MB)?/, 'number'],
        [/[A-Za-z_][\w]*/, { cases: { '@keywords': 'keyword', '@default': 'identifier' } }],
      ],
      comment: [[/[^/*]+/, 'comment'], [/\*\//, 'comment', '@pop'], [/[/*]/, 'comment']],
    },
  })
}

onMounted(async () => {
  try {
    const [monaco, { default: EditorWorker }] = await Promise.all([
      import('monaco-editor/editor/editor.api'),
      import('monaco-editor/editor/editor.worker?worker'),
    ])
    self.MonacoEnvironment = { getWorker: () => new EditorWorker() }
    registerYara(monaco)
    monaco.editor.defineTheme('cyber-range', { base: 'vs-dark', inherit: true, rules: [
      { token: 'keyword', foreground: '22D3EE' }, { token: 'string', foreground: 'A78BFA' }, { token: 'variable', foreground: 'FBBF24' },
      { token: 'regexp', foreground: 'F05262' }, { token: 'number.hex', foreground: '22C58B' }, { token: 'comment', foreground: '64748B' }],
    colors: { 'editor.background': '#0B1424', 'editor.lineHighlightBackground': '#111D30' } })
    editor.value = monaco.editor.create(el.value, {
      value: props.modelValue, language: props.language, theme: 'cyber-range', readOnly: props.readonly, minimap: { enabled: false },
      fontFamily: 'JetBrains Mono Variable, monospace', fontSize: 12, automaticLayout: true, scrollBeyondLastLine: false, tabSize: 4,
      ariaLabel: props.label || 'Editor kode',
    })
    editor.value.onDidChangeModelContent(() => { const v = editor.value.getValue(); if (v !== props.modelValue) emit('update:modelValue', v) })
  } catch {
    failed.value = true // fall back to a plain textarea; editing still works
  }
})
watch(() => props.modelValue, (v) => { if (editor.value && v !== editor.value.getValue()) editor.value.setValue(v || '') })
watch(() => props.readonly, (r) => editor.value?.updateOptions({ readOnly: r }))
onBeforeUnmount(() => editor.value?.dispose())
</script>

<template>
  <textarea v-if="failed" class="input font-mono text-xs" :style="{ height }" :value="modelValue" :readonly="readonly" :aria-label="label" @input="emit('update:modelValue', $event.target.value)" />
  <div v-else ref="el" class="overflow-hidden rounded border border-ink-700" :style="{ height }" data-test="code-editor" />
</template>
