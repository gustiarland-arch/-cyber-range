// Training helpers. Markdown is rendered from ESCAPED text with a tiny whitelist (headings, bold, italics, inline code,
// code blocks, lists, paragraphs). No raw HTML and no links survive, so authored content cannot inject markup.
import { api } from '@/services/api'

export const DIFF_TONE = { beginner: 'ok', intermediate: 'warn', advanced: 'bad' }
export const DIFF_LABEL = { beginner: 'pemula', intermediate: 'menengah', advanced: 'mahir' }
export const CAT_LABEL = { web: 'Web', network: 'Jaringan', forensics: 'Forensik', crypto: 'Crypto', malware: 'Malware', 'blue-team': 'Blue team', osint: 'OSINT', misc: 'Lain-lain', course: 'Kursus', mission: 'Misi' }
export const KIND_LABEL = { answer: 'Jawaban', challenge: 'Challenge CTF', vuln_finding: 'Temuan kerentanan', assessment: 'Assessment yang disetujui', sensor: 'Sensor jaringan di lab', alert_closed: 'Alert dituntaskan', incident_closed: 'Insiden ditutup' }

const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')

function inline(s) {
  // s is already escaped
  return s
    .replace(/`([^`]+)`/g, '<code class="rounded bg-ink-800 px-1 font-mono text-[0.85em] text-accent-200">$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong class="text-ink-100">$1</strong>')
    .replace(/(^|[\s(])\*([^*\s][^*]*)\*/g, '$1<em>$2</em>')
}

export function renderMarkdown(src) {
  const lines = String(src || '').replace(/\r\n?/g, '\n').split('\n')
  const out = []
  let para = [], list = null, code = null
  const flushPara = () => { if (para.length) { out.push(`<p class="mb-3 leading-relaxed">${inline(para.join(' '))}</p>`); para = [] } }
  const flushList = () => { if (list) { out.push(`<${list.tag} class="mb-3 ml-5 ${list.tag === 'ol' ? 'list-decimal' : 'list-disc'} space-y-1">${list.items.map((i) => `<li>${inline(i)}</li>`).join('')}</${list.tag}>`); list = null } }
  for (const raw of lines) {
    if (code !== null) {
      if (raw.trim().startsWith('```')) { out.push(`<pre class="mb-3 overflow-x-auto rounded border border-ink-700 bg-ink-950 p-3 font-mono text-xs text-ink-200">${code.join('\n')}</pre>`); code = null } else code.push(esc(raw))
      continue
    }
    if (raw.trim().startsWith('```')) { flushPara(); flushList(); code = []; continue }
    const line = esc(raw)
    const h = /^(#{1,4})\s+(.*)$/.exec(line)
    const ul = /^\s*[-*]\s+(.*)$/.exec(line)
    const ol = /^\s*\d+[.)]\s+(.*)$/.exec(line)
    if (h) { flushPara(); flushList(); const n = Math.min(4, h[1].length + 1); out.push(`<h${n} class="mb-2 mt-4 font-semibold text-ink-100 ${n <= 2 ? 'text-lg' : 'text-base'}">${inline(h[2])}</h${n}>`) }
    else if (ul || ol) { flushPara(); const tag = ul ? 'ul' : 'ol'; if (list && list.tag !== tag) flushList(); list ||= { tag, items: [] }; list.items.push((ul || ol)[1]) }
    else if (!line.trim()) { flushPara(); flushList() }
    else { flushList(); para.push(line) }
  }
  if (code !== null) out.push(`<pre class="mb-3 overflow-x-auto rounded border border-ink-700 bg-ink-950 p-3 font-mono text-xs">${code.join('\n')}</pre>`)
  flushPara(); flushList()
  return out.join('')
}

export async function launchPracticeLab(kind, id) {
  return api('/training/practice-lab', { method: 'POST', body: { kind, id } })
}
