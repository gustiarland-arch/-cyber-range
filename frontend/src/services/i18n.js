// Indonesian display helpers for values the API stores in English.
// st(): raw status/enum values -> label. trMsg(): event/timeline/validation messages -> Indonesian, by pattern.
// Unknown values are returned unchanged, so nothing is hidden when a new value appears.

// Industry-standard security and infrastructure terms stay in English (owner's decision, 2026-11-19); everything else is
// shown in Indonesian.
const KEEP_EN = {
  running: 'running', stopped: 'stopped', starting: 'starting', stopping: 'stopping', deploying: 'deploying', provisioning: 'provisioning',
  destroying: 'destroying', destroyed: 'destroyed', resetting: 'resetting', restoring: 'restoring', snapshotting: 'snapshotting',
  not_deployed: 'not deployed', exited: 'exited', created: 'created', up: 'up', down: 'down', online: 'online', offline: 'offline',
  healthy: 'healthy', degraded: 'degraded', error: 'error',
  new: 'new', open: 'open', acknowledged: 'acknowledged', triaged: 'triaged', investigating: 'investigating', in_progress: 'in progress',
  escalated: 'escalated', contained: 'contained', eradicated: 'eradicated', recovered: 'recovered', resolved: 'resolved', closed: 'closed',
  false_positive: 'false positive', true_positive: 'true positive', benign: 'benign', reopened: 'reopened',
  in_remediation: 'in remediation', fixed: 'fixed', fixed_pending_verification: 'fixed (pending verification)', verified: 'verified', risk_accepted: 'risk accepted',
  sealed: 'sealed', collected: 'collected', released: 'released', quarantined: 'quarantined', analysing: 'analysing', analyzed: 'analyzed',
  detected: 'detected', missed: 'missed', ok: 'ok',
}
const STATUS = {
  pending: 'menunggu', pending_approval: 'menunggu persetujuan', approved: 'disetujui', rejected: 'ditolak', queued: 'dalam antrean', sent: 'terkirim',
  completed: 'selesai', done: 'selesai', aborted: 'dibatalkan', failed: 'gagal', expired: 'kedaluwarsa',
  cancelled: 'dibatalkan', canceled: 'dibatalkan', ready: 'siap', draft: 'draf', published: 'terbit', archived: 'diarsipkan',
  active: 'aktif', inactive: 'nonaktif', disabled: 'nonaktif', enabled: 'aktif',
  todo: 'belum', blocked: 'terhambat', success: 'berhasil', partial: 'sebagian', skipped: 'dilewati',
  valid: 'valid', invalid: 'tidak valid', warning: 'peringatan', unknown: 'tidak diketahui',
  requested: 'diajukan', abort_requested: 'pembatalan diminta', started: 'dimulai', step_started: 'langkah dimulai', step_finished: 'langkah selesai',
  missing: 'hilang', denied: 'ditolak', reported: 'dilaporkan', closed_port: 'tertutup',
  awaiting_approval: 'menunggu persetujuan', executed: 'dieksekusi',
  ...KEEP_EN,
}

export function st(v) {
  if (v === null || v === undefined || v === '') return v
  return STATUS[v] ?? STATUS[String(v).toLowerCase()] ?? v
}

const P = [
  // red team timeline
  [/^(\S+) requested '(.+)' against (\d+) target\(s\) in lab (.+)$/, (m) => `${m[1]} mengajukan '${m[2]}' terhadap ${m[3]} target di lab ${m[4]}`],
  [/^(Approved|Rejected) by (\S+): ([\s\S]*)$/, (m) => `${m[1] === 'Approved' ? 'Disetujui' : 'Ditolak'} oleh ${m[2]}: ${m[3]}`],
  [/^Execution started by (\S+)$/, (m) => `Eksekusi dimulai oleh ${m[1]}`],
  [/^Cancelled by (\S+)$/, (m) => `Dibatalkan oleh ${m[1]}`],
  [/^Abort requested by (\S+)$/, (m) => `Pembatalan diminta oleh ${m[1]}`],
  [/^Running (\d+) step\(s\) from (\S+) \((\S+)\)$/, (m) => `Menjalankan ${m[1]} langkah dari ${m[2]} (${m[3]})`],
  [/^Stopped before step (\d+): ([\s\S]*)$/, (m) => `Dihentikan sebelum langkah ${m[1]}: ${m[2]}`],
  [/^Step (\d+) done: (\d+) hosts up, (\d+) open ports, (\d+) HTTP responses, (\d+) findings, (\d+) telemetry records$/,
    (m) => `Langkah ${m[1]} selesai: ${m[2]} host aktif, ${m[3]} port terbuka, ${m[4]} respons HTTP, ${m[5]} temuan, ${m[6]} record telemetri`],
  [/^Step (\d+): ([\s\S]*)$/, (m) => `Langkah ${m[1]}: ${m[2]}`],
  [/^Execution failed: ([\s\S]*)$/, (m) => `Eksekusi gagal: ${m[1]}`],
  [/^Telegram is not configured \(CR_TELEGRAM_BOT_TOKEN\)$/, () => 'Telegram belum dikonfigurasi (CR_TELEGRAM_BOT_TOKEN)'],
  [/^SMTP is not configured \(CR_SMTP_HOST, CR_SMTP_FROM\)$/, () => 'SMTP belum dikonfigurasi (CR_SMTP_HOST, CR_SMTP_FROM)'],
  [/^Telegram HTTP (\d+) ?(.*)$/, (m) => `Telegram menolak (HTTP ${m[1]}) ${m[2]}`.trim()],
  [/^Assessment completed$/, () => 'Assessment selesai'],
  [/^Authorisation window ended before execution$/, () => 'Jendela otorisasi berakhir sebelum eksekusi'],
  // lab lifecycle
  [/^Lab created from '(.+)' v(\d+): (\d+) containers, (\d+) networks$/, (m) => `Lab dibuat dari '${m[1]}' v${m[2]}: ${m[3]} container, ${m[4]} jaringan`],
  [/^Lab deployed: (\d+) containers on (\d+) isolated networks$/, (m) => `Lab di-deploy: ${m[1]} container di ${m[2]} jaringan terisolasi`],
  [/^Deploy requested by (\S+)$/, (m) => `Deploy diminta oleh ${m[1]}`],
  [/^(Start|Stop|Reset|Destroy|Restore|Snapshot) requested by (\S+)$/, (m) => `${{ Start: 'Start', Stop: 'Stop', Reset: 'Reset', Destroy: 'Penghancuran', Restore: 'Pemulihan', Snapshot: 'Snapshot' }[m[1]]} diminta oleh ${m[2]}`],
  [/^Lab started$/, () => 'Lab dijalankan'],
  [/^Lab stopped$/, () => 'Lab dihentikan'],
  [/^Lab reset to its clean baseline$/, () => 'Lab direset ke kondisi awal yang bersih'],
  [/^Lab destroyed; containers and networks removed$/, () => 'Lab dihancurkan; container dan jaringan dihapus'],
  [/^Kill switch engaged: stopping lab$/, () => 'Kill switch aktif: lab dihentikan'],
  [/^Restored snapshot '(.+)'$/, (m) => `Snapshot '${m[1]}' dipulihkan`],
  [/^Snapshot '(.+)' created \((\d+) images\)$/, (m) => `Snapshot '${m[1]}' dibuat (${m[2]} image)`],
  [/^Snapshot failed: ([\s\S]*)$/, (m) => `Snapshot gagal: ${m[1]}`],
  [/^(\S+) is (\w+) \(outside platform control\)$/, (m) => `${m[1]} berstatus ${st(m[2])} (di luar kendali platform)`],
  [/^(.+): no VM provider on the lab host, running as a container \(compatible mode\)$/, (m) => `${m[1]}: tidak ada penyedia VM di host lab, dijalankan sebagai container (mode kompatibel)`],
  [/^Internet is simulated only; labs have no egress \(default-deny\)$/, () => 'Internet hanya disimulasikan; lab tidak punya akses keluar (default-deny)'],
  [/^Realised by the subnet's isolated bridge network$/, () => 'Diwujudkan oleh jaringan bridge terisolasi milik subnet'],
  [/^(.+): (Internet is simulated only.*|Realised by the subnet.*)$/, (m) => `${m[1]}: ${trMsg(m[2])}`],
  // vulnerability / malware history
  [/^Detected by scan #(\d+)$/, (m) => `Terdeteksi oleh scan #${m[1]}`],
  [/^Fix verified: not detected by scan #(\d+)$/, (m) => `Perbaikan terverifikasi: tidak terdeteksi oleh scan #${m[1]}`],
  [/^Not detected by scan #(\d+); mark it fixed to have the next scan verify it$/, (m) => `Tidak terdeteksi oleh scan #${m[1]}; tandai diperbaiki agar scan berikutnya memverifikasi`],
  [/^Still present in scan #(\d+) \(was (\w+)\)$/, (m) => `Masih ada di scan #${m[1]} (sebelumnya ${st(m[2])})`],
  [/^Owner set by (\S+)$/, (m) => `Pemilik ditetapkan oleh ${m[1]}`],
  [/^Recorded manually by (\S+)$/, (m) => `Dicatat manual oleh ${m[1]}`],
  [/^Risk acceptance expired; finding reopened$/, () => 'Penerimaan risiko kedaluwarsa; temuan dibuka kembali'],
  [/^Re-analysis requested by (\S+)$/, (m) => `Analisis ulang diminta oleh ${m[1]}`],
  [/^Submitted again by (\S+) as (.+)$/, (m) => `Dikirim ulang oleh ${m[1]} sebagai ${m[2]}`],
  [/^Received from (\S+) as (.+) \((\d+) bytes, (.+)\); stored neutralised in quarantine$/, (m) => `Diterima dari ${m[1]} sebagai ${m[2]} (${m[3]} byte, ${m[4]}); disimpan ternetralisasi di karantina`],
  [/^Verdict (\S+) → (\S+) by (\S+): ([\s\S]*)$/, (m) => `Verdict ${m[1]} → ${m[2]} oleh ${m[3]}: ${m[4]}`],
  [/^(\d+) indicator\(s\) promoted to threat intel by (\S+)$/, (m) => `${m[1]} indikator dipromosikan ke threat intel oleh ${m[2]}`],
  [/^Static analysis failed: (.*)$/, (m) => `Analisis statis gagal: ${m[1]}`],
  [/^Static analysis done: (\d+) strings, (\d+) IOC candidates, ([\s\S]*)$/, (m) => `Analisis statis selesai: ${m[1]} string, ${m[2]} kandidat IOC, ${m[3]}`],
  [/^Sandbox report received \(run #(\d+)\): (\d+) signature\(s\)$/, (m) => `Laporan sandbox diterima (run #${m[1]}): ${m[2]} signature`],
  [/^Submitted to (\S+) sandbox by (\S+) \(network: none, timeout (\d+)s\): (\w+)$/, (m) => `Dikirim ke sandbox ${m[1]} oleh ${m[2]} (jaringan: none, timeout ${m[3]} dtk): ${st(m[4])}`],
  [/^Task '(.+)' created by (\S+)$/, (m) => `Tugas '${m[1]}' dibuat oleh ${m[2]}`],
  [/^Task '(.+)' → (\w+) by (\S+)$/, (m) => `Tugas '${m[1]}' → ${st(m[2])} oleh ${m[3]}`],
  // topology validation
  [/^Duplicate (\w+) key '(.+)'$/, (m) => `Kunci ${m[1]} '${m[2]}' duplikat`],
  [/^Subnet '(.+)' references unknown zone '(.+)'$/, (m) => `Subnet '${m[1]}' merujuk zona '${m[2]}' yang tidak dikenal`],
  [/^Node '(.+)' references unknown zone '(.+)'$/, (m) => `Node '${m[1]}' merujuk zona '${m[2]}' yang tidak dikenal`],
  [/^Node '(.+)' has interface '(.+)' twice$/, (m) => `Node '${m[1]}' memiliki interface '${m[2]}' dua kali`],
  [/^Interface (\S+) references unknown subnet '(.+)'$/, (m) => `Interface ${m[1]} merujuk subnet '${m[2]}' yang tidak dikenal`],
  [/^Link '(.+)' references unknown node '(.+)'$/, (m) => `Link '${m[1]}' merujuk node '${m[2]}' yang tidak dikenal`],
  [/^Subnet '(.+)': invalid CIDR (\S+) \((.*)\)$/, (m) => `Subnet '${m[1]}': CIDR ${m[2]} tidak valid (${m[3]})`],
  [/^Subnet '(.+)': gateway (\S+) is not inside (\S+)$/, (m) => `Subnet '${m[1]}': gateway ${m[2]} tidak berada di dalam ${m[3]}`],
  [/^Subnet '(.+)': gateway (\S+) is the network\/broadcast address$/, (m) => `Subnet '${m[1]}': gateway ${m[2]} adalah alamat network/broadcast`],
  [/^Subnet '(.+)': invalid gateway '(.*)'$/, (m) => `Subnet '${m[1]}': gateway '${m[2]}' tidak valid`],
  [/^Subnets (\S+) and (\S+) overlap$/, (m) => `Subnet ${m[1]} dan ${m[2]} bertabrakan`],
  [/^(\S+): invalid IP '(.*)'$/, (m) => `${m[1]}: IP '${m[2]}' tidak valid`],
  [/^(\S+): IP (\S+) is not attached to a subnet$/, (m) => `${m[1]}: IP ${m[2]} tidak terhubung ke subnet`],
  [/^(\S+): (\S+) is outside (\S+)$/, (m) => `${m[1]}: ${m[2]} berada di luar ${m[3]}`],
  [/^(\S+): (\S+) is the network\/broadcast address of (\S+)$/, (m) => `${m[1]}: ${m[2]} adalah alamat network/broadcast dari ${m[3]}`],
  [/^(\S+): (\S+) is the subnet gateway but node is a (\S+)$/, (m) => `${m[1]}: ${m[2]} adalah gateway subnet tetapi node bertipe ${m[3]}`],
  [/^IP (\S+) is assigned to both '(.+)' and '(.+)'$/, (m) => `IP ${m[1]} dipakai oleh '${m[2]}' dan '${m[3]}' sekaligus`],
  [/^Link '(.+)' connects '(.+)' to itself$/, (m) => `Link '${m[1]}' menghubungkan '${m[2]}' ke dirinya sendiri`],
  [/^'(.+)' and '(.+)' are in different zones without a router\/firewall between them$/, (m) => `'${m[1]}' dan '${m[2]}' berada di zona berbeda tanpa router/firewall di antaranya`],
  [/^Internet node is linked directly into a protected zone via '(.+)' \(add a firewall\)$/, (m) => `Node internet terhubung langsung ke zona terlindungi melalui '${m[1]}' (tambahkan firewall)`],
  [/^'(.+)' and '(.+)' are linked but share no subnet$/, (m) => `'${m[1]}' dan '${m[2]}' terhubung tetapi tidak berbagi subnet`],
  [/^(\d+) links between '(.+)' and '(.+)'$/, (m) => `${m[1]} link antara '${m[2]}' dan '${m[3]}'`],
  [/^'(.+)' has no connections$/, (m) => `'${m[1]}' tidak memiliki koneksi`],
  [/^'(.+)' has no network interfaces configured$/, (m) => `'${m[1]}' belum memiliki interface jaringan`],
]

export function trMsg(msg) {
  if (!msg || typeof msg !== 'string') return msg
  for (const [re, fn] of P) {
    const m = msg.match(re)
    if (m) return fn(m)
  }
  return msg
}

export default {
  install(app) {
    app.config.globalProperties.$st = st
    app.config.globalProperties.$tr = trMsg
  },
}
