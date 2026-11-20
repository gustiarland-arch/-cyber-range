"""Indonesian translations of user-facing API error messages.

The API keeps English messages for clients that do not ask for Indonesian (tests, scripts). When the request carries
`Accept-Language: id` (the web UI always sends it), the error handler translates the message here: exact matches first,
then patterns for messages built with values. Unknown messages are returned unchanged, so a missing entry never hides
an error. Error `code` values never change.
"""
import re

EXACT: dict[str, str] = {
    "Too many Lab Kit downloads; try again later": "Terlalu banyak unduhan Lab Kit; coba lagi nanti",
    "This topology cannot be turned into a Lab Kit": "Topologi ini tidak bisa dijadikan Lab Kit",
    "Write a short authorisation note (at least 10 characters) confirming the targets are your own isolated lab": "Tulis catatan otorisasi singkat (minimal 10 karakter) yang menegaskan target adalah lab terisolasi milik Anda sendiri",
    "A local session can only be opened from this computer (http://localhost)": "Sesi lokal hanya bisa dibuka dari komputer ini (http://localhost)",
    "Server labs are not available for self-registered accounts on this server. Download a Lab Kit and run the lab on your own computer":
        "Lab di server tidak tersedia untuk akun yang mendaftar sendiri. Unduh Lab Kit dan jalankan lab di komputer Anda sendiri",
    "The topology has validation errors; fix them in the editor first": "Topologi masih punya error validasi; perbaiki dulu di editor",
    "This challenge is solved by submitting a rule, not a flag": "Challenge ini diselesaikan dengan mengirim rule, bukan flag",
    "This challenge is solved with a flag": "Challenge ini diselesaikan dengan flag",
    "Enter a rule (at most 20 KB)": "Masukkan rule (maksimal 20 KB)",
    "Too many attempts. Wait a few minutes before submitting again.": "Terlalu banyak percobaan. Tunggu beberapa menit sebelum mengirim lagi.",
    "Choose a lab template": "Pilih template lab",
    "'from' must be before 'to'": "'from' harus sebelum 'to'",
    "A catalogue entry with this code exists": "Entri katalog dengan kode ini sudah ada",
    "A custom profile needs 1-200 ports between 1 and 65535": "Profil kustom memerlukan 1-200 port antara 1 dan 65535",
    "A flag is required": "Flag wajib diisi",
    "A justification of at least 10 characters is required": "Justifikasi minimal 10 karakter wajib diisi",
    "A log source with this name exists": "Sumber log dengan nama ini sudah ada",
    "A report is available once the assessment has run": "Laporan tersedia setelah assessment dijalankan",
    "Unknown role": "Role tidak dikenal",
    "A resolution note is required to close an alert": "Catatan penyelesaian wajib diisi untuk menutup alert",
    "A rule with this code exists": "Rule dengan kode ini sudah ada",
    "A rule's code cannot change": "Kode rule tidak dapat diubah",
    "A ruleset with this name exists": "Ruleset dengan nama ini sudah ada",
    "A scenario with this code exists": "Skenario dengan kode ini sudah ada",
    "A source with this name exists": "Sumber dengan nama ini sudah ada",
    "A user with that email or username already exists": "Pengguna dengan email atau username itu sudah ada",
    "Access token expired": "Token akses kedaluwarsa",
    "Account disabled": "Akun dinonaktifkan",
    "Active lab quota per user reached; stop or destroy another lab first": "Kuota lab aktif per pengguna tercapai; hentikan atau hancurkan lab lain terlebih dahulu",
    "An objective learners have met cannot be removed": "Tujuan yang sudah dicapai peserta tidak dapat dihapus",
    "Analysis already running": "Analisis sedang berjalan",
    "Assessments can only target a running lab": "Assessment hanya dapat menargetkan lab yang sedang berjalan",
    "Assignee must be an active analyst or responder": "Penanggung jawab harus analis atau responder yang aktif",
    "At most 10 attachments per challenge": "Maksimal 10 lampiran per challenge",
    "Attachment names may contain letters, digits, '.', '_' and '-' only": "Nama lampiran hanya boleh berisi huruf, angka, '.', '_' dan '-'",
    "Authentication required": "Perlu login",
    "Both indicators must exist and differ": "Kedua indikator harus ada dan berbeda",
    "Built-in rules can be disabled but not deleted": "Rule bawaan dapat dinonaktifkan tetapi tidak dapat dihapus",
    "Built-in scenarios are read-only; others can be edited by their author": "Skenario bawaan hanya-baca; skenario lain dapat diubah oleh penyusunnya",
    "Built-in scenarios cannot be archived": "Skenario bawaan tidak dapat diarsipkan",
    "Builtin entries are maintained with the scanner checks and cannot be edited": "Entri bawaan dikelola bersama pemeriksaan scanner dan tidak dapat diubah",
    "Builtin rulesets cannot be edited; copy it into a new ruleset": "Ruleset bawaan tidak dapat diubah; salin ke ruleset baru",
    "Changing case sensitivity requires re-entering the flag": "Mengubah sensitivitas huruf memerlukan pengisian ulang flag",
    "Choose 1-50 target nodes other than the attacker": "Pilih 1-50 node target selain node penyerang",
    "Choose 1-50 target nodes other than the scanner": "Pilih 1-50 node target selain node scanner",
    "Choose a non-DEMO source": "Pilih sumber yang bukan DEMO",
    "Closing a case needs a closure note (at least 10 characters)": "Menutup kasus memerlukan catatan penutupan (minimal 10 karakter)",
    "Closing an incident needs a closing note": "Menutup insiden memerlukan catatan penutupan",
    "Confirm that the sample will run only in the isolated, disposable sandbox": "Konfirmasi bahwa sampel hanya berjalan di sandbox terisolasi sekali pakai",
    "Destroy the running lab before deleting it": "Hancurkan lab yang berjalan sebelum menghapusnya",
    "Enter a flag (at most 512 characters)": "Masukkan flag (maksimal 512 karakter)",
    "Enter an answer (at most 512 characters)": "Masukkan jawaban (maksimal 512 karakter)",
    "Evidence is already sealed": "Evidence sudah disegel",
    "Explain the verdict (at least 10 characters): which evidence supports it": "Jelaskan verdict (minimal 10 karakter): evidence apa yang mendukungnya",
    "Exporting SIEM events needs blueteam.alerts.view": "Ekspor event SIEM memerlukan izin blueteam.alerts.view",
    "Host lab capacity reached": "Kapasitas lab host tercapai",
    "Image already on the allowlist": "Image sudah ada di allowlist",
    "Imported document does not match the topology schema": "Dokumen yang diimpor tidak sesuai skema topologi",
    "Integrity check failed; evidence cannot be sealed": "Pemeriksaan integritas gagal; evidence tidak dapat disegel",
    "Invalid access token": "Token akses tidak valid",
    "Invalid refresh token": "Token refresh tidak valid",
    "Invalid rule": "Rule tidak valid",
    "Invalid scenario": "Skenario tidak valid",
    "Lab reports are limited to the lab owner or lab.manage": "Laporan lab hanya untuk pemilik lab atau pemegang lab.manage",
    "Learners have met objectives of this mission; unpublish it instead": "Peserta sudah mencapai tujuan misi ini; batalkan publikasinya saja",
    "Malware samples are not downloadable; analyse them in Malware Analysis": "Sampel malware tidak dapat diunduh; analisis di Analisis Malware",
    "No container for this node in the running lab": "Tidak ada container untuk node ini di lab yang berjalan",
    "No refresh token": "Tidak ada token refresh",
    "No transcript stored for this session": "Tidak ada transkrip tersimpan untuk sesi ini",
    "None of the events exist": "Tidak ada event yang ditemukan",
    "Not allowed": "Tidak diizinkan",
    "Nothing to change": "Tidak ada yang diubah",
    "Only IOCs extracted from this sample can be promoted": "Hanya IOC yang diekstrak dari sampel ini yang dapat dipromosikan",
    "Only the current custodian or the case lead can transfer custody": "Hanya kustodian saat ini atau pemimpin kasus yang dapat menyerahkan custody",
    "Only the requester can abort this scan": "Hanya pemohon yang dapat membatalkan scan ini",
    "Only the requester can execute an approved assessment": "Hanya pemohon yang dapat menjalankan assessment yang sudah disetujui",
    "Only the requester, an approver or a kill-switch holder can stop an assessment": "Hanya pemohon, penyetuju atau pemegang kill switch yang dapat menghentikan assessment",
    "Outside the approved authorisation window": "Di luar jendela otorisasi yang disetujui",
    "Owner must be an incident responder": "Pemilik harus seorang incident responder",
    "Payload too large (max 10 MB)": "Data terlalu besar (maks 10 MB)",
    "Practice labs need permission to operate labs": "Lab latihan memerlukan izin untuk mengoperasikan lab",
    "Remove attachments before changing the slug": "Hapus lampiran sebelum mengubah slug",
    "Risk acceptance needs an expiry date within the next 365 days": "Penerimaan risiko memerlukan tanggal kedaluwarsa dalam 365 hari ke depan",
    "Scans can only target a running lab": "Scan hanya dapat menargetkan lab yang sedang berjalan",
    "Scenario is invalid": "Skenario tidak valid",
    "Sealed evidence can only be released": "Evidence tersegel hanya dapat dilepas",
    "Select between 1 and 5000 events (or an alert with events)": "Pilih antara 1 dan 5000 event (atau alert yang memiliki event)",
    "Session expired": "Sesi kedaluwarsa",
    "Session is no longer valid": "Sesi tidak berlaku lagi",
    "Session revoked": "Sesi dicabut",
    "Set an analyst verdict of suspicious or malicious before promoting indicators": "Tetapkan verdict analis suspicious atau malicious sebelum mempromosikan indikator",
    "Snapshot is not ready": "Snapshot belum siap",
    "Snapshot is still being created": "Snapshot masih dibuat",
    "Snapshots need a running or stopped lab": "Snapshot memerlukan lab yang berjalan atau berhenti",
    "That slug is already used": "Slug itu sudah dipakai",
    "That user is already the custodian": "Pengguna itu sudah menjadi kustodian",
    "The DEMO feed is managed by the platform": "Feed DEMO dikelola oleh platform",
    "The approved lab deployment is no longer running; request a new assessment": "Deployment lab yang disetujui sudah tidak berjalan; ajukan assessment baru",
    "The asset must be a node of the selected lab": "Aset harus berupa node dari lab yang dipilih",
    "The attacker node must be a deployed node of this lab": "Node penyerang harus node yang sudah di-deploy di lab ini",
    "The authorisation window must end in the future and last at most 72 hours": "Jendela otorisasi harus berakhir di masa depan dan paling lama 72 jam",
    "The case is closed; reopen it to add evidence": "Kasus sudah ditutup; buka kembali untuk menambah evidence",
    "The case lead must hold evidence.manage": "Pemimpin kasus harus memiliki izin evidence.manage",
    "The collection time cannot be in the future": "Waktu pengumpulan tidak boleh di masa depan",
    "The file is empty": "File kosong",
    "The flag must be at least 3 characters": "Flag minimal 3 karakter",
    "The indicator has sightings; deactivate it instead to keep the history": "Indikator sudah memiliki sighting; nonaktifkan saja agar riwayatnya tetap ada",
    "The lab is not running": "Lab tidak sedang berjalan",
    "The lab kill switch is engaged": "Kill switch lab sedang aktif",
    "The lab kill switch is engaged; no lab may start": "Kill switch lab sedang aktif; tidak ada lab yang boleh dimulai",
    "The recipient must hold evidence.manage": "Penerima harus memiliki izin evidence.manage",
    "The report is not ready": "Laporan belum siap",
    "The rule has alerts; disable it instead to keep their history": "Rule ini sudah memiliki alert; nonaktifkan saja agar riwayatnya tetap ada",
    "The scanner node must be a deployed node of this lab": "Node scanner harus node yang sudah di-deploy di lab ini",
    "The source defines no rule": "Sumber tidak mendefinisikan rule apa pun",
    "The topology cannot be deployed": "Topologi tidak dapat di-deploy",
    "The topology has validation errors; fix them in the editor before deploying": "Topologi memiliki error validasi; perbaiki di editor sebelum deploy",
    "This challenge has submissions; unpublish it instead": "Challenge ini sudah memiliki submission; batalkan publikasinya saja",
    "This item has no practice lab": "Item ini tidak memiliki lab latihan",
    "This lab is already deployed": "Lab ini sudah di-deploy",
    "This relationship exists": "Relasi ini sudah ada",
    "This rule is driven by threat intelligence; enable or disable it here and manage indicators in Threat Intelligence": "Rule ini digerakkan oleh threat intelligence; aktifkan atau nonaktifkan di sini dan kelola indikator di Threat Intelligence",
    "This sample is already evidence in the case": "Sampel ini sudah menjadi evidence di kasus tersebut",
    "This setting is enforced by policy and cannot be changed": "Pengaturan ini ditetapkan oleh kebijakan dan tidak dapat diubah",
    "This topology was changed by someone else. Reload to get the latest version.": "Topologi ini diubah oleh orang lain. Muat ulang untuk mendapatkan versi terbaru.",
    "This vulnerability is already recorded for that asset and port": "Kerentanan ini sudah tercatat untuk aset dan port tersebut",
    "Time range is limited to 90 days": "Rentang waktu dibatasi 90 hari",
    "Too many attempts. Wait a few minutes before answering again.": "Terlalu banyak percobaan. Tunggu beberapa menit sebelum menjawab lagi.",
    "Topology has structural errors and cannot be saved": "Topologi memiliki error struktur dan tidak dapat disimpan",
    "URL must start with http:// or https:// and contain no spaces": "URL harus diawali http:// atau https:// dan tanpa spasi",
    "Unknown action": "Aksi tidak dikenal",
    "Unknown category": "Kategori tidak dikenal",
    "Unknown lab template": "Template lab tidak dikenal",
    "Unknown objective kind": "Jenis tujuan tidak dikenal",
    "Unknown or disabled ingest key": "Ingest key tidak dikenal atau nonaktif",
    "Unknown report kind or format": "Jenis atau format laporan tidak dikenal",
    "Unknown role(s)": "Role tidak dikenal",
    "Unknown scan profile": "Profil scan tidak dikenal",
    "Unknown setting": "Pengaturan tidak dikenal",
    "Unknown status filter": "Filter status tidak dikenal",
    "Unknown status": "Status tidak dikenal",
    "Unknown template": "Template tidak dikenal",
    "Unsupported kind": "Jenis tidak didukung",
    "Vulnerability or lab not found": "Kerentanan atau lab tidak ditemukan",
    "You can only act on your own resources": "Anda hanya dapat bertindak atas sumber daya milik sendiri",
    "You can view this network but not edit it": "Anda dapat melihat jaringan ini tetapi tidak dapat mengubahnya",
    "You cannot operate this lab": "Anda tidak dapat mengoperasikan lab ini",
    "You do not have access to the data for this report": "Anda tidak memiliki akses ke data laporan ini",
    "You do not have permission to perform this action": "Anda tidak memiliki izin untuk melakukan tindakan ini",
    "You may only assess labs you own (or hold lab.manage)": "Anda hanya dapat melakukan assessment pada lab milik sendiri (atau memiliki lab.manage)",
    "You may only scan labs you own (or hold lab.manage)": "Anda hanya dapat melakukan scan pada lab milik sendiri (atau memiliki lab.manage)",
    "You no longer have access to this report's data": "Anda tidak lagi memiliki akses ke data laporan ini",
    "include statements are not allowed": "pernyataan include tidak diizinkan",
    "Request validation failed": "Validasi permintaan gagal",
    "Internal server error": "Terjadi kesalahan internal pada server",
    "Assessment completed": "Assessment selesai",
    "Authorisation window ended before execution": "Jendela otorisasi berakhir sebelum eksekusi",
}

NOUNS = {
    "Alert": "Alert", "Assessment": "Assessment", "Assignee": "Penanggung jawab", "Attachment": "Lampiran", "CTF event": "Event CTF",
    "Case": "Kasus", "Catalogue entry": "Entri katalog", "Challenge": "Challenge", "Conversation": "Percakapan", "Course": "Kursus",
    "Document": "Dokumen", "Event": "Event", "Evidence": "Evidence", "Finding": "Temuan", "Hint": "Hint", "Image": "Image",
    "Incident": "Insiden", "Indicator": "Indikator", "Lab": "Lab", "Lesson": "Pelajaran", "Message": "Pesan", "Mission": "Misi",
    "Network": "Jaringan", "Objective": "Tujuan", "Open incident": "Insiden terbuka", "Recipient": "Penerima", "Relationship": "Relasi",
    "Report": "Laporan", "Role": "Role", "Rule": "Rule", "Ruleset": "Ruleset", "Sample": "Sampel", "Sandbox run": "Run sandbox",
    "Scan job": "Job scan", "Scenario": "Skenario", "Session": "Sesi", "Snapshot": "Snapshot", "Source": "Sumber", "Task": "Tugas",
    "Terminal session": "Sesi terminal", "User": "Pengguna",
}

STATUS = {
    "pending_approval": "menunggu persetujuan", "approved": "disetujui", "rejected": "ditolak", "queued": "dalam antrean",
    "running": "berjalan", "completed": "selesai", "aborted": "dibatalkan", "failed": "gagal", "expired": "kedaluwarsa",
    "cancelled": "dibatalkan", "stopped": "berhenti", "not deployed": "belum di-deploy", "open": "terbuka", "resolved": "selesai",
    "in_remediation": "dalam remediasi", "sealed": "disegel", "released": "dilepas", "exited": "berhenti",
}


_PW = {"both upper and lower case letters": "huruf besar dan huruf kecil", "a digit": "angka"}


def _pwpart(x: str) -> str:
    m = re.match(r"at least (\d+) characters", x)
    return f"minimal {m[1]} karakter" if m else _PW.get(x, x)


def _st(v: str) -> str:
    return STATUS.get(v, v)


PATTERNS: list[tuple[re.Pattern, callable]] = [
    (re.compile(r"^(.+) not found$"), lambda m: f"{NOUNS.get(m[1], m[1])} tidak ditemukan"),
    (re.compile(r"^Answer all (\d+) questions$"), lambda m: f"Jawab semua {m[1]} pertanyaan"),
    (re.compile(r"^Assessment is (\w+); it must be approved first$"), lambda m: f"Assessment berstatus {_st(m[1])}; harus disetujui terlebih dahulu"),
    (re.compile(r"^Assessment is (\w+)$"), lambda m: f"Assessment berstatus {_st(m[1])}"),
    (re.compile(r"^At most (\d+) indicators per import$"), lambda m: f"Maksimal {m[1]} indikator per impor"),
    (re.compile(r"^At most (\d+) terminal sessions may be open at once$"), lambda m: f"Maksimal {m[1]} sesi terminal boleh terbuka bersamaan"),
    (re.compile(r"^Batch too large \(max (\d+) records\)$"), lambda m: f"Batch terlalu besar (maks {m[1]} record)"),
    (re.compile(r"^Cannot move a finding from (\w+) to (\w+)$"), lambda m: f"Temuan tidak dapat dipindah dari {_st(m[1])} ke {_st(m[2])}"),
    (re.compile(r"^Cannot (\w+) a lab that is (.+)$"), lambda m: f"Tidak dapat menjalankan aksi {m[1]} pada lab yang berstatus {_st(m[2])}"),
    (re.compile(r"^Could not parse (\w+): (.*)$", re.S), lambda m: f"Tidak dapat membaca {m[1]}: {m[2]}"),
    (re.compile(r"^Evidence is already (\w+)$"), lambda m: f"Evidence sudah {_st(m[1])}"),
    (re.compile(r"^File exceeds the maximum size of (\d+) MB$"), lambda m: f"File melebihi ukuran maksimal {m[1]} MB"),
    (re.compile(r"^File type (.+) is not accepted for analysis\. Accepted: (.*)$", re.S), lambda m: f"Tipe file {m[1]} tidak diterima untuk analisis. Yang diterima: {m[2]}"),
    (re.compile(r"^Finding is (\w+)$"), lambda m: f"Temuan berstatus {_st(m[1])}"),
    (re.compile(r"^Images not on the allowlist: (.*)$"), lambda m: f"Image tidak ada di allowlist: {m[1]}"),
    (re.compile(r"^Invalid CVE identifiers: (.*)$"), lambda m: f"ID CVE tidak valid: {m[1]}"),
    (re.compile(r"^Invalid query: (.*)$", re.S), lambda m: f"Query tidak valid: {m[1]}"),
    (re.compile(r"^Lab exceeds resource quota: (.*)$", re.S), lambda m: f"Lab melebihi kuota sumber daya: {m[1]}"),
    (re.compile(r"^Modules not allowed: (.*)$", re.S), lambda m: f"Modul tidak diizinkan: {m[1]}"),
    (re.compile(r"^Objective '(.+)' needs an answer$"), lambda m: f"Tujuan '{m[1]}' memerlukan jawaban"),
    (re.compile(r"^Objective '(.+)': unknown (.+)$"), lambda m: f"Tujuan '{m[1]}': {m[2]} tidak dikenal"),
    (re.compile(r"^Objective (\d+) has been met by learners and cannot change its check$"), lambda m: f"Tujuan {m[1]} sudah dicapai peserta dan pemeriksaannya tidak dapat diubah"),
    (re.compile(r"^Password must contain (.*)$"), lambda m: "Password harus berisi " + ", ".join(_pwpart(x.strip()) for x in m[1].split(","))),
    (re.compile(r"^Rule source exceeds (\d+) characters$"), lambda m: f"Sumber rule melebihi {m[1]} karakter"),
    (re.compile(r"^Scan is (\w+)$"), lambda m: f"Scan berstatus {_st(m[1])}"),
    (re.compile(r"^Subnet (\S+) overlaps (\S+) used by running lab #(\d+)\. Stop that lab or change the CIDR\.$"),
     lambda m: f"Subnet {m[1]} bertabrakan dengan {m[2]} yang dipakai lab #{m[3]} yang sedang berjalan. Hentikan lab itu atau ubah CIDR-nya."),
    (re.compile(r"^Target (\S+) has no address inside the lab networks$"), lambda m: f"Target {m[1]} tidak memiliki alamat di dalam jaringan lab"),
    (re.compile(r"^Target (\S+) is not a deployed node of this lab$"), lambda m: f"Target {m[1]} bukan node yang sudah di-deploy di lab ini"),
    (re.compile(r"^The container is (\w+)$"), lambda m: f"Container berstatus {_st(m[1])}"),
    (re.compile(r"^Too many attempts\. Wait a few minutes before submitting again \(limit (\d+) wrong attempts per (\d+) minutes\)\.$"),
     lambda m: f"Terlalu banyak percobaan. Tunggu beberapa menit sebelum mengirim lagi (batas {m[1]} jawaban salah per {m[2]} menit)."),
    (re.compile(r"^YARA (syntax )?error: (.*)$", re.S), lambda m: f"Error {'sintaks ' if m[1] else ''}YARA: {m[2]}"),
    (re.compile(r"^You already have a network named '(.+)'$"), lambda m: f"Anda sudah memiliki jaringan bernama '{m[1]}'"),
    (re.compile(r"^Setting (\S+) must be at most (\d+) characters$"), lambda m: f"Pengaturan {m[1]} maksimal {m[2]} karakter"),
    (re.compile(r"^Setting (\S+) must be between (\S+) and (\S+)$"), lambda m: f"Pengaturan {m[1]} harus antara {m[2]} dan {m[3]}"),
    (re.compile(r"^Builtin (\w+)s are maintained by the platform; only publishing can be toggled$"),
     lambda m: "Item bawaan dikelola oleh platform; hanya status publikasi yang dapat diubah"),
    (re.compile(r"^network (\S+) \((\S+)\): Pool overlaps with other one on this address space$"),
     lambda m: f"Jaringan {m[1]} ({m[2]}): rentang alamat bertabrakan dengan jaringan Docker lain. Hentikan lab lain yang memakai subnet yang sama atau ubah CIDR."),
    (re.compile(r"^container for (\S+) no longer exists; reset the lab$"), lambda m: f"Container untuk {m[1]} sudah tidak ada; reset lab"),
    (re.compile(r"^cannot pull image (\S+)(: .*)?$", re.S), lambda m: f"Tidak dapat mengunduh image {m[1]}{m[2] or ''}"),
    (re.compile(r"^kind must be one of (.*) \(submit samples through Malware Analysis\)$"),
     lambda m: f"Jenis harus salah satu dari {m[1]} (kirim sampel melalui Analisis Malware)"),
    # assessment timeline (stored in English; translated for display)
    (re.compile(r"^(\S+) requested '(.+)' against (\d+) target\(s\) in lab (.+)$"), lambda m: f"{m[1]} mengajukan '{m[2]}' terhadap {m[3]} target di lab {m[4]}"),
    (re.compile(r"^(Approved|Rejected) by (\S+): (.*)$", re.S), lambda m: f"{'Disetujui' if m[1] == 'Approved' else 'Ditolak'} oleh {m[2]}: {m[3]}"),
    (re.compile(r"^Execution started by (\S+)$"), lambda m: f"Eksekusi dimulai oleh {m[1]}"),
    (re.compile(r"^Cancelled by (\S+)$"), lambda m: f"Dibatalkan oleh {m[1]}"),
    (re.compile(r"^Abort requested by (\S+)$"), lambda m: f"Pembatalan diminta oleh {m[1]}"),
    (re.compile(r"^Running (\d+) step\(s\) from (\S+) \((\S+)\)$"), lambda m: f"Menjalankan {m[1]} langkah dari {m[2]} ({m[3]})"),
    (re.compile(r"^Stopped before step (\d+): (.*)$", re.S), lambda m: f"Dihentikan sebelum langkah {m[1]}: {m[2]}"),
    (re.compile(r"^Step (\d+) done: (\d+) hosts up, (\d+) open ports, (\d+) HTTP responses, (\d+) findings, (\d+) telemetry records$"),
     lambda m: f"Langkah {m[1]} selesai: {m[2]} host aktif, {m[3]} port terbuka, {m[4]} respons HTTP, {m[5]} temuan, {m[6]} record telemetri"),
    (re.compile(r"^Step (\d+): (.*)$", re.S), lambda m: f"Langkah {m[1]}: {m[2]}"),
    (re.compile(r"^Execution failed: (.*)$", re.S), lambda m: f"Eksekusi gagal: {m[1]}"),
]

PYDANTIC = [
    (re.compile(r"^Field required$"), lambda m: "Wajib diisi"),
    (re.compile(r"^String should have at least (\d+) characters?$"), lambda m: f"Minimal {m[1]} karakter"),
    (re.compile(r"^String should have at most (\d+) characters?$"), lambda m: f"Maksimal {m[1]} karakter"),
    (re.compile(r"^Input should be a valid integer.*$"), lambda m: "Harus berupa angka bulat"),
    (re.compile(r"^Input should be a valid (.+)$"), lambda m: f"Format tidak valid ({m[1]})"),
    (re.compile(r"^Input should be greater than or equal to (\S+)$"), lambda m: f"Harus lebih besar atau sama dengan {m[1]}"),
    (re.compile(r"^Input should be less than or equal to (\S+)$"), lambda m: f"Harus lebih kecil atau sama dengan {m[1]}"),
    (re.compile(r"^value is not a valid email address: (.*)$"), lambda m: "Alamat email tidak valid"),
    (re.compile(r"^Value error, (.*)$", re.S), lambda m: translate(m[1])),
    (re.compile(r"^List should have at least (\d+) items?.*$"), lambda m: f"Minimal {m[1]} item"),
    (re.compile(r"^List should have at most (\d+) items?.*$"), lambda m: f"Maksimal {m[1]} item"),
]


def translate(message: str) -> str:
    if not message:
        return message
    if message in EXACT:
        return EXACT[message]
    for pat, fn in PATTERNS:
        m = pat.match(message)
        if m:
            return fn(m)
    return message


def translate_validation(msg: str) -> str:
    for pat, fn in PYDANTIC:
        m = pat.match(msg)
        if m:
            return fn(m)
    return translate(msg)


def wants_indonesian(accept_language: str | None) -> bool:
    if not accept_language:
        return False
    first = accept_language.split(",")[0].strip().lower()
    return first == "id" or first.startswith("id-")
