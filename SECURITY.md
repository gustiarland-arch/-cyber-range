# Keamanan

Edisi lokal ditujukan untuk **satu pengguna di komputer sendiri**. Batas keamanannya:

* Web hanya dibuka di `127.0.0.1`. Sesi hanya diberikan bila `Host`/`Origin` adalah localhost
  (`CR_LOCAL_ALLOWED_HOSTS`), sehingga situs lain dan DNS rebinding tertahan.
* Tanpa token akses lokal, **program apa pun di komputer ini** yang bisa menghubungi 127.0.0.1 bisa membuka sesi operator.
  Isi `CR_LOCAL_ACCESS_TOKEN` (lihat README) bila komputer dipakai bersama atau menjalankan perangkat lunak yang tidak
  dipercaya.
* `lab-worker` dan `terminal-gateway` memegang socket Docker. Akses ke socket itu setara root di host. Jalankan di
  komputer atau VM khusus lab bila memungkinkan, dan jangan buka port aplikasi, MySQL, atau Redis ke jaringan lain.
* Container lab berjalan tanpa capability Linux kecuali `NET_RAW` (bagian dari set default Docker, dibutuhkan ping). Dengan
  `NET_RAW`, proses di dalam lab bisa membuat paket mentah di jaringan lab itu sendiri. Jaringannya tetap internal.
* Lab memakai jaringan Docker internal tanpa internet. Subnet lab yang berbeda juga terisolasi satu sama lain di host,
  bahkan lewat router/firewall lab. Ini disengaja dan tidak dilonggarkan. Aksi red team terbatas pada katalog non-destruktif di
  `backend/app/redteam/actions.py`, hanya ke node lab milik sendiri, dalam jendela waktu yang disetujui, dan diaudit.

## Melaporkan celah

Laporkan secara pribadi, bukan lewat issue publik:

* Bila repositori ada di GitHub: tab **Security → Report a vulnerability** (private vulnerability reporting harus
  diaktifkan pemilik repo di Settings → Code security).
* Selain itu: hubungi pengelola lewat kontak yang tercantum di halaman rilis.

Sertakan versi (lihat `CHANGELOG.md`), langkah reproduksi, dan dampaknya. Jangan sertakan isi file `.env`.

## Versi yang didukung

Hanya rilis terbaru yang menerima perbaikan keamanan.
