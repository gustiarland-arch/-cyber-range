# Changelog

## 2.0.0

Rilis publik pertama Cyber Range (Edisi Lokal).

* **Lab jaringan terisolasi** di Docker (opsional VM KVM/libvirt atau Proxmox, eksperimental), termasuk template
  kantor dengan Active Directory (Samba AD), portal intranet, karyawan simulasi, dan host agent ke SIEM.
* **Red team terotorisasi** dengan katalog aksi non-destruktif, 8 skenario, jendela waktu yang disetujui, dan audit.
* **Blue team dan SOC:** SIEM, 21 rule deteksi bawaan dengan pemetaan MITRE ATT&CK, impor rule Sigma, replay file
  PCAP, alert, insiden, SOAR, dan SLA.
* **Purple team:** tampilan 3D lab hidup dengan panel Red | Blue berdampingan, pembaruan real-time, timeline yang bisa
  diputar ulang, dan skor yang memisahkan bukti sensor (Zeek/Suricata) dari catatan aplikasi.
* **Intelijen dan forensik:** threat intelligence, manajemen kerentanan, analisis malware statis dan YARA, forensik
  dengan chain of custody.
* **Latihan:** CTF dan misi.
* **Lab Kit:** ekspor lab ke Docker Compose atau Vagrant untuk dijalankan di komputer atau VM lain.
* **Keamanan edisi lokal:** hanya dibuka di 127.0.0.1, penjaga Host/Origin, token akses lokal opsional, secret acak
  per pemasangan, jaringan lab tanpa internet.
* **Pemasangan:** `start.bat` (Windows) atau `start.sh` (Linux/macOS) membuat `.env`, memindah port yang sudah
  terpakai, membangun, dan menunggu sampai siap.
* **Dokumentasi:** modul belajar bergambar di `docs/`, panduan uji di komputer sendiri, panduan VM Windows,
  pedoman penggunaan, kebijakan keamanan, dan daftar lisensi pihak ketiga.
