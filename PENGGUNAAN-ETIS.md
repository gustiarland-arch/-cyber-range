# Pedoman penggunaan

Cyber Range (Edisi Lokal) dibuat untuk **belajar dan berlatih keamanan siber di lab milik sendiri**. Fitur red team-nya
menjalankan alat dan teknik sungguhan, walaupun terbatas pada katalog aksi non-destruktif, di dalam jaringan Docker
atau VM yang terisolasi.

## Boleh

* Berlatih menyerang dan mendeteksi **node lab yang dibuat oleh aplikasi ini** di komputer Anda sendiri.
* Mengajar di kelas atau komunitas, selama setiap peserta menjalankan lab di komputer atau VM masing-masing.
* Menguji dan menulis rule deteksi, lalu memutar ulang file PCAP milik sendiri atau capture publik yang lisensinya
  membolehkan.
* Mengubah, memperbaiki, dan membagikan ulang kode sesuai `LICENSE`.

## Tidak boleh

* Mengarahkan aksi, alat, atau teknik dari aplikasi ini ke sistem, jaringan, atau akun **yang bukan milik Anda** atau
  yang tidak memberi izin tertulis.
* Membuka port aplikasi, MySQL, atau Redis ke jaringan lain atau ke internet. Edisi ini tidak punya login.
* Melonggarkan isolasi jaringan lab supaya bisa menjangkau jaringan kantor, kampus, atau internet.
* Memakai data DEMO seolah-olah itu hasil deteksi atau intelijen sungguhan.

## Tanggung jawab

Aplikasi ini disediakan "apa adanya" tanpa jaminan (lihat `LICENSE`). Pengguna bertanggung jawab atas cara ia memakainya.
Di Indonesia, akses tanpa izin ke sistem elektronik orang lain dapat melanggar hukum, antara lain UU ITE. Bila aplikasi
ini akan dipakai atas nama institusi (kampus, kantor, pelatihan berbayar), mintalah pendapat bagian hukum institusi
tersebut lebih dahulu. Pedoman ini bukan nasihat hukum.

## Bila menemukan celah keamanan di aplikasi ini

Lihat `SECURITY.md`. Jangan mengumumkannya di forum publik sebelum ada perbaikan.
