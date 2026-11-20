# CYBER RANGE di dalam VM

Folder ini menjalankan CYBER RANGE Edisi Lokal di sebuah VM Ubuntu 24.04, bukan langsung di komputer Anda.
Cocok bila Anda tidak mau memasang Docker di komputer utama, atau ingin semua lab terkurung di satu VM.

## Kebutuhan
* Vagrant 2.4+ dan VirtualBox 7 (Windows/macOS/Linux), atau libvirt + plugin `vagrant-libvirt` (Linux).
* RAM bebas minimal 8 GB untuk VM (bawaan: 4 CPU, 8 GB RAM) dan sekitar 25 GB disk.
* Internet saat `vagrant up` pertama (mengunduh box, Docker, dan membangun image).

## Menjalankan
1. Buka terminal di folder `vm` ini.
2. Jalankan `vagrant up`. Pertama kali bisa 15–30 menit.
3. Buka **http://localhost:8080** di browser komputer Anda. Tidak ada login.

Bila port 8080 sudah dipakai, Vagrant memindahkannya otomatis; lihat port yang dipakai dengan `vagrant port`.

| Perintah | Fungsi |
|---|---|
| `vagrant halt` | Matikan VM (data tetap) |
| `vagrant up` | Nyalakan lagi; aplikasi ikut menyala |
| `vagrant provision` | Pasang ulang aplikasi dari folder induk ke VM (data dan `.env` tetap) |
| `vagrant ssh` | Masuk ke VM. Aplikasi ada di `/opt/cyber-range` (`cd /opt/cyber-range && docker compose ps`) |
| `vagrant destroy -f` | Hapus VM beserta semua datanya |

Ubah sumber daya sebelum `vagrant up`, misalnya di Windows (PowerShell):
`$env:CR_VM_MEMORY="12288"; $env:CR_VM_CPUS="6"; vagrant up`. Variabel lain: `CR_VM_PORT`, `CR_VM_BOX`.

## Keamanan
* Port aplikasi hanya diteruskan ke `127.0.0.1` komputer Anda, bukan ke jaringan LAN.
* VM tidak punya adapter jaringan tambahan; hanya NAT milik Vagrant.
* Di dalam VM aplikasi mendengar di semua antarmuka VM agar port forward bisa masuk, tetapi sesi lokal tetap ditolak
  bila alamat yang dipakai bukan `localhost`.
* `.env` dibuat di dalam VM dengan secret acak sendiri. `.env` di komputer Anda tidak pernah disalin ke VM.
* Lab di dalam VM berjalan sebagai container Docker di VM itu. Node VM sungguhan (KVM) di dalam VM butuh nested
  virtualization dan tidak diaktifkan oleh folder ini.
