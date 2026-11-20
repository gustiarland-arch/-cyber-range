# Memasang Windows sungguhan sebagai node VM (libvirt/KVM)

Status: **jalur ini ada di kode (`CR_VM_PROVIDER=libvirt`) tetapi belum pernah dibuktikan sampai Windows benar-benar
menyala**, karena memerlukan host Linux dengan virtualisasi perangkat keras aktif, yang tidak tersedia di lingkungan
pengembangan. Ikuti halaman ini sebagai panduan terbaik yang bisa diberikan dari membaca kode, bukan dari pengujian
langsung, dan laporkan setiap langkah yang tidak cocok dengan kenyataan.

Tanpa mengikuti panduan ini, node bertipe **VM** di topologi tetap bisa dipakai: ia berjalan sebagai container Linux
yang diperketat ("mode kompatibel"), bukan Windows sungguhan. Panduan ini hanya untuk yang benar-benar butuh Windows.

## Yang perlu dipahami lebih dulu

Aplikasi **tidak menginstal Windows untuk Anda**. Yang dilakukan aplikasi hanyalah: mengambil satu *image dasar*
yang sudah berisi Windows terpasang (`base.qcow2`), membuat salinan copy-on-write per lab darinya, dan menyalakannya
di jaringan lab yang terisolasi. Menginstal Windows ke dalam image dasar itu adalah pekerjaan satu kali yang Anda
lakukan sendiri di komputer (host), di luar aplikasi, dengan `virt-install`.

## Prasyarat

| Kebutuhan | Keterangan |
| --- | --- |
| Sistem operasi host | Linux asli (bukan lewat Docker Desktop di Windows/macOS). WSL2 di Windows bisa bekerja jika mendukung virtualisasi bersarang, tetapi belum diuji. |
| Virtualisasi perangkat keras | VT-x (Intel) atau AMD-V aktif di BIOS/UEFI. Periksa dengan `egrep -c '(vmx|svm)' /proc/cpuinfo` (harus > 0). |
| `/dev/kvm` | Harus ada di host. Cek: `ls -l /dev/kvm`. Halaman VM Manager di aplikasi menampilkan status ini. |
| Paket host | `qemu-kvm`, `libvirt-daemon-system`, `libvirt-clients`, `virtinst`, `bridge-utils` |
| RAM dan disk | Minimal 4 GB RAM dan 40 GB disk kosong khusus untuk satu VM Windows, di luar kebutuhan aplikasi |
| ISO Windows | Unduh sendiri dari sumber resmi Microsoft (misalnya Windows 11 Evaluation atau Windows Server Evaluation). Aplikasi tidak menyertakannya karena lisensi. |

## Langkah 1: pasang libvirt di host (bukan di container)

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y qemu-kvm libvirt-daemon-system libvirt-clients virtinst bridge-utils
sudo systemctl enable --now libvirtd
sudo usermod -aG libvirt,kvm "$USER"
# keluar dan masuk ulang (atau reboot) agar keanggotaan grup berlaku
```

Verifikasi:

```bash
virsh -c qemu:///system list --all
```

Bila ini gagal dengan izin ditolak, keanggotaan grup belum aktif pada sesi shell Anda.

## Langkah 2: instal Windows ke image dasar (sekali saja, di host)

Buat folder tempat aplikasi akan mencari image dasar:

```bash
sudo mkdir -p /var/lib/cyber-range/vm-images /var/lib/cyber-range/vm-disks
sudo chown "$USER" /var/lib/cyber-range/vm-images
```

Jalankan instalasi interaktif. Perintah ini membuka jendela VNC tempat Anda menginstal Windows seperti biasa:

```bash
virt-install \
  --name win-base-install \
  --memory 4096 --vcpus 2 \
  --disk path=/var/lib/cyber-range/vm-images/win11.qcow2,size=40,format=qcow2 \
  --cdrom /path/ke/windows.iso \
  --os-variant win11 \
  --network none \
  --graphics vnc,listen=127.0.0.1 \
  --noautoconsole
```

Lalu sambungkan dengan penampil VNC (misalnya `virt-viewer` atau klien VNC apa pun) ke `127.0.0.1:5900` dan selesaikan
instalasi Windows seperti biasa. `--network none` sengaja dipakai agar instalasi tidak pernah tersambung ke jaringan
apa pun, termasuk jaringan lab, sebelum Anda sendiri yang menilainya aman.

Setelah instalasi selesai dan Windows bisa masuk ke desktop:

```bash
virsh shutdown win-base-install
# tunggu sampai benar-benar mati, lalu:
virsh undefine win-base-install
```

Domain `win-base-install` dihapus (undefine); yang disimpan hanyalah berkas disknya
(`/var/lib/cyber-range/vm-images/win11.qcow2`). Berkas itulah yang menjadi *template* read-only yang akan disalin
aplikasi untuk setiap lab. **Jangan pernah menjalankan berkas ini langsung lagi** setelah ini; aplikasi menolak menulis
ke template, tetapi kebiasaan yang aman adalah menandainya hanya-baca:

```bash
chmod 0444 /var/lib/cyber-range/vm-images/win11.qcow2
```

Disarankan menjalankan Sysprep (`sysprep /generalize /oobe /shutdown`) di dalam Windows sebelum langkah shutdown di
atas, agar setiap salinan lab mendapat identitas Windows yang unik, bukan kloning identik. Ini praktik umum
pembuatan image dasar VM dan tidak spesifik untuk aplikasi ini.

## Langkah 3: aktifkan penyedia VM di aplikasi

Di file `.env`:

```bash
CR_VM_PROVIDER=libvirt
CR_LIBVIRT_IMAGES=win11=win11.qcow2
CR_LIBVIRT_IMAGE_DIR=/var/lib/cyber-range/vm-images
CR_LIBVIRT_DISK_DIR=/var/lib/cyber-range/vm-disks
LIBVIRT_GID=<gid grup libvirt di host, lihat: getent group libvirt>
```

Bangun ulang dan jalankan dengan overlay VM:

```bash
docker compose -f docker-compose.yml -f docker-compose.vm-libvirt.yml --profile lab up -d --build
```

Overlay ini membangun ulang `backend` dan `lab-worker` dengan `WITH_LIBVIRT=1` (menambahkan pustaka `libvirt-python`
yang tidak ada di image bawaan) dan menyambungkan keduanya ke soket `libvirtd` milik host.

## Langkah 4: pakai lewat aplikasi

1. Buka **Manajer Virtual Machine**. Kartu "Perangkat KVM" harus menunjukkan tersedia, dan "Mode aktif" harus
   berbunyi "VM penuh melalui libvirt" dengan template `win11` terdaftar.
2. Klik **Uji koneksi**. Harus menunjukkan terhubung beserta versi hypervisor.
3. Di Editor Topologi, tambahkan node bertipe **vm**, atur propertinya: `vm_template: win11`, `cpus`, `memory_mb`.
4. Buat dan deploy lab seperti biasa. Node VM akan muncul di Lab Manager dengan mode "VM (libvirt)".
5. Di tampilan 3D hidup, status node mengikuti status VM sungguhan (berjalan, mati, error).

## Yang perlu Anda buktikan sendiri (belum pernah diuji)

- Apakah `virt-install` dan Sysprep benar-benar menghasilkan image yang bisa dikloning berulang kali tanpa Windows
  meminta aktivasi ulang atau gagal boot.
- Apakah jaringan bridge yang dibuat Docker untuk subnet lab benar-benar bisa dipakai libvirt sebagai `<source
  bridge=...>` tanpa konfigurasi tambahan di host (kode mengasumsikan nama bridge Docker bisa dipakai langsung).
- Performa nyata menjalankan Windows lewat emulasi grafis VNC headless (tanpa akselerasi GPU) untuk latihan.
- Waktu boot Windows di dalam copy-on-write overlay, yang memengaruhi berapa lama "Deploy" terasa macet.

## Pemecahan masalah cepat

| Gejala | Kemungkinan penyebab |
| --- | --- |
| "libvirt-python is not installed in this image" | Belum dibangun dengan overlay `docker-compose.vm-libvirt.yml` |
| "cannot connect to libvirt at qemu:///system" | Soket `/var/run/libvirt/libvirt-sock` tidak termount, atau `libvirtd` tidak jalan di host |
| Template tidak terdaftar di VM Manager | `CR_LIBVIRT_IMAGES` salah format (harus `nama=file.qcow2`, dipisah koma untuk lebih dari satu) |
| "base image for 'win11' not found on the lab host" | Berkas tidak ada di `CR_LIBVIRT_IMAGE_DIR` dengan nama persis yang didaftarkan |
| VM dibuat tapi tidak pernah running | Cek log `lab-worker`: `docker compose logs --tail 80 lab-worker`; kemungkinan `/dev/kvm` tidak terlihat dari dalam container |
