---
name: Laporan pemasangan / uji coba
about: Laporkan hasil memasang atau mencoba Cyber Range di komputer Anda (berhasil maupun gagal)
title: "[Uji] <OS> - <berhasil/gagal di langkah ...>"
labels: uji-coba
---

**Jangan tempel isi file `.env`.** Isinya password dan token. Hapus password dari log sebelum dikirim.

## Komputer
- Sistem operasi dan versi (mis. Windows 11 23H2, Ubuntu 24.04, macOS 15):
- RAM total / RAM kosong saat menjalankan:
- CPU (mis. Intel i5 gen 10, Apple M2, AMD Ryzen 5):
- Versi Docker (`docker version --format "{{.Server.Version}}"`):
- Versi Compose (`docker compose version`):
- Cara menjalankan: start.bat / start.sh / vagrant up (folder vm)

## Hasil per langkah (ikuti UJI-DI-KOMPUTER-ANDA.md)
- [ ] 1. Start selesai dengan `SIAP: http://localhost:8080`
- [ ] 2. `docker compose ps` semua running/healthy, `/api/v1/health/ready` = ok
- [ ] 3. Lab "Corporate DMZ (DEMO)" berstatus running, sensor running
- [ ] 4. Panel Blue menampilkan deteksi "oleh sensor" > 0

Lama build pertama (perkiraan menit):

## Bila gagal
Langkah yang gagal:

Pesan error (teks, bukan screenshot bila bisa):

```
tempel di sini
```

Hasil `docker compose logs --tail 80 backend` (bila relevan):

```
tempel di sini
```
