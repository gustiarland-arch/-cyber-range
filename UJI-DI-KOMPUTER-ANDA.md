# Uji Cyber Range di komputer Anda

Tujuan: membuktikan tiga hal yang belum bisa diuji di luar komputer Anda. Pertama, aplikasi jalan lewat `start.bat`.
Kedua, sensor Zeek/Suricata melihat lalu lintas lab. Ketiga, deteksi didukung bukti sensor, bukan hanya catatan aplikasi.
Waktu yang dibutuhkan sekitar 20 menit (build pertama 5–15 menit).

Kirim hasil tiap langkah, teks atau screenshot. Bila repositori ada di GitHub, pakai formulir issue
**Laporan pemasangan / uji coba** (berisi daftar isian yang sama). Kalau ada yang gagal, berhenti di situ dan kirim pesan error-nya.

## 1. Jalankan
1. Pastikan Docker Desktop berjalan dan komputer terhubung ke internet (image harus diunduh dari Docker Hub).
2. Klik dua kali `start.bat` (Linux/macOS: `./start.sh`).
3. **Kirim:** baris terakhir jendela start (`SIAP: http://localhost:8080` atau pesan error-nya).

## 2. Cek kesehatan
Di PowerShell atau Terminal, dari folder ini:

```
docker compose ps
curl http://localhost:8080/api/v1/health/ready
```

**Kirim:** kedua hasilnya. Semua servis harus `running`/`healthy`, dan JSON-nya `"status": "ok"`.

## 3. Lab dan sensor
1. Di aplikasi: menu **Template Lab** → kartu **Corporate DMZ (DEMO)** → **Gunakan template** (membuat topologi).
   Lalu **Lab Manager → Lab baru** → pilih topologi itu → buka lab → **Deploy**, dan tunggu status "running".
2. Buka lab itu → **Tampilan 3D hidup** → tombol **Sensor → Pasang Zeek + Suricata di semua subnet**.
3. Tunggu sekitar 1 menit, lalu buka lagi panel Sensor.
4. **Kirim:** screenshot panel Sensor (status tiap sensor: running atau failed, beserta pesannya).

Kalau sensor gagal, kirim juga:
```
docker ps -a --filter label=cyber-range.sensor --format "{{.Names}} {{.Status}}"
docker compose logs --tail 80 lab-worker
```

## 4. Bukti sensor sungguhan
1. Di Red Team → **Simulasi Serangan → Ajukan assessment**: skenario **RT-PURPLE-04**, penyerang satu PC di LAN,
   target node lain di subnet LAN yang sama. Setujui, lalu jalankan dari panel Red Team di tampilan 3D.
2. Setelah selesai, lihat panel **Blue Team**.
3. **Kirim:** screenshot panel Blue (kotak "oleh sensor" dan lencana SENSOR/APP per langkah).

Bila "oleh sensor" lebih dari 0, sensor terbukti melihat serangan sungguhan. Bila 0 padahal sensor `running`, kirim
hasil query SIEM berikut (menu **SIEM & Analisis Log**, rentang 1 jam): `dataset:zeek.*` dan `dataset:suricata.*`.

## Jangan kirim
Isi file `.env` (berisi password dan token). Kalau log menampilkan password, hapus dulu sebelum dikirim.
