# Komponen pihak ketiga

Lisensi `LICENSE` (MIT) hanya berlaku untuk kode di repositori ini. Komponen di bawah tetap memakai lisensinya
masing-masing. Komponen ini **tidak disertakan** di dalam ZIP. Semuanya diunduh oleh Docker, pip, atau npm saat build
di komputer pengguna.

Versi di tabel adalah versi yang terpasang saat rilis ini diuji. Lisensi pustaka Python dan npm dibaca langsung dari
metadata paket yang terpasang. Lisensi image Docker ditulis dari dokumentasi proyeknya, jadi periksa ulang bila
Anda mendistribusikan image hasil build.

## Image Docker (layanan aplikasi dan lab)

| Image | Dipakai untuk | Lisensi proyek |
|---|---|---|
| `mysql:8.4` | Database | GPL-2.0 (MySQL Community) |
| `redis:7-alpine` | Antrian dan cache | Redis 7.4 ke atas: RSALv2 / SSPLv1 (dual). Redis 7.2 ke bawah: BSD-3-Clause |
| `python:3.13-slim`, `python:3.13-alpine` | Backend, worker, shipper | PSF-2.0 |
| `node:22-alpine` | Build frontend | MIT |
| `nginx:1.27-alpine` | Menyajikan frontend | BSD-2-Clause |
| `ubuntu:24.04` + Samba AD | Image lab kantor (`lab-images/office`) | Samba: GPL-3.0; paket Ubuntu: lisensi masing-masing |
| `jasonish/suricata:7.0.8` | Sensor IDS lab | Suricata: GPL-2.0 |
| `zeek/zeek:7.0.5` | Sensor jaringan lab | BSD-3-Clause |
| `busybox:1.36` | Node lab ringan | GPL-2.0 |

Catatan Redis: lisensi RSALv2/SSPLv1 membolehkan pemakaian seperti di aplikasi ini (dijalankan sendiri di komputer
sendiri). Yang dibatasi adalah menawarkan Redis sebagai layanan terkelola. Bila Anda memerlukan lisensi OSI, ganti
image ke `redis:7.2-alpine` (BSD) atau `valkey/valkey` (BSD). Penggantian ini belum diuji.

## Pustaka Python (`backend/requirements.txt`)

| Paket | Versi | Lisensi |
|---|---|---|
| fastapi | 0.165.0 | MIT |
| uvicorn | 0.54.0 | BSD-3-Clause |
| sqlalchemy | 2.1.9 | MIT |
| alembic | 1.20.1 | MIT |
| pymysql | 1.2.4 | MIT |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause |
| pydantic | 2.14.3 | MIT |
| pydantic-settings | 2.16.3 | MIT |
| email-validator | 2.4.0 | Unlicense |
| argon2-cffi | 25.1.0 | MIT |
| pyjwt | 2.15.1 | MIT |
| redis (klien) | 8.1.0 | MIT |
| celery | 5.7.0 | BSD-3-Clause |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause |
| structlog | 26.1.0 | MIT OR Apache-2.0 |
| pyyaml | 6.0.3 | MIT |
| docker | 7.2.0 | Apache-2.0 |
| httpx | 0.28.1 | BSD-3-Clause |
| yara-python | 4.5.4 | Apache-2.0 |
| pefile | 2024.8.26 | MIT |
| minio | 7.2.15 | Apache-2.0 |
| python-multipart | 0.0.31 | Apache-2.0 |
| fpdf2 | 2.8.8 | LGPL-3.0-only (dipakai sebagai pustaka, tidak diubah) |
| maxminddb | 2.6.2 | Apache-2.0 |
| libvirt-python (opsional, VM) | 12.9.0 | LGPL-2.1 |

## Pustaka frontend (`frontend/package.json`)

| Paket | Versi | Lisensi |
|---|---|---|
| vue | 3.5.45 | MIT |
| vue-router | 5.5.1 | MIT |
| pinia | 4.1.0 | MIT |
| three | 0.187.0 | MIT |
| echarts | 6.1.0 | Apache-2.0 |
| monaco-editor | 0.57.0 | MIT |
| @xterm/xterm, @xterm/addon-fit | 5.5.0, 0.10.0 | MIT |
| @vue-flow/* | 1.x | MIT |
| lucide-vue-next | 1.0.0 | ISC |
| qrcode | 1.5.4 | MIT |
| topojson-client | 3.1.0 | ISC |
| world-atlas | 2.0.2 | ISC (data Natural Earth, domain publik) |
| @fontsource-variable/inter | 5.3.0 | OFL-1.1 |
| @fontsource-variable/jetbrains-mono | 5.3.0 | OFL-1.1 |

## Data yang dipasok pengguna

* **GeoLite2** (MaxMind) tidak disertakan. Bila Anda memasangnya sendiri di `storage/geoip`, berlaku lisensi
  GeoLite2 EULA dari MaxMind.
* **Windows** (VM, Lab Kit) tidak disertakan. Image Windows Evaluation atau berlisensi tunduk pada lisensi Microsoft.
