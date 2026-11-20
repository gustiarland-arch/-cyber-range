# CYBER RANGE launcher for Windows (PowerShell 5.1+). Run through start.bat (double click).
# 1. creates .env from .env.example on first run and fills every empty secret with a random value
#    (existing values are never changed, nothing secret is printed);
# 2. moves host ports that are already in use (e.g. a local MySQL on 3306) to a free port;
# 3. checks Docker Desktop + Compose v2, builds and starts the stack, waits until it is ready and opens the browser.
$ErrorActionPreference = 'Continue'   # native tools write progress to stderr
Set-Location -Path $PSScriptRoot

function Say($m, $c = 'Gray') { Write-Host $m -ForegroundColor $c }
function Fail($m) { Say ''; Say "GAGAL: $m" Red; Say ''; Read-Host 'Tekan Enter untuk menutup'; exit 1 }
function NewSecret {
  $b = New-Object byte[] 32
  [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
  ([Convert]::ToBase64String($b) -replace '[+/=]', '')
}
function PortBusy([int]$p) {
  try { return [bool](Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue) } catch { return $false }
}
function WriteLines($lines) {
  # UTF-8 without BOM so Docker Compose reads the first key correctly
  [IO.File]::WriteAllLines((Join-Path $PSScriptRoot '.env'), [string[]]$lines, (New-Object Text.UTF8Encoding($false)))
}

Say '=== CYBER RANGE ===' Cyan

# --- 1. .env -------------------------------------------------------------------------------------
if (-not (Test-Path .env)) { Copy-Item .env.example .env; Say 'File .env dibuat dari .env.example' }
$lines = New-Object 'System.Collections.Generic.List[string]'
foreach ($l in @(Get-Content .env)) { $lines.Add([string]$l) }
function Get-Val($k) { foreach ($l in $lines) { if ($l -match "^$k=(.*)$") { return $Matches[1] } }; return $null }
function Set-Val($k, $v) {
  for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match "^$k=") { $lines[$i] = "$k=$v"; return } }
  $lines.Add("$k=$v")
}
foreach ($k in 'MYSQL_PASSWORD', 'MYSQL_ROOT_PASSWORD', 'CR_JWT_SECRET', 'REDIS_PASSWORD') {
  if ([string]::IsNullOrWhiteSpace((Get-Val $k))) { Set-Val $k (NewSecret); Say "  secret $k dibuat (acak)" }
}
if ([string]::IsNullOrWhiteSpace((Get-Val 'DOCKER_GID'))) { Set-Val 'DOCKER_GID' '0' }   # Docker Desktop socket group

# --- 2. ports --------------------------------------------------------------------------------------
$firstRun = -not (Test-Path '.cr-started')
foreach ($pair in @(@('FRONTEND_PORT', 8080), @('MYSQL_HOST_PORT', 3306), @('REDIS_HOST_PORT', 6379))) {
  $k = $pair[0]; $p = [int]$(if (Get-Val $k) { Get-Val $k } else { $pair[1] })
  if ($firstRun -and (PortBusy $p)) {
    $n = $p + 10000; while (PortBusy $n) { $n++ }
    Set-Val $k $n; Say "  port $p sudah dipakai aplikasi lain, $k dipindah ke $n" Yellow
  }
}
WriteLines $lines
$port = Get-Val 'FRONTEND_PORT'; if (-not $port) { $port = 8080 }

# --- 3. Docker -------------------------------------------------------------------------------------
Say 'Memeriksa Docker...'
$null = & docker version --format '{{.Server.Version}}' 2>$null
if ($LASTEXITCODE -ne 0) {
  $dd = Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'
  if (Test-Path $dd) {
    Say 'Docker Desktop belum berjalan, sedang dibuka (tunggu sampai 2 menit)...' Yellow
    Start-Process $dd
    for ($i = 0; $i -lt 60; $i++) { Start-Sleep 2; $null = & docker version --format '{{.Server.Version}}' 2>$null; if ($LASTEXITCODE -eq 0) { break } }
  }
  if ($LASTEXITCODE -ne 0) { Fail 'Docker Desktop tidak berjalan. Install/buka Docker Desktop (https://www.docker.com/products/docker-desktop/), tunggu "Engine running", lalu jalankan start.bat lagi.' }
}
$null = & docker compose version 2>$null
if ($LASTEXITCODE -ne 0) { Fail 'Perintah "docker compose" (Compose v2) tidak tersedia. Update Docker Desktop ke versi terbaru.' }

Say 'Membangun dan menjalankan container (pertama kali bisa 5-15 menit)...' Cyan
& docker compose up -d --build
if ($LASTEXITCODE -ne 0) { Fail 'docker compose up gagal. Kirim teks error di atas, atau jalankan: docker compose logs backend' }
New-Item -ItemType File -Force '.cr-started' | Out-Null
Say 'Membangun image lab kantor (domain controller, portal, workstation). Pertama kali 5-10 menit...' Cyan
& docker compose --profile lab-images build lab-office
if ($LASTEXITCODE -ne 0) { Say 'PERINGATAN: image lab kantor gagal dibangun. Template "Kantor dengan Active Directory" belum bisa dipakai; aplikasi tetap berjalan. Coba lagi nanti dengan start.bat.' Yellow }

Say 'Menunggu aplikasi siap...'
$url = "http://localhost:$port"
$ready = $false
for ($i = 0; $i -lt 120; $i++) {
  try { $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 "$url/api/v1/health/ready"; if ($r.StatusCode -eq 200) { $ready = $true; break } } catch { }
  Start-Sleep 5
}
if (-not $ready) { Fail "Aplikasi belum siap setelah 10 menit. Jalankan: docker compose ps   dan   docker compose logs backend" }

Say ''
Say "SIAP: $url" Green
Say 'Tidak ada login: aplikasi langsung terbuka (edisi lokal, hanya dari komputer ini).'
Say 'Berhenti: jalankan stop.bat (data tetap tersimpan).'
$tok = Get-Val 'CR_LOCAL_ACCESS_TOKEN'
if (-not [string]::IsNullOrWhiteSpace($tok)) { Start-Process "$url/#cr-token=$tok" } else { Start-Process $url }
Read-Host 'Tekan Enter untuk menutup jendela ini'
