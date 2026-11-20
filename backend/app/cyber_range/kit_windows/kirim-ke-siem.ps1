# CYBER RANGE Lab Kit: ship the lab's telemetry (telemetry\*.jsonl) to the SIEM of your CYBER RANGE app (Windows).
# 1. In CYBER RANGE: SIEM & Analisis Log -> Sumber log -> tambah sumber jenis "json". Save the configuration file as
#    cr-shipper.env in this kit folder (it holds the ingest key; this kit never contains one).
# 2. Double-click kirim-ke-siem.bat. It sends new lines every 15 seconds; close the window to stop.
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Conf = Join-Path $Here "cr-shipper.env"
$Tel = Join-Path $Here "telemetry"
$State = Join-Path $Tel ".terkirim.json"
if (-not (Test-Path $Conf)) { Write-Host "cr-shipper.env tidak ditemukan. Buat sumber log jenis json di SIEM, lalu simpan file konfigurasinya di folder ini."; exit 1 }
$c = @{}
foreach ($line in Get-Content $Conf) { if ($line -match '^([A-Z_]+)=(.*)$') { $c[$Matches[1]] = $Matches[2] } }
if ($c.CR_INGEST_KIND -ne "json") { Write-Host "Sumber log harus berjenis json (CR_INGEST_KIND=json)."; exit 1 }
if (-not $c.CR_INGEST_URL -or -not $c.CR_INGEST_KEY) { Write-Host "cr-shipper.env tidak lengkap."; exit 1 }
New-Item -ItemType Directory -Force -Path $Tel | Out-Null
$sent = @{}
if (Test-Path $State) { (Get-Content -Raw $State | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $sent[$_.Name] = [long]$_.Value } }
Write-Host "Mengirim telemetri dari $Tel ke $($c.CR_INGEST_URL) (tutup jendela ini untuk berhenti)"
while ($true) {
    foreach ($f in Get-ChildItem -Path $Tel -Filter *.jsonl) {
        $off = 0; if ($sent.ContainsKey($f.Name)) { $off = $sent[$f.Name] }
        if ($f.Length -lt $off) { $off = 0 }
        if ($f.Length -eq $off) { continue }
        $fs = [IO.File]::Open($f.FullName, 'Open', 'Read', 'ReadWrite')
        try {
            [void]$fs.Seek($off, 'Begin')
            $buf = New-Object byte[] ([Math]::Min(8000000, $f.Length - $off))
            $n = $fs.Read($buf, 0, $buf.Length)
        } finally { $fs.Close() }
        $end = [Array]::LastIndexOf($buf, [byte]10, $n - 1)
        if ($end -lt 0) { continue }
        $text = [Text.Encoding]::UTF8.GetString($buf, 0, $end + 1)
        $lines = @($text -split "`n" | Where-Object { $_.Trim() })
        try {
            for ($i = 0; $i -lt $lines.Count; $i += 2000) {
                $body = ($lines[$i..([Math]::Min($i + 1999, $lines.Count - 1))] -join "`n") + "`n"
                Invoke-RestMethod -Method Post -Uri $c.CR_INGEST_URL -ContentType "text/plain; charset=utf-8" `
                    -Headers @{ "X-Ingest-Key" = $c.CR_INGEST_KEY } -Body ([Text.Encoding]::UTF8.GetBytes($body)) | Out-Null
            }
        } catch {
            Write-Host "$($f.Name): gagal mengirim ($($_.Exception.Message)). Dicoba lagi nanti."
            continue
        }
        $sent[$f.Name] = $off + $end + 1
        $sent | ConvertTo-Json -Compress | Set-Content -Encoding ASCII $State
        Write-Host "$(Get-Date -Format HH:mm:ss) $($f.Name): $(@($lines).Count) event terkirim"
    }
    Start-Sleep -Seconds 15
}
