# CYBER RANGE Lab Kit: one task of a simulated employee on a Windows 11 PC (DEMO). Runs as the employee's domain account
# every two minutes. Ordinary office work only, the background a SOC has to tell apart from attacks:
#   open the public or department file share and read a document     -> Kerberos service ticket, 4624 on the DC
#   look up internal names (DNS to the domain controller)
#   open the intranet portal home page (no sign-in: the password is not available to this script)
#   check the domain controller (nltest), refresh group policy
#   now and then mistype the password once when mapping a drive      -> 4771 on the DC, then work continues
# No traffic leaves the lab; nothing is exploited.
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
$cfg = Get-Content -Raw "C:\ProgramData\CyberRange\employee.json" | ConvertFrom-Json
$dc = $cfg.dc
$domain = $cfg.domain

function Share {
    $name = if ($cfg.dept -eq "Keuangan" -and (Get-Random -Maximum 10) -lt 6) { "Keuangan" } else { "Umum" }
    $files = Get-ChildItem "\\$dc\$name" -File
    if ($files) { Get-Content -TotalCount 20 ($files | Get-Random).FullName | Out-Null }
}

function Names {
    foreach ($n in ("portal", "intranet", "printer-lt2", "fileserver", $dc.Split(".")[0]) | Get-Random -Count 2) {
        Resolve-DnsName "$n.$domain" -DnsOnly | Out-Null
    }
}

function Portal {
    Invoke-WebRequest -UseBasicParsing -TimeoutSec 10 -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edg/130.0" "http://intranet.$domain/" | Out-Null
}

function Domain {
    if ((Get-Random -Maximum 2) -eq 0) { & nltest.exe /dsgetdc:$domain | Out-Null } else { & gpupdate.exe /target:user | Out-Null }
}

function Typo {
    # A wrong password (random, never a real one) for a drive mapping: one failed pre-authentication, then nothing.
    $bad = "Salah-" + [guid]::NewGuid().ToString("N").Substring(0, 10)
    $cred = New-Object Management.Automation.PSCredential("$env:USERDOMAIN\$($cfg.user)", (ConvertTo-SecureString $bad -AsPlainText -Force))
    New-PSDrive -Name "CRT" -PSProvider FileSystem -Root "\\$dc\Umum" -Credential $cred | Out-Null
    Remove-PSDrive -Name "CRT" -Force
}

$tasks = @("Share", "Share", "Names", "Portal", "Portal", "Domain")
if ((Get-Random -Maximum 100) -lt 6) { $tasks = @("Typo") }
Start-Sleep -Seconds (Get-Random -Minimum 0 -Maximum 50)
& ($tasks | Get-Random)
