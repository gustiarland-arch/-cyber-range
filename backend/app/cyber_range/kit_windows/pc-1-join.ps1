# CYBER RANGE Lab Kit: Windows 11 employee PC, step 1 of 2 (first `vagrant up`).
# Points the lab adapter's DNS at the domain controller and joins the PC to the lab domain with the DEMO IT admin
# account, as an IT department would. The password is derived from the per-kit seed (.lab-seed) inside the VM, used
# once for the join and never written to disk. Vagrant restarts the PC afterwards.
param([string]$Seed, [Parameter(Mandatory)][string]$LabIp)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
if (-not $Seed -or $Seed.Length -lt 32) { throw "Missing lab seed (the Vagrantfile passes it from .lab-seed)" }
$Domain = "@@DOMAIN@@"
$Netbios = "@@NETBIOS@@"
$DcIp = "@@DC_IP@@"
$Admin = "@@JOIN_ADMIN@@"

$cs = Get-CimInstance Win32_ComputerSystem
if ($cs.PartOfDomain -and $cs.Domain -eq $Domain) {
    Write-Host "$env:COMPUTERNAME is already a member of $Domain"
    exit 0
}

function Get-LabPassword([string]$User) {
    # Same derivation as dc-2-org.ps1 and the office lab scripts: sha256("<seed>:<user>")
    $sha = [Security.Cryptography.SHA256]::Create()
    $h = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("${Seed}:$User")) | ForEach-Object { $_.ToString("x2") })
    return "Lab-$($h.Substring(0, 6))-$($h.Substring(6, 6).ToUpper())-$($h.Substring(12, 4))!"
}

# DNS: the lab adapter asks the domain controller; the Vagrant NAT adapter must not register in the lab's DNS.
$lab = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -eq $LabIp } | Select-Object -First 1
if (-not $lab) { throw "No adapter with the lab address $LabIp" }
Set-DnsClientServerAddress -InterfaceIndex $lab.InterfaceIndex -ServerAddresses $DcIp
foreach ($n in (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne $LabIp -and $_.IPAddress -ne "127.0.0.1" })) {
    Set-DnsClient -InterfaceIndex $n.InterfaceIndex -RegisterThisConnectionsAddress $false
}
Set-DnsClientGlobalSetting -SuffixSearchList @($Domain)

Write-Host "Waiting for the domain controller ($DcIp) of $Domain"
$ready = $false
for ($i = 0; $i -lt 90; $i++) {
    try { Resolve-DnsName -Type SRV "_ldap._tcp.dc._msdcs.$Domain" -Server $DcIp -DnsOnly | Out-Null; $ready = $true; break }
    catch { Start-Sleep -Seconds 20 }
}
if (-not $ready) { throw "The domain controller did not answer in 30 minutes. Run 'vagrant up' for the DC first, then 'vagrant provision $env:COMPUTERNAME'." }

$cred = New-Object Management.Automation.PSCredential("$Netbios\$Admin", (ConvertTo-SecureString (Get-LabPassword $Admin) -AsPlainText -Force))
for ($i = 0; $i -lt 10; $i++) {
    try { Add-Computer -DomainName $Domain -Credential $cred -Force -WarningAction SilentlyContinue; break }
    catch { if ($i -eq 9) { throw }; Write-Host "Join not possible yet ($($_.Exception.Message)); retrying"; Start-Sleep -Seconds 30 }
}
Write-Host "$env:COMPUTERNAME joined $Domain. Vagrant restarts the PC now."
