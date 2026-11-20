# CYBER RANGE Lab Kit: Windows Server domain controller, step 2 of 3.
# Creates the DEMO organisation: departments (groups), employees, file shares with DEMO documents, DNS records for the
# other lab hosts. Employee passwords are derived from the per-kit seed (.lab-seed, created on your computer by the
# Vagrantfile at the first `vagrant up`); they are the same values the simulated employees on the Linux VMs use, are
# never written to disk here and are never shown.
param([string]$Seed)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
if (-not $Seed -or $Seed.Length -lt 32) { throw "Missing lab seed (the Vagrantfile passes it from .lab-seed)" }

$Domain = "@@DOMAIN@@"
$LabIp = "@@LAB_IP@@"
$Employees = @(
@@EMPLOYEES@@
)
$Groups = @(@@GROUPS@@)
$Docs = @{
@@DOCS@@
}
$Records = @{
@@RECORDS@@
}

Write-Host "Waiting for Active Directory Web Services"
for ($i = 0; $i -lt 60; $i++) {
    try { Import-Module ActiveDirectory; Get-ADDomain | Out-Null; break } catch { Start-Sleep -Seconds 10 }
}
$dom = Get-ADDomain
$dn = $dom.DistinguishedName
$nb = $dom.NetBIOSName

function Get-LabPassword([string]$User) {
    # Same derivation as common.password() in the office lab scripts: sha256("<seed>:<user>")
    $sha = [Security.Cryptography.SHA256]::Create()
    $h = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("${Seed}:$User")) | ForEach-Object { $_.ToString("x2") })
    return "Lab-$($h.Substring(0, 6))-$($h.Substring(6, 6).ToUpper())-$($h.Substring(12, 4))!"
}

foreach ($ou in "Karyawan", "Grup") {
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$ou'" -SearchBase $dn -SearchScope OneLevel)) {
        New-ADOrganizationalUnit -Name $ou -Path $dn -ProtectedFromAccidentalDeletion $false
    }
}
foreach ($g in $Groups) {
    if (-not (Get-ADGroup -Filter "Name -eq '$g'")) {
        New-ADGroup -Name $g -GroupScope Global -GroupCategory Security -Path "OU=Grup,$dn" -Description "Departemen $g (DEMO)"
    }
}
foreach ($e in $Employees) {
    $pw = ConvertTo-SecureString (Get-LabPassword $e.User) -AsPlainText -Force
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$($e.User)'")) {
        New-ADUser -Name $e.Name -SamAccountName $e.User -UserPrincipalName "$($e.User)@$Domain" -GivenName $e.First `
            -Surname $e.Last -Department $e.Dept -Description "Karyawan DEMO ($($e.Dept))" -Path "OU=Karyawan,$dn" `
            -AccountPassword $pw -Enabled $true -PasswordNeverExpires $true
    } else {
        Set-ADAccountPassword -Identity $e.User -Reset -NewPassword $pw   # the seed may be new after `vagrant destroy`
    }
    Add-ADGroupMember -Identity $e.Dept -Members $e.User
}
Add-ADGroupMember -Identity "Domain Admins" -Members "andi.saputra"   # the IT admin: a realistic privileged account to watch

foreach ($share in $Docs.Keys) {
    $path = "C:\Shares\$share"
    New-Item -ItemType Directory -Force -Path $path | Out-Null
    foreach ($f in $Docs[$share].Keys) {
        [IO.File]::WriteAllText("$path\$f", $Docs[$share][$f], (New-Object Text.UTF8Encoding $false))
    }
    if (-not (Get-SmbShare -Name $share -ErrorAction SilentlyContinue)) {
        $who = if ($share -eq "Umum") { "$nb\Domain Users" } else { "$nb\$share" }
        New-SmbShare -Name $share -Path $path -ReadAccess $who -FullAccess "$nb\Domain Admins" -Description "Share $share (DEMO)" | Out-Null
    }
}

# DNS: lab hosts by name; the NAT adapter that Vagrant uses for management must not appear in the lab's DNS.
foreach ($name in $Records.Keys) {
    if (-not (Get-DnsServerResourceRecord -ZoneName $Domain -Name $name -RRType A -ErrorAction SilentlyContinue)) {
        Add-DnsServerResourceRecordA -ZoneName $Domain -Name $name -IPv4Address $Records[$name]
    }
}
if ($Records.ContainsKey("portal") -and -not (Get-DnsServerResourceRecord -ZoneName $Domain -Name "intranet" -ErrorAction SilentlyContinue)) {
    Add-DnsServerResourceRecordCName -ZoneName $Domain -Name "intranet" -HostNameAlias "portal.$Domain"
}
$nat = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne $LabIp -and $_.IPAddress -ne "127.0.0.1" }
foreach ($n in $nat) {
    Set-DnsClient -InterfaceIndex $n.InterfaceIndex -RegisterThisConnectionsAddress $false
    Get-DnsServerResourceRecord -ZoneName $Domain -RRType A -ErrorAction SilentlyContinue |
        Where-Object { $_.RecordData.IPv4Address.IPAddressToString -eq $n.IPAddress } |
        Remove-DnsServerResourceRecord -ZoneName $Domain -Force
}
& dnscmd.exe /ResetListenAddresses $LabIp | Out-Null
Restart-Service DNS
Write-Host "DEMO organisation ready: $($Employees.Count) employees, $($Groups.Count) departments, shares $($Docs.Keys -join ', ')"
