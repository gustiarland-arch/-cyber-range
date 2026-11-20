# CYBER RANGE Lab Kit: Windows Server domain controller, step 1 of 3 (first `vagrant up`).
# Installs Active Directory Domain Services and DNS, then creates the forest of the lab domain.
# Vagrant reboots the VM afterwards. Windows Server Evaluation; isolated lab network only.
param([string]$Domain = "@@DOMAIN@@", [string]$Netbios = "@@NETBIOS@@")
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) {
    Write-Host "dc01 is already a domain controller of $Domain"
    exit 0
}

function New-RandomSecret {
    # Used once, never stored, never shown: nobody needs these accounts; Vagrant manages the VM with its own account.
    $bytes = New-Object byte[] 24
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return "Cr-" + ([Convert]::ToBase64String($bytes) -replace '[+/=]', 'x') + "-9a!"
}

# The built-in Administrator becomes the domain administrator and must have a password before promotion.
$admin = Get-LocalUser | Where-Object { $_.SID -like "S-1-5-21-*-500" }
if ($admin) {
    $admin | Set-LocalUser -Password (ConvertTo-SecureString (New-RandomSecret) -AsPlainText -Force)
}

Write-Host "Installing AD DS and DNS (this takes a few minutes)"
Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools | Out-Null
Import-Module ADDSDeployment
$dsrm = ConvertTo-SecureString (New-RandomSecret) -AsPlainText -Force
Install-ADDSForest -DomainName $Domain -DomainNetbiosName $Netbios -SafeModeAdministratorPassword $dsrm `
    -InstallDns -NoRebootOnCompletion -Force -WarningAction SilentlyContinue | Out-Null
Write-Host "Forest $Domain created. Vagrant restarts dc01 now."
