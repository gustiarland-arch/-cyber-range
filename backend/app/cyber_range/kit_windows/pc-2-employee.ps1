# CYBER RANGE Lab Kit: Windows 11 employee PC, step 2 of 2.
# Gives the PC its simulated employee (the same choice of employee per PC name as the Linux office lab) and registers a
# scheduled task that runs employee.ps1 as that domain user every two minutes. The password is derived from the seed
# and handed to Task Scheduler, which keeps it in its own protected store; it is not written to any file.
param([string]$Seed, [Parameter(Mandatory)][string]$Node)
$ErrorActionPreference = "Stop"
if (-not $Seed -or $Seed.Length -lt 32) { throw "Missing lab seed (the Vagrantfile passes it from .lab-seed)" }
$Domain = "@@DOMAIN@@"
$Netbios = "@@NETBIOS@@"
$DcHost = "@@DC_HOST@@"
$Users = @(@@USERS@@)
$Depts = @(@@DEPTS@@)
$Dir = "C:\ProgramData\CyberRange"

function Get-LabPassword([string]$User) {
    $sha = [Security.Cryptography.SHA256]::Create()
    $h = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("${Seed}:$User")) | ForEach-Object { $_.ToString("x2") })
    return "Lab-$($h.Substring(0, 6))-$($h.Substring(6, 6).ToUpper())-$($h.Substring(12, 4))!"
}

# bot.py: idx = sum(NODE.encode()) % len(EMPLOYEES)
$sum = 0; foreach ($b in [Text.Encoding]::UTF8.GetBytes($Node)) { $sum += $b }
$idx = $sum % $Users.Count
$user = $Users[$idx]; $dept = $Depts[$idx]

New-Item -ItemType Directory -Force -Path $Dir | Out-Null
Copy-Item -Force "C:\Windows\Temp\cr-employee.ps1" "$Dir\employee.ps1"
# Non-secret settings for the employee script
[ordered]@{ domain = $Domain; dc = "$DcHost.$Domain"; user = $user; dept = $dept; node = $Node } |
    ConvertTo-Json | Set-Content -Encoding UTF8 "$Dir\employee.json"

# The employee works on this PC: a member of the local Users group, like any domain user who signs in here.
Add-LocalGroupMember -Group "Users" -Member "$Netbios\$user" -ErrorAction SilentlyContinue

$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Dir\employee.ps1`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Minutes 2)
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -StartWhenAvailable
# Task Scheduler grants the account "Log on as a batch job" when a task is registered with a stored password.
Register-ScheduledTask -TaskName "CYBER RANGE karyawan simulasi" -Action $action -Trigger $trigger -Settings $settings `
    -User "$Netbios\$user" -Password (Get-LabPassword $user) -RunLevel Limited -Force | Out-Null
Write-Host "${Node}: simulated employee $user ($dept) works here every 2 minutes"
