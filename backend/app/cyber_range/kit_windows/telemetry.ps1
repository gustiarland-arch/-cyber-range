# CYBER RANGE Lab Kit: telemetry for the Windows VMs (domain controller and Windows 11 PCs), last step.
# Turns on the audit policy a SOC expects, installs Sysmon (downloaded from Microsoft Sysinternals while the VM still
# has internet), and registers a scheduled task that exports the relevant events every minute as JSON lines to the
# kit's telemetry folder. kirim-ke-siem on your computer ships them to the SIEM.
param([Parameter(Mandatory)][string]$Node, [Parameter(Mandatory)][string]$LabIp, [ValidateSet("dc", "pc")][string]$Role = "dc")
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$Dir = "C:\ProgramData\CyberRange"
New-Item -ItemType Directory -Force -Path "$Dir\telemetry" | Out-Null

Write-Host "Audit policy: logon, Kerberos, credential validation, account and group management, process creation"
$subs = if ($Role -eq "dc") {
    "Logon", "Kerberos Authentication Service", "Kerberos Service Ticket Operations", "Credential Validation",
    "User Account Management", "Security Group Management", "Process Creation"
} else {
    "Logon", "Other Logon/Logoff Events", "Credential Validation", "User Account Management", "Security Group Management", "Process Creation"
}
foreach ($sub in $subs) {
    & auditpol.exe /set /subcategory:"$sub" /success:enable /failure:enable | Out-Null
}
# Command line in process creation events (4688), as recommended for SOC visibility
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force `
    -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -PropertyType DWord | Out-Null

if (-not (Get-Service Sysmon64 -ErrorAction SilentlyContinue)) {
    try {
        Write-Host "Installing Sysmon from download.sysinternals.com"
        Invoke-WebRequest -UseBasicParsing -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
        Expand-Archive -Force "$env:TEMP\Sysmon.zip" "$Dir\Sysmon"
        # Minimal configuration: process creation only (network and file events would flood a small lab).
        @'
<Sysmon schemaversion="4.90">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <CommandLine condition="contains">export-events.ps1</CommandLine>
      </ProcessCreate>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or"><NetworkConnect onmatch="include"/></RuleGroup>
    <RuleGroup name="" groupRelation="or"><FileCreate onmatch="include"/></RuleGroup>
  </EventFiltering>
</Sysmon>
'@ | Set-Content -Encoding ASCII "$Dir\Sysmon\cr-sysmon.xml"
        & "$Dir\Sysmon\Sysmon64.exe" -accepteula -i "$Dir\Sysmon\cr-sysmon.xml" | Out-Null
    } catch {
        Write-Warning "Sysmon could not be installed ($($_.Exception.Message)). Security events (4688) still cover process starts."
    }
}

Copy-Item -Force "C:\Windows\Temp\cr-export-events.ps1" "$Dir\export-events.ps1"
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Dir\export-events.ps1`" -Node $Node -LabIp $LabIp -Role $Role"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -StartWhenAvailable
Register-ScheduledTask -TaskName "CYBER RANGE telemetry export" -Action $action -Trigger $trigger -Settings $settings `
    -User "SYSTEM" -RunLevel Highest -Force | Out-Null
Write-Host "Telemetry export runs every minute -> telemetry\$Node.jsonl in the kit folder"
