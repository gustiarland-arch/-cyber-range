# CYBER RANGE Lab Kit: exports Windows events as normalized JSON lines (runs every minute as SYSTEM).
# Domain controller (-Role dc):
#   ad.auth       4624/4625 logon, 4768 Kerberos TGT, 4771 Kerberos pre-authentication failed, 4776 NTLM validation
#   ad.change     4720 user created, 4728/4732/4756 member added to a group
# Workstation (-Role pc):
#   host.auth     4624/4625 logon on the PC (interactive, network, batch...), 4648 logon with explicit credentials
# Both:
#   host.process  Sysmon event 1 (or Security 4688 when Sysmon is not installed)
# Output: C:\ProgramData\CyberRange\telemetry\<node>.jsonl, mirrored to C:\cr-telemetry (the kit's telemetry folder).
# Command lines are redacted before they are written.
param([string]$Node = $env:COMPUTERNAME.ToLower(), [string]$LabIp = "", [ValidateSet("dc", "pc")][string]$Role = "dc")
$ErrorActionPreference = "SilentlyContinue"
$Dir = if ($env:CR_EXPORT_DIR) { $env:CR_EXPORT_DIR } else { "C:\ProgramData\CyberRange" }   # override for tests only
$AuthSet = if ($Role -eq "dc") { "ad.auth" } else { "host.auth" }
$Out = Join-Path (Join-Path $Dir "telemetry") "$Node.jsonl"
$StateFile = Join-Path $Dir "export-state.json"
$Utf8 = New-Object Text.UTF8Encoding $false
$Text = @{
    4624 = "An account was successfully logged on"; 4625 = "An account failed to log on"
    4768 = "A Kerberos authentication ticket (TGT) was requested"; 4771 = "Kerberos pre-authentication failed"
    4776 = "The computer attempted to validate the credentials for an account"; 4720 = "A user account was created"
    4728 = "A member was added to a security-enabled global group"; 4732 = "A member was added to a security-enabled local group"
    4756 = "A member was added to a security-enabled universal group"; 4688 = "A new process has been created"
    4648 = "A logon was attempted using explicit credentials"
}
# vagrant: the box account Vagrant uses to manage the VM over WinRM (lab management, not part of the scenario)
$Quiet = "^(ANONYMOUS LOGON|SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-\d+|UMFD-\d+|vagrant|-)$"

$state = @{ Security = 0; Sysmon = 0 }
if (Test-Path $StateFile) {
    try { $s = Get-Content -Raw $StateFile | ConvertFrom-Json; $state.Security = [long]$s.Security; $state.Sysmon = [long]$s.Sysmon } catch { }
}

function Redact([string]$s) {
    if (-not $s) { return $s }
    $s = $s -replace '(Lab|Cr)-[0-9A-Za-z+/=x-]{8,}!?', '[REDACTED]'
    $s = $s -replace '(?i)(-(Account)?Password\s+)\S+', '$1[REDACTED]'
    $s = $s -replace '(?i)(/p(assword)?:)\S+', '$1[REDACTED]'
    $s = $s -replace '(?i)(net(\.exe)?\s+user\s+\S+\s+)(?!/)\S+', '$1[REDACTED]'
    return $s
}

function Ip([string]$a) {
    if (-not $a -or $a -eq "-" -or $a -eq "::1" -or $a -eq "127.0.0.1") { return $null }
    return ($a -replace '^::ffff:', '')
}

function Get-EventData($e) {
    $d = @{}
    foreach ($x in ([xml]$e.ToXml()).Event.EventData.Data) { $d[$x.Name] = [string]$x.'#text' }
    return $d
}

function Emit($rec) {
    $clean = [ordered]@{}
    foreach ($k in $rec.Keys) { if ($null -ne $rec[$k] -and "$($rec[$k])" -ne "") { $clean[$k] = $rec[$k] } }
    $clean["host"] = $Node
    $script:lines.Add(($clean | ConvertTo-Json -Compress -Depth 3))
}

function Auth($e, $d) {
    $id = $e.Id
    $user = ("" + $d.TargetUserName).ToLower()
    if ($user.EndsWith('$') -or $user -match $Quiet -or $d.TargetUserName -match $Quiet) { return }
    $status = $d.Status
    switch ($id) {
        4624 { if ($d.LogonType -eq "5") { return }; $ok = $true; $proto = ("" + $d.AuthenticationPackageName).ToLower(); $port = $null }
        4625 { $ok = $false; $proto = ("" + $d.AuthenticationPackageName).ToLower(); $port = $null; $status = $d.SubStatus }
        4768 { $ok = ($status -eq "0x0"); $proto = "kerberos"; $port = 88 }
        4771 { $ok = $false; $proto = "kerberos"; $port = 88 }
        4776 { $ok = ($status -eq "0x0"); $proto = "ntlm"; $port = $null }
        4648 { $ok = $true; $proto = "explicit"; $port = $null }
    }
    $src = Ip $d.IpAddress
    $from = if ($src) { $src } elseif ($d.Workstation) { $d.Workstation } else { "-" }
    Emit ([ordered]@{
        timestamp = $e.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ")
        dataset = $AuthSet; category = "auth"
        action = $(if ($id -eq 4768) { "tgt_request" } elseif ($id -eq 4648) { "explicit_credentials" } elseif ($ok) { "logon" } else { "logon_failed" })
        outcome = $(if ($ok) { "success" } else { "failure" }); severity = $(if ($ok) { "info" } else { "low" })
        src_ip = $src; src_port = $(if ($d.IpPort -match '^\d+$' -and $d.IpPort -ne "0") { [int]$d.IpPort } else { $null })
        dst_ip = $LabIp; dst_port = $port; protocol = $proto; user = $user
        signature = "$id $($Text[$id])"; signature_id = "$id"
        message = "$($Text[$id]): $($d.TargetUserName) via $proto from $from" + $(if ($status) { " (status $status)" } else { "" }) + $(if ($d.LogonType) { " logon type $($d.LogonType)" } else { "" })
    })
}

function Change($e, $d) {
    $id = $e.Id
    $by = $d.SubjectUserName
    if ($id -eq 4720) {
        $msg = "$($Text[$id]): $($d.TargetUserName) by $by"; $action = "user_created"; $sev = "low"
    } else {
        $msg = "$($Text[$id]): $($d.MemberName) -> CN=$($d.TargetUserName) by $by"; $action = "group_member_added"; $sev = "medium"
    }
    Emit ([ordered]@{
        timestamp = $e.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ")
        dataset = "ad.change"; category = "auth"; action = $action; outcome = "success"; severity = $sev
        dst_ip = $LabIp; user = ("" + $by).ToLower(); signature = "$id $($Text[$id])"; signature_id = "$id"; message = $msg
    })
}

function Proc($e, $image, $cmd, $user, $parent) {
    if ($cmd -match 'export-events\.ps1') { return }
    $exe = Split-Path -Leaf $image
    $msg = (Redact $cmd) + " (parent $(Split-Path -Leaf $parent))"
    if ($msg.Length -gt 900) { $msg = $msg.Substring(0, 900) }
    Emit ([ordered]@{
        timestamp = $e.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ")
        dataset = "host.process"; category = "host"; action = "process_start"; outcome = "success"; severity = "info"
        src_ip = $LabIp; user = $user; signature = $exe
        message = $msg
    })
}

$script:lines = New-Object System.Collections.Generic.List[string]
$sysmon = [bool](Get-Service Sysmon64 -ErrorAction SilentlyContinue)
$ids = $(if ($Role -eq "dc") { "4624,4625,4768,4771,4776,4720,4728,4732,4756" } else { "4624,4625,4648" }) + $(if (-not $sysmon) { ",4688" } else { "" })
$idQuery = ($ids.Split(",") | ForEach-Object { "EventID=$_" }) -join " or "
$q = "*[System[($idQuery) and EventRecordID > $($state.Security)]]"
$events = Get-WinEvent -LogName Security -FilterXPath $q -MaxEvents 5000 | Sort-Object RecordId
foreach ($e in $events) {
    $d = Get-EventData $e
    if ($e.Id -in 4624, 4625, 4648, 4768, 4771, 4776) { Auth $e $d }
    elseif ($e.Id -eq 4688) { Proc $e $d.NewProcessName $d.CommandLine ("" + $d.SubjectUserName).ToLower() $d.ParentProcessName }
    else { Change $e $d }
    $state.Security = [Math]::Max($state.Security, $e.RecordId)
}
if ($sysmon) {
    $q = "*[System[EventID=1 and EventRecordID > $($state.Sysmon)]]"
    foreach ($e in (Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath $q -MaxEvents 5000 | Sort-Object RecordId)) {
        $d = Get-EventData $e
        Proc $e $d.Image $d.CommandLine (("" + $d.User) -replace '^.*\\', '').ToLower() $d.ParentImage
        $state.Sysmon = [Math]::Max($state.Sysmon, $e.RecordId)
    }
}

if ($script:lines.Count -gt 0) {
    [IO.File]::AppendAllText($Out, (($script:lines -join "`n") + "`n"), $Utf8)
}
[IO.File]::WriteAllText($StateFile, ($state | ConvertTo-Json -Compress), $Utf8)
# Mirror to the kit folder on your computer (VirtualBox shared folder). The file only grows, so offsets stay valid.
if ((Test-Path "C:\cr-telemetry") -and (Test-Path $Out)) {
    Copy-Item -Force $Out "C:\cr-telemetry\$Node.jsonl"
}
