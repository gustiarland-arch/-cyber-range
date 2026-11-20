# CYBER RANGE Lab Kit isolation for Windows VMs (runs on every boot).
# Blocks new outbound connections on the Vagrant NAT adapter: the lab has no internet egress. Vagrant keeps managing
# the VM over WinRM, because replies to inbound connections are still allowed by the stateful firewall.
param([Parameter(Mandatory)][string]$LabIp)
$ErrorActionPreference = "Stop"
Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True
$nat = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne $LabIp -and $_.IPAddress -ne "127.0.0.1" }
foreach ($n in $nat) {
    $name = "CYBER RANGE isolate $($n.InterfaceAlias)"
    if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $name -Direction Outbound -InterfaceAlias $n.InterfaceAlias -Action Block | Out-Null
    }
}
# The domain controller's DNS must not forward lab queries to the internet either (PCs have no DNS server role)
if (Get-Command Get-DnsServerForwarder -ErrorAction SilentlyContinue) {
    Get-DnsServerForwarder -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress } |
        ForEach-Object { Remove-DnsServerForwarder -IPAddress $_.IPAddress -Force -ErrorAction SilentlyContinue }
}
Write-Host "CYBER RANGE isolation applied on $($nat.Count) NAT adapter(s)"
