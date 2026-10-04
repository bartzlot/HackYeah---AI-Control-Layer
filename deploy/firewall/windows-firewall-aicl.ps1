# AICL reference egress rules for managed Windows workstations (GPO / Intune would deploy the same rules).
# Run elevated. Addresses are documentation examples: set the AICL resolver and the provider ranges you verified.
# Effect: DNS only to AICL, no DNS-over-TLS, no direct HTTPS to the AI providers, so DHCP-provided AICL DNS +
# the trusted AICL root CA is the only working path (research/14 s.1).
$Aicl = "10.77.0.2"
$Providers = @("160.79.104.0/23")

New-NetFirewallRule -DisplayName "AICL: block DNS except AICL" -Direction Outbound -Protocol UDP -RemotePort 53 `
  -RemoteAddress @("0.0.0.0-10.77.0.1", "10.77.0.3-255.255.255.255") -Action Block
New-NetFirewallRule -DisplayName "AICL: block DNS over TCP except AICL" -Direction Outbound -Protocol TCP -RemotePort 53 `
  -RemoteAddress @("0.0.0.0-10.77.0.1", "10.77.0.3-255.255.255.255") -Action Block
New-NetFirewallRule -DisplayName "AICL: block DNS-over-TLS" -Direction Outbound -Protocol TCP -RemotePort 853 -Action Block
New-NetFirewallRule -DisplayName "AICL: no direct AI provider API" -Direction Outbound -Protocol TCP -RemotePort 443 `
  -RemoteAddress $Providers -Action Block
# Browsers: turn off their own DNS-over-HTTPS by policy (Chrome DnsOverHttpsMode=off, Edge the same, Firefox
# network.trr.mode=5); the AICL resolver also answers NXDOMAIN for known DoH hosts and raises an alert.
Write-Output "AICL egress rules installed; AICL resolver $Aicl"
