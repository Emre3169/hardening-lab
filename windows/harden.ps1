<#
.SYNOPSIS
  CIS-style hardening for the Windows 11 ARM64 lab VM (PLAN.md section 3, trimmed scope).

.DESCRIPTION
  Groups, in run order: Services, DefenderFirewall, AuditPolicy, AccountPolicy.
  Every check prints OK (already compliant), WOULD CHANGE (-DryRun) or CHANGED.
  A real run snapshots what it is about to change into C:\hardening-lab\backups\<UTC ts>\
  and records every change in manifest.json there; rollback.ps1 replays it in reverse.
  Re-running is safe: compliant items are left alone.
  Patch level is recorded by score.ps1 (Get-HotFix), not changed here.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File harden.ps1 -DryRun
  powershell -NoProfile -ExecutionPolicy Bypass -File harden.ps1 -Only Services,AuditPolicy
#>
[CmdletBinding()]
param(
  [switch]$DryRun,
  [ValidateSet('Services', 'DefenderFirewall', 'AuditPolicy', 'AccountPolicy')]
  [string[]]$Only,
  [switch]$KeepSpooler   # keep the Print Spooler if this VM ever needs a printer
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

$AllGroups = 'Services', 'DefenderFirewall', 'AuditPolicy', 'AccountPolicy'
$Root = 'C:\hardening-lab'
$Ts = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$RunDir = Join-Path $Root "backups\$Ts"
$ManifestPath = Join-Path $RunDir 'manifest.json'
$script:Manifest = New-Object System.Collections.ArrayList
$script:Snapshots = @{}
$script:Counts = @{ OK = 0; WOULD = 0; CHANGED = 0 }

# --- output and bookkeeping ------------------------------------------------------

function Ok([string]$m)      { $script:Counts.OK++;      '  {0,-13} {1}' -f 'OK', $m }
function Would([string]$m)   { $script:Counts.WOULD++;   '  {0,-13} {1}' -f 'WOULD CHANGE', $m }
function Changed([string]$m) { $script:Counts.CHANGED++; '  {0,-13} {1}' -f 'CHANGED', $m }
function Note([string]$m)    { '  {0,-13} {1}' -f 'NOTE', $m }

# Record a manifest entry and save the manifest at once, so a crash mid-run still leaves
# rollback.ps1 everything it needs.
function Record([hashtable]$entry) {
  if ($DryRun) { return }
  [void]$script:Manifest.Add([pscustomobject]$entry)
  ConvertTo-Json -InputObject @($script:Manifest) -Depth 6 | Set-Content -Path $ManifestPath -Encoding UTF8
}

# Snapshot <kind> once per run, right before the first change of that kind.
function Ensure-Snapshot([string]$kind) {
  if ($DryRun -or $script:Snapshots.ContainsKey($kind)) { return }
  $rc = 0
  switch ($kind) {
    'firewall' { $f = Join-Path $RunDir 'firewall.wfw'; & netsh advfirewall export "$f" | Out-Null; $rc = $LASTEXITCODE }
    'auditpol' { $f = Join-Path $RunDir 'auditpol.csv'; & auditpol /backup "/file:$f" | Out-Null; $rc = $LASTEXITCODE }
    'secedit'  { $f = Join-Path $RunDir 'secpol.inf';   & secedit /export /cfg "$f" /quiet | Out-Null; $rc = $LASTEXITCODE }
    'defender' { $f = Join-Path $RunDir 'defender.json'; Get-MpPreference | ConvertTo-Json -Depth 3 | Set-Content $f -Encoding UTF8 }
  }
  if ($rc -or -not (Test-Path $f)) { throw "snapshot $kind failed (exit $rc)" }
  $script:Snapshots[$kind] = $f
  Record @{ kind = 'snapshot'; type = $kind; file = (Split-Path $f -Leaf) }
}

# --- registry helper (records old value or absence) -------------------------------

function Get-RegValue([string]$path, [string]$name) {
  if (-not (Test-Path $path)) { return $null }
  $item = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
  if ($null -eq $item) { return $null }
  return $item.$name
}

function Set-RegDword([string]$path, [string]$name, [int]$value, [string]$why) {
  $cur = Get-RegValue $path $name
  if ($null -ne $cur -and [int]$cur -eq $value) { Ok "$path\$name = $value"; return }
  $shown = if ($null -eq $cur) { '<unset>' } else { $cur }
  if ($DryRun) { Would "$path\$name $shown -> $value ($why)"; return }
  Record @{ kind = 'reg'; path = $path; name = $name; existed = ($null -ne $cur); old = $cur; type = 'DWord' }
  if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
  New-ItemProperty -Path $path -Name $name -PropertyType DWord -Value $value -Force | Out-Null
  Changed "$path\$name $shown -> $value ($why)"
}

# --- groups ------------------------------------------------------------------------

function Group-Services {
  $svcs = [ordered]@{
    RemoteRegistry = 'remote registry editing is not needed'
    XblAuthManager = 'no Xbox gaming'
    XblGameSave    = 'no Xbox gaming'
    XboxNetApiSvc  = 'no Xbox gaming'
    XboxGipSvc     = 'no Xbox accessories'
    Fax            = 'no fax'
    MapsBroker     = 'offline maps not used'
    lfsvc          = 'geolocation not used'
    SharedAccess   = 'no Internet Connection Sharing'
    RetailDemo     = 'not a retail demo unit'
    WMPNetworkSvc  = 'no media sharing'
    SSDPSrv        = 'no UPnP discovery'
    upnphost       = 'no UPnP hosting'
    DiagTrack      = 'telemetry'
  }
  if (-not $KeepSpooler) { $svcs['Spooler'] = 'no printer; PrintNightmare-class attack surface' }

  foreach ($name in $svcs.Keys) {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($null -eq $svc -or -not (Test-Path $key)) { Ok "$name not installed"; continue }
    $start = [int](Get-RegValue $key 'Start')
    $delayed = Get-RegValue $key 'DelayedAutostart'
    if ($start -eq 4 -and $svc.Status -ne 'Running') { Ok "$name disabled"; continue }
    if ($DryRun) { Would "$name Start=$start/$($svc.Status) -> Disabled ($($svcs[$name]))"; continue }
    Record @{ kind = 'service'; name = $name; start = $start; delayed = $delayed; wasRunning = ($svc.Status -eq 'Running') }
    if ($svc.Status -eq 'Running') { Stop-Service -Name $name -Force -ErrorAction SilentlyContinue }
    # Registry, not Set-Service: some services refuse Set-Service even for admins.
    Set-ItemProperty -Path $key -Name Start -Value 4
    Changed "$name Start=$start -> 4 Disabled ($($svcs[$name]))"
  }
}

function Set-MpPref([string]$name, $want, [string]$why) {
  $cur = (Get-MpPreference).$name
  if ("$cur" -eq "$want") { Ok "Defender $name = $want"; return }
  if ($DryRun) { Would "Defender $name $cur -> $want ($why)"; return }
  Ensure-Snapshot 'defender'
  Record @{ kind = 'mpref'; name = $name; old = $cur }
  $splat = @{ $name = $want }
  Set-MpPreference @splat
  $after = (Get-MpPreference).$name
  if ("$after" -eq "$want") { Changed "Defender $name $cur -> $want ($why)" }
  else { Note "Defender $name still $after after setting $want (Tamper Protection or policy blocked it)" }
}

function Group-DefenderFirewall {
  # Defender. Values: MAPSReporting 2=Advanced, SubmitSamplesConsent 1=SendSafeSamples,
  # PUAProtection 1=Enabled (2 is audit only), EnableNetworkProtection 1=Enabled.
  Set-MpPref 'DisableRealtimeMonitoring' $false 'real-time protection on'
  Set-MpPref 'MAPSReporting' 2 'cloud-delivered protection'
  Set-MpPref 'SubmitSamplesConsent' 1 'send safe samples'
  Set-MpPref 'PUAProtection' 1 'block potentially unwanted apps'
  Set-MpPref 'EnableNetworkProtection' 1 'block malicious domains'

  # ASR rules in Audit mode (2) first; switch to Block (1) after a clean run.
  $asr = [ordered]@{
    '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'abuse of vulnerable signed drivers'
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Adobe Reader child processes'
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Office child processes'
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'credential stealing from LSASS'
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'executable content from email'
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'obfuscated scripts'
    'd3e037e1-3eb8-44c8-a917-57927947596d' = 'JS/VBS launching downloaded executables'
    '3b576869-a4ec-4529-8536-b80a7769e899' = 'Office creating executable content'
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Office code injection'
    '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Office communication app child processes'
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'persistence through WMI event subscription'
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'untrusted processes from USB'
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Win32 API calls from Office macros'
    'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'advanced ransomware protection'
  }
  $m = Get-MpPreference
  $ids = @($m.AttackSurfaceReductionRules_Ids)
  $acts = @($m.AttackSurfaceReductionRules_Actions)
  foreach ($id in $asr.Keys) {
    $i = [array]::IndexOf(($ids | ForEach-Object { "$_".ToLower() }), $id)
    $cur = if ($i -ge 0) { [int]$acts[$i] } else { $null }
    if ($null -ne $cur -and $cur -ne 0) { Ok "ASR $($asr[$id]) = $cur"; continue }   # never weaken an existing Block
    if ($DryRun) { Would "ASR $($asr[$id]) -> Audit"; continue }
    Ensure-Snapshot 'defender'
    Record @{ kind = 'asr'; id = $id; old = $cur }
    Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions AuditMode
    Changed "ASR $($asr[$id]) -> Audit"
  }

  # Firewall. Lockout guard: the SSH allow rule must be on for every profile first.
  $ssh = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue
  if ($null -eq $ssh -or "$($ssh.Enabled)" -ne 'True') {
    throw "firewall: rule OpenSSH-Server-In-TCP missing or disabled; refusing to touch profiles (lockout risk)"
  }
  Ok "lockout guard: OpenSSH-Server-In-TCP enabled ($($ssh.Profile))"
  $logFile = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
  foreach ($p in Get-NetFirewallProfile) {
    $want = @{ Enabled = 'True'; DefaultInboundAction = 'Block'; DefaultOutboundAction = 'Allow'; AllowInboundRules = 'True'; LogBlocked = 'True' }
    $diff = @($want.Keys | Where-Object { "$($p.$_)" -ne $want[$_] })
    if ($diff.Count -eq 0 -and $p.LogMaxSizeKilobytes -ge 16384) { Ok "firewall $($p.Name) profile"; continue }
    $what = ($diff | ForEach-Object { "$_ $($p.$_)->$($want[$_])" }) -join ', '
    if ($DryRun) { Would "firewall $($p.Name): $what, log 16 MB"; continue }
    Ensure-Snapshot 'firewall'
    Set-NetFirewallProfile -Name $p.Name -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow `
      -AllowInboundRules True -LogBlocked True -LogMaxSizeKilobytes 16384 -LogFileName $logFile
    Changed "firewall $($p.Name): $what, log 16 MB"
  }
}

function Group-AuditPolicy {
  # Subcategory GUIDs, so this works on any display language. S = success, F = failure.
  $sub = [ordered]@{
    '{0CCE923F-69AE-11D9-BED3-505054503030}' = @('Credential Validation', 'SF')
    '{0CCE9237-69AE-11D9-BED3-505054503030}' = @('Security Group Management', 'S')
    '{0CCE9235-69AE-11D9-BED3-505054503030}' = @('User Account Management', 'SF')
    '{0CCE922B-69AE-11D9-BED3-505054503030}' = @('Process Creation', 'S')
    '{0CCE9215-69AE-11D9-BED3-505054503030}' = @('Logon', 'SF')
    '{0CCE9216-69AE-11D9-BED3-505054503030}' = @('Logoff', 'S')
    '{0CCE9217-69AE-11D9-BED3-505054503030}' = @('Account Lockout', 'F')
    '{0CCE921B-69AE-11D9-BED3-505054503030}' = @('Special Logon', 'S')
    '{0CCE922F-69AE-11D9-BED3-505054503030}' = @('Audit Policy Change', 'SF')
    '{0CCE9230-69AE-11D9-BED3-505054503030}' = @('Authentication Policy Change', 'S')
    '{0CCE9228-69AE-11D9-BED3-505054503030}' = @('Sensitive Privilege Use', 'SF')
    '{0CCE9210-69AE-11D9-BED3-505054503030}' = @('Security State Change', 'S')
    '{0CCE9211-69AE-11D9-BED3-505054503030}' = @('Security System Extension', 'S')
    '{0CCE9212-69AE-11D9-BED3-505054503030}' = @('System Integrity', 'SF')
  }
  $label = @{ 'S' = 'Success'; 'F' = 'Failure'; 'SF' = 'Success and Failure' }
  foreach ($guid in $sub.Keys) {
    $name, $want = $sub[$guid]
    $row = (& auditpol /get "/subcategory:$guid" /r | Where-Object { $_ } | ConvertFrom-Csv | Select-Object -First 1)
    $cur = $row.'Inclusion Setting'
    # Never remove auditing that is already there; only add what is missing.
    $needS = $want.Contains('S') -and $cur -notmatch 'Success'
    $needF = $want.Contains('F') -and $cur -notmatch 'Failure'
    if (-not ($needS -or $needF)) { Ok "audit $name ($cur)"; continue }
    if ($DryRun) { Would "audit $name '$cur' -> include $($label[$want])"; continue }
    Ensure-Snapshot 'auditpol'
    $a = @("/subcategory:$guid")
    if ($needS) { $a += '/success:enable' }
    if ($needF) { $a += '/failure:enable' }
    & auditpol /set @a | Out-Null
    if ($LASTEXITCODE) { throw "auditpol /set $name failed ($LASTEXITCODE)" }
    Changed "audit $name '$cur' -> include $($label[$want])"
  }
  Set-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy' 1 'subcategory settings override legacy categories'
  Set-RegDword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1 'command line in event 4688'

  $want = 1GB
  $cur = (Get-WinEvent -ListLog Security).MaximumSizeInBytes
  if ($cur -ge $want) { Ok "Security log max $([math]::Round($cur/1MB)) MB" }
  elseif ($DryRun) { Would "Security log max $([math]::Round($cur/1MB)) MB -> 1024 MB" }
  else {
    Record @{ kind = 'evtlog'; log = 'Security'; old = $cur }
    & wevtutil sl Security "/ms:$want"
    Changed "Security log max $([math]::Round($cur/1MB)) MB -> 1024 MB"
  }
}

function Group-AccountPolicy {
  $want = [ordered]@{
    MinimumPasswordLength = 14; PasswordComplexity = 1; PasswordHistorySize = 24
    MaximumPasswordAge = 365; MinimumPasswordAge = 1
    LockoutBadCount = 5; ResetLockoutCount = 15; LockoutDuration = 15
    EnableGuestAccount = 0; EnableAdminAccount = 0
  }
  $tmp = Join-Path $env:TEMP "lab-secpol-$Ts.inf"
  & secedit /export /cfg "$tmp" /areas SECURITYPOLICY /quiet | Out-Null
  $cur = @{}
  foreach ($line in Get-Content $tmp) { if ($line -match '^\s*(\w+)\s*=\s*(-?\d+)\s*$') { $cur[$Matches[1]] = [int]$Matches[2] } }
  Remove-Item $tmp -Force
  $todo = [ordered]@{}
  foreach ($k in $want.Keys) {
    $c = if ($cur.ContainsKey($k)) { $cur[$k] } else { '<unset>' }
    if ("$c" -eq "$($want[$k])") { Ok "$k = $c" } else { $todo[$k] = $c }
  }
  if ($todo.Count) {
    foreach ($k in $todo.Keys) { if ($DryRun) { Would "$k $($todo[$k]) -> $($want[$k])" } }
    if (-not $DryRun) {
      Ensure-Snapshot 'secedit'
      $inf = Join-Path $RunDir 'lab-account-policy.inf'
      $lines = @('[Unicode]', 'Unicode=yes', '[System Access]') + ($want.Keys | ForEach-Object { "$_ = $($want[$_])" }) +
               @('[Version]', 'signature="$CHICAGO$"', 'Revision=1')
      Set-Content -Path $inf -Value $lines -Encoding Unicode
      & secedit /configure /db (Join-Path $RunDir 'lab.sdb') /cfg "$inf" /areas SECURITYPOLICY /quiet | Out-Null
      if ($LASTEXITCODE) { throw "secedit /configure failed ($LASTEXITCODE)" }
      foreach ($k in $todo.Keys) { Changed "$k $($todo[$k]) -> $($want[$k])" }
    }
  }

  # 2 = LSA protection without the UEFI lock (1 would set a UEFI variable rollback can't clear).
  Set-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' 2 'LSA protection, no UEFI lock (takes effect after reboot)'
  Set-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0 'no cleartext WDigest credentials'
  Set-RegDword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0 'LLMNR off'
  foreach ($k in Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces') {
    Set-RegDword $k.PSPath.Replace('Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE', 'HKLM:') 'NetbiosOptions' 2 'NetBIOS over TCP/IP off'
  }
  $smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
  if (-not $smb1) { Ok 'SMB1 server disabled' }
  elseif ($DryRun) { Would 'SMB1 server -> disabled' }
  else {
    Record @{ kind = 'smb1'; old = $smb1 }
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Changed 'SMB1 server -> disabled'
  }
}

# --- main ----------------------------------------------------------------------------

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'run elevated (administrator)' }

if (-not $DryRun) {
  New-Item -ItemType Directory -Force -Path $RunDir | Out-Null
  '[]' | Set-Content -Path $ManifestPath -Encoding UTF8
  Start-Transcript -Path (Join-Path $RunDir 'harden.log') | Out-Null
}
try {
  "== harden.ps1 $Ts$(if ($DryRun) { ' (dry run)' })"
  foreach ($g in $AllGroups) {
    if ($Only -and $Only -notcontains $g) { continue }
    "== $g"
    & "Group-$g"
  }
  "== summary: $($script:Counts.CHANGED) changed, $($script:Counts.WOULD) would change, $($script:Counts.OK) already OK"
  if (-not $DryRun) {
    if ($script:Manifest.Count) { "backups and manifest: $RunDir"; "undo with: rollback.ps1 -Backup $Ts" }
    else { "nothing changed; rollback.ps1 will skip $RunDir" }
  }
}
finally {
  if (-not $DryRun) { Stop-Transcript | Out-Null }
}
