<#
.SYNOPSIS
  Undo one harden.ps1 run by replaying its manifest.json in reverse (PLAN.md section 5).

.DESCRIPTION
  Default run: the newest one under C:\hardening-lab\backups that changed something and
  hasn't been rolled back. Run it again to unwind older runs, newest first.
  Restores: service start types (and running state), registry values (or removes values
  harden created), Defender preferences and ASR rules, the Security log size, SMB1, and
  the firewall / audit policy / security policy from the run's snapshots.
  Prints OK / WOULD CHANGE / CHANGED like harden.ps1. For a guaranteed clean slate,
  re-clone the VM from windows-lab-clean instead.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File rollback.ps1 -DryRun
  powershell -NoProfile -ExecutionPolicy Bypass -File rollback.ps1 -Backup 20261001T120000Z
#>
[CmdletBinding()]
param(
  [switch]$DryRun,
  [string]$Backup,   # timestamp folder name under C:\hardening-lab\backups
  [switch]$Force     # allow rolling back a run while a newer one is still applied
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

$BackupRoot = 'C:\hardening-lab\backups'
$script:Counts = @{ OK = 0; WOULD = 0; CHANGED = 0 }
function Ok([string]$m)      { $script:Counts.OK++;      '  {0,-13} {1}' -f 'OK', $m }
function Would([string]$m)   { $script:Counts.WOULD++;   '  {0,-13} {1}' -f 'WOULD CHANGE', $m }
function Changed([string]$m) { $script:Counts.CHANGED++; '  {0,-13} {1}' -f 'CHANGED', $m }
function Note([string]$m)    { '  {0,-13} {1}' -f 'NOTE', $m }

# Do it, or only say it under -DryRun.
function Act([string]$desc, [scriptblock]$do) {
  if ($DryRun) { Would $desc; return }
  & $do
  Changed $desc
}

function Read-Manifest([string]$dir) {
  $p = Join-Path $dir 'manifest.json'
  if (-not (Test-Path $p)) { return @() }
  # Windows PowerShell 5.1 emits a JSON array as ONE object; piping it on enumerates the entries.
  $j = Get-Content $p -Raw | ConvertFrom-Json
  return @($j | ForEach-Object { $_ })
}
function Test-Pending([string]$dir) {
  (-not (Test-Path (Join-Path $dir 'ROLLED_BACK'))) -and (@(Read-Manifest $dir).Count -gt 0)
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'run elevated (administrator)' }

# --- pick the run ------------------------------------------------------------------

$runs = @(Get-ChildItem $BackupRoot -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
if ($Backup) {
  $RunDir = Join-Path $BackupRoot $Backup
  if (-not (Test-Pending $RunDir)) { throw "$RunDir has no pending changes (missing, empty or already rolled back)" }
  foreach ($r in $runs) {
    if ($r.FullName -eq $RunDir) { break }
    if ((Test-Pending $r.FullName) -and -not $Force) { throw "newer run $($r.Name) is still applied; roll it back first (or -Force)" }
  }
} else {
  $RunDir = ($runs | Where-Object { Test-Pending $_.FullName } | Select-Object -First 1).FullName
  if (-not $RunDir) { throw "no pending harden runs under $BackupRoot" }
}
"== rollback.ps1 $(Split-Path $RunDir -Leaf)$(if ($DryRun) { ' (dry run)' })"

$entries = @(Read-Manifest $RunDir)
[array]::Reverse($entries)

# --- replay --------------------------------------------------------------------------

foreach ($e in $entries) {
  switch ($e.kind) {
    'service' {
      $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$($e.name)"
      $cur = [int](Get-ItemProperty $key -Name Start).Start
      if ($cur -eq [int]$e.start) { Ok "$($e.name) Start=$cur" }
      else { Act "$($e.name) Start $cur -> $($e.start)" { Set-ItemProperty $key -Name Start -Value ([int]$e.start) } }
      if ($null -ne $e.delayed) {
        Act "$($e.name) DelayedAutostart -> $($e.delayed)" { Set-ItemProperty $key -Name DelayedAutostart -Value ([int]$e.delayed) }
      }
      if ($e.wasRunning -and (Get-Service $e.name).Status -ne 'Running') {
        Act "start $($e.name) (was running)" { Start-Service $e.name -ErrorAction SilentlyContinue }
      }
    }
    'reg' {
      $item = Get-ItemProperty -Path $e.path -Name $e.name -ErrorAction SilentlyContinue
      $cur = if ($item) { $item.($e.name) } else { $null }
      if ($e.existed) {
        if ("$cur" -eq "$($e.old)") { Ok "$($e.path)\$($e.name) = $cur" }
        else { Act "$($e.path)\$($e.name) $cur -> $($e.old)" { New-ItemProperty -Path $e.path -Name $e.name -PropertyType DWord -Value ([int]$e.old) -Force | Out-Null } }
      } else {
        if ($null -eq $cur) { Ok "$($e.path)\$($e.name) absent" }
        else { Act "remove $($e.path)\$($e.name) (harden created it)" { Remove-ItemProperty -Path $e.path -Name $e.name } }
      }
    }
    'mpref' {
      $cur = (Get-MpPreference).($e.name)
      if ("$cur" -eq "$($e.old)") { Ok "Defender $($e.name) = $cur" }
      else {
        Act "Defender $($e.name) $cur -> $($e.old)" { $s = @{ $e.name = $e.old }; Set-MpPreference @s }
        if (-not $DryRun -and "$((Get-MpPreference).($e.name))" -ne "$($e.old)") { Note "Defender $($e.name) didn't revert (Tamper Protection?)" }
      }
    }
    'asr' {
      if ($null -eq $e.old) {
        Act "remove ASR rule $($e.id) (harden added it)" { Remove-MpPreference -AttackSurfaceReductionRules_Ids $e.id }
      } else {
        Act "ASR rule $($e.id) -> action $($e.old)" { Add-MpPreference -AttackSurfaceReductionRules_Ids $e.id -AttackSurfaceReductionRules_Actions ([int]$e.old) }
      }
    }
    'evtlog' {
      $cur = (Get-WinEvent -ListLog $e.log).MaximumSizeInBytes
      if ($cur -eq [long]$e.old) { Ok "$($e.log) log max $([math]::Round($cur/1MB)) MB" }
      else { Act "$($e.log) log max -> $([math]::Round($e.old/1MB)) MB" { & wevtutil sl $e.log "/ms:$($e.old)" } }
    }
    'smb1' {
      Act "SMB1 server -> $($e.old)" { Set-SmbServerConfiguration -EnableSMB1Protocol ([bool]$e.old) -Force }
    }
    'snapshot' {
      $f = Join-Path $RunDir $e.file
      if (-not (Test-Path $f)) { Note "snapshot $($e.file) missing; $($e.type) not restored"; continue }
      switch ($e.type) {
        'firewall' { Act "firewall policy <- $($e.file) (netsh advfirewall import)" { & netsh advfirewall import "$f" | Out-Null; if ($LASTEXITCODE) { throw 'netsh import failed' } } }
        'auditpol' { Act "audit policy <- $($e.file) (auditpol /restore)" { & auditpol /restore "/file:$f" | Out-Null; if ($LASTEXITCODE) { throw 'auditpol /restore failed' } } }
        'secedit'  { Act "security policy <- $($e.file) (secedit /configure)" {
                       & secedit /configure /db (Join-Path $RunDir 'rollback.sdb') /cfg "$f" /areas SECURITYPOLICY /quiet | Out-Null
                       if ($LASTEXITCODE) { throw 'secedit /configure failed' } } }
        'defender' { Ok "defender.json kept for reference (individual settings restored above)" }
      }
    }
    default { Note "unknown manifest entry kind '$($e.kind)'" }
  }
}

"== summary: $($script:Counts.CHANGED) changed, $($script:Counts.WOULD) would change, $($script:Counts.OK) already OK"
if (-not $DryRun) {
  (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') | Set-Content (Join-Path $RunDir 'ROLLED_BACK')
  "marked $(Split-Path $RunDir -Leaf) as rolled back"
  Note 'RunAsPPL changes take effect after a reboot'
}
