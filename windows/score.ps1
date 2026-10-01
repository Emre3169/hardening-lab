<#
.SYNOPSIS
  Score the Windows lab VM with HardeningKitty and record the patch level (PLAN.md section 4).

.DESCRIPTION
  score.ps1 before|after
  - Installs HardeningKitty (pinned tag) from GitHub into C:\hardening-lab\HardeningKitty if missing.
  - Runs Invoke-HardeningKitty -Mode Audit -Log -Report against the newest CIS Windows 11
    machine finding list (the same list for before and after, so scores compare).
  - Writes to C:\hardening-lab\scores\:
      hardeningkitty-<label>.csv   report (one row per check)
      hardeningkitty-<label>.log   log
      hardeningkitty-<label>.json  summary (score, passed/total, severities, tool, list, OS build)
      hotfix-<label>.csv           Get-HotFix (patch level on record; nothing is installed)
  windows/run-remote.sh pulls these into the repo and fills the scores/SCORES.md row.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File score.ps1 before
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, Position = 0)][ValidateSet('before', 'after')][string]$Label,
  [switch]$Force,                      # overwrite existing hardeningkitty-<label>.* files
  [string]$Version = 'v.0.9.4',        # HardeningKitty release tag
  [string]$Machine = 'windows-lab'     # name used in the SCORES.md row
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

$Root = 'C:\hardening-lab'
$HkDir = Join-Path $Root 'HardeningKitty'
$Scores = Join-Path $Root 'scores'
$Csv = Join-Path $Scores "hardeningkitty-$Label.csv"
$Log = Join-Path $Scores "hardeningkitty-$Label.log"
$Json = Join-Path $Scores "hardeningkitty-$Label.json"
$HotFix = Join-Path $Scores "hotfix-$Label.csv"

function Ok([string]$m)      { '  {0,-13} {1}' -f 'OK', $m }
function Changed([string]$m) { '  {0,-13} {1}' -f 'CHANGED', $m }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'run elevated (administrator)' }
if ((Test-Path $Csv) -and -not $Force) { throw "$Csv exists; use -Force to overwrite" }
New-Item -ItemType Directory -Force -Path $Scores | Out-Null

# --- HardeningKitty ------------------------------------------------------------------
$psd1 = Get-ChildItem $HkDir -Recurse -Filter HardeningKitty.psd1 -ErrorAction SilentlyContinue | Select-Object -First 1
$marker = Join-Path $HkDir 'VERSION'
if ($psd1 -and (Test-Path $marker) -and ((Get-Content $marker -Raw).Trim() -eq $Version)) {
  Ok "HardeningKitty $Version present"
} else {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $zip = Join-Path $env:TEMP "HardeningKitty-$Version.zip"
  Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/scipag/HardeningKitty/archive/refs/tags/$Version.zip" -OutFile $zip
  if (Test-Path $HkDir) { Remove-Item $HkDir -Recurse -Force }
  Expand-Archive -Path $zip -DestinationPath $HkDir -Force
  Remove-Item $zip -Force
  Get-ChildItem $HkDir -Recurse -File | Unblock-File
  Set-Content -Path $marker -Value $Version
  $psd1 = Get-ChildItem $HkDir -Recurse -Filter HardeningKitty.psd1 | Select-Object -First 1
  if (-not $psd1) { throw "HardeningKitty.psd1 not found after extracting $Version" }
  Changed "installed HardeningKitty $Version into $HkDir"
}
Import-Module $psd1.FullName -Force

# Newest CIS Windows 11 machine list; fall back to HardeningKitty's own machine list.
$lists = Join-Path $psd1.DirectoryName 'lists'
$list = Get-ChildItem $lists -Filter 'finding_list_cis_microsoft_windows_11*_machine.csv' | Sort-Object Name | Select-Object -Last 1
if (-not $list) { $list = Get-ChildItem $lists -Filter 'finding_list_0x6d69636b_machine.csv' | Select-Object -First 1 }
if (-not $list) { throw "no machine finding list under $lists" }
Ok "finding list $($list.Name)"

# --- patch level -------------------------------------------------------------------------
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$build = "$($cv.CurrentBuild).$($cv.UBR)"
Get-HotFix | Sort-Object InstalledOn | Select-Object HotFixID, Description, InstalledOn, InstalledBy |
  Export-Csv -Path $HotFix -NoTypeInformation -Encoding UTF8
Changed "$HotFix ($(@(Import-Csv $HotFix).Count) hotfixes, OS build $build)"

# --- audit -------------------------------------------------------------------------------
"== HardeningKitty audit ($Label), takes a few minutes"
Remove-Item $Csv, $Log -Force -ErrorAction SilentlyContinue
Invoke-HardeningKitty -Mode Audit -Log -LogFile $Log -Report -ReportFile $Csv -FileFindingList $list.FullName | Out-Null
if (-not (Test-Path $Csv)) { throw "HardeningKitty produced no report at $Csv" }
Changed $Csv
Changed $Log

$text = Get-Content $Log -Raw
# The log line ends "score is: 3.28. HardeningKitty Statistics", so don't let the
# sentence's full stop into the number.
$score = if ($text -match 'HardeningKitty score is:\s*(\d+(?:\.\d+)?)') { [double]$Matches[1] } else { $null }
$stats = [ordered]@{}
if ($text -match 'Total checks:\s*(\d+)\s*-\s*Passed:\s*(\d+),\s*Low:\s*(\d+),\s*Medium:\s*(\d+),\s*High:\s*(\d+)') {
  $stats.total = [int]$Matches[1]; $stats.passed = [int]$Matches[2]
  $stats.low = [int]$Matches[3]; $stats.medium = [int]$Matches[4]; $stats.high = [int]$Matches[5]
}
if ($null -eq $score) { throw "no 'HardeningKitty score is:' line in $Log" }

[ordered]@{
  date     = (Get-Date).ToString('yyyy-MM-dd')
  label    = $Label
  machine  = $Machine
  tool     = "HardeningKitty $Version / $($list.BaseName -replace '^finding_list_', '')"
  score    = $score
  stats    = $stats
  os_build = $build
  hotfixes = @(Import-Csv $HotFix).Count
} | ConvertTo-Json -Depth 3 | Set-Content -Path $Json -Encoding UTF8
Changed $Json

"HardeningKitty score ($Machine, $Label): $score  (passed $($stats.passed)/$($stats.total); low $($stats.low), medium $($stats.medium), high $($stats.high))"
