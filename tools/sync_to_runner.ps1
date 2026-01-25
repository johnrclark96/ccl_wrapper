Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot  = Split-Path -Parent $(Split-Path -Parent $PSCommandPath)
$Source    = Join-Path $RepoRoot 'ccl_wrapper.py'
$RunnerDir = 'C:\Users\johnr\Documents\Forensic\ccl'
$Dest      = Join-Path $RunnerDir 'ccl_wrapper_current.py'

Copy-Item -LiteralPath $Source -Destination $Dest -Force
Write-Host ("Synced: {0} -> {1}" -f $Source, $Dest)
