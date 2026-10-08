[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\\\\\.\\PHYSICALDRIVE\d+$')]
    [string]$Device
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$script = Join-Path $PSScriptRoot 'smk37_wl82_guarded_restore.py'
$log = Join-Path $PSScriptRoot ('guarded-restore-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run PowerShell as Administrator.'
}

& py -3 $script restore `
    --device $Device `
    --prep $repo `
    --confirm I_UNDERSTAND_THIS_ERASES_EXACTLY_TWO_H0_SECTORS `
    --confirm I_HAVE_TWO_IDENTICAL_1MIB_DUMPS_AND_H0_TARGET_HASHES `
    --confirm RESTORE_OFFICIAL_V15_SECTORS_NOW 2>&1 | Tee-Object -FilePath $log
exit $LASTEXITCODE
