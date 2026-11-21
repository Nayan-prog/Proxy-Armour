<#
.SYNOPSIS
  Proxy Armour Docker stack (Windows PowerShell wrapper around scripts/stack.py).
.EXAMPLE
  .\scripts\armour.ps1 up
  .\scripts\armour.ps1 seed --password "my-long-password"
  .\scripts\armour.ps1 demo
  .\scripts\armour.ps1 logs proxy
  .\scripts\armour.ps1 down --volumes
#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("up", "down", "logs", "ps", "test", "seed", "demo")]
    [string]$Command,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Rest
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$script = Join-Path $root "scripts\stack.py"
if (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 $script $Command @Rest          # Windows Python launcher
} else {
    & python $script $Command @Rest
}
exit $LASTEXITCODE
