param(
  [string]$Database = "dev.db",
  [string]$Destination = "backups"
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $Database)) { throw "Database file not found: $Database" }
if (-not (Test-Path -LiteralPath $Destination)) { New-Item -ItemType Directory -Path $Destination | Out-Null }
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
Copy-Item -LiteralPath $Database -Destination (Join-Path $Destination "nexus-$stamp.db")
Write-Output "Backup created in $Destination"
