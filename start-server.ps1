param(
  [ValidateRange(1, 65535)]
  [int]$Port = 8787
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$env:REVERSEAI_PORT = "$Port"
Write-Host "ReverseAI Lab API + UI is serving at http://127.0.0.1:$Port/" -ForegroundColor Cyan
Write-Host "API health: http://127.0.0.1:$Port/api/health" -ForegroundColor DarkCyan
Write-Host "Use http:// (not https://); this local server does not use TLS." -ForegroundColor DarkGray
Write-Host "Press Ctrl+C to stop." -ForegroundColor DarkGray
python server.py
