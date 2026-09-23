param([ValidateRange(1,65535)][int]$Port = 8081)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
& "$PSScriptRoot\.venv-mcp\Scripts\python.exe" "$PSScriptRoot\tools\start_mcp_bridge.py" --port $Port
