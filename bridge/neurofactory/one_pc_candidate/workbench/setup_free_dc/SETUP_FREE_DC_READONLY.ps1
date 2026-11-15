# Free Desktop Commander MCP: owner-only, read-only local candidate staging.
# This does NOT register a ChatGPT connector, start a process, or modify ONE Agent.
$ErrorActionPreference = 'Stop'
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run from a normal, non-administrator Windows user session.'
    }

    $sourceDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $source = Join-Path $sourceDir 'one_files_dc_mcp.py'
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw 'one_files_dc_mcp.py is missing in the extracted folder.'
    }
    $nodeCmd = Get-Command node.exe -ErrorAction Stop
    $npxCmd = Get-Command npx.cmd -ErrorAction Stop
    $pyCmd = Get-Command python.exe -ErrorAction Stop
    $nodeVersionText = (& $nodeCmd.Source '--version').Trim()
    $nodeVersion = [version]($nodeVersionText.TrimStart('v'))
    if ($nodeVersion -lt [version]'22.12.0') {
        throw ('Node.js 22.12.0+ is required; found ' + $nodeVersionText)
    }
    $pythonExe = (& $pyCmd.Source '-c' 'import sys; print(sys.executable)').Trim()
    if (-not (Test-Path -LiteralPath $pythonExe -PathType Leaf)) {
        throw 'Python installation path could not be verified.'
    }

    $workspace = 'C:\ChatGPTProjects\ONE-DC-Isolated'
    if (-not (Test-Path -LiteralPath $workspace)) {
        $null = New-Item -ItemType Directory -Path $workspace -ErrorAction Stop
    }
    $wsInfo = Get-Item -LiteralPath $workspace -ErrorAction Stop
    if (-not $wsInfo.PSIsContainer -or ($wsInfo.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Workspace must be a real directory, not a junction or symlink.'
    }
    $base = Join-Path $env:LOCALAPPDATA 'Neurofactory\ONE-Free-DC\candidate-20261115'
    if (-not (Test-Path -LiteralPath $base)) {
        $null = New-Item -ItemType Directory -Path $base -Force
    }
    $destination = Join-Path $base 'one_files_dc_mcp.py'
    $sourceSha = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    if (Test-Path -LiteralPath $destination) {
        $destSha = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
        if ($sourceSha -ne $destSha) { throw 'Existing candidate differs; no overwrite. Review the folder manually.' }
    } else {
        Copy-Item -LiteralPath $source -Destination $destination -ErrorAction Stop
    }
    $destSha = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
    if ($sourceSha -ne $destSha) { throw 'Source integrity check failed.' }

    $configuration = [ordered]@{
        mcpServers = [ordered]@{
            'one-files' = [ordered]@{
                command = $pythonExe
                args = @($destination, '--workspace', $workspace)
            }
        }
    }
    $json = ConvertTo-Json -InputObject $configuration -Depth 8
    $configPath = Join-Path $base 'ONE-Free-DC-local-mcp.json'
    if (Test-Path -LiteralPath $configPath) {
        if ((Get-Content -LiteralPath $configPath -Raw -Encoding UTF8).Trim() -ne $json.Trim()) {
            throw 'Existing MCP config differs; no overwrite.'
        }
    } else {
        Set-Content -LiteralPath $configPath -Value $json -Encoding UTF8 -ErrorAction Stop
    }
    Write-Host 'SUCCESS: read-only local MCP candidate is staged.' -ForegroundColor Green
    Write-Host ('MCP config: ' + $configPath)
    Write-Host 'Import this config into a compatible LOCAL MCP client.'
    Write-Host 'This does not connect this ChatGPT chat or enable browser automation.'
    Write-Host 'No advertising, browser, CRM or hosting settings were touched.'
    exit 0
} catch {
    Write-Host ('STOPPED: ' + $_.Exception.Message) -ForegroundColor Red
    exit 1
}
