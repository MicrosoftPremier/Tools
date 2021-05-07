<#

.SYNOPSIS
    Download latest Azure Pipelines agent

.DESCRIPTION
    Downloads the latest Azure Pipelines agent from GitHub

.PARAMETER Platform
    Specify the platform for which you need to download an agent (win-x86, win-x64, osx-64, linux-x64, linux-arm, linux-arm64, rhel.6-x64).

.PARAMETER DownloadFolder
    Specify the folder you want to download the agent to. If this parameter is omitted, the current working directory is used.

.PARAMETER ExcludeNode6
    Specify this switch to exclude Node6 runtime from the agent.
    
.EXAMPLE
    .\Get-LatestAzurePipelinesAgent.ps1 -Platform win-x64
    Downloads the latest Azure Pipelines agent for the Windows x64 platform to the current working directory.

.EXAMPLE
    .\Get-LatestAzurePipelinesAgent.ps1 -Platform linux-x64 -ExcludeNode6 -DownloadFolder /azagents
    Downloads the latest Azure Pipelines agent that does not include the Node6 runtime for the Linux x64 platform to the folder /azagents.

#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Specify the platform for which you need to download an agent (win-x86, win-x64, osx-64, linux-x64, linux-arm, linux-arm64, rhel.6-x64).")]
    [ValidateSet("win-x86", "win-x64", "osx-64", "linux-x64", "linux-arm", "linux-arm64", "rhel.6-x64")]
    [string] $Platform,

    [Parameter(Mandatory = $false, HelpMessage = "Specify the folder you want to download the agent to. If this parameter is omitted, the current working directory is used.")]
    [string] $DownloadFolder = $PWD,

    [Parameter(Mandatory = $false, HelpMessage = "Specify this switch to exclude Node6 runtime from the agent.")]
    [switch] $ExcludeNode6
)

$agentReleasesUri = "https://api.github.com/repos/microsoft/azure-pipelines-agent/releases/latest"

$latestAgentInfo = Invoke-RestMethod $agentReleasesUri
$assets = Invoke-RestMethod $latestAgentInfo.assets[0].browser_download_url

$platformAgents = $assets | Where-Object { $_.platform -eq $Platform }
$agent = $null

if ($ExcludeNode6) {
    $agent = $platformAgents | Where-Object { $_.name.StartsWith("pipelines") }
} else {
    $agent = $platformAgents | Where-Object { $_.name.StartsWith("vsts") }
}
if ($agent) {
    $outFile = Join-Path $DownloadFolder ([System.IO.Path]::GetFileName($agent.downloadUrl))
    Write-Host "Downloading latest $Platform agent to $outFile..."
    Invoke-WebRequest $agent.downloadUrl -OutFile $outFile | Out-Null
    Write-Host "Done"
} else {
    Write-Host "ERROR: Invalid asset information" -ForegroundColor Red
    exit 1
}