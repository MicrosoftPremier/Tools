<#

.SYNOPSIS
    Azure DevOps PowerShell Sample

.DESCRIPTION
    Quick start sample for creating PowerShell scripts targeting Azure DevOps Server/Services.

.PARAMETER ServiceUri
    Provide the URI of the Azure DevOps Services organization or Azure DevOps Server collection you want to work on.

.PARAMETER Quiet
    Specify this switch to suppress confirmation prompts.

.PARAMETER GetCredentials
    Specify this switch if you need to use special credentials when connecting to your Azure DevOps Server.

.PARAMETER UsePAT
    Specify this switch if you need to provide a Personal Access Token to connect your Azure DevOps Server/Services.

.PARAMETER AllowHttp
    Specify this switch if you need connect to Azure DevOps over unencrypted http (not https).

.PARAMETER MaxRestCallRetries
    Provide the number of retries for failing REST calls. In general, you shouldn't need this option. However, when running in an
    unstable environment (e.g., unreliable network connection), retries can help by automatically rerunning failing REST calls.

.PARAMETER TraceErrors
    Specify this switch to enabled extended error tracing using netsh. If you combine this with the MaxRestCallRetries parameter,
    only the last retry is traced. Otherwise, every request is trace, but traces for succeeding network calls are deleted for security reasons.
    Note: You need to run the script as a local administrator when using this switch. Otherwise, network tracing is not allowed.
    
.EXAMPLE
    .\AzDOPSSample.ps1 -ServiceUri http://MyTfs:8080/tfs/DefaultCollection -GetCredentials
    Runs the script on the DefaultCollection of your local Azure DevOps Server using Windows credentials.

.EXAMPLE
    .\AzDOPSSample.ps1 -ServiceUri https://dev.azure.com/myOrg -Quiet -UsePAT
    Runs the script on the Azure DevOps Services organization myOrg, suppressing confirmations and using a PAT for authentication.

#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true, HelpMessage="Enter the URI of the Azure DevOps Services organization or Azure DevOps Server collection you want to work on.")]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceUri,

# You should add your additional script parameters here.

    [Parameter(Mandatory=$false, HelpMessage="Specify this switch to suppress confirmation prompts.")]
    [switch]$Quiet,

    [Parameter(Mandatory=$false, HelpMessage="Specify this switch if you need to use special credentials when connecting to your Azure DevOps Server.")]
    [switch]$GetCredentials,

    [Parameter(Mandatory=$false, HelpMessage="Specify this switch if you need to provide a Personal Access Token to connect your Azure DevOps Server/Services.")]
    [switch]$UsePAT,

    [Parameter(Mandatory=$false, HelpMessage="Specify this switch if you need connect to Azure DevOps over unencrypted http (not https).")]
    [switch]$AllowHttp,

    [Parameter(Mandatory=$false, HelpMessage="Provide the number of retries for failing REST calls. In general, you shouldn't need this option.")]
    [int]$MaxRestCallRetries = 1,

    [Parameter(Mandatory=$false, HelpMessage="Specify this switch to enable extended error tracing using netsh.")]
    [switch]$TraceErrors
)

################################################################################
# Configuration section
# Put general configuration stuff and validations here
################################################################################

#Requires -Version 6.2
Set-StrictMode -Version 3.0

$scriptName = "Azure DevOps PowerShell Sample"
# Use semantic versioning here
$version = "0.0.1"
$year = "2020"

$Global:quietAnswer = $true
$Global:defaultAnswer = $false

$RestCallRetryDelayInSeconds = 2

function Test-Parameters()
{
    $validationResult = $true;

    Write-Host "       Service: $ServiceUri" -NoNewline
    if (!([System.Uri]::IsWellFormedUriString($ServiceUri, [System.UriKind]::Absolute)))
    {
        Write-Host " (invalid)" -ForegroundColor Red -NoNewline
        $validationResult = $false
    }
    Write-Host

    # Add your own parameters and parameter validations here

    Write-Host "Authentication: $(if ($UsePAT) { "PAT" } elseif ($GetCredentials) { "Custom Credentials" } else { "Default Credentials" })"
    Write-Host "     Allow HTTP: $AllowHttp"
    $Global:isQuiet = $Quiet
    Write-Host "         Quiet: $Quiet"
    Write-Host "   Max Retries: $MaxRestCallRetries" -NoNewline
    if ($MaxRestCallRetries -lt 1) {
        Write-Host " (invalid)" -ForegroundColor Red -NoNewline
        $validationResult = $false;
    }
    Write-Host
    Write-Host "  Trace Errors: $TraceErrors"
    Write-Host "--------------------------------------------------------------------------------"

    return $validationResult
}

################################################################################
# Helper functions
################################################################################

function Write-Header()
{
    Write-Host "--------------------------------------------------------------------------------"
    Write-Host "$scriptName - v$version"
    Write-Host "Copyright (c) $year Microsoft Premier Services - Microsoft Deutschland GmbH"
    Write-Host "--------------------------------------------------------------------------------"
}

function Write-SimpleError($message)
{
    Write-Host $message -ForegroundColor red -BackgroundColor black
}

function Exit-WithError($message, $exitCode)
{
    Write-SimpleError $message
    exit $exitCode
}

function Get-Consent([string] $message)
{
    if ($Global:isQuiet)
    {
        return $Global:quietAnswer
    }

    Write-Host "$message"
    if ($Global:defaultAnswer) {
        Write-Host "[Y] Yes" -ForegroundColor Yellow -NoNewline
        Write-Host "  [A] Yes to All  [N] No  [L] No to All  (default is `"Y`"): " -NoNewline
    }
    else
    {
        Write-Host "[Y] Yes  [A] Yes to All  " -NoNewline
        Write-Host "[N] No" -ForegroundColor Yellow -NoNewline
        Write-Host "  [L] No to All  (default is `"N`"): " -NoNewline
    }
    switch (Read-Host)
    {
        "y" { $true }
        "a" { $Global:quietAnswer = $true; $Global:isQuiet = $true; return $true }
        "n" { return $false }
        "l" { $Global:quietAnswer = $false; $Global:isQuiet = $true; return $false }
        default { return $Global:defaultAnswer }
    }
}

function Get-SpecialConsent([string] $message)
{
    Write-Host "$message" -ForegroundColor Red
    if ($Global:defaultAnswer) {
        Write-Host "[Y] Yes" -ForegroundColor Yellow -NoNewline
        Write-Host "  [N] No  (default is `"Y`"): " -NoNewline
    }
    else
    {
        Write-Host "[Y] Yes  " -NoNewline
        Write-Host "[N] No" -ForegroundColor Yellow -NoNewline
        Write-Host "  (default is `"N`"): " -NoNewline
    }
    switch (Read-Host)
    {
        "y" { $true }
        "n" { return $false }
        default { return $Global:defaultAnswer }
    }
}

function Get-Encoding($encodingString)
{
    switch($encodingString.ToLower())
    {
        "ascii" { return [System.Text.Encoding]::ASCII }
        "unicode" { return [System.Text.Encoding]::Unicode }
        "utf7" { return [System.Text.Encoding]::UTF7 }
        "utf8" { return [System.Text.Encoding]::UTF8 }
        "utf32" { return [System.Text.Encoding]::UTF32 }        
    }
}

function ConvertTo-Base64String
{
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline)]
        [string] $InputString,
        [ValidateSet("ascii", "unicode", "utf7", "utf8", "utf32")]
        [string] $Encoding
    )
    Process {
        $enc = Get-Encoding $Encoding
        $bytes = $enc.GetBytes($inputString)
        return [System.Convert]::ToBase64String($bytes)
    }
}

Function ConvertFrom-Base64String
{
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline)]
        [string] $InputString,
        [ValidateSet("ascii", "unicode", "utf7", "utf8", "utf32")]
        [string] $Encoding
    )
    Process {
        $enc = Get-Encoding $Encoding
        $bytes = [System.Convert]::FromBase64String($inputString)
        return $enc.GetString($bytes)
    }
}

function Test-Elevation()
{
    # https://gist.github.com/jhochwald/46014a3de425dc21c1f1f7e31cd49cf1
    return  ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
}

function Assert-Preconditions()
{
    Write-Header
    if (!(Test-Parameters)) { Exit-WithError "One or more input parameters are invalid. Aborting." -1 }
    Get-HttpHeadersAndCredentials
}

################################################################################
# REST call functions
################################################################################

# HTTP Headers
$Global:headers = @{}
$Global:credentials = $null

function Get-HttpHeadersAndCredentials()
{
    $Global:headers = @{ Accept="application/json" }
    $Global:headers["Accept-Charset"] = "utf-8"
    if ($UsePAT)
    {
        $PAT = Read-Host "Enter PAT" -AsSecureString
        $patString = "pat:$([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PAT)))"
        $Global:headers["Authorization"] = "Basic $(ConvertTo-Base64String -InputString $patString -Encoding ascii)"
    }
    if ($GetCredentials)
    {
        $Global:credentials = Get-Credential
    }
}

function Get-ErrorForWebException([System.Net.Http.HttpRequestException] $Exception, [string] $reqBody)
{
    try 
    {
        # see https://stackoverflow.com/questions/35986647/how-do-i-get-the-body-of-a-web-request-that-returned-400-bad-request-from-invoke
        $respStream = $Exception.Response.GetResponseStream()
        $respStream.Position = 0
        $reader = New-Object System.IO.StreamReader($respStream)
        $respBody = $reader.ReadToEnd()
        $respStatusCode = $Exception.Response.StatusCode
        $respStatusCodeInt = [System.Convert]::ToInt32($respStatusCode)
        return "Status Code $respStatusCode ($respStatusCodeInt): $respBody `n $reqBody"
    }
    catch 
    {
        return $(if ($Exception) { $Exception.ToString() } else { "Unknown Error." })
    }
}

function Invoke-RestGet($uri, [ref]$responseHeader)
{
    Invoke-Rest $uri "Get" ([ref]$responseHeader)
}

function Invoke-RestPost($uri, $body, [ref]$responseHeader)
{
    if ($null -eq $body) {
        Invoke-Rest $uri "Post" ([ref]$responseHeader)
    } else {
        Invoke-RestWithBody $uri "Post" $body ([ref]$responseHeader)
    }
}

function Invoke-RestPut($uri, $body, [ref]$responseHeader)
{
    if ($null -eq $body) {
        Invoke-Rest $uri "Put" ([ref]$responseHeader)
    } else {
        Invoke-RestWithBody $uri "Put" $body ([ref]$responseHeader)
    }
}

function Invoke-RestPatch($uri, $body, [ref]$responseHeader)
{
    if ($null -eq $body) {
        Invoke-Rest $uri "Patch" ([ref]$responseHeader)
    } else {
        Invoke-RestWithBody $uri "Patch" $body ([ref]$responseHeader)
    }
}

function Invoke-RestDelete($uri, [ref]$responseHeader)
{
    Invoke-Rest $uri "Delete" ([ref]$responseHeader)
}

function Invoke-RestOptions($uri, [ref]$responseHeader)
{
    Invoke-Rest $uri "Options" ([ref]$responseHeader)
}

function Invoke-RestWithRetriesAndTracing($uri, $method, $body = $null, [ref]$responseHeader)
{
    $success = $false
    $tries = 0
    $delaySeconds = $RestCallRetryDelayInSeconds

    while (-not $success -and $tries -lt $MaxRestCallRetries)
    {
        $isLastTry = ($tries -eq ($MaxRestCallRetries - 1))
        if ($isLastTry -and $TraceErrors)
        {
            if (Test-Elevation)
            {
                $traceFilePath = [System.IO.Path]::Combine($env:TEMP, "Invoke-Rest$method-$((Get-Date).Ticks.ToString()).etl")
                Write-Host "Tracing last try for $uri at $traceFilePath..."
                Invoke-Command -ScriptBlock {netsh trace start persistent=yes capture=yes tracefile="$traceFilePath"}
            }
            else
            {
                Write-Warning "Cannot create a network trace for communication with URI $uri. Please run the script as local administrator."
            }
        }
        $tries += 1
        try
        {
            if ($null -eq $body)
            {
                $result = Invoke-Rest $uri $method ([ref]$responseHeaderValue)
            }
            else
            {
                $result = Invoke-RestWithBody $uri $method $body ([ref]$responseHeaderValue)
            }
            $success = $true
        }
        catch
        {
            if ($_.Exception.GetType().FullName -eq "System.Net.Http.HttpRequestException")
            {
                $exceptionMessage = GetErrorForWebException -Exception $_.Exception
            }
            else
            {
                $exceptionMessage = $_.Exception.Message
            }
            $message = "Call failed with $exceptionMessage."
            if ($isLastTry)
            {
                Exit-WithError $message 1
            }
            else
            {
                Write-Warning $message
                Write-Host "Retrying after $delaySeconds seconds..." -ForegroundColor Yellow
                Start-Sleep -Seconds $delaySeconds
                $delaySeconds *= 2 # Exponential Backoff
            }
        }
        finally
        {
            if ($isLastTry -and $TraceErrors -and (Test-Elevation)) {
                Write-Host "Finishing network trace. This will take a while... Please do not interrupt!"
                Invoke-Command -ScriptBlock {netsh trace stop}
                if ($success)
                {
                    Remove-Item $traceFilePath
                }
            }
        }
    }
    return $result
}

function Invoke-Rest($uri, $method, [ref]$responseHeader)
{
    $responseHeaderValue = @{}

    if ($UsePAT)
    {
        return Invoke-RestMethod $uri -Method $method -Headers $Global:headers -ResponseHeadersVariable "responseHeaderValue" -AllowUnencrypted:$AllowHttp
    }
    elseif ($GetCredentials)
    {
        return Invoke-RestMethod $uri -Method $method -Headers $Global:headers -Credential $Global:credentials -ResponseHeadersVariable "responseHeaderValue" -AllowUnencrypted:$AllowHttp
    }
    else
    {
        return Invoke-RestMethod $uri -Method $method -Headers $Global:headers -UseDefaultCredentials -ResponseHeadersVariable "responseHeaderValue" -AllowUnencrypted:$AllowHttp
    }

    if ($responseHeader) {
        $responseHeader.Value = $responseHeaderValue
    }
}

function Invoke-RestWithBody($uri, $method, $body, [ref]$responseHeader)
{
    $jsonBody = ConvertTo-Json $body -Depth 100 -Compress
    $jsonBody = $jsonBody.Replace("\u0026", "&")

    $responseHeaderValue = @{}
    
    if ($UsePAT)
    {
        return Invoke-RestMethod $uri -Method $method -Headers $Global:headers -ContentType "application/json" -Body ([System.Text.Encoding]::UTF8.GetBytes($jsonBody)) -ResponseHeadersVariable "responseHeaderValue" -AllowUnencrypted:$AllowHttp
    }
    elseif ($GetCredentials)
    {
        return Invoke-RestMethod $uri -Method $method -Headers $Global:headers -ContentType "application/json" -Body ([System.Text.Encoding]::UTF8.GetBytes($jsonBody)) -Credential $Global:credentials -ResponseHeadersVariable "responseHeaderValue" -AllowUnencrypted:$AllowHttp
    }
    else
    {
        return Invoke-RestMethod $uri -Method $method -Headers $Global:headers -ContentType "application/json" -Body ([System.Text.Encoding]::UTF8.GetBytes($jsonBody)) -UseDefaultCredentials -ResponseHeadersVariable "responseHeaderValue" -AllowUnencrypted:$AllowHttp
    }

    if ($responseHeader) {
        $responseHeader.Value = $responseHeaderValue
    }
}

################################################################################
# Business logic functions
################################################################################


################################################################################
# Main script starts here
################################################################################

# Do not remove this!
Assert-Preconditions

# Write your business logic here
Write-Warning "This is just a sample. Don't expect it to do anyting! :-)"