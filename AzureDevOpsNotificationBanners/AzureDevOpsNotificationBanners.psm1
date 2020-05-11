################################################################################
# Configuration section
# Put general configuration stuff and validations here
################################################################################

#Requires -Version 6.2
Set-StrictMode -Version 3.0

$scriptName = "Azure DevOps Notification Banner Administration"
# Use semantic versioning here
$version = "1.1.0"
$year = "2020"

$Global:quietAnswer = $true
$Global:defaultAnswer = $false

$RestCallRetryDelayInSeconds = 2

function Test-Parameters-New-NotificationBanner()
{
    Write-Host "          Type: $NotificationType"
    Write-Host "       Message: $Message"
}

function Test-Parameters-Get-NotificationBanners()
{
    # Nothing to check
}

function Test-Parameters-Remove-NotificationBanner()
{
    Write-Host "            ID: $BannerId"
}

function Test-Parameters-Clear-NotificationBanners()
{
    # Nothing to check
}

function Test-Parameters([string] $command)
{
    $validationResult = $true;

    Write-Host "       Command: $command"
    Write-Host "       Service: $ServiceUri" -NoNewline
    if (!([System.Uri]::IsWellFormedUriString($ServiceUri, [System.UriKind]::Absolute)))
    {
        Write-Host " (invalid)" -ForegroundColor Red -NoNewline
        $validationResult = $false
    }
    Write-Host

    &"Test-Parameters-$command"

    Write-Host "Authentication: $(if ($UsePAT) { "PAT" } elseif ($GetCredentials) { "Custom Credentials" } else { "Default Credentials" })"
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

function Assert-Preconditions([string] $command)
{
    Write-Header
    if (!(Test-Parameters -command $command)) { Exit-WithError "One or more input parameters are invalid. Aborting." -1 }
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
    Invoke-RestWithBody $uri "Post" $body ([ref]$responseHeader)
}

function Invoke-RestPut($uri, $body, [ref]$responseHeader)
{
    Invoke-RestWithBody $uri "Put" $body ([ref]$responseHeader)
}

function Invoke-RestPatch($uri, $body, [ref]$responseHeader)
{
    Invoke-RestWithBody $uri "Patch" $body ([ref]$responseHeader)
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
        return Invoke-RestMethod $uri -Method $method -Headers $Global:headers -ResponseHeadersVariable "responseHeaderValue"
    }
    elseif ($GetCredentials)
    {
        return Invoke-RestMethod $uri -Method $method -Headers $Global:headers -Credential $Global:credentials -ResponseHeadersVariable "responseHeaderValue"
    }
    else
    {
        return Invoke-RestMethod $uri -Method $method -Headers $Global:headers -UseDefaultCredentials -ResponseHeadersVariable "responseHeaderValue"
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
        return Invoke-RestMethod $uri -Method $method -Headers $Global:headers -ContentType "application/json" -Body ([System.Text.Encoding]::UTF8.GetBytes($jsonBody)) -ResponseHeadersVariable "responseHeaderValue"
    }
    elseif ($GetCredentials)
    {
        return Invoke-RestMethod $uri -Method $method -Headers $Global:headers -ContentType "application/json" -Body ([System.Text.Encoding]::UTF8.GetBytes($jsonBody)) -Credential $Global:credentials -ResponseHeadersVariable "responseHeaderValue"
    }
    else
    {
        return Invoke-RestMethod $uri -Method $method -Headers $Global:headers -ContentType "application/json" -Body ([System.Text.Encoding]::UTF8.GetBytes($jsonBody)) -UseDefaultCredentials -ResponseHeadersVariable "responseHeaderValue"
    }

    if ($responseHeader) {
        $responseHeader.Value = $responseHeaderValue
    }
}

################################################################################
# Business logic functions
################################################################################

function Get-ApiVersion()
{
    $optionsUri = "$ServiceUri/_apis/settings"
    $availableApis = Invoke-RestOptions $optionsUri
    $entriesApis = $availableApis.value | Where-Object -Property resourceName -eq entries

    if ($null -ne $entriesApis)
    {
        if ($entriesApis[0].releasedVersion -ne "0.0")
        {
            return "api-version=$($entriesApis[0].releasedVersion)"
        }
        else
        {
            return "api-version=$($entriesApis[0].maxVersion)-preview"
        }
    }
    Exit-WithError -message "Notification Banners are not suppoted!" -exitCode 100
}

################################################################################
# Exported functions
################################################################################

<#

.SYNOPSIS
    New-NotificationBanner

.DESCRIPTION
    Create notification banners for Azure DevOps.

.PARAMETER ServiceUri
    Provide the URI of the Azure DevOps Services organization or Azure DevOps Server collection you want to work on.

.PARAMETER NotificationType
    Specify the notification type. This can be either Information, Warning, or Error.

.PARAMETER Message
    pecify the notification message.
    
.PARAMETER Quiet
    Specify this switch to suppress confirmation prompts.

.PARAMETER GetCredentials
    Specify this switch if you need to use special credentials when connecting to your Azure DevOps Server.

.PARAMETER UsePAT
    Specify this switch if you need to provide a Personal Access Token to connect your Azure DevOps Server/Services.

.PARAMETER MaxRestCallRetries
    Provide the number of retries for failing REST calls. In general, you shouldn't need this option. However, when running in an
    unstable environment (e.g., unreliable network connection), retries can help by automatically rerunning failing REST calls.

.PARAMETER TraceErrors
    Specify this switch to enabled extended error tracing using netsh. If you combine this with the MaxRestCallRetries parameter,
    only the last retry is traced. Otherwise, every request is trace, but traces for succeeding network calls are deleted for security reasons.
    Note: You need to run the script as a local administrator when using this switch. Otherwise, network tracing is not allowed.
    
.EXAMPLE
    .\New-NotificationBanner.ps1 -ServiceUri http://MyTfs:8080/tfs/DefaultCollection -NotificationType Information -Message "Happy holiday season to all!" -GetCredentials
    Creates a new information banner in the DefaultCollection of your local Azure DevOps Server using Windows credentials.

.EXAMPLE
    .\New-NotificationBanner.ps1 -ServiceUri https://dev.azure.com/myOrg -NotificationType Warning -Message "There are currently issues with our license distribution. Please contact the help desk if you are missing licensed features." -Quiet -UsePAT
    Creates a new warning banner in the Azure DevOps Services organization myOrg, suppressing confirmations and using a PAT for authentication.

#>
function New-NotificationBanner() {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, HelpMessage="Enter the URI of the Azure DevOps Services organization or Azure DevOps Server collection you want to work on.")]
        [ValidateNotNullOrEmpty()]
        [string]$ServiceUri,

        [Parameter(Mandatory=$true, HelpMessage="Specify the notification type. This can be either Information, Warning, or Error.")]
        [ValidateSet("Information", "Warning", "Error")]
        [string]$NotificationType,

        [Parameter(Mandatory=$true, HelpMessage="Specify the notification message.")]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
    
        [Parameter(Mandatory=$false, HelpMessage="Specify this switch to suppress confirmation prompts.")]
        [switch]$Quiet,
    
        [Parameter(Mandatory=$false, HelpMessage="Specify this switch if you need to use special credentials when connecting to your Azure DevOps Server.")]
        [switch]$GetCredentials,
    
        [Parameter(Mandatory=$false, HelpMessage="Specify this switch if you need to provide a Personal Access Token to connect your Azure DevOps Server/Services.")]
        [switch]$UsePAT,
    
        [Parameter(Mandatory=$false, HelpMessage="Provide the number of retries for failing REST calls. In general, you shouldn't need this option.")]
        [int]$MaxRestCallRetries = 1,
    
        [Parameter(Mandatory=$false, HelpMessage="Specify this switch to enable extended error tracing using netsh.")]
        [switch]$TraceErrors
    )

    Assert-Preconditions -command New-NotificationBanner

    if (!(Get-Consent -message "Do you want to create this new notification?"))
    {
        Write-Host "Aborted."
        exit 0
    }

    $apiVersion = Get-ApiVersion
    $uri = "$ServiceUri/_apis/settings/entries/host?$apiVersion"

    $messageId = [Guid]::NewGuid()
    $body = @{
        "GlobalMessageBanners/$messageId" = @{
            "level" = $NotificationType
            "message" = $Message
        }
    }

    Invoke-RestPatch -uri $uri -body $body
    Write-Host "Notification banner with ID $messageId created."
}

<#

.SYNOPSIS
    Get-NotificationBanners

.DESCRIPTION
    Lists all existing notification banners for Azure DevOps.

.PARAMETER ServiceUri
    Provide the URI of the Azure DevOps Services organization or Azure DevOps Server collection you want to work on.
    
.PARAMETER Quiet
    Specify this switch to suppress confirmation prompts.

.PARAMETER GetCredentials
    Specify this switch if you need to use special credentials when connecting to your Azure DevOps Server.

.PARAMETER UsePAT
    Specify this switch if you need to provide a Personal Access Token to connect your Azure DevOps Server/Services.

.PARAMETER MaxRestCallRetries
    Provide the number of retries for failing REST calls. In general, you shouldn't need this option. However, when running in an
    unstable environment (e.g., unreliable network connection), retries can help by automatically rerunning failing REST calls.

.PARAMETER TraceErrors
    Specify this switch to enabled extended error tracing using netsh. If you combine this with the MaxRestCallRetries parameter,
    only the last retry is traced. Otherwise, every request is trace, but traces for succeeding network calls are deleted for security reasons.
    Note: You need to run the script as a local administrator when using this switch. Otherwise, network tracing is not allowed.
    
.EXAMPLE
    .\Get-NotificationBanners.ps1 -ServiceUri http://MyTfs:8080/tfs/DefaultCollection -GetCredentials
    Lists all notification banners in the DefaultCollection of your local Azure DevOps Server using Windows credentials.

.EXAMPLE
    .\Get-NotificationBanners.ps1 -ServiceUri https://dev.azure.com/myOrg -UsePAT
    Lists all notification banners in the Azure DevOps Services organization myOrg using a PAT for authentication.

#>
function Get-NotificationBanners() {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, HelpMessage="Enter the URI of the Azure DevOps Services organization or Azure DevOps Server collection you want to work on.")]
        [ValidateNotNullOrEmpty()]
        [string]$ServiceUri,
    
        [Parameter(Mandatory=$false, HelpMessage="Specify this switch to suppress confirmation prompts.")]
        [switch]$Quiet,
    
        [Parameter(Mandatory=$false, HelpMessage="Specify this switch if you need to use special credentials when connecting to your Azure DevOps Server.")]
        [switch]$GetCredentials,
    
        [Parameter(Mandatory=$false, HelpMessage="Specify this switch if you need to provide a Personal Access Token to connect your Azure DevOps Server/Services.")]
        [switch]$UsePAT,
    
        [Parameter(Mandatory=$false, HelpMessage="Provide the number of retries for failing REST calls. In general, you shouldn't need this option.")]
        [int]$MaxRestCallRetries = 1,
    
        [Parameter(Mandatory=$false, HelpMessage="Specify this switch to enable extended error tracing using netsh.")]
        [switch]$TraceErrors
    )

    Assert-Preconditions -command Get-NotificationBanners

    $apiVersion = Get-ApiVersion
    $uri = "$ServiceUri/_apis/settings/entries/host/GlobalMessageBanners?$apiVersion"

    $banners = Invoke-RestGet -uri $uri
    Write-Host "Found $($banners.count) notification banner(s):"
    if ($banners.count -gt 0)
    {
        foreach ($banner in $banners.value)
        {
            $messageId = ($banner | Get-Member -Type NoteProperty).Name
            Write-Host "ID: $messageId"
            Write-Host "    Type: $($banner."$messageId".level)"
            Write-Host "    Message: $($banner."$messageId".message)"
        }
    }
}

<#

.SYNOPSIS
    Remove-NotificationBanner

.DESCRIPTION
    Deletes a notification banner from Azure DevOps.

.PARAMETER ServiceUri
    Provide the URI of the Azure DevOps Services organization or Azure DevOps Server collection you want to work on.

.PARAMETER BannerId
    Provide the ID of the notification banner that should bel deleted.
    
.PARAMETER Quiet
    Specify this switch to suppress confirmation prompts.

.PARAMETER GetCredentials
    Specify this switch if you need to use special credentials when connecting to your Azure DevOps Server.

.PARAMETER UsePAT
    Specify this switch if you need to provide a Personal Access Token to connect your Azure DevOps Server/Services.

.PARAMETER MaxRestCallRetries
    Provide the number of retries for failing REST calls. In general, you shouldn't need this option. However, when running in an
    unstable environment (e.g., unreliable network connection), retries can help by automatically rerunning failing REST calls.

.PARAMETER TraceErrors
    Specify this switch to enabled extended error tracing using netsh. If you combine this with the MaxRestCallRetries parameter,
    only the last retry is traced. Otherwise, every request is trace, but traces for succeeding network calls are deleted for security reasons.
    Note: You need to run the script as a local administrator when using this switch. Otherwise, network tracing is not allowed.
    
.EXAMPLE
    .\Remove-NotificationBanner.ps1 -ServiceUri http://MyTfs:8080/tfs/DefaultCollection -Id c6bd264d-3fe7-4e11-9e2d-a4e8d86e5fec -GetCredentials
    Deletes the notification banner with ID c6bd264d-3fe7-4e11-9e2d-a4e8d86e5fec in the DefaultCollection of your local Azure DevOps Server using Windows credentials.

.EXAMPLE
    .\Remove-NotificationBanner.ps1 -ServiceUri https://dev.azure.com/myOrg -Id c6bd264d-3fe7-4e11-9e2d-a4e8d86e5fec -UsePAT
    Deletes the notification banner with ID c6bd264d-3fe7-4e11-9e2d-a4e8d86e5fec in the Azure DevOps Services organization myOrg using a PAT for authentication.

#>
function Remove-NotificationBanner() {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, HelpMessage="Enter the URI of the Azure DevOps Services organization or Azure DevOps Server collection you want to work on.")]
        [ValidateNotNullOrEmpty()]
        [string]$ServiceUri,

        [Parameter(Mandatory=$true, HelpMessage="Provide the ID of the notification banner that should bel deleted.")]
        [ValidateNotNullOrEmpty()]
        [string]$BannerId,
    
        [Parameter(Mandatory=$false, HelpMessage="Specify this switch to suppress confirmation prompts.")]
        [switch]$Quiet,
    
        [Parameter(Mandatory=$false, HelpMessage="Specify this switch if you need to use special credentials when connecting to your Azure DevOps Server.")]
        [switch]$GetCredentials,
    
        [Parameter(Mandatory=$false, HelpMessage="Specify this switch if you need to provide a Personal Access Token to connect your Azure DevOps Server/Services.")]
        [switch]$UsePAT,
    
        [Parameter(Mandatory=$false, HelpMessage="Provide the number of retries for failing REST calls. In general, you shouldn't need this option.")]
        [int]$MaxRestCallRetries = 1,
    
        [Parameter(Mandatory=$false, HelpMessage="Specify this switch to enable extended error tracing using netsh.")]
        [switch]$TraceErrors
    )

    Assert-Preconditions -command Remove-NotificationBanner

    if (!(Get-Consent -message "Do you want to delete notification ID $($BannerId)?"))
    {
        Write-Host "Aborted."
        exit 0
    }

    $apiVersion = Get-ApiVersion
    $uri = "$ServiceUri/_apis/settings/entries/host/GlobalMessageBanners/$($BannerId)?$apiVersion"

    Invoke-RestDelete -uri $uri
    Write-Host "Notification banner deleted."
}

<#

.SYNOPSIS
    Clear-NotificationBanners

.DESCRIPTION
    Deletes all notification banners from Azure DevOps.

.PARAMETER ServiceUri
    Provide the URI of the Azure DevOps Services organization or Azure DevOps Server collection you want to work on.
    
.PARAMETER Quiet
    Specify this switch to suppress confirmation prompts.

.PARAMETER GetCredentials
    Specify this switch if you need to use special credentials when connecting to your Azure DevOps Server.

.PARAMETER UsePAT
    Specify this switch if you need to provide a Personal Access Token to connect your Azure DevOps Server/Services.

.PARAMETER MaxRestCallRetries
    Provide the number of retries for failing REST calls. In general, you shouldn't need this option. However, when running in an
    unstable environment (e.g., unreliable network connection), retries can help by automatically rerunning failing REST calls.

.PARAMETER TraceErrors
    Specify this switch to enabled extended error tracing using netsh. If you combine this with the MaxRestCallRetries parameter,
    only the last retry is traced. Otherwise, every request is trace, but traces for succeeding network calls are deleted for security reasons.
    Note: You need to run the script as a local administrator when using this switch. Otherwise, network tracing is not allowed.
    
.EXAMPLE
    .\Clear-NotificationBanners.ps1 -ServiceUri http://MyTfs:8080/tfs/DefaultCollection -GetCredentials
    Deletes all notification banners in the DefaultCollection of your local Azure DevOps Server using Windows credentials.

.EXAMPLE
    .\Clear-NotificationBanners.ps1 -ServiceUri https://dev.azure.com/myOrg -Id c6bd264d-3fe7-4e11-9e2d-a4e8d86e5fec -Quiet -UsePAT
    Deletes all notification banners in the Azure DevOps Services organization myOrg without confirmation using a PAT for authentication.

#>
function Clear-NotificationBanners() {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, HelpMessage="Enter the URI of the Azure DevOps Services organization or Azure DevOps Server collection you want to work on.")]
        [ValidateNotNullOrEmpty()]
        [string]$ServiceUri,
    
        [Parameter(Mandatory=$false, HelpMessage="Specify this switch to suppress confirmation prompts.")]
        [switch]$Quiet,
    
        [Parameter(Mandatory=$false, HelpMessage="Specify this switch if you need to use special credentials when connecting to your Azure DevOps Server.")]
        [switch]$GetCredentials,
    
        [Parameter(Mandatory=$false, HelpMessage="Specify this switch if you need to provide a Personal Access Token to connect your Azure DevOps Server/Services.")]
        [switch]$UsePAT,
    
        [Parameter(Mandatory=$false, HelpMessage="Provide the number of retries for failing REST calls. In general, you shouldn't need this option.")]
        [int]$MaxRestCallRetries = 1,
    
        [Parameter(Mandatory=$false, HelpMessage="Specify this switch to enable extended error tracing using netsh.")]
        [switch]$TraceErrors
    )

    Assert-Preconditions -command Clear-NotificationBanners

    if (!(Get-Consent -message "Are you sure you want to delete all notification banners?"))
    {
        Write-Host "Aborted."
        exit 0
    }

    $apiVersion = Get-ApiVersion
    $uri = "$ServiceUri/_apis/settings/entries/host/GlobalMessageBanners?$apiVersion"

    Invoke-RestDelete -uri $uri
    Write-Host "Notification banners deleted."
}

Export-ModuleMember -Function New-NotificationBanner, Get-NotificationBanners, Remove-NotificationBanner, Clear-NotificationBanners