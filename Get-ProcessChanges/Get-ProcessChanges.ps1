<#

.SYNOPSIS
    Get changes and affected projects in inherited processes.

.DESCRIPTION
    The script retrieves all inherited processes from Azure DevOps, compares them to their base proccesses and lists all changes in the inherited
    processes along with the projects that are using the inherited processes.

.PARAMETER ServiceUri
    Provide the URI of the Azure DevOps Services organization or Azure DevOps Server collection you want to work on.

.PARAMETER OutputPath
    Provide the path in which reports are generated.

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
    .\Get-ProcessChanges.ps1 -ServiceUri http://MyTfs:8080/tfs/DefaultCollection -GetCredentials
    Runs the script on the DefaultCollection of your local Azure DevOps Server using Windows credentials.

.EXAMPLE
    .\Get-ProcessChanges.ps1 -ServiceUri https://dev.azure.com/myOrg -UsePAT
    Runs the script on the Azure DevOps Services organization myOrg and using a PAT for authentication.

#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true, HelpMessage="Enter the URI of the Azure DevOps Services organization or Azure DevOps Server collection you want to work on.")]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceUri,

    [Parameter(Mandatory=$false, HelpMessage="Provide the path in which reports are generated.")]
    [string]$OutputPath = $PWD,

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

################################################################################
# Configuration section
# Put general configuration stuff and validations here
################################################################################

#Requires -Version 6.2
Set-StrictMode -Version 3.0

$scriptName = "Get Inherited Process Changes"
# Use semantic versioning here
$version = "1.0.1"
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

    Write-Host "   Output Path: $OutputPath" -NoNewline
    if (!(Test-Path $OutputPath -PathType Container))
    {
        try
        {
            New-Item -Path $OutputPath -ItemType Directory
        }
        catch
        {
            Write-Host " (invalid - does not exist and couldn't be created)" - -ForegroundColor Red -NoNewline
            $validationResult = $false
        }
    }
    Write-Host

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
# HTML helper functions
################################################################################

Add-Type -AssemblyName System.Collections

$Global:indentation = "  "
$Global:htmlHead = @"
  <head>
    <style>
      * { font-family: Calibri, sans-serif; }
      .crossedout { text-decoration: line-through; }
      .root { margin-top: 0; }
      .indented { margin-left: 12px; }
      h1 { margin-bottom: 6px; }
      h2 { margin-bottom: 6px; }
      h3 { margin-bottom: 6px; }
      h4 { margin-bottom: 6px; }
      div > h2:first-child, div > h3:first-child, div > h4:first-child, div > h5:first-child { margin-top: 0; }
      h1 + h2, h2 + h3, h3 + h4, h4 + h5 { margin-top: 0; }
      h1 + p, h2 + p, h3 + p, h4 + p, h5 + p { margin-top: 0; }
      h1 + ol, h2 + ol, h3 + ol, h4 + ol, h5 + ol { margin-top: 0; }
      h1 + ul, h2 + ul, h3 + ul, h4 + ul, h5 + ul { margin-top: 0; }
    </style>
  </head>
"@

$Global:htmlDocuments = @{}

function Open-HtmlDocument($filePath)
{
    $documentId = [Guid]::NewGuid().ToString()

    $elementStack = New-Object System.Collections.Stack
    $writer = [System.IO.File]::CreateText($filePath)

    $Global:htmlDocuments.Add($documentId, @{
        writer = $writer;
        elementStack = $elementStack;
    })

    $writer.WriteLine("<html>")
    $elementStack.Push("html")
    $writer.WriteLine($Global:htmlHead)
    $writer.WriteLine("$($Global:indentation)<body>")
    $elementStack.Push("body")

    return $documentId
}

function Close-HtmlDocument($documentId)
{
    if (!$Global:htmlDocuments.ContainsKey($documentId))
    {
        return;
    }

    Close-Element -documentId $documentId -element "html"

    $documentInfo = $Global:htmlDocuments[$documentId]
    $documentInfo.writer.Close()
    $documentInfo.writer.Dispose()
    $Global:htmlDocuments.Remove($documentId)
}

function Close-AllHtmlDocuments()
{
    $documents = $Global:htmlDocuments.Keys | ForEach-Object ToString
    foreach ($document in $documents)
    {
        Close-HtmlDocument -documentId $document
    }
}

function Open-Element($documentId, $element, $attributes = $null)
{
    if (!$Global:htmlDocuments.ContainsKey($documentId))
    {
        return
    }

    $documentInfo = $Global:htmlDocuments[$documentId]
    Write-Indentation -writer $documentInfo.writer -indentLevel $documentInfo.elementStack.Count
    $documentInfo.writer.Write("<$element")
    Write-Attributes -writer $documentInfo.writer -attributes $attributes
    $documentInfo.writer.WriteLine(">")
    $documentInfo.elementStack.Push($element)
}

function Close-Element($documentId, $element)
{
    if (!$Global:htmlDocuments.ContainsKey($documentId))
    {
        return
    }

    $documentInfo = $Global:htmlDocuments[$documentId]
    $currentElement = ""
    $openElements = $documentInfo.elementStack.Count
    while (($openElements -gt 0) -and ($currentElement -ne $element))
    {
        $currentElement = $documentInfo.elementStack.Pop()
        $openElements -= 1
        Write-Indentation -writer $documentInfo.writer -indentLevel $openElements
        $documentInfo.writer.WriteLine("</$currentElement>")
    }
}

function Write-Indentation($writer, $indentLevel)
{
    $writer.Write("$($Global:indentation * $indentLevel)")
}

function Write-Attributes($writer, $attributes)
{
    if ($null -eq $attributes)
    {
        return
    }

    foreach ($attribute in $attributes.Keys)
    {
        $writer.Write(" $attribute=""$($attributes[$attribute])""")
    }
}

function Write-Element($documentId, $element, $attributes = $null, $value = $null, [switch] $noNewLine, [switch] $noIndentation)
{
    if (!$Global:htmlDocuments.ContainsKey($documentId))
    {
        return
    }

    $documentInfo = $Global:htmlDocuments[$documentId]
    if (!$noIndentation)
    {
        Write-Indentation -writer $documentInfo.writer -indentLevel $documentInfo.elementStack.Count
    }
    $documentInfo.writer.Write("<$element")
    Write-Attributes -writer $documentInfo.writer -attributes $attributes
    if ($null -ne $value)
    {
        if ($noNewLine)
        {
            $documentInfo.writer.Write(">$value</$element>")
        }
        else
        {
            $documentInfo.writer.WriteLine(">$value</$element>")
        }
    }
    else
    {
        if ($noNewLine)
        {
            $documentInfo.writer.Write(" />")
        }
        else
        {
            $documentInfo.writer.WriteLine(" />")
        }
    }
}

function Open-Div($documentId, $attributes = $null)
{
    Open-Element -documentId $documentId -element "div" -attributes $attributes
}

function Close-Div($dcumentId)
{
    Close-Element -documentId $documentId -element "div"
}

function Open-Paragraph($documentId, $attributes = $null)
{
    Open-Element -documentId $documentId -element "p" -attributes $attributes
}

function Close-Paragraph($documentId)
{
    Close-Element -documentId $documentId -element "p"
}

function Open-OrderedList($documentId, $attributes = $null)
{
    Open-Element -documentId $documentId -element "ol" -attributes $attributes
}

function Close-OrderedList($documentId)
{
    Close-Element -documentId $documentId -element "ol"
}

function Open-UnorderedList($documentId, $attributes = $null)
{
    Open-Element -documentId $documentId -element "ul" -attributes $attributes
}

function Close-UnorderedList($documentId)
{
    Close-Element -documentId $documentId -element "ul"
}

function Write-ListEntry($documentId, $value, $attributes = $null)
{
    Write-Element -documentId $documentId -element "li" -value $value -attributes $attributes
}

function Write-Heading($documentId, $headingLevel, $headingText, $attributes = $null)
{
    Write-Element -documentId $documentId -element "h$headingLevel" -value $headingText -attributes $attributes
}

function Write-Text($documentId, $text, [switch] $noNewLine, [switch] $noIndentation)
{
    if (!$Global:htmlDocuments.ContainsKey($documentId))
    {
        return
    }

    $documentInfo = $Global:htmlDocuments[$documentId]
    if (!$noIndentation)
    {
        $documentInfo.writer.Write("$($Global:indentation * $documentInfo.elementStack.Count)")
    }
    if ($noNewLine)
    {
        $documentInfo.writer.Write($text)
    }
    else
    {
        $documentInfo.writer.WriteLine($text)
    }
}

function Write-LineBreak($documentId)
{
    Write-Element -documentId $documentId -element "br"
}

################################################################################
# Process information retrieval functions
################################################################################

$Global:baseProcesses = @{}
$Global:inheritedProcesses = @{}
$Global:workItemTypes = @{}

function Initialize-ProcessInformation()
{
    Write-Host "Getting processes..."
    $processesUri = "$ServiceUri/_apis/work/processes?`$expand=projects"
    $allProcesses = Invoke-RestGet -uri $processesUri

    foreach ($process in $allProcesses.value)
    {
        switch ($process.customizationType)
        {
            "system" { $Global:baseProcesses.Add($process.typeId, $process) }
            "inherited" { $Global:inheritedProcesses.Add($process.typeId, $process) }
        }
    }
}

function Get-WorkItemTypeInformation($processId, $onlyCustom = $false)
{
    $wiTypesUri = "$ServiceUri/_apis/work/processes/$processId/workitemtypes?`$expand=3"
    $workItemTypesInProcess = Invoke-RestGet -uri $wiTypesUri

    $workItemTypes = @{}

    foreach ($workItemType in $workItemTypesInProcess.value)
    {
        if ((!$onlyCustom) -or ($workItemType.customization -ne "system"))
        {
            $workItemTypes.Add($workItemType.referenceName, $workItemType)
        }
    }
    $Global:workItemTypes.Add($processId, $workItemTypes)
}

function Initialize-WorkItemTypeInformation()
{
    Write-Host "Getting work item types for system processes..."
    foreach ($processId in $Global:baseProcesses.Keys)
    {
        Get-WorkItemTypeInformation -processId $processId
    }
    Write-Host "Getting work item types for inherited processes..."
    foreach ($processId in $Global:inheritedProcesses.Keys)
    {
        Get-WorkItemTypeInformation -processId $processId -onlyCustom $true
    }
}

function Get-WorkItemTypeFieldInformation($processId, $workItemTypeRefName, $onlyCustom = $false)
{
    $fieldsUri = "$ServiceUri/_apis/work/processes/$processId/workitemtypes/$workItemTypeRefName/fields"
    $fields = Invoke-RestGet -uri $fieldsUri

    $workItemTypeFields = @()
    foreach ($field in $fields.value)
    {
        if ((!$onlyCustom) -or ($field.customization -ne "system"))
        {
            $workItemTypeFields += $field
        }
    }

    $Global:workItemTypes[$processId][$workItemTypeRefName] | Add-Member -NotePropertyName fields -NotePropertyValue $workItemTypeFields
}

function Get-WorkItemTypeRuleInformation($processId, $workItemTypeRefName, $onlyCustom = $false)
{
    $rulesUri = "$ServiceUri/_apis/work/processes/$processId/workitemtypes/$workItemTypeRefName/rules"
    $rules = Invoke-RestGet -uri $rulesUri

    $workItemTypeRules = @()
    foreach ($rule in $rules.value)
    {
        if ((!$onlyCustom) -or ($rule.customizationType -ne "system"))
        {
            $workItemTypeRules += $rule
        }
    }

    $Global:workItemTypes[$processId][$workItemTypeRefName] | Add-Member -NotePropertyName rules -NotePropertyValue $workItemTypeRules
}

function Initialize-AdditionalWorkItemTypeInformation()
{
    foreach ($processId in $Global:workItemTypes.Keys)
    {
        $onlyCustom = !$Global:baseProcesses.ContainsKey($processId)

        foreach ($workItemType in $Global:workItemTypes[$processId].Keys)
        {
            Write-Host "Getting work item type information for $workItemType..."
            Get-WorkItemTypeFieldInformation -processId $processId -workItemTypeRefName $workItemType -onlyCustom $onlyCustom
            Get-WorkItemTypeRuleInformation -processId $processId -workItemTypeRefName $workItemType -onlyCustom $onlyCustom
        }
    }
}

################################################################################
# Report creation functions
################################################################################

function Write-ReportHeader($documentId, $process)
{
    Write-Heading -documentId $documentId -headingLevel 1 -headingText "Process Changes Report for Process $($process.name)" -attributes @{ "class" = "root" }
    Open-Paragraph -documentId $documentId
    Write-Text -documentId $documentId -text "This report describes all changes between the process $($process.name) and its base process."
    Write-LineBreak -documentId $documentId
    Write-Text -documentId $documentId -text "Generated: $([DateTime]::Now.ToLocalTime())"
    Close-Paragraph -documentId $documentId
}

function Write-BaseProcessAndProjects($documentId, $process)
{
    Write-Heading -documentId $documentId -headingLevel 2 -headingText "General Information"
    Open-UnorderedList -documentId $documentId
    Write-ListEntry -documentId $documentId -value "<strong>Process Name:</strong> $($process.name)"
    Write-ListEntry -documentId $documentId -value "<strong>Description:</strong> $($process.description)"

    $baseProcess = $Global:baseProcesses[$process.parentProcessTypeId]
    Write-ListEntry -documentId $documentId -value "<strong>Base Process:</strong> $($baseProcess.name)"

    if ($process.PSObject.Properties.name -match "projects")
    {
        $projects = $process.projects | ForEach-Object { $_.name }
        Write-ListEntry -documentId $documentId -value "<strong>Projects:</strong> $([string]::Join(", ", $projects))"
    }
    else
    {
        Write-ListEntry -documentId $documentId -value "<strong>Projects:</strong> None"
    }
    Close-UnorderedList -documentId $documentId
}

function Write-DisabledWorkItemTypes($documentId, $disabledWorkItemTypes)
{
    Write-Heading -documentId $documentId -headingLevel 3 -headingText "Disabled Work Item Types"
    Open-UnorderedList -documentId $documentId
    if ($null -eq $disabledWorkItemTypes)
    {
        Write-ListEntry -documentId $documentId -value "None"
    }
    else
    {
        foreach ($disabledWorkItemType in $disabledWorkItemTypes)
        {
            Write-ListEntry -documentId $documentId -value $disabledWorkItemType
        }
    }
    Close-UnorderedList -documentId $documentId
}

function Write-WorkItemTypeStatesInformation($documentId, $workItemType)
{
    Write-Heading -documentId $documentId -headingLevel 4 -headingText "States"
    Open-Paragraph -documentId $documentId
    Write-Text -documentId $documentId -text "States in regular print match the base process definition, <strong>bold</strong> states have been added, <span class='crossedout'>crossed out</span> states have been hidden."
    Close-Paragraph -documentId $documentId
    Open-UnorderedList -documentId $documentId
    
    $states = @()
    $stateTypes = @()
    $stateCategories = @()
    foreach ($state in $workItemType.states)
    {
        if (!$states.Contains($state.name))
        {
            $states +=  $state.name
            $stateTypes += $state.customizationType
            $stateCategories += $state.stateCategory
        }
        $index = $states.IndexOf($state.name)
        if (($state.customizationType -eq "inherited") -and ($state.hidden))
        {
            $stateTypes[$index] = "hidden"
        }
    }
    for ($i = 0; $i -lt $states.Count; $i++)
    {
        switch ($stateTypes[$i])
        {
            "system" { $listValue = "$($states[$i]) ($($stateCategories[$i]))" }
            "custom" { $listValue = "<strong>$($states[$i])</strong> ($($stateCategories[$i]))" }
            "hidden" { $listValue = "<span class='crossedout'>$($states[$i])</span> ($($stateCategories[$i]))" }
        }
        Write-ListEntry -documentId $documentId -value $listValue
    }

    Close-UnorderedList -documentId $documentId
}

$Global:fieldProperties = @("type", "description", "required", "defaultValue")

function Write-WorkItemTypeCustomFieldInformation($documentId, $field)
{
    Write-ListEntry -documentId $documentId -value "<strong>$($field.name)</strong>"
    Open-UnorderedList -documentId $documentId

    foreach ($property in $Global:fieldProperties)
    {
        if ($field.PSObject.Properties.name -match $property)
        {
            Write-ListEntry -documentId $documentId -value "$($property): $($field.$property)"
        }
    }

    Close-UnorderedList -documentId $documentId
}

function Write-WorkItemTypeChangedFieldInformation($documentId, $field, $baseField)
{
    if ($null -eq $baseField)
    {
        Write-WorkItemTypeCustomFieldInformation -documentId $documentId -field $field
        return
    }

    Write-ListEntry -documentId $documentId -value $field.name
    Open-UnorderedList -documentId $documentId

    foreach ($property in $Global:fieldProperties)
    {
        if (($field.PSObject.Properties.name -match $property) -and !($baseField.PSObject.Properties.name -match $property))
        {
            Write-ListEntry -documentId $documentId -value "$($property): $($field.$property)"
        }
        if (!($field.PSObject.Properties.name -match $property) -and ($baseField.PSObject.Properties.name -match $property))
        {
            Write-ListEntry -documentId $documentId -value "$($property): <span class='crossedout'>$($baseField.$property)</span>"
        }
        if (($field.PSObject.Properties.name -match $property) -and ($baseField.PSObject.Properties.name -match $property) -and ($field.$property -ne $baseField.$property))
        {
            Write-ListEntry -documentId $documentId -value "$($property): <span class='crossedout'>$($baseField.$property)</span> $($field.$property)"
        }
    }

    Close-UnorderedList -documentId $documentId
}

function Write-WorkItemTypeFieldsInformation($documentId, $workItemType, $baseWorkItemType)
{
    Write-Heading -documentId $documentId -headingLevel 4 -headingText "Fields"
    Open-Paragraph -documentId $documentId
    Write-Text -documentId $documentId -text "Fields in <strong>bold</strong> print are custom, changed fields are printed in regular text. For custom fields, all properties are listed, whereas for changed fields only changed properties are listed."
    Close-Paragraph -documentId $documentId

    Open-UnorderedList -documentId $documentId

    foreach ($field in $workItemType.fields)
    {
        switch ($field.customization)
        {
            "custom" { Write-WorkItemTypeCustomFieldInformation -documentId $documentId -field $field }
            "inherited"
            {
                if ($null -eq $baseWorkItemType)
                {
                    Write-WorkItemTypeCustomFieldInformation -documentId $documentId -field $field
                }
                else
                {
                    Write-WorkItemTypeChangedFieldInformation -documentId $documentId -field $field -baseField ($baseWorkItemType.fields | Where-Object { $_.referenceName -eq $field.referenceName })
                }
            }
        }
    }

    Close-UnorderedList -documentId $documentId
}

function Write-WorkItemTypeRuleConditionsInformation($documentId, $conditions)
{
    Write-ListEntry -documentId $documentId -value "<strong>Conditions</strong>"
    Open-UnorderedList -documentId $documentId

    foreach ($condition in $conditions)
    {
        Write-ListEntry -documentId $documentId -value "<strong>Type:</strong> $($condition.conditionType); <strong>Field:</strong> $($condition.field); <strong>Value:</strong> $($condition.value)"
    }

    Close-UnorderedList -documentId $documentId
}

function Write-WorkItemTypeRuleActionsInformation($documentId, $actions)
{
    Write-ListEntry -documentId $documentId -value "<strong>Actions</strong>"
    Open-UnorderedList -documentId $documentId

    foreach ($action in $actions)
    {
        Write-ListEntry -documentId $documentId -value "<strong>Action:</strong> $($action.actionType); <strong>Target Field:</strong> $($action.targetField); <strong>Value:</strong> $($action.value)"
    }

    Close-UnorderedList -documentId $documentId
}

function Write-WorkItemTypeRuleInformation($documentId, $rule)
{
    Write-ListEntry -documentId $documentId -value "<strong>Name:</strong> $($rule.name)"
    Write-WorkItemTypeRuleConditionsInformation -documentId $documentId -conditions $rule.conditions
    Write-WorkItemTypeRuleActionsInformation -documentId $documentId -actions $rule.actions
}

function Write-WorkItemTypeRulesInformation($documentId, $workItemType)
{
    Write-Heading -documentId $documentId -headingLevel 4 -headingText "Rules"
    Open-UnorderedList -documentId $documentId

    if ($workItemType.rules.Count -eq 0)
    {
        Write-ListEntry -documentId $documentId -value "None"
    }
    else
    {
        foreach ($rule in $workItemType.rules)
        {
            Write-WorkItemTypeRuleInformation -documentId $documentId -rule $rule
        }   
    }

    Close-UnorderedList -documentId $documentId
}

function Write-WorkItemTypeInformation($documentId, $workItemType, $baseWorkItemType)
{
    if ($workItemType.isDisabled)
    {
        return
    }

    switch ($workItemType.customization)
    {
        "custom" { $headingText = "$($workItemType.name) (custom)" }
        "inherited" { $headingText = "$($workItemType.name) (changed)" }
    }
    Write-Heading -documentId $documentId -headingLevel 3 -headingText $headingText
    Open-Div -documentId $documentId -attributes @{ "class" = "indented" }

    Write-WorkItemTypeStatesInformation -documentId $documentId -workItemType $workITemType
    Write-WorkItemTypeFieldsInformation -documentId $documentId -workItemType $workItemType -baseWorkItemType $baseWorkItemType
    Write-WorkItemTypeRulesInformation -documentId $documentId -workItemType $workItemType

    Close-Div -documentId $documentId
}

function Write-WorkItemTypesInformation($documentId, $process)
{
    $workItemTypes = $Global:workItemTypes[$process.typeId]
    $baseWorkItemTypes = $Global:workItemTypes[$process.parentProcessTypeId]

    if ($workItemTypes.Count -eq 0)
    {
        return
    }

    Write-Heading -documentId $documentId -headingLevel 2 -headingText "Work Item Types"
    Open-Paragraph -documentId $documentId
    Write-Text -documentId $documentId -text "This section lists all custom, changed, and disabled work item types. Work item types that match the definition in the base process are not listed to keep the report short. For each work item type all states, all custom or changed fields, and custom rules are listed."
    Close-Paragraph -documentId $documentId
    Open-Div -documentId $documentId -attributes @{ "class" = "indented" }

    if ($workItemTypes.Count)
    {
        $disabledWorkItemTypes = [string[]] (($workItemTypes.Values | Where-Object { $_.isDisabled })  | ForEach-Object { $_.name })
        Write-DisabledWorkItemTypes -documentId $documentId -disabledWorkItemTypes $disabledWorkItemTypes
    }

    foreach ($workItemTypeRefName in $workItemTypes.Keys)
    {
        $workItemType = $workItemTypes[$workItemTypeRefName]
        if ($null -eq $workItemType.inherits) { $baseWorkItemType = $null } else { $baseWorkItemType = $baseWorkItemTypes[$workItemType.inherits] }
        Write-WorkItemTypeInformation -documentId $documentId -workItemType $workItemType -baseWorkItemType $baseWorkItemType
    }

    Close-Div -dcumentId $documentId
}

function New-ProcessChangesReport($processId)
{
    $process = $Global:inheritedProcesses[$processId]

    $filePath = Join-Path $OutputPath "$($process.name) Process Report.html"
    Write-Host "Generating report for process '$($process.name)' to '$filePath'..."
    $documentId = Open-HtmlDocument -filePath $filePath

    Write-ReportHeader -documentId $documentId -process $process
    Write-BaseProcessAndProjects -documentId $documentId -process $process
    Write-WorkItemTypesInformation -documentId $documentId -process $process

    Close-HtmlDocument -documentId $documentId
}

################################################################################
# Main script starts here
################################################################################

# Do not remove this!
Assert-Preconditions

try
{
    Initialize-ProcessInformation
    Initialize-WorkItemTypeInformation
    Initialize-AdditionalWorkItemTypeInformation    
}
catch
{
    Write-Host "Error during process information retrieval:" -ForegroundColor Red
    throw
}

try
{
    foreach ($processId in $Global:inheritedProcesses.Keys)
    {
        New-ProcessChangesReport -processId $processId
    }
}
catch
{
    Write-Host "Error during process report generation:" -ForegroundColor Red
    throw
}
finally
{
    Close-AllHtmlDocuments
}