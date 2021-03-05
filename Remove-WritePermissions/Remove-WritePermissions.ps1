<#

.SYNOPSIS
    Remove Write Permissions

.DESCRIPTION
    Removes all write permissions from Azure DevOps (cloud and on-prem) for specific or all projects by moving all identities to the Readers group.

.PARAMETER ServiceUri
    Provide the URI of the Azure DevOps Services organization or Azure DevOps Server collection you want to work on.

.PARAMETER Projects
    Enter a comma-separated list of projects from which you want to remove write permissions. If omitted, permissions will be removed from all projects.

.PARAMETER RemoveProjectAdmins
    Specify this switch to remove all project administrators from projects.

.PARAMETER FixPermissions
    Specify this switch to fix project permissions. To minimize the effort and runtime for the script, this parameter only ensures the following:
      - Ensure that project-level permissions of the Readers group are correct.
      - Remove all direct permissions on all areas, enable inheritance, ensure that permissions of the Readers group are correct.
      - Remove all direct permissions on all Git repositories and refs, enable inheritance, ensure that permissions of the Readers group are correct.

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
    .\AzDOPSSample.ps1 -ServiceUri http://MyTfs:8080/tfs/DefaultCollection -Projects "Project1, Project2" -GetCredentials
    Removes write permissions from projects Project1 and Project2 in the DefaultCollection, using custom credentials.

.EXAMPLE
    .\AzDOPSSample.ps1 -ServiceUri https://dev.azure.com/myOrg -RemoveProjectAdmins -Quiet -UsePAT
    Removes write permissions and project administrators from all projects in the Azure DevOps Services organization myOrg, suppressing confirmations and using a PAT for authentication.

#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true, HelpMessage="Enter the URI of the Azure DevOps Services organization or Azure DevOps Server collection you want to work on.")]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceUri,

    [Parameter(Mandatory=$false, HelpMessage="Enter a comma-separated list of projects from which you want to remove write permissions. If omitted, permissions will be removed from all projects.")]
    [string]$Projects,

    [Parameter(Mandatory=$false, HelpMessage="Specify this switch to remove all project administrators from projects.")]
    [switch]$RemoveProjectAdmins,

    [Parameter(Mandatory=$false, HelpMessage="Specify this switch to fix project permissions (see help details).")]
    [switch]$FixPermissions,

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

$scriptName = "Remove Write Permissions"
# Use semantic versioning here
$version = "1.2.0"
$year = "2020"

$Global:quietAnswer = $true
$Global:defaultAnswer = $false

$RestCallRetryDelayInSeconds = 2

function Test-Parameters()
{
    $validationResult = $true;

    Write-Host "        Service: $ServiceUri" -NoNewline
    if (!([System.Uri]::IsWellFormedUriString($ServiceUri, [System.UriKind]::Absolute)))
    {
        Write-Host " (invalid)" -ForegroundColor Red -NoNewline
        $validationResult = $false
    }
    Write-Host

    Write-Host "       Projects: $(if ([string]::IsNullOrEmpty($Projects.Trim())) { "All" } else { $Projects.Trim() })"
    Write-Host "  Remove Admins: $RemoveProjectAdmins"
    Write-Host "Fix Permissions: $FixPermissions"

    Write-Host " Authentication: $(if ($UsePAT) { "PAT" } elseif ($GetCredentials) { "Custom Credentials" } else { "Default Credentials" })"
    Write-Host "     Allow HTTP: $AllowHttp"
    $Global:isQuiet = $Quiet
    Write-Host "          Quiet: $Quiet"
    Write-Host "    Max Retries: $MaxRestCallRetries" -NoNewline
    if ($MaxRestCallRetries -lt 1) {
        Write-Host " (invalid)" -ForegroundColor Red -NoNewline
        $validationResult = $false;
    }
    Write-Host
    Write-Host "   Trace Errors: $TraceErrors"
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

$projectSecNamespaceId = "52d39943-cb85-4d7f-8fa8-c6baac873819"
$taggingSecNamespaceId = "bb50f182-8e5e-40b8-bc21-e8752a1e7ae2"
$cssSecNamespaceId = "83e28ad4-2d72-4ceb-97b0-c7726d5502c3"
$gitSecNamespaceId = "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87"

$projectLevelReaderAllow = 513
$projectLevelTeamsAllow = 1
$taggingAllow = 1
$rootAreaAllow = 17
$gitAllow = 2

function Get-Projects() {
    $projectInformation = New-Object System.Collections.ArrayList
    $projectsUri = "$ServiceUri/_apis/projects"
    $result = Invoke-RestGet $projectsUri

    $selectedProjects = @()
    if (![string]::IsNullOrEmpty($Projects.Trim())) {
        $projs = $Projects.Split(",", [System.StringSplitOptions]::RemoveEmptyEntries)
        foreach ($p in $projs) {
            $selectedProjects += $p.ToLower()
        }
    }
    foreach ($p in $result.value)
    {
        if (($selectedProjects.Length -eq 0) -or ($selectedProjects.Contains($p.Name.ToLower()))) {
            $projectInformation.Add((New-Object PSObject -Property @{ Name=$p.name; Id=$p.id })) | Out-Null
        }
    }

    return ,$projectInformation
}

$Global:teams = $null
function Get-Teams($projectId) {
    $Global:teams = $null

    $teamsUri = "$ServiceUri/_apis/projects/$projectId/teams"
    $result = Invoke-RestGet $teamsUri

    $teamsInfo = New-Object System.Collections.ArrayList
    foreach ($t in $result.value) {
        $teamsInfo.Add((New-Object PSObject -Property @{ Name=$t.name; Id=$t.id; IdentityType=$null; Descriptor=$null })) | Out-Null
    }

    $Global:teams = $teamsInfo
}

function Get-ProjectGroups($projectId) {
    $groupsUri = "$ServiceUri/_apis/groups?scopeIds=$projectId"
    $result = Invoke-RestGet $groupsUri

    $groupInfo = New-Object System.Collections.ArrayList
    foreach ($g in $result) {
        $groupInfo.Add((New-Object PSObject -Property @{ Name=$g.DisplayName.Substring($g.DisplayName.IndexOf("\") + 1); Id=$g.Id; IdentityType=$g.Descriptor.IdentityType; Descriptor=$g.Descriptor.Identifier })) | Out-Null
    }

    return ,$groupInfo
}

function Set-TeamDescriptorsFromGroupInfos($groups) {
    foreach ($g in $groups) {
        $team = $Global:teams | Where-Object { $_.Name -eq $g.Name }
        if ($team) {
            $team.IdentityType = $g.IdentityType
            $team.Descriptor = $g.Descriptor
        }
    }
}

$Global:readersGroup = $null
function Find-ReadersGroup($groups) {
    $Global:readersGroup = $null
    foreach ($g in $groups) {
        if ($g.Name.ToLower() -eq "readers") {
            $Global:readersGroup = $g
        }
    }
}

function Get-GroupMembers($groupId) {
    $membersUri = "$ServiceUri/_apis/identities/$groupId/members"
    return Invoke-RestGet $membersUri
}

function Get-Areas($projectId) {
    $areasUri = "$ServiceUri/$projectId/_apis/wit/classificationnodes/areas?`$depth=999"
    return Invoke-RestGet $areasUri
}

function Get-GitRepositories($projectId) {
    $gitUri = "$ServiceUri/$projectId/_apis/git/repositories"
    $result = Invoke-RestGet $gitUri
    
    $repoInfo = New-Object System.Collections.ArrayList
    foreach ($r in $result.value) {
        $repoInfo.Add((New-Object PSObject -Property @{ Name=$r.name; Id=$r.Id })) | Out-Null
    }

    return ,$repoInfo
}

function Get-AzDOAcl($securityNamespace, $token) {
    $aclUri = "$ServiceUri/_apis/accesscontrollists/$securityNamespace`?token=$token"
    $result = Invoke-RestGet $aclUri
    if ($result.count -gt 0) {
        return $result.value[0]
    }
    return $null
}

function Get-AzDOAcls($securityNamespace, $token) {
    $aclUri = "$ServiceUri/_apis/accesscontrollists/$securityNamespace`?token=$token&recurse=true"
    return (Invoke-RestGet $aclUri).value
}

function Set-AzDOAcl($securityNamespace, $token, $inheritPermissions, $aces) {
    $aclUri = "$ServiceUri/_apis/accesscontrollists/$securityNamespace`?api-version=4.1"
    $body = @{
        "value" = @(
            @{
                "token" = $token
                "inheritPermissions" = $inheritPermissions
                "acesDictionary" = $aces
            }
        )
    }

    Invoke-RestPost -uri $aclUri -body $body | Out-Null
}

function Set-AzDOAce($securityNamespace, $token, $merge, $descriptor, $allow = 0, $deny = 0) {
    $aceUri = "$ServiceUri/_apis/accesscontrolentries/$securityNamespace`?api-version=4.1"
    $body = @{
        "token" = $token
        "merge" = $merge
        "accessControlEntries" = @(
            @{
                "descriptor" = $descriptor
                "allow" = $allow
                "deny" = $deny
            }
        )
    }
    Invoke-RestPost -uri $aceUri -body $body | Out-Null
}

function Remove-NonServerAndTeamIdentities($aces) {
    $externalIdentities = $aces.psobject.properties | Where-Object { !$_.Name.StartsWith("Microsoft.TeamFoundation") }
    foreach ($extId in $externalIdentities) {
        $aces.psobject.properties.Remove($extId.Name)
    }
    foreach ($team in $Global:teams) {
        $aces.psobject.properties.Remove("$($team.IdentityType);$($team.Descriptor)")
    }
    return $aces
}

function Move-MembersFromGroupToGroup($members, $fromGroup, $toGroup) {
    Write-Host "         $($fromGroup.Name): $($members.Length) members"
    foreach ($m in $members) {
        $addMemberUri = "$ServiceUri/_apis/identities/$($toGroup.Id)/members/$m"
        $removeMemberUri = "$ServiceUri/_apis/identities/$($fromGroup.Id)/members/$m"
        Invoke-RestPut $addMemberUri | Out-Null
        Invoke-RestDelete $removeMemberUri | Out-Null
    }
}

function Move-AllMembersToReaders($projectInfo) {
    Write-Host "      Moving all identities to Readers group"

    $groupsToIgnore = @(
        "readers",
        "project valid users"
    )

    $allGroups = Get-ProjectGroups $projectInfo.Id
    Get-Teams $projectInfo.Id
    # Keep teams intact and don't move team members to Readers
    # Usually, teams are members of other groups so every team should end up in the Readers group
    foreach ($t in $Global:teams) {
        $groupsToIgnore += $t.Name.ToLower()
    }
    Find-ReadersGroup $allGroups
    if ($null -eq $Global:readersGroup) {
        Write-Host "WARNING: No Readers group found!" -ForegroundColor Yellow
        return $false
    }

    Set-TeamDescriptorsFromGroupInfos $allGroups

    foreach ($g in $allGroups) {
        $groupName = $g.Name.ToLower()
        if ($groupsToIgnore.Contains($groupName)) {
            continue
        }
        if (($groupName -ne "project administrators") -or (($groupName -eq "project administrators") -and $RemoveProjectAdmins)) {
            $members = Get-GroupMembers $g.Id
            Move-MembersFromGroupToGroup $members $g $readersGroup
        }
    }
    return $true
}

function Restore-ProjectLevelGroupPermissions($projectId, $group, $allow = 0, $deny = 0) {
    Write-Host "         $($group.Name)"

    $token = "`$PROJECT:vstfs:///Classification/TeamProject/$projectId"
    Set-AzDOAce $projectSecNamespaceId $token $false "$($group.IdentityType);$($group.Descriptor)" $allow $deny
}

function Restore-TaggingPermissions($projectId, $group, $allow = 0, $deny = 0) {
    $token = "/$projectId"
    Set-AzDOAce $taggingSecNamespaceId $token $false "$($group.IdentityType);$($group.Descriptor)" $allow $deny
}

function Restore-GroupPermissions($projectId) {
    Write-Host "      Project-level groups"

    foreach ($t in $Global:teams) {
        Restore-ProjectLevelGroupPermissions $projectInfo.Id $t $projectLevelTeamsAllow
        Restore-TaggingPermissions $projectInfo.Id $t $taggingAllow
    }
    Restore-ProjectLevelGroupPermissions $projectInfo.Id $Global:readersGroup $projectLevelReaderAllow
    Restore-TaggingPermissions $projectInfo.Id $Global:readersGroup $taggingAllow
}

function Restore-RootAreaPermissions($projectId, $areaId) {
    Write-Host "         Root area"

    $token = "vstfs:///Classification/Node/$areaId"
    $acl = Get-AzDOAcl $cssSecNamespaceId $token
    if ($null -eq $acl) {
        Write-Host "         WARNING: No ACL found for root area!" -ForegroundColor Yellow
        return
    }

    $aces = Remove-NonServerAndTeamIdentities $acl.acesDictionary
    Set-AzDOAcl $cssSecNamespaceId $token $true $aces
    Set-AzDOAce $cssSecNamespaceId $token $false "$($Global:readersGroup.IdentityType);$($Global:readersGroup.Descriptor)" $rootAreaAllow
}

function Restore-InheritedAreaPermissions($projectId, $area, $parentAreaName, $parentAreaToken) {
    $areaName = "$parentAreaName\\$($area.name)"
    $areaToken = "$parentAreaToken`:vstfs:///Classification/Node/$($area.identifier)"
    
    Write-Host "         $areaName"
    Set-AzDOAcl $cssSecNamespaceId $areaToken $true @{}

    if ($area.hasChildren) {
        foreach ($childArea in $area.children) {
            Restore-InheritedAreaPermissions $projectId $childArea $areaName $areaToken
        }
    }
}

function Restore-AreaPermissions($projectId) {
    Write-Host "      Areas"

    $rootArea = Get-Areas $projectId

    Restore-RootAreaPermissions $projectId $rootArea.identifier
    if ($rootArea.hasChildren) {
        foreach ($childArea in $rootArea.children) {
            Restore-InheritedAreaPermissions $projectId $childArea $rootArea.name "vstfs:///Classification/Node/$($rootArea.identifier)"
        }
    }
}

function Restore-AllGitReposPermissions($projectId) {
    Write-Host "         All repos"

    $token = "repoV2/$projectId"
    $acl = Get-AzDOAcl $gitSecNamespaceId $token
    if ($null -eq $acl) {
        Write-Host "         WARNING: No ACL found for all Git repos!" -ForegroundColor Yellow
        return
    }

    $aces = Remove-NonServerAndTeamIdentities $acl.acesDictionary
    Set-AzDOAcl $gitSecNamespaceId $token $true $aces
    Set-AzDOAce $gitSecNamespaceId $token $false "$($Global:readersGroup.IdentityType);$($Global:readersGroup.Descriptor)" $gitAllow
}

function Restore-GitRepoPermissions($projectId, $repo) {
    Write-Host "         $($repo.Name)"

    $token = "repoV2/$projectId/$($repo.Id)"
    $acls = Get-AzDOAcls $gitSecNamespaceId $token
    foreach ($acl in $acls) {
        Set-AzDOAcl $gitSecNamespaceId $acl.token $true @{}
    }
}

function Restore-GitPermissions($projectId) {
    Write-Host "      Git repositories"

    Restore-AllGitReposPermissions $projectId

    $gitRepos = Get-GitRepositories $projectId
    foreach ($repo in $gitRepos) {
        Restore-GitRepoPermissions $projectId $repo
    }
}

function Restore-DefaultPermissions($projectInfo, $teams) {
    Write-Host "   Fixing permissions for project '$($projectInfo.Name)'..."

    Restore-GroupPermissions $projectInfo.Id
    Restore-AreaPermissions $projectInfo.Id
    Restore-GitPermissions $projectInfo.Id
}

################################################################################
# Main script starts here
################################################################################

Assert-Preconditions

# Write your business logic here
$selectedProjects = Get-Projects

if ($selectedProjects.Count -eq 0) {
    Write-Host "No matching projects found."
    exit 0
}

Write-Host "You are about to remove write permissions for $($selectedProjects.Count) projects." -ForegroundColor Yellow
if ($RemoveProjectAdmins -and !(Get-SpecialConsent "ATTENTION: You are removing all project administrator permissions! Only collection/organization administrators or server administrators (on-prem) will have access to the projects! Continue?")) {
    Write-Host "Aborted."
    exit 0
}

foreach ($p in $selectedProjects) {
    if (Get-Consent "Are you sure you want to remove write permissions from project '$($p.Name)'?") {
        Write-Host "   Removing write permissions for project '$($p.Name)'..."
        if (Move-AllMembersToReaders $p) {
            if ($FixPermissions) {
                Restore-DefaultPermissions $p
            }
        }
    }
}
