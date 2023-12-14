function Add-OidcAuthHeader {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "The header object to which to add authentication.")]
        $Headers,

        [Parameter(Mandatory = $true, HelpMessage = "Tenant ID for Workload Identity Federation (OIDC).")]
        [string] $TenantId,

        [Parameter(Mandatory = $true, HelpMessage = "Client ID for Workload Identity Federation (OIDC).")]
        [string] $ClientId,

        [Parameter(Mandatory = $true, HelpMessage = "Service Connection ID for Workload Identity Federation (OIDC).")]
        [string] $ServiceConnectionId
    )

    $IdTokenUri = "$($env:SYSTEM_COLLECTIONURI)$($env:SYSTEM_TEAMPROJECTID)/_apis/distributedtask/hubs/build/plans/$($env:SYSTEM_PLANID)/jobs/$($env:SYSTEM_JOBID)/oidctoken?serviceConnectionID=$ServiceConnectionId&api-version=7.1-preview.1"
    $IdTokenHeaders = @{
        Authorization = "Bearer $($env:SYSTEM_ACCESSTOKEN)";
        "Content-Type" = "application/json"
    }
    $IdTokenResult = Invoke-RestMethod -Uri $IdTokenUri -Method POST -Headers $IdTokenHeaders -SkipHttpErrorCheck -StatusCodeVariable TokenStatusCode

    if ($TokenStatusCode -ne 200) {
        Write-Host "Failed to get access OIDC token. Status code: $TokenStatusCode" -ForegroundColor Red
        exit 100
    }
    $TokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $AzDOScope = "499b84ac-1321-427f-aa17-267ca6975798/.default"
    $FormData = @{
        scope = $AzDOScope;
        client_id = $ClientId;
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
        client_assertion = $IdTokenResult.oidcToken;
        grant_type = "client_credentials"
    }
    $TokenResult = Invoke-RestMethod -Method POST -Uri $TokenUri -Form $FormData -Headers @{"Content-Type"="application/x-www-form-urlencoded"} -SkipHttpErrorCheck -StatusCodeVariable TokenStatusCode
    
    if ($TokenStatusCode -ne 200) {
        Write-Host "Failed to get access token. Status code: $TokenStatusCode" -ForegroundColor Red
        exit 101
    }
    $Headers.Authorization = "Bearer $($TokenResult.access_token)"
    return $Headers
}