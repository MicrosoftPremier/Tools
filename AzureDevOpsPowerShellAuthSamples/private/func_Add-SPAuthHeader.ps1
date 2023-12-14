function Add-SPAuthHeader {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "The header object to which to add authentication.")]
        $Headers,

        [Parameter(Mandatory = $true, HelpMessage = "Tenant ID of Service Principal.")]
        [string] $TenantId,

        [Parameter(Mandatory = $true, HelpMessage = "Client ID of Service Principal.")]
        [string] $ClientId,

        [Parameter(Mandatory = $true, HelpMessage = "Client Secret of Service Principal.")]
        [securestring] $ClientSecret
    )

    $AzDOScope = "499b84ac-1321-427f-aa17-267ca6975798/.default"
    $TokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $TokenHeaders = @{
        "Content-Type" = "application/x-www-form-urlencoded"
    }
    $FormData = @{
        "grant_type" = "client_credentials";
        "client_id" = $ClientId;
        "client_secret" = $ClientSecret | ConvertFrom-SecureString -AsPlainText;
        "scope" = $AzDOScope
    }
    $TokenResult = Invoke-RestMethod -Uri $TokenUri -Method POST -Form $FormData -Headers $TokenHeaders -SkipHttpErrorCheck -StatusCodeVariable TokenStatusCode

    if ($TokenStatusCode -ne 200) {
        Write-Host "Failed to get access token for Service Principal authentication. Status code: $TokenStatusCode" -ForegroundColor Red
        exit 100
    }
    $Headers.Authorization = "Bearer $($TokenResult.access_token)"
    return $Headers
}