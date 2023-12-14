function Add-MIAuthHeader {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "The header object to which to add authentication.")]
        $Headers,

        [Parameter(Mandatory = $false, HelpMessage = "Client ID of user-assigned Managed Identity.")]
        [string] $ClientId,

        [Parameter(Mandatory = $false, HelpMessage = "Runtime environment (vm or app) for Managed Identity (MI) authentication.")]
        [ValidateSet("vm", "app")]
        [string] $RuntimeEnvironment = "vm"
    )

    if ($RuntimeEnvironment -eq "vm") {
        $AzDOScope = "499b84ac-1321-427f-aa17-267ca6975798"
        $TokenUri = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$AzDOScope"
        $TokenHeaders = @{
            Metadata = $true
        }
    } else {
        $AzDOScope = "499b84ac-1321-427f-aa17-267ca6975798/.default"
        $TokenUri = "$($env:IDENTITY_ENDPOINT)?api-version=2019-08-01&resource=$AzDOScope"
        $TokenHeaders = @{
            "X-IDENTITY-HEADER" = $env:IDENTITY_HEADER
        }
    }
    if ($ClientId) {
        $TokenUri += "&client_id=$ClientId"
    }
    $TokenResult = Invoke-RestMethod -Uri $TokenUri -Method GET -Headers $TokenHeaders -SkipHttpErrorCheck -StatusCodeVariable TokenStatusCode

    if ($TokenStatusCode -ne 200) {
        Write-Host "Failed to get access token for Managed Identity authentication. Status code: $TokenStatusCode" -ForegroundColor Red
        exit 100
    }
    $Headers.Authorization = "Bearer $($TokenResult.access_token)"
    return $Headers
}