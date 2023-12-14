function Get-AzDOWorkItem {
    [CmdletBinding(DefaultParameterSetName = "PAT")]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "The name of the organization on which to operate.")]
        [string] $Organization,

        [Parameter(Mandatory = $true, HelpMessage = "The name of the project on which to operate.")]
        [string] $Project,

        [Parameter(Mandatory = $true, HelpMessage = "The name of the repository.")]
        [int] $WorkItemId,

        # Authentication options
        [Parameter(ParameterSetName = "PAT", Mandatory = $true, HelpMessage = "Use Personal Access Token (PAT) authentication.")]
        [switch] $UsePAT,
        [Parameter(ParameterSetName = "PAT", Mandatory = $true, HelpMessage = "Personal Access Token (PAT) used to authenticate to Azure DevOps.")]
        [securestring] $PAT,

        [Parameter(ParameterSetName = "ServicePrincipal", Mandatory = $true, HelpMessage = "Use Service Principal (SP) authentication.")]
        [switch] $UseSP,
        [Parameter(ParameterSetName = "ServicePrincipal", Mandatory = $true, HelpMessage = "Tenant ID of Service Principal.")]
        [Parameter(ParameterSetName = "OIDC", Mandatory = $true, HelpMessage = "Tenant ID for Identity Workload Federation (OIDC).")]
        [string] $TenantId,
        [Parameter(ParameterSetName = "ServicePrincipal", Mandatory = $true, HelpMessage = "Client ID of Service Principal.")]
        [Parameter(ParameterSetName = "ManagedIdentity", Mandatory = $false, HelpMessage = "Client ID of user-assigned Managed Identity.")]
        [Parameter(ParameterSetName = "OIDC", Mandatory = $true, HelpMessage = "Client ID for Identity Workload Federation (OIDC).")]
        [string] $ClientId,
        [Parameter(ParameterSetName = "ServicePrincipal", Mandatory = $true, HelpMessage = "Client Secret of Service Principal.")]
        [securestring] $ClientSecret,

        [Parameter(ParameterSetName = "ManagedIdentity", Mandatory = $true, HelpMessage = "Use Managed Identity (MI) authentication.")]
        [switch] $UseMI,
        [Parameter(ParameterSetName = "ManagedIdentity", Mandatory = $false, HelpMessage = "Runtime environment (vm or app) for Managed Identity (MI) authentication.")]
        [ValidateSet("vm", "app")]
        [string] $RuntimeEnvironment = "vm",

        [Parameter(ParameterSetName = "OIDC", Mandatory = $true, HelpMessage = "Use Identity Workload Federation (OIDC) authentication (only works within Azure Pipelines!).")]
        [switch] $UseOidc,
        [Parameter(ParameterSetName = "OIDC", Mandatory = $true, HelpMessage = "Service Connection ID for Workload Identity Federation (OIDC).")]
        [string] $ServiceConnectionId
    )

    # Prepare requests
    $ApiVersion = "7.0"
    $Headers = @{
        "Content-Type" = "application/json"
    }
    $BaseUri = "https://dev.azure.com/$Organization"

    # Add authentication header
    if ($UsePAT) {
        $Headers = Add-PATAuthHeader -Headers $Headers -PAT $PAT
        $AuthParams = @{ UsePAT = $true; PAT = $PAT }
    }
    if ($UseSP) {
        $Headers = Add-SPAuthHeader -Headers $Headers -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
        $AuthParams = @{ UseSP = $true; TenantId = $TenantId; ClientId = $ClientId; ClientSecret = $ClientSecret }
    }
    if ($UseMI) {
        $Headers = Add-MIAuthHeader -Headers $Headers -ClientId $ClientId -RuntimeEnvironment $RuntimeEnvironment
        if ($ClientId) {
            $AuthParams = @{ UseMI = $true; ClientId = $ClientId; RuntimeEnvironment = $RuntimeEnvironment }
        } else {
            $AuthParams = @{ UseMI = $true; RuntimeEnvironment = $RuntimeEnvironment }
        }
    }
    if ($UseOidc) {
        $Headers = Add-OidcAuthHeader -Headers $Headers -TenantId $TenantId -ClientId $ClientId -ServiceConnectionId $ServiceConnectionId
        $AuthParams = @{ UseOidc = $true; TenantId = $TenantId; ClientId = $ClientId; ServiceConnectionId = $ServiceConnectionId }
    }

    # Get work item
    $ApiResult = Invoke-RestMethod -Uri "$BaseUri/$Project/_apis/wit/workitems/$($WorkItemId)?api-version=$ApiVersion" -Method Get -Headers $Headers -SkipHttpErrorCheck -StatusCodeVariable ApiStatusCode
    if ($ApiStatusCode -ne 200) {
        if ($ApiResult.message) {
            Write-Host $ApiResult.message -ForegroundColor Red
        } else {
            Write-Host "Unable to read work item information!" -ForegroundColor Red
        }
        exit 1
    }

    return $ApiResult
}