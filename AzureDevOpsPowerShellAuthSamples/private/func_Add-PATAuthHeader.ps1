function Add-PATAuthHeader {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "The header object to which to add authentication.")]
        $Headers,

        [Parameter(Mandatory = $true, HelpMessage = "Personal Access Token (PAT) used to authenticate to Azure DevOps.")]
        [securestring] $PAT
    )

    $Headers.Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("pat:$($PAT | ConvertFrom-SecureString -AsPlainText)"))
    return $Headers
}