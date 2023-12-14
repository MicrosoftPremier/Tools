@{
    RootModule = 'AzureDevOpsPowerShellAuthSamples.psm1'
    ModuleVersion = '1.0.0'
    CompatiblePSEditions = @('Core')
    GUID = '32d32dcb-8eb2-4583-b252-2d33b37360e0'
    Author = 'René Schumacher'
    CompanyName = 'Microsoft Deutschland GmbH'
    Description = 'Azure DevOps Authentication Sample Module'
    # Important: Make sure that functions needed by other functions in the module are exported after the functions that need them!
    FunctionsToExport = @(
        'Set-AzDOWorkItemFields',
        'Get-AzDOWorkItem'
    )
    CmdletsToExport = @()
    VariablesToExport = ''
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{}
    }
}

