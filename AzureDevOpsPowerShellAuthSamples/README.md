# Azure DevOps PowerShell Authentication Samples
This sample PowerShell module shows how to authenticate against Azure DevOps Services from PowerShell scripts. The sample supports personal access token (PAT), service principal (SP), managed identity (MI), and workload identity federation (OIDC) authentication. You can combine it with the [AzureDevOpsPowerShellTemplate](../AzureDevOpsPowerShellTemplate) to make API calls to Azure DevOps Services.

## Building the Module
To build the module, make sure you have the latest version of NuGet (see [NuGet.org](https://www.nuget.org/downloads)) and PowerShell Core (see [PowerShell on GitHub](https://github.com/PowerShell/PowerShell)) installed. Then follow these steps:

1. Open a PowerShell Core console and navigate to the AzureDevOpsPowerShellAuthSamples folder of the repository.
2. Run the command `nuget pack .\AzureDevOpsPowerShellAuthSamples.nuspec`.
3. Push the resulting package to a NuGet feed of your choice.
4. Install the module from the NuGet feed. If you are using Azure Artifacts as your NuGet feed, follow the steps described at [Use an Azure Artifacts feed as a private PowerShell repository](https://learn.microsoft.com/en-us/azure/devops/artifacts/tutorials/private-powershell-library?view=azure-devops&tabs=windows).

## Using the Module
Once the module has been built, pushed to your NuGet feed, and the feed has been registered as a PowerShell repository, you can install the module using the command `Install-Module -Name AzureDevOpsPowerShellAuthSamples -Repository <your repository name>`. After that, you can use the module in your scripts by importing it using the command `Import-Module -Name AzureDevOpsPowerShellAuthSamples`.

Due to the different authentication options, the module can be used in a variety of scenarios:

### Manual Use from the PowerShell Console
Whenever you want to automate things for yourself (e.g., creating a new repository with pre-defined settings), you can use the module from the PowerShell console and use personal access token (PAT) authentication. You would run your command with the parameter `-UsePAT`. The module will then prompt you for your PAT and use it to authenticate against Azure DevOps Services.

**Example**
```PowerShell
Import-Module -Name AzureDevOpsPowerShellAuthSamples
Update-AzDOWorkItemFields -Organization <your organization> -Project <your project> -WorkItemId <your work item id> -Fields "System.Title=SomeTitle","System.Description=Changed from PowerShell" -UsePAT
```

**NOTE:** You should **not** provide the PAT through the `-PAT` parameter. If you do, it will be stored in your command history and can be read by other users of the machine.

### Automation with a Technical Account
When you need to automate things regularly (e.g., scheduled or triggered by an event), you usually don't want to run the automation in the context of a user account. Instead, you want to use a technical account that is not tied to a specific person. For this scenario, you can use service principal (SP) authentication. You would run your command with the parameters `-UseSP`, `-TenantId`, and `-ClientId`. The module will then prompt you for the client secret and use service principal authentication against Azure DevOps Services. To properly set up the service principal in Azure DevOps Services, follow the steps described at [Use service principals & managed identities](https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/service-principal-managed-identity?view=azure-devops).

**Example**
```PowerShell
Import-Module -Name AzureDevOpsPowerShellAuthSamples
Update-AzDOWorkItemFields -Organization <your organization> -Project <your project> -WorkItemId <your work item id> -Fields "System.Title=SomeTitle","System.Description=Changed from PowerShell" -UseSP -TenantId <your tenant id> -ClientId <your client id>
```

**NOTE:** You should **not** provide the client secret through the `-ClientSecret` parameter. If you do, it will be stored in your command history and can be read by other users of the machine.

### Getting Rid of Secrets
In the previous two scenarios, you had to provide a secret (PAT or client secret) to the module. This is not ideal, as the secrets may leak and become a security risk. In addition, PAT and client secrets only have a limited lifespan and must be rotated from time to time, which - if forgotten - might suddenly break your automation. To get rid of the secret, you can use managed identity (MI) authentication. You would run your command with the parameter `-UseMI`. The module will then use managed identity authentication against Azure DevOps Services. To properly set up the managed identity in Azure DevOps Services, follow the steps described at [Use service principals & managed identities](https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/service-principal-managed-identity?view=azure-devops).

**NOTE:** Managed identity authentication only works if your script runs in an environment that supports managed identities (e.g., on an Azure VM or App Service with an attached managed identity).

**Example**
```PowerShell
Import-Module -Name AzureDevOpsPowerShellAuthSamples

# This will use the system-assigned managed identity on a VM
Update-AzDOWorkItemFields -Organization <your organization> -Project <your project> -WorkItemId <your work item id> -Fields "System.Title=SomeTitle","System.Description=Changed from PowerShell" -UseMI

# This will use the system-assigned managed identity in an App Service
Update-AzDOWorkItemFields -Organization <your organization> -Project <your project> -WorkItemId <your work item id> -Fields "System.Title=SomeTitle","System.Description=Changed from PowerShell" -UseMI -RunTimeEnvironment app

# This will use the user-assigned managed identity on a VM
Update-AzDOWorkItemFields -Organization <your organization> -Project <your project> -WorkItemId <your work item id> -Fields "System.Title=SomeTitle","System.Description=Changed from PowerShell" -UseMI -ClientId <your client id>

# This will use the user-assigned managed identity in an App Service
Update-AzDOWorkItemFields -Organization <your organization> -Project <your project> -WorkItemId <your work item id> -Fields "System.Title=SomeTitle","System.Description=Changed from PowerShell" -UseMI -ClientId <your client id> -RunTimeEnvironment app
```

### Workload Identity Federation (OIDC)
In case you are using Azure Pipelines to run your automation, you can also use workload identity federation (OIDC) authentication. You would run your command with the parameters `-UseOIDC`, `-TenantId`, `-ClientId`, and `-ServiceConnectionId`. The module will then use workload identity federation (OIDC) authentication against Azure DevOps Services. To properly set up the workload identity federation in Azure DevOps Services, follow the steps described at [Create an Azure Resource Manager service connection using workload identity federation](https://learn.microsoft.com/en-us/azure/devops/pipelines/library/connect-to-azure?view=azure-devops#create-an-azure-resource-manager-service-connection-using-workload-identity-federation) and [Use service principals & managed identities](https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/service-principal-managed-identity?view=azure-devops).

**NOTE:** The `-ServiceConnectionId` parameter requires the ID of an Azure Resource Manager service connection in your Azure DevOps Services project (**not** the name of the connection). You can find the ID by navigating to the service connection in the Azure DevOps Services UI and looking at the URL. The ID is the GUID at the end of the URL.

**Example**
```PowerShell
Import-Module -Name AzureDevOpsPowerShellAuthSamples
Update-AzDOWorkItemFields -Organization <your organization> -Project <your project> -WorkItemId <your work item id> -Fields "System.Title=SomeTitle","System.Description=Changed from PowerShell" -UseOIDC -TenantId <your tenant id> -ClientId <your client id> -ServiceConnectionId <your service connection id>
```

**IMPORTANT:** Since regular scripts in Azure Pipelines are not allowed to access service connections, you must *activate* the service connection before you run the PowerShell commands as shown above. To do so, add the following task to your pipeline before the PowerShell task:

```YAML
- task: AzureCLI@2
  displayName: Activate OIDC service connection
  inputs:
    azureSubscription: <your service connection> # This can be either the connection ID or the connection name
    scriptType: ps
    scriptLocation: inlineScript
    inlineScript: |
      Write-Host "Service connection activated"
```