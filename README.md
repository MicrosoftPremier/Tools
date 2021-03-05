# Welcome to the Microsoft Premier Services Tools Repository
We will use this repository to share small tools or samples with the public. Most of those tools and samples originate from demands we have seen during our work with Microsoft Premier customers. Some of them are very specific to a particular customer, while others quickly turn out to be valuable to many customers around the world. It's those latter tools and samples that we want to share here.

## Available Tools/Samples
Here's a list of all the tools and sample you'll find in this repository grouped by area:

### General
- **[AzureDevOpsPowerShellTemplate](./AzureDevOpsPowerShellTemplate)**  
  This sample can be used as a template for PowerShell scripts that target Azure DevOps Services or Server. It provides a couple standard parameters that those scripts usually share and some easy to use methods for making REST calls to Azure DevOps that automatically take care of authentication.

- **[AzureDevOpsNotificationBanners](./AzureDevOpsNotificationBanners)**  
  This PowerShell module can be used to display notification banners on Team Foundation Server/Azure DevOps Server (>= 2018) and Azure DevOps Services. You might also consider using the [Banner Settings](https://marketplace.visualstudio.com/items?itemName=ms-eswm.banner-settings-hub) extension instead of this PowerShell module.

- **[Remove-WritePermissions](./Remove-WritePermissions)**  
  This PowerShell Core script can be used to remove (most) write permissions from a project. Use it if you want to archive a project and make sure that nobody is able to change its content. The script works by moving all project-level identities/groups to the readers group and - if specified - fixing permissions of readers groups and teams for the project, all areas, and all Git repositories. It currently doesn't fix permissions for other elements like iterations, pipelines, wiki, query folders, or test plans. **Note:** The script has been designed for Team Foundation Server 2018. It should work on 2018.3 and later server versions as well as Azure DevOps Services, but it has only been tested with Team Foundation Server 2018.3.

### Process Customization
- **[Get-ProcessChanges](./Get-ProcessChanges)**  
  This script can be used to compare inherited processes to their base processes.