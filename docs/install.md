# Installing the Module

Verify that your system has a [supported edition and version](/powershell-module-for-vmware-cloud-foundation-certificate-management/#powershell) of PowerShell installed.

Install the PowerShell [module dependencies](/powershell-module-for-vmware-cloud-foundation-certificate-management/#module-dependencies) from the PowerShell Gallery by running the following commands:

```powershell
--8<-- "./docs/snippets/install-module.ps1"
```

If using PowerShell Core, import the modules before proceeding:

For example:

```powershell
--8<-- "./docs/snippets/import-module.ps1"
```

Once installed, any cmdlets associated with `VMware.CloudFoundation.CertificateManagement` and the its dependencies will be available for use.

To view the cmdlets for available in the module, run the following command in the PowerShell console.

```powershell
Get-Command -Module VMware.CloudFoundation.CertificateManagement
```

To view the help for any cmdlet, run the `Get-Help` command in the PowerShell console.

For example:

```powershell
Get-Help -Name <cmdlet-name>
```

```powershell
Get-Help -Name <cmdlet-name> -Examples
```
