<!-- markdownlint-disable first-line-h1 no-inline-html -->

<img src=".github/icon-400px.svg" alt="A PowerShell Module for Cloud Foundation Certificate Management" width="150"></br></br>

# PowerShell Module for VMware Cloud Foundation Certificate Management

[<img src="https://img.shields.io/badge/Changelog-Read-blue?style=for-the-badge&logo=github&logoColor=white" alt="CHANGELOG" >][changelog]&nbsp;&nbsp;

## Overview

`VMware.CloudFoundation.CertificateManagement` is a PowerShell module that has been written to support the ability to managed certificates across your VMware Cloud Foundatiоn instance.

## Requirements

### Platforms

- [VMware Cloud Foundation][vmware-cloud-foundation] 4.4 or later

### Operating Systems

- Microsoft Windows Server 2019 and 2022
- Microsoft Windows 10 and 11
- [VMware Photon OS][vmware-photon] 3.0 and 4.0

### PowerShell Editions and Versions

- [Microsoft Windows PowerShell 5.1][microsoft-powershell]
- [PowerShell Core 7.2.0 or later][microsoft-powershell]

### PowerShell Modules

- [`VMware.PowerCLI`][module-vmware-powercli] 12.7.0 or later
- [`VMware.vSphere.SsoAdmin`][module-vmware-vsphere-ssoadmin] 1.3.8 or later
- [`PowerVCF`][module-powervcf] 2.2.0 or later
- [`PowerValidatedSolutions`][module-powervalidatedsolutions] 2.1.0 or later

## Installing the Module

Verify that your system has a supported edition and version of PowerShell installed.

Install the supporting PowerShell modules from the PowerShell Gallery by running the following commands:

```powershell
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name VMware.PowerCLI -MinimumVersion 12.7.0
Install-Module -Name VMware.vSphere.SsoAdmin -MinimumVersion 1.3.8
Install-Module -Name PowerVCF -MinimumVersion 2.2.0
Install-Module -Name PowerValidatedSolutions -MinimumVersion 2.1.0
Install-Module -Name VMware.CloudFoundation.CertificateManagement
```

If using PowerShell Core, import the modules before proceeding:

For example:

```powershell
Import-Module -Name VMware.PowerCLI
Import-Module -Name VMware.vSphere.SsoAdmin
Import-Module -Name PowerVCF
Import-Module -Name PowerValidatedSolutions
Import-Module -Name VMware.CloudFoundation.CertificateManagement
```

Once installed, any cmdlets associated with `VMware.CloudFoundation.CertificateManagement` and the supporting PowerShell modules will be available for use.

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

## Updating the Module

Update the PowerShell module from the PowerShell Gallery by running the following commands:

```powershell
Update-Module -Name VMware.CloudFoundation.CertificateManagement
```

To verify that the PowerShell module is updated, run the following command in the PowerShell console.

```powershell
Get-InstalledModule -Name VMware.CloudFoundation.CertificateManagement
```

## User Access

Each cmdlet may provide one or more usage examples. Many of the cmdlets require that credentials are provided to output to the PowerShell console or a report.

The cmdlets in this module, and its dependencies, return data from multple platform components. The credentials for most of the platform components are returned to the cmdlets by retrieving credentials from the SDDC Manager inventory and using these credentials, as needed, within cmdlet operations.

For the best expereince, for cmdlets that connect to SDDC Manager, use the VMware Cloud Foundation API user `admin@local` or an account with the **ADMIN** role in SDDC Manager (e.g., `administrator@vsphere.local`).

## Contributing

The project team welcomes contributions from the community. Please read our [Developer Certificate of Origin][vmware-cla-dco]. All contributions to this repository must be signed as described on that page. Your signature certifies that you wrote the patch or have the right to pass it on as an open-source patch.

For more detailed information, refer to the [contribution guidelines][contributing] to get started.

## Support

This PowerShell module is not supported by VMware Support.

We welcome you to use the GitHub [issues][issues] tracker to report bugs or suggest features and enhancements.

When filing an issue, please check existing open, or recently closed, issues to make sure someone else hasn't already
reported the issue.

Please try to include as much information as you can. Details like these are incredibly useful:

- A reproducible test case or series of steps.
- Any modifications you've made relevant to the bug.
- Anything unusual about your environment or deployment.

## License

Copyright 2023 VMware, Inc.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

[//]: Links

[changelog]: CHANGELOG.md
[contributing]: CONTRIBUTING_DCO.md
[issues]: https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/issues
[microsoft-powershell]: https://docs.microsoft.com/en-us/powershell
[module-vmware-powercli]: https://www.powershellgallery.com/packages/VMware.PowerCLI
[module-vmware-vsphere-ssoadmin]: https://www.powershellgallery.com/packages/VMware.vSphere.SsoAdmin
[module-powervcf]: https://www.powershellgallery.com/packages/PowerVCF/2.2.0
[module-reporting]: https://www.powershellgallery.com/packages/VMware.CloudFoundation.CertificateManagement
[module-powervalidatedsolutions]: https://www.powershellgallery.com/packages/PowerValidatedSolutions
[vmware-photon]: https://vmware.github.io/photon/
[vmware-cla-dco]: https://cla.vmware.com/dco
[vmware-cloud-foundation]: https://docs.vmware.com/en/VMware-Cloud-Foundation
