<!-- markdownlint-disable first-line-h1 no-inline-html -->

<img src="assets/images/icon-color.svg" alt="PowerShell Module for VMware Cloud Foundation Certificate Management" width="150">

# PowerShell Module for VMware Cloud Foundation Certificate Management

`VMware.CloudFoundation.CertificateManagement` is a PowerShell module that has been written to support the ability to manage ESXi host certificates across your [VMware Cloud Foundatiоn][docs-vmware-cloud-foundation] instance.

[:material-powershell: &nbsp; PowerShell Gallery][psgallery-module-certificate-management]{ .md-button .md-button--primary }

## Requirements

### Platforms

The following table lists the supported platforms for this module.

Platform                                                     | Support
-------------------------------------------------------------|------------------------------------
:fontawesome-solid-cloud: &nbsp; VMware Cloud Foundation 5.0 | :fontawesome-solid-x:{ .red }
:fontawesome-solid-cloud: &nbsp; VMware Cloud Foundation 4.5 | :fontawesome-solid-check:{ .green }
:fontawesome-solid-cloud: &nbsp; VMware Cloud Foundation 4.4 | :fontawesome-solid-x:{ .red }
:fontawesome-solid-cloud: &nbsp; VMware Cloud Foundation 4.3 | :fontawesome-solid-x:{ .red }

### Operating Systems

The following table lists the supported operating systems for this module.

Operating System                                                       | Version
-----------------------------------------------------------------------|-----------
:fontawesome-brands-windows: &nbsp; Microsoft Windows Server           | 2019, 2022
:fontawesome-brands-windows: &nbsp; Microsoft Windows                  | 10, 11

### PowerShell

The following table lists the supported editions and versions of PowerShell for this module.

Edition                                                                           | Version
----------------------------------------------------------------------------------|----------
:material-powershell: &nbsp; [Microsoft Windows PowerShell][microsoft-powershell] | 5.1

### Module Dependencies

The following table lists the required PowerShell module dependencies for this module.

PowerShell Module                                    | Version   | Publisher    | Reference
-----------------------------------------------------|-----------|--------------|---------------------------------------------------------------------------
[VMware.PowerCLI][psgallery-module-powercli]         | >= 13.0.0 | VMware, Inc. | :fontawesome-solid-book: &nbsp; [Documentation][developer-module-powercli]
[PowerVCF][psgallery-module-powervcf]                | >= 2.3.0  | VMware, Inc. | :fontawesome-brands-github: &nbsp; [GitHub][github-module-powervcf]
[PowerValidatedSolutions][psgallery-module-pvs]      | >= 2.2.0  | VMware, Inc. | :fontawesome-brands-github: &nbsp; [GitHub][github-module-pvs]

[docs-vmware-cloud-foundation]: https://docs.vmware.com/en/VMware-Cloud-Foundation/index.html
[microsoft-powershell]: https://docs.microsoft.com/en-us/powershell
[psgallery-module-powercli]: https://www.powershellgallery.com/packages/VMware.PowerCLI
[psgallery-module-powervcf]: https://www.powershellgallery.com/packages/PowerVCF
[psgallery-module-certificate-management]: https://www.powershellgallery.com/packages/VMware.CloudFoundation.CertificateManagement
[psgallery-module-pvs]: https://www.powershellgallery.com/packages/PowerValidatedSolutions
[developer-module-powercli]: https://developer.vmware.com/tool/vmware-powercli
[github-module-powervcf]: https://github.com/vmware/powershell-module-for-vmware-cloud-foundation
[github-module-pvs]: https://github.com/vmware-samples/power-validated-solutions-for-cloud-foundation
