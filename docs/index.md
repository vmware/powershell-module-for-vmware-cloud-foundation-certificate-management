<!-- markdownlint-disable first-line-h1 no-inline-html -->

<img src="assets/images/icon-color.svg" alt="PowerShell Module for VMware Cloud Foundation Certificate Management" width="150">

# PowerShell Module for VMware Cloud Foundation Certificate Management

<img src="https://img.shields.io/powershellgallery/dt/VMware.CloudFoundation.CertificateManagement?style=for-the-badge&logo=powershell&logoColor=white" alt="PowerShell Gallery Downloads">

VMware.CloudFoundation.CertificateManagement` is a PowerShell module designed to provide you the ability to manage
certificates within your VMware Cloud Foundation environment.

Using this module, you can perform various tasks on a VMware Cloud Foundation instance or a specific
workload domain.

- Configure the Certificate Authority for SDDC Manager.
- Generate certificate signing requests for a workload domain.
- Request signed-certificates for a workload domain.
- Install and replace CA-signed certificates for a workload domain.+
- Generate certificate signing requests for ESX hosts.
- Set the ESX Certificate Mode in vCenter.
- Install and replace CA-signed certificates for a ESX hosts.

[:material-powershell: &nbsp; PowerShell Gallery][psgallery-module-certificate-management]{ .md-button .md-button--primary }

## Requirements

### VMware Cloud Foundation

The following table lists the supported releases for this module.

| Platform                                                     | Support                             |
|--------------------------------------------------------------| ----------------------------------- |
| :fontawesome-solid-cloud: &nbsp; VMware Cloud Foundation 5.2 | :fontawesome-solid-check:{ .green } |
| :fontawesome-solid-cloud: &nbsp; VMware Cloud Foundation 5.1 | :fontawesome-solid-check:{ .green } |

???+ tip "Support for Newer Major Releases"

    This module will **only** be sustained for supported versions of the VMware Cloud Foundation releases listed above to address critical issues. You can find general details on supported versions in the [Broadcom Product Lifecycle](https://support.broadcom.com/group/ecx/productlifecycle).

    Please note that this module **will not** provide support or new enhancements for future major releases of VMware Cloud Foundation. If you're planning to upgrade to those newer releases, we encourage you to explore alternative in-product or custom automation solutions.

    We truly appreciate your reliance on and support of this module. Thank you for your understanding as we transition to sustaining the module for these specific major versions.

???+ note

    ESX certificate management for VMware Cloud Foundation on Dell EMC VxRail is not supported.

### PowerShell

The following table lists the supported editions and versions of PowerShell for this module.

| Edition                                                              | Version  |
| -------------------------------------------------------------------- | -------- |
| :material-powershell: &nbsp; [PowerShell Core][microsoft-powershell] | >= 7.2.0 |

### Module Dependencies

The following table lists the required PowerShell module dependencies for this module.

| PowerShell Module                               | Version   | Publisher | Reference                                                                  |
| ----------------------------------------------- | --------- | --------- | -------------------------------------------------------------------------- |
| [VMware.PowerCLI][psgallery-module-powercli]    | >= 13.3.0 | Broadcom  | :fontawesome-solid-book: &nbsp; [Documentation][developer-module-powercli] |
| [PowerVCF][psgallery-module-powervcf]           | >= 2.4.1  | Broadcom  | :fontawesome-solid-book: &nbsp; [Documentation][docs-module-powervcf]      |
| [PowerValidatedSolutions][psgallery-module-pvs] | >= 2.12.0 | Broadcom  | :fontawesome-solid-book: &nbsp; [Documentation][docs-module-pvs]           |

[docs-vmware-cloud-foundation]: https://docs.vmware.com/en/VMware-Cloud-Foundation/index.html
[microsoft-powershell]: https://docs.microsoft.com/en-us/powershell
[psgallery-module-powercli]: https://www.powershellgallery.com/packages/VMware.PowerCLI
[psgallery-module-powervcf]: https://www.powershellgallery.com/packages/PowerVCF
[psgallery-module-certificate-management]: https://www.powershellgallery.com/packages/VMware.CloudFoundation.CertificateManagement
[psgallery-module-pvs]: https://www.powershellgallery.com/packages/PowerValidatedSolutions
[developer-module-powercli]: https://developer.vmware.com/tool/vmware-powercli
[docs-module-powervcf]: https://vmware.github.io/powershell-module-for-vmware-cloud-foundation
[docs-module-pvs]: https://vmware.github.io/power-validated-solutions-for-cloud-foundation
[github-photon-os]: https://github.com/vmware/photon
