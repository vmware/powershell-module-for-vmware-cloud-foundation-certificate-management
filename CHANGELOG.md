# Release History

## v1.2.0 (Unreleased)

Enhancement:

- Updated module to use `Test-VCFConnection` instead of `Test-Connection` where applicable. [GH-45](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/45)
- Updated module to use `Test-EsxiConnection` instead of `Test-NetConnection` where applicable. [GH-45](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/45)

Chore:

- Added the `RequiredModules` key to the module manifest to specify the minimum dependencies required to install and run the PowerShell module. [GH-48](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/48)
- Updated `PowerValidatedSolutions` module dependency from v2.3.0 to v2.5.0. [GH-48](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/48)

## [v1.1.0](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/releases/tag/v1.1.0)

> Release Date: 2023-06-27

Enhancement:

- Added support for an ESXi certificate management pre-check with `Test-EsxiCertMgmtChecks` cmdlet. [GH-37](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/37)
- Added support for PowerShell Core. [GH-37](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/37)
- Added support for VMware PhotonOS. [GH-37](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/37)
- Enhanced `Get-vSANHealthSummary` cmdlet improving log messages and adding a check for vSAN services. [GH-37](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/37)

Bugfix:

- Added a disconnect from vCenter Server prior to an ESXi host reboot. [GH-36](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/36)

## [v1.0.0](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/releases/tag/v1.0.0)

> Release Date: 2023-05-30

Initial availability of the PowerShell module for VMware Cloud Foundation Certificate Management.
