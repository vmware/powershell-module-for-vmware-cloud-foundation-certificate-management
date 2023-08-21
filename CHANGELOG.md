# Release History

## [v1.3.0](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/releases/tag/v1.3.0)

> Release Date: (Not Released)

Enhancements:

- Added the `Set-SddcCertificateAuthority` cmdlet to set the certificate authority in SDDC Manager to use a Microsoft Certificate Authority. [GH-52](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/52)
- Added the `Request-SddcCsr` cmdlet to request SDDC Manager to generate and store certificate signing request files. [GH-52](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/52)
- Added the `Request-SddcCertificate` cmdlet to request SDDC Manager to connect to certificate authority to sign the certificate signing request files and to store the signed certificates. [GH-52](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/52)
- Added the `Install-SddcCertificates` cmdlet to install the signed certificates for all components associated with the given workload domain. [GH-52](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/52)

## [v1.2.0](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/releases/tag/v1.2.0)

> Release Date: 2023-07-25

Enhancement:

- Updated module to use `Test-VCFConnection` instead of `Test-Connection` where applicable. [GH-45](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/45)
- Updated module to use `Test-EsxiConnection` instead of `Test-NetConnection` where applicable. [GH-45](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/45)

Chore:

- Added the `RequiredModules` key to the module manifest to specify the minimum dependencies required to install and run the PowerShell module. [GH-48](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/48)
- Updated `PowerValidatedSolutions` from v2.2.0 to v2.5.0. [GH-49](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/49)

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
