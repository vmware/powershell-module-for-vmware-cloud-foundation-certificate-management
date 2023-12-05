# Release History

## v1.5.0

> Release Date: Unreleased

Enhancement:

- Added support for use of secure strings for sensitive parameters. [GH-95](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/95)

## v1.4.1

> Release Date: 2023-11-27

Bug Fix:

- Updated `Test-EsxiCertMgmtChecks` to pass the `server` parameter value for the Certificate Authority and vSAN status checks. [GH-90](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/90)

## v1.4.0

> Release Date: 2023-10-05

Enhancement:

- **Breaking Change**: Renamed `Set-SddcCertificateAuthority` to `Set-VCFCertificateAuthority`. [GH-74](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/74)
- **Breaking Change**: Renamed `Request-SddcCertificate` to `Request-VCFSignedCertificate`. [GH-74](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/74)
- **Breaking Change**: Refactored `Set-SddcCertificateAuthority` to support OpenSSL Certificate Authority configuration. [GH-68](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/68)
- **Breaking Change**: Refactored `Get-EsxiCertificateThumbprint` and `Get-vCenterCertificateThumbprint` to a single function `Get-VCFCertificateThumbprint`. [GH-68](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/68)
- Added `Request-VcfCsr`as a wrapper for `Request-EsxiCsr` and `Request-SddcCsr`. [GH-68](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/68)
- Added `Install-VcfCertificate` as a wrapper for `Install-EsxiCertificate` and `Install-SddcCertificate`. [GH-68](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/68)

Bugfix:

- Updated `Get-vSANHealthSummary` to report correct status [GH-78](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/78)

Documentation:

- Added reference guide for VMware Cloud Foundation Certificate Operations. [GH-68](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/68)

Chore:

- Updated `PowerVCF` from v2.3.0 to v2.4.0. [GH-81](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/81)
- Updated cmdlet content for Aria Suite, formerly known as vRealize Suite, products to use the new Aria names where applicable. [GH-66](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/66)
- Updated cmdlet content in the `/docs/documentation`. [GH-68](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/68)

## v1.3.0

> Release Date: 2023-08-29

Enhancement:

- Added the `Set-SddcCertificateAuthority` cmdlet to set the certificate authority in SDDC Manager to use a Microsoft Certificate Authority. [GH-52](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/52)
- Added the `Request-SddcCsr` cmdlet to request SDDC Manager to generate and store certificate signing request files. [GH-52](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/52)
- Added the `Request-SddcCertificate` cmdlet to request SDDC Manager to connect to certificate authority to sign the certificate signing request files and to store the signed certificates. [GH-52](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/52)
- Added the `Install-SddcCertificates` cmdlet to install the signed certificates for all components associated with the given workload domain. [GH-52](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/52)

Chore:

- Updated `VMware.PowerCLI` from v13.0.0 to v13.1.0 [GH-58](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/58)
- Updated `PowerValidatedSolutions` from v2.5.0 to v2.6.0. [GH-58](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/58)

## v1.2.0

> Release Date: 2023-07-25

Enhancement:

- Updated module to use `Test-VCFConnection` instead of `Test-Connection` where applicable. [GH-45](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/45)
- Updated module to use `Test-EsxiConnection` instead of `Test-NetConnection` where applicable. [GH-45](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/45)

Chore:

- Added the `RequiredModules` key to the module manifest to specify the minimum dependencies required to install and run the PowerShell module. [GH-48](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/48)
- Updated `PowerValidatedSolutions` from v2.2.0 to v2.5.0. [GH-49](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/49)

## v1.1.0

> Release Date: 2023-06-27

Enhancement:

- Added support for an ESXi certificate management pre-check with `Test-EsxiCertMgmtChecks` cmdlet. [GH-37](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/37)
- Added support for PowerShell Core. [GH-37](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/37)
- Added support for VMware PhotonOS. [GH-37](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/37)
- Enhanced `Get-vSANHealthSummary` cmdlet improving log messages and adding a check for vSAN services. [GH-37](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/37)

Bugfix:

- Added a disconnect from vCenter Server prior to an ESXi host reboot. [GH-36](https://github.com/vmware/powershell-module-for-vmware-cloud-foundation-certificate-management/pull/36)

## v1.0.0

> Release Date: 2023-05-30

Initial availability of the PowerShell module for VMware Cloud Foundation Certificate Management.
