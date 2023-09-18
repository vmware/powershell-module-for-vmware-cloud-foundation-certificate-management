# VMware Cloud Foundation Certificate Management

This section provides information on how to use the PowerShell module for VMware Cloud Foundation Certificate Management to manage certificates for SDDC Manager and workload domain components [with the exception of ESXi hosts](esxi-certificate-management.md) in your VMware Cloud Foundation instance.

## Configuring the Certificate Authority for SDDC Manager

The [`Set-SddcCertificateAuthority`](/powershell-module-for-vmware-cloud-foundation-certificate-management/documentation/functions/Set-SddcCertificateAuthority/) configures Microsoft Certificate Authority or OpenSSL Certificate Authority as SDDC Manager's Certificate Authority.

### Configuring the Microsoft Certificate Authority for SDDC Manager

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation and run the commands in the PowerShell console.

    **Example**:

    ```powershell
    --8<-- "./docs/snippets/vars-vcf.ps1"
    --8<-- "./docs/snippets/vars-sddc-cer-auth.ps1"
    ```

3. Configuring the Certificate Authority for SDDC Manager by running the command in the PowerShell console.

```powershell
Set-SddcCertificateAuthority -certAuthority Microsoft -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -certAuthorityFqdn $certAuthorityFqdn -certAuthorityUser $certAuthorityUser -certAuthorityPass $certAuthorityPass -certAuthorityTemplate $certAuthorityTemplate
```

This example will configure Microsoft Certificate Authority `rpl-ad01.rainpole.io` in SDDC Manager.

### Configuring the OpenSSL Certificate Authority for SDDC Manager

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation and run the commands in the PowerShell console.

    **Example**:

    ```powershell
    --8<-- "./docs/snippets/vars-vcf.ps1"
    --8<-- "./docs/snippets/vars-sddc-cer-auth-openssl.ps1"
    --8<-- "./docs/snippets/vars-csr.ps1"
    ```

3. Configuring the Certificate Authority for SDDC Manager by running the command in the PowerShell console.

```powershell
Set-SddcCertificateAuthority -certAuthority OpenSSL -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -commonName $commonName -organization $organization -organizationUnit $organizationUnit -locality $locality -state $stateOrProvince -country $country
```

This example will configure an OpenSSL Certificate Authority in SDDC Manager.

## Request a Certificate Signing Request for a Workload Domain

The [`Request-VCFCsr`](/powershell-module-for-vmware-cloud-foundation-certificate-management/documentation/functions/Request-VCFCsr/) cmdlet will request SDDC Manager to generate and store certificate signing request files.

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation and run the commands in the PowerShell console.

    **Example**:

    ```powershell
    --8<-- "./docs/snippets/vars-vcf.ps1"
    --8<-- "./docs/snippets/vars-domain.ps1"
    --8<-- "./docs/snippets/vars-csr.ps1"
    --8<-- "./docs/snippets/vars-csr-windows.ps1"
    --8<-- "./docs/snippets/vars-csr-sddc-windows.ps1"
    ```

3. Request Certificate Signing Request files by running the command in the PowerShell console.

    ```powershell
    Request-VCFCsr -sddcManager -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -domain $workloadDomain -Country $country -keySize $keySize -Locality $locality -Organization $organization -OrganizationUnit $organizationUnit -StateOrProvince $stateOrProvince -email $email
    ```

This example will request SDDC Manager to generate certificate signing request files for all components associated with the given workload domain.

## Request Certificate Authority Signed Certificates for a Workload Domain

The [`Request-SddcCertificate`](/powershell-module-for-vmware-cloud-foundation-certificate-management/documentation/functions/Request-SddcCertificate/) will request SDDC Manager to connect to the certificate authority to sign the generated certificate signing request files for all components associated with the given workload domain

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation and run the commands in the PowerShell console.

    **Example**:

    ```powershell
    --8<-- "./docs/snippets/vars-vcf.ps1"
    --8<-- "./docs/snippets/vars-domain.ps1"
    ```

3. Request Certificate Authority Signed Certificates for a workload domain by running the command in the PowerShell console.

```powershell
Request-SddcCertificate -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $workloadDomain
```

This example will connect to SDDC Manager to request to have the certificate signing request files for a given workload domain to be signed.

## Installing and Replacing Certificate Authority Signed Certificates for a Workload Domain

The [`Install-VCFCertificate`](/powershell-module-for-vmware-cloud-foundation-certificate-management/documentation/functions/Install-VCFCertificate/) cmdlet installs the signed certificates for all components (except ESXi hosts) associated with the given workload domain.

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation and run the commands in the PowerShell console.

    **Example**:

    ```powershell
    --8<-- "./docs/snippets/vars-vcf.ps1"
    --8<-- "./docs/snippets/vars-domain.ps1"
    ```

3. Install a Certificate Authority Signed Certificates for SDDC Manager and the workload domain components by running the command in the PowerShell console.

    ```powershell
    Install-VCFCertificate -sddcManager -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -domain $workloadDomain
    ```
