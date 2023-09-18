# ESXi Certificate Management

This section provides information on how to use the PowerShell module for VMware Cloud Foundation Certificate Management to manage ESXi host certificates across your VMware Cloud Foundation instance.

## Set the ESXi Certificate Mode in vCenter Server

The [`Set-EsxiCertificateMode`](/powershell-module-for-vmware-cloud-foundation-certificate-management/documentation/functions/Set-EsxiCertificateMode/) cmdlet sets the certificate management mode in vCenter Server for the ESXi hosts in a workload domain.

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation and run the commands in the PowerShell console.

    **Example**:

    ```powershell
    --8<-- "./docs/snippets/vars-vcf.ps1"
    --8<-- "./docs/snippets/vars-domain.ps1"
    --8<-- "./docs/snippets/vars-esxi-cer-mode.ps1"
    ```

3. Set the ESXi certificate management mode in vCenter Server by running the command in the PowerShell console.

    ```powershell
    Set-EsxiCertificateMode -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -domain $workloadDomain -mode $mode
    ```

## Request a Certificate Signing Request

The [`Request-VCFCsr`](/powershell-module-for-vmware-cloud-foundation-certificate-management/documentation/functions/Request-VCFCsr/) cmdlet will generate the Certificate Signing Request for ESXi host(s) and saves it to file(s) in an output directory.

## Request Certificate Signing Request for each ESXi Host in a Cluster

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation and run the commands in the PowerShell console.

    **Example**:

    ```powershell
    --8<-- "./docs/snippets/vars-vcf.ps1"
    --8<-- "./docs/snippets/vars-domain.ps1"
    --8<-- "./docs/snippets/vars-cluster.ps1"
    --8<-- "./docs/snippets/vars-csr.ps1"
    --8<-- "./docs/snippets/vars-csr-windows.ps1"
    ```

3. Request Certificate Signing Request files by running the command in the PowerShell console.

    ```powershell
    Request-VCFCsr -esxi -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -domain $workloadDomain -cluster $cluster -Country $country -Locality $location -Organization $organization -OrganizationUnit $organizationUnit -StateOrProvince $stateOrProvince -outputDirectory $outputDirectory
    ```

## Request a Certificate Signing Request for an ESXi Host

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation and run the commands in the PowerShell console.

    **Example**:

    ```powershell
    --8<-- "./docs/snippets/vars-vcf.ps1"
    --8<-- "./docs/snippets/vars-domain.ps1"
    --8<-- "./docs/snippets/vars-esxi.ps1"
    --8<-- "./docs/snippets/vars-csr.ps1"
    --8<-- "./docs/snippets/vars-csr-windows.ps1"
    ```

3. Request a Certificate Signing Request file by running the command in the PowerShell console.

    ```powershell
    Request-VCFCsr -esxi -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -domain $workloadDomain -esxiFqdn $esxiFqdn -Country $country -Locality $locality -Organization $organization -OrganizationUnit $organizationUnit -StateOrProvince $stateOrProvince -outputDirectory $outputDirectory
    ```

## Verify the Certificate Authority is Trusted in vCenter Server

The [`Confirm-CAInvCenterServer`](/powershell-module-for-vmware-cloud-foundation-certificate-management/documentation/functions/Confirm-CAInvCenterServer/) cmdlet gets the thumbprint from the root certificate and matches it with the CA thumbprint from the vCenter Server instance. You need to pass in the complete path for the certificate file. Returns true if thumbprint matches, else returns false.

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation and run the commands in the PowerShell console.

    **Example**:

    ```powershell
    --8<-- "./docs/snippets/vars-vcf.ps1"
    --8<-- "./docs/snippets/vars-domain.ps1"
    --8<-- "./docs/snippets/vars-issuer.ps1"
    --8<-- "./docs/snippets/vars-signedcer-windows.ps1"
    ```

3. Verify the Certificate Authority is trusted in vCenter server by running the command in the PowerShell console.

    ```powershell
    Confirm-CAInvCenterServer -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -domain $workloadDomain -issuer $issuer -signedCertificate $signedCertificate
    ```

## Set the Lockdown Mode for ESXi Hosts

The [`Set-EsxiLockdownMode`](/powershell-module-for-vmware-cloud-foundation-certificate-management/documentation/functions/Set-EsxiLockdownMode/) cmdlet sets the lockdown mode for all ESXi hosts in a given cluster.

### Disable Lockdown Mode for Each ESXi Host in a Cluster

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation and run the commands in the PowerShell console.

    **Example**:

    ```powershell
    --8<-- "./docs/snippets/vars-vcf.ps1"
    --8<-- "./docs/snippets/vars-domain.ps1"
    --8<-- "./docs/snippets/vars-cluster.ps1"
    ```

3. Set the lockdown mode to `disable` by running the command in the PowerShell console.

    ```powershell
    Set-EsxiLockdownMode -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -domain $workloadDomain -cluster $cluster -disable
    ```

### Enable Lockdown Mode for Each ESXi Host in a Cluster

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation and run the commands in the PowerShell console.

    **Example**:

    ```powershell
    --8<-- "./docs/snippets/vars-vcf.ps1"
    --8<-- "./docs/snippets/vars-domain.ps1"
    --8<-- "./docs/snippets/vars-cluster.ps1"
    ```

3. Set the lockdown mode to `enable` by running the command in the PowerShell console.

    ```powershell
    Set-EsxiLockdownMode -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -domain $workloadDomain -cluster $cluster -enable
    ```

## Get the vSAN Health Summary from vCenter Server for a Cluster

The [`Get-vSANHealthSummary`](/powershell-module-for-vmware-cloud-foundation-certificate-management/documentation/functions/Get-vSANHealthSummary/) cmdlet gets the vSAN health summary from vCenter Server for a cluster. If any status is YELLOW or RED, a WARNING or ERROR will be raised.

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation and run the commands in the PowerShell console.

    **Example**:

    ```powershell
    --8<-- "./docs/snippets/vars-vcf.ps1"
    --8<-- "./docs/snippets/vars-domain.ps1"
    --8<-- "./docs/snippets/vars-cluster.ps1"
    ```

3. Get the vSAN health summary from vCenter server for a cluster by running the command in the PowerShell console.

    ```powershell
    Get-vSANHealthSummary -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -domain $workloadDomain -cluster $cluster
    ```

## Run the checks required for ESXi Certificate Management for a Cluster

The [`Test-EsxiCertMgmtChecks`](/powershell-module-for-vmware-cloud-foundation-certificate-management/documentation/functions/Test-EsxiCertMgmtChecks/) cmdlet runs the checks required for ESXi Certificate Management for a given cluster or an ESXi host.
The following checks are run:

- Check ESXi Certificate Mode
- Check ESXi Lockdown Mode
- Confirm CA In vCenter Server
- Check vSAN Health Status

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation and run the commands in the PowerShell console.

    **Example**:

    ```powershell
    --8<-- "./docs/snippets/vars-vcf.ps1"
    --8<-- "./docs/snippets/vars-domain.ps1"
    --8<-- "./docs/snippets/vars-cluster.ps1"
    --8<-- "./docs/snippets/vars-issuer.ps1"
    --8<-- "./docs/snippets/vars-signedcer-windows.ps1"
    ```

3. Run the checks required for ESXi Certificate management for a cluster by running the command in the PowerShell console.

    ```powershell
    Test-EsxiCertMgmtChecks -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -domain $workloadDomain -cluster $cluster -signedCertificate $signedCertificate -issuer $issuer
    ```

## Install a Certificate

The [`Install-VCFCertificate`](/powershell-module-for-vmware-cloud-foundation-certificate-management/documentation/functions/Install-VCFCertificate/) cmdlet will replace the certificate for an ESXi host or for each ESXi host in a cluster. You must provide the directory containing the signed certificate files. Certificate names should be in format <FQDN>.cer (_e.g._, sfo01-m01-esx01.sfo.rainpole.io.cer.) The workflow will put the ESXi host in maintenance mode (with full data migration for vSAN only), disconnect the ESXi host from the vCenter Server, replace the certificate, restart the ESXi host, and the exit maintenance mode once the ESXi host is online.

### Install a Certificate to Each ESXi Host in a Cluster

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation and run the commands in the PowerShell console.

    **Example**:

    ```powershell
    --8<-- "./docs/snippets/vars-vcf.ps1"
    --8<-- "./docs/snippets/vars-domain.ps1"
    --8<-- "./docs/snippets/vars-cluster.ps1"
    --8<-- "./docs/snippets/vars-cer-windows.ps1"
    --8<-- "./docs/snippets/vars-cer-ext.ps1"
    ```

3. Install a Certificate for each ESXi host in cluster by running the command in the PowerShell console.

    ```powershell
    Install-VCFCertificate -esxi -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -domain $domain -cluster $cluster -certificateDirectory $certificateDirectory -certificateFileExt $certificateFileExt
    ```

### Install a Certificate to an ESXi Host

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation and run the commands in the PowerShell console.

    **Example**:

    ```powershell
    --8<-- "./docs/snippets/vars-vcf.ps1"
    --8<-- "./docs/snippets/vars-domain.ps1"
    --8<-- "./docs/snippets/vars-esxi.ps1"
    --8<-- "./docs/snippets/vars-cer-windows.ps1"
    --8<-- "./docs/snippets/vars-cer-ext.ps1"
    ```

3. Install a certificate to an ESXi host by running the command in the PowerShell console.

    ```powershell
    Install-VCFCertificate -esxi -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -domain $domain -esxiFqdn $esxiFqdn -certificateDirectory $certificateDirectory -certificateFileExt $certificateFileExt
    ```
