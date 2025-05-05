# ESX Certificate Management

This section provides information on how to use the PowerShell module for VMware Cloud Foundation Certificate Management to manage ESX host certificates across your VMware Cloud Foundation instance.

## Set the ESX Certificate Mode in vCenter

The [`Set-EsxiCertificateMode`](../functions/Set-EsxiCertificateMode.md) cmdlet sets the certificate management mode in vCenter for the ESX hosts in a workload domain.

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation and run the commands in the PowerShell console.

    **Example**:

    ```powershell
    --8<-- "./docs/snippets/vars-vcf.ps1"
    --8<-- "./docs/snippets/vars-domain.ps1"
    --8<-- "./docs/snippets/vars-esxi-cer-mode.ps1"
    ```

3. Set the ESX certificate management mode in vCenter by running the command in the PowerShell console.

    ```powershell
    Set-EsxiCertificateMode -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -domain $workloadDomain -mode $mode
    ```

## Request a Certificate Signing Request

The [`Request-VcfCsr`](../functions/Request-VcfCsr.md) cmdlet will generate the Certificate Signing Request for ESX host(s) and saves it to file(s) in an output directory.

## Request Certificate Signing Request for each ESX Host in a Cluster

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
    Request-VcfCsr -esxi -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -domain $workloadDomain -cluster $cluster -Country $country -Locality $location -Organization $organization -OrganizationUnit $organizationUnit -StateOrProvince $stateOrProvince -outputDirectory $outputDirectory
    ```

## Request a Certificate Signing Request for an ESX Host

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
    Request-VcfCsr -esxi -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -domain $workloadDomain -esxiFqdn $esxiFqdn -Country $country -Locality $locality -Organization $organization -OrganizationUnit $organizationUnit -StateOrProvince $stateOrProvince -outputDirectory $outputDirectory
    ```

## Verify the Certificate Authority is Trusted in vCenter

The [`Confirm-CAInvCenterServer`](../functions/Confirm-CAInvCenterServer.md) cmdlet gets the thumbprint from the root certificate and matches it with the CA thumbprint from the vCenter instance. You need to pass in the complete path for the certificate file. Returns true if thumbprint matches, else returns false.

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation and run the commands in the PowerShell console.

    **Example**:

    ```powershell
    --8<-- "./docs/snippets/vars-vcf.ps1"
    --8<-- "./docs/snippets/vars-domain.ps1"
    --8<-- "./docs/snippets/vars-issuer.ps1"
    --8<-- "./docs/snippets/vars-signedcer-windows.ps1"
    ```

3. Verify the Certificate Authority is trusted in vCenter by running the command in the PowerShell console.

    ```powershell
    Confirm-CAInvCenterServer -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -domain $workloadDomain -issuer $issuer -signedCertificate $signedCertificate
    ```

## Set the Lockdown Mode for ESX Hosts

The [`Set-EsxiLockdownMode`](../functions/Set-EsxiLockdownMode.md) cmdlet sets the lockdown mode for all ESX hosts in a given cluster.

### Disable Lockdown Mode for Each ESX Host in a Cluster

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

### Enable Lockdown Mode for Each ESX Host in a Cluster

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

## Get the vSAN Health Summary from vCenter for a Cluster

The [`Get-vSANHealthSummary`](../functions/Get-vSANHealthSummary.md) cmdlet gets the vSAN health summary from vCenter for a cluster. If any status is YELLOW or RED, a WARNING or ERROR will be raised.

1. Start PowerShell (Run as Administrator).

2. Replace the values in the sample code with values for the instance of VMware Cloud Foundation and run the commands in the PowerShell console.

    **Example**:

    ```powershell
    --8<-- "./docs/snippets/vars-vcf.ps1"
    --8<-- "./docs/snippets/vars-domain.ps1"
    --8<-- "./docs/snippets/vars-cluster.ps1"
    ```

3. Get the vSAN health summary from vCenter for a cluster by running the command in the PowerShell console.

    ```powershell
    Get-vSANHealthSummary -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -domain $workloadDomain -cluster $cluster
    ```

## Run the checks required for ESX Certificate Management for a Cluster

The [`Test-EsxiCertMgmtChecks`](../functions/Test-EsxiCertMgmtChecks.md) cmdlet runs the checks required for ESX Certificate Management for a given cluster or an ESX host.
The following checks are run:

- Check ESX Certificate Mode
- Check ESX Lockdown Mode
- Confirm CA In vCenter
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

3. Run the checks required for ESX Certificate management for a cluster by running the command in the PowerShell console.

    ```powershell
    Test-EsxiCertMgmtChecks -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -domain $workloadDomain -cluster $cluster -signedCertificate $signedCertificate -issuer $issuer
    ```

## Install a Certificate

The [`Install-VcfCertificate`](../functions/Install-VcfCertificate.md) cmdlet will replace the certificate for an ESX host or for each ESX host in a cluster. You must provide the directory containing the signed certificate files. Certificate names should be in format <FQDN>.cer (_e.g._, sfo01-m01-esx01.sfo.rainpole.io.cer.) The workflow will put the ESX host in maintenance mode (with full data migration for vSAN only), disconnect the ESX host from the vCenter, replace the certificate, restart the ESX host, and the exit maintenance mode once the ESX host is online.

### Install a Certificate to Each ESX Host in a Cluster

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

3. Install a Certificate for each ESX host in cluster by running the command in the PowerShell console.

    ```powershell
    Install-VcfCertificate -esxi -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -domain $workloadDomain -cluster $cluster -certificateDirectory $certificateDirectory -certificateFileExt $certificateFileExt
    ```

### Install a Certificate to an ESX Host

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

3. Install a certificate to an ESX host by running the command in the PowerShell console.

    ```powershell
    Install-VcfCertificate -esxi -server $sddcManagerFqdn -user $sddcManagerUser -pass $sddcManagerPass -domain $workloadDomain -esxiFqdn $esxiFqdn -certificateDirectory $certificateDirectory -certificateFileExt $certificateFileExt
    ```
