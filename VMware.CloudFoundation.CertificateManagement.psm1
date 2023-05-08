# Copyright 2023 VMware, Inc.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# Note:
# This PowerShell module should be considered entirely experimental. It is still in development and not tested beyond lab
# scenarios. It is recommended you don't use it for any production environment without testing extensively!

# Allow communication with self-signed certificates when using Powershell Core. If you require all communications to be
# secure and do not wish to allow communication with self-signed certificates, remove lines 15-41 before importing the
# module.

if ($PSEdition -eq 'Core') {
    $PSDefaultParameterValues.Add("Invoke-RestMethod:SkipCertificateCheck", $true)
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null
}

if ($PSEdition -eq 'Desktop') {
    # Allow communication with self-signed certificates when using Windows PowerShell
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null

    if ("TrustAllCertificatePolicy" -as [type]) {} else {
        Add-Type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertificatePolicy : ICertificatePolicy {
        public TrustAllCertificatePolicy() {}
        public bool CheckValidationResult(
            ServicePoint sPoint, X509Certificate certificate,
            WebRequest wRequest, int certificateProblem) {
            return true;
        }
    }
"@
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertificatePolicy
    }
}


#######################################################################################################################
########################################################  FUNCTIONS  ##################################################


Function Get-vCenterServerConnection {
    <#
        .SYNOPSIS
        Get connection to vCenter Server via SDDC Manager using either domain or ESXi FQDN

        .DESCRIPTION
        The cmdlet connects to SDDC Manager using the -server, -user, and -password values
        - Validates that network connectivity and authentication is possible to SDDC Manager
        - Validates that network connectivity and authentication is possible to vCenter Server
        - Validates that the workload domain exists in the SDDC Manager inventory
        - Connect to vCenter server and returns its details

        .EXAMPLE
        Get-vCenterServerConnection -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -esxiFqdn sfo01-m01-esx03.sfo.rainpole.io

        .EXAMPLE 
        Get-vCenterServerConnection -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true, ParameterSetName = "domain")] [String] $domain,  
        [Parameter (Mandatory = $true, ParameterSetName = "esxifqdn")] [String] $esxiFqdn

    )
    
    if (Test-Connection -server $server) {
        if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
            if ($PsBoundParameters.ContainsKey("domain")) { 
                $domain = $(Get-VCFWorkloadDomain | Where-Object { $_.name -eq $domain }).name
            }
            else {
                $esxiHost = Get-VCFHost -fqdn $esxiFqdn
                if (!$esxiHost) {
                    Throw "ESXi host not found. Please check the provided FQDN $esxiFqdn"
                    return 
                }
                $domain = $(Get-VCFWorkloadDomain -id $($esxiHost.domain.id)).name
            }
            if ($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $domain) {
                if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                    if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                        return $vcfVcenterDetails
                    }
                }
            }
            else {
                Throw "Unable to get vCenter details"
            }
        }
    }
}

Export-ModuleMember -Function Get-vCenterServerConnection

Function Get-EsxiCertificateThumbprint {
    <#
        .SYNOPSIS
        Retrieves ESXi host's certificates thumbprint

        .DESCRIPTION
        The Get-EsxiCertificateThumbprint cmdlet retrieves the ESXi host's trusted thumbprints

        .EXAMPLE
        Get-EsxiCertificateThumbprint -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -esxiFqdn sfo01-m01-esx01.sfo.rainpole.io
        This example retrieves the ESXi trusted thumbprints for esxi with FQDN sfo01-m01-esx01.sfo.rainpole.io

    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $esxiFqdn
    )
    
    Try {
        $vcfVcenterDetails = Get-vCenterServerConnection -server $server -user $user -pass $pass -esxiFqdn $esxiFqdn
        $esxiTrustedThumbprint = $(Get-VIMachineCertificate -Server $($vcfVcenterDetails.fqdn) -VMHost $esxiFqdn).Certificate.Thumbprint
        return $esxiTrustedThumbprint                       
    }
    Catch {
        Debug-ExceptionWriter -object $_
    }
}
Export-ModuleMember -Function Get-EsxiCertificateThumbprint


Function Get-vCenterCertificateThumbprints {
    <#
        .SYNOPSIS
        Retrieves either all of vCenter Servers certificates thumbprints ot the ones which match the provided issuer name

        .DESCRIPTION
        The Get-vCenterCertificateThumbprint cmdlet retrieves the vCenter Server's certificate thumbprints. By default it retrievs all thumbprints. 
        If issuer is provided, then only the thumbprint of the matching certificate is returned.

        .EXAMPLE
        Get-vCenterCertificateThumbprint -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01 
        This example retrieves the certificate thumbprints for the vCenter server belonging to domain sfo-m01.       
        
        .EXAMPLE
        Get-vCenterCertificateThumbprint -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01 -issuer rainpole
        This example retrieves the certificate thumbprints for the vCenter server belonging to domain sfo-m01 and matching issuer rainpole.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $issuer
    )
    
    Try {
        $vcfVcenterDetails = Get-vCenterServerConnection -server $server -user $user -pass $pass -domain $domain
        $vcTrustedcert = Get-VITrustedCertificate -Server $vcfVcenterDetails.fqdn
        
        if ($vcTrustedcert) {
            if ($PsBoundParameters.ContainsKey("issuer")) {
                $vcTrustedcert = $vcTrustedcert | Where-Object { $_.issuer -match $issuer }
            }
            $vcTrustedThumbprint = $vcTrustedcert.Certificate.Thumbprint
        }
        else {
            Write-Error "Unable to retrieve certificates from vCenter server $($vcfVcenterDetails.fqdn)" -ErrorAction Stop
        }
        return $vcTrustedThumbprint                       
    }
    Catch {
        Debug-ExceptionWriter -object $_
    }
}
Export-ModuleMember -Function Get-vCenterCertificateThumbprints


Function Confirm-ESXiCertificateAlreadyInstalled {
    <#
    Verify if the provided certificate is already on the ESXi host. 

     .DESCRIPTION
    This cmdlet will get the thumbprint from the provided signed certificate and matches it with the certificate thumbprint from ESXi host. 
    You need to pass in the complete path for the certificate file. 
    Returns true if certificate is already installed, returns false if otherwise. 

    .EXAMPLE
    Confirm-ESXiCertificateAlreadyInstalled -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -esxiFqdn sfo01-w02-esx01.sfo.rainpole.io -signedCertificate F:\TB02A-sfo-w02-certs\sfo01-w02-esx01.sfo.rainpole.io.cer
    This example checks the thumbprint of the provided signed certificate with the thumbprint on ESXi host.
    #>
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $esxiFqdn,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $signedCertificate
    )
    
    Try {
        if (Test-Path $signedCertificate -PathType Leaf ) {
            Write-Host "Certificate file found - $signedCertificate"
        }
        else {
            Write-Error "Could not find certificate in $signedCertificate." -ErrorAction Stop
            return
        }
        $esxiHostThumbprint = Get-EsxiCertificateThumbprint -server $server -user $user -pass $pass -esxiFqdn $esxiFqdn
        $crt = New-Object System.Security.Cryptography.X509Certificates.X509Certificate
        $crt.Import($signedCertificate)
        $signedCertThumbprint = $crt.GetCertHashString()

        if ($esxiHostThumbprint -eq $signedCertThumbprint) {
            Write-Host "Signed certificate thumbprint matches with the ESXi host thumbprint"
            Write-Warning "Provided certificate is already installed on ESXi host $esxiFqdn"
            return $true
        }
        else {
            Write-Host "ESXi host's certificate thumbprint - $esxiHostThumbprint does not match with the thumbprint of provided certificate = $signedCertThumbprint"
            Write-Host "Provided certificate is NOT installed on ESXi Host $esxiFqdn"
            return $false
        }
    }
    Catch {
        Debug-ExceptionWriter -object $_
    }
}
Export-ModuleMember -Function Confirm-ESXiCertificateAlreadyInstalled

Function Confirm-CAInVcenterServer {
    <#
    Verify the root certificate thumbprint matches with one of the CA thumbprints from vCenter server

    .DESCRIPTION
    This cmdlet will get the thumbprint from the root certificate and matches it with the CA thumbprint from vCenter. 
    You need to pass in the complete path for the certificate file. 
    Returns true if thumbprint matches, else returns false.


    .EXAMPLE
    Confirm-CAInVcenterServer -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01 -issuer rainpole -signedCertificate F:\powershell-module-for-vmware-cloud-foundation-certificate-management\Root64.cer
    This command will match the thumbprint of provided root certificate file with the thumbprints on the vCenter server matching the issuer "rainpole"
    #>
    
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $signedCertificate,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $issuer
    )
    
    try {

        if ($PsBoundParameters.ContainsKey("issuer")) { 
            $vcThumbprints = Get-vCenterCertificateThumbprints -server $server -user $user -pass $pass -domain $domain -issuer $issuer
        }
        else {
            $vcThumbprints = Get-vCenterCertificateThumbprints -server $server -user $user -pass $pass -domain $domain
        }
        if (Test-Path $signedCertificate -PathType Leaf ) {
            Write-Host "Certificate file found - $signedCertificate"
        }
        else {
            Write-Error "Could not find certificate in $signedCertificate." -ErrorAction Stop
            return
        }
        $crt = New-Object System.Security.Cryptography.X509Certificates.X509Certificate
        $crt.Import($signedCertificate)
        $signedCertThumbprint = $crt.GetCertHashString()

        $match = $false
        Foreach ($vcThumbprint in $vcThumbprints) { 
            if ($vcThumbprint -eq $signedCertThumbprint) {
                Write-Host "Signed certificate thumbprint matches with the vCenter server CA thumbprint"
                $match = $true
                break
            }
        }
        if (!$match) {
            Write-Error "Signed certificate thumbprint DOESNT match with any of the vCenter server certificates thumbprints"
        }
        return $match    
    }
    Catch {
        Debug-ExceptionWriter -object $_
    }
}

Export-ModuleMember -Function Confirm-SignedCertificateWithCA

Function Get-EsxiCSR {
    <#
        .SYNOPSIS
        Generate the ESXi Certificate Sign Request in a specified cluster or single ESXi host and saves it to file(s) in a folder

        .DESCRIPTION
        The Get-EsxiCSR cmdlet will generate the Certificate Sign Request from a cluster or infividual ESXi host and saves it to file(s) in provided output folder.
        The cmdlet connects to SDDC Manager using the -server, -user, and -password values.
        - Validates that network connectivity and authentication is possible to SDDC Manager
        - Validates that the workload domain exists in the SDDC Manager inventory
        - Validates that network connectivity and authentication is possible to vCenter Server
        - Gathers the ESXi hosts from the cluster
        - Request ESXi CSR and save it in the output directory as FQDN.csr e.g. sfo01-m01-esx01.sfo.rainpole.io.csr
        - Defines possible country codes as per: https://www.digicert.com/kb/ssl-certificate-country-codes.htm

        .EXAMPLE
        Get-EsxiCSR -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01 -cluster sfo-m01-cl01 -Country US -Locality "Test Location" -Organization "VMware LTD" -OrganizationUnit "VCF Deployment" -StateOrProvince "California" -outputFolder F:\csr
        This example generates CSRs and stores them in the provided output directory for all ESXi hosts in the cluster sfo-m01-cl01 with the specified fields

    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $true, ParameterSetName = "cluster")] [ValidateNotNullOrEmpty()] [String] $cluster,
        [Parameter (Mandatory = $true, ParameterSetName = "host")] [ValidateNotNullOrEmpty()] [String] $esxiFqdn,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$outputFolder,
        [Parameter (Mandatory = $true)] [ValidateSet ("US", "CA", "AX", "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AN", "AO", "AQ", "AR", "AS", "AT", "AU", `
                "AW", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BM", "BN", "BO", "BR", "BS", "BT", "BV", "BW", "BZ", "CA", "CC", "CF", "CH", "CI", "CK", `
                "CL", "CM", "CN", "CO", "CR", "CS", "CV", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", `
                "FM", "FO", "FR", "FX", "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM", "HN", `
                "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KR", "KW", "KY", "KZ", "LA", `
                "LC", "LI", "LK", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", `
                "MW", "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NT", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM", `
                "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW", "SA", "SB", "SC", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SR", "ST", `
                "SU", "SV", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TM", "TN", "TO", "TP", "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", `
                "VC", "VE", "VG", "VI", "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "COM", "EDU", "GOV", "INT", "MIL", "NET", "ORG", "ARPA")] [String]$Country,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $Locality,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $Organization,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $OrganizationUnit,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $StateOrProvince
    
    )
    
    Try {
        if (!(Test-Path $outputFolder)) {
            Write-Error "Please specify a valid directory to save the CSR files." -ErrorAction Stop
            return
        }
        $vcfVcenterDetails = Get-vCenterServerConnection -server $server -user $user -pass $pass -domain $domain 
        if ($PsBoundParameters.ContainsKey("cluster")) {
            if (Get-Cluster | Where-Object { $_.Name -eq $cluster }) {
                $esxiHosts = Get-Cluster $cluster | Get-VMHost | Sort-Object -Property Name
                if (!$esxiHosts) { Write-Warning "No ESXi hosts found within $cluster cluster." }
            }
            else {
                Write-Error "Unable to locate Cluster $cluster in $($vcfVcenterDetails.fqdn) vCenter Server: PRE_VALIDATION_FAILED"
                Throw "Unable to locate Cluster $cluster in $($vcfVcenterDetails.fqdn) vCenter Server: PRE_VALIDATION_FAILED"
            }
        }
        else {
            $esxiHosts = Get-VMHost -Name $esxiFqdn
            if (!$esxiHosts) { Write-Warning "No ESXi host '$esxiFqdn' found within workload domain '$domain'." }
        }

        if ($esxiHosts) {
            Foreach ($esxiHost in $esxiHosts) {
                $csrPath = "$outputFolder\$($esxiHost.Name).csr"
                $esxRequest = New-VIMachineCertificateSigningRequest -Server $vcfVcenterDetails.fqdn -VMHost $esxiHost.Name -Country "$Country" -Locality "$Locality" -Organization "$Organization" -OrganizationUnit "$OrganizationUnit" -StateOrProvince "$StateOrProvince" -CommonName $esxiHost.Name
                $esxRequest.CertificateRequestPEM | Out-File $csrPath -Force
                if (Test-Path $csrPath -PathType Leaf ) {
                    Write-Host "CSR for $($esxiHost.Name) has been generated and saved to $csrPath"
                }
                else {
                    Write-Error "Unable to generate CSR for $($esxiHost.Name)."
                    Throw "Unable to generate CSR for $($esxiHost.Name)"
                }
            }
        }                        
    }
    Catch {
        Debug-ExceptionWriter -object $_
    }
    Finally {
        Disconnect-VIServer $vcfVcenterDetails.fqdn -Confirm:$false -WarningAction SilentlyContinue
    }
}
Export-ModuleMember -Function Get-EsxiCSR


Function Get-CertManagementModeForESXi {
    <#
        .SYNOPSIS
        Retrieves the certificate management mode value from the vcenter server for the given domain.

        .DESCRIPTION
        Get-CertManagementModeForESXi cmdlet retrieves the cert management mode value from vcenter for the given domain.

        .EXAMPLE
        Get-CertManagementModeForESXi -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01
        This example retrieves the certificate management mode value for the vcenter server belonging to domain sfo-m01.

    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain
    )
    
    Try {
        $vcfVcenterDetails = Get-vCenterServerConnection -server $server -user $user -pass $pass -domain $domain
        $entity = Connect-VIServer -Server $vcfVcenterDetails.fqdn -User $vcfVcenterDetails.ssoAdmin -Pass $vcfVcenterDetails.ssoAdminPass
        $certModeSetting = Get-AdvancedSetting "vpxd.certmgmt.mode" -Entity $entity
        return $certModeSetting.value
    }  
    Catch {
        Debug-ExceptionWriter -object $_
    }
    Finally {
        Disconnect-VIServer $vcfVcenterDetails.fqdn -Confirm:$false -WarningAction SilentlyContinue
    }
}    

Export-ModuleMember -Function Get-CertManagementModeForESXi

Function Set-CertManagementModeForESXi {

    <#
        .SYNOPSIS
        Sets the ESXi host's management mode in the vCenter Server to either custom or vmca.

        .DESCRIPTION
        Set-CertManagementModeForESXi cmdlet sets the ESXi host's management mode on the vCenter server belonging to given domain.

        .EXAMPLE
        Set-CertManagementModeForESXi -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01 -mode custom
        This example sets the ESXi management mode to custom for the vCenter Server belonging to domain sfo-m01
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $true)] [ValidateSet ("custom", "vmca")] [String] $mode

    )
    Try {
        $vcfVcenterDetails = Get-vCenterServerConnection -server $server -user $user -pass $pass -domain $domain
        $entity = Connect-VIServer -Server $vcfVcenterDetails.fqdn -User $vcfVcenterDetails.ssoAdmin -Pass $vcfVcenterDetails.ssoAdminPass
        $certModeSetting = Get-AdvancedSetting "vpxd.certmgmt.mode" -Entity $entity
        if ($certModeSetting.value -ne $mode) {
            Set-AdvancedSetting $certModeSetting -Value $mode
            Write-Host "ESXi Certificate Management Mode is set to $mode on the vCenter server $($vcfVcenterDetails.fqdn)"
        }
        else {
            Write-Host "ESXi Certificate Management Mode already set to $mode on the vCenter server $($vcfVcenterDetails.fqdn)"
        }
    }
    Catch {
        Debug-ExceptionWriter -object $_
    }
    Finally {
        Disconnect-VIServer $vcfVcenterDetails.fqdn -Confirm:$false -WarningAction SilentlyContinue
    }
}
Export-ModuleMember -Function Set-CertManagementModeForESXi



Function Get-vSANHealthSummary {

    <#
        .SYNOPSIS
        Get the vSAN health summary from vCenter Server for given cluster 

        .DESCRIPTION
        This function gets the vSAN health summary from vCenter Server for a given cluster. If any status is YELLOW or RED, a WARNING or ERROR will be raised

        .EXAMPLE
        Get-vSANHealthSummary -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01 -cluster sfo-m01-cl01 
        This example gets the vSAN health summary for cluster sfo-m01-cl01 
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $cluster

    )
    Try {
        $vcfVcenterDetails = Get-vCenterServerConnection -server $server -user $user -pass $pass -domain $domain
        $vSANClusterHealthSystem = Get-VSANView -Id "VsanVcClusterHealthSystem-vsan-cluster-health-system"
        $cluster_view = (Get-Cluster -Name $cluster).ExtensionData.MoRef
        $results = $vSANClusterHealthSystem.VsanQueryVcClusterHealthSummary($cluster_view, $null, $null, $true, $null, $null, 'defaultView')
        $healthCheckGroups = $results.groups

        foreach ($healthCheckGroup in $healthCheckGroups) {     
            $health = @("Yellow", "Red")
            $output = $healthCheckGroup.grouptests | Where-Object TestHealth -in $health | Select-Object TestHealth, @{l = "TestId"; e = { $_.testid.split(".") | Select-Object -last 1 } }, TestName, TestShortDescription, @{l = "Group"; e = { $healthCheckGroup.GroupName } }
            $healthCheckTestHealth = $output.TestHealth
            $healthCheckTestName = $output.TestName
            $healthCheckTestShortDescription = $output.TestShortDescription
            if ($healthCheckTestName) {
                if ($healthCheckTestHealth -eq "yellow") {
                    $overallStatus = ($overallStatus, 1 | Measure-Object -Max).Maximum
                    Write-Warning "$vCenter - vSAN cluster $Cluster | vSAN Alarm Name - $healthCheckTestName | Alarm Description - $healthCheckTestShortDescription" 
                }
                if ($healthCheckTestHealth -eq "red") {
                    $overallStatus = ($overallStatus, 2 | Measure-Object -Max).Maximum
                    Write-Error "vSAN status is RED. Please check vSAN health before continuing..."
                    Write-Error " $vCenter - vSAN Clustername $Cluster | vSAN Alarm Name - $healthCheckTestName | Alarm Description - $healthCheckTestShortDescription" 
                }
            }
        }
        return $overallStatus
    }
    Catch {
        Debug-ExceptionWriter -object $_
    }
    Finally {
        Disconnect-VIServer $vcfVcenterDetails.fqdn -Confirm:$false -WarningAction SilentlyContinue
    }
}

Export-ModuleMember -Function Get-vSANHealthSummary


Function Get-ESXiState {
    <#
        .SYNOPSIS
        Get the ESXi state from vCenter Server

        .DESCRIPTION
        This cmdlet gets the current configuration state of the ESXi host. Possible outputs are "Connected", "Disconnected", "Maintenance" and "NotResponding"
        Can only be used after you have run Get-vCenterServerConnection cmdlet

        .EXAMPLE
        Get-ESXiState -esxiFqdn sfo01-m01-esx04.sfo.rainpole.io
    #>
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $esxiFqdn
    )
    $esxiHost = Get-VMHost -name $esxiFqdn
    return $esxiHost.ConnectionState
}
Export-ModuleMember -Function Get-ESXiState


Function Set-ESXiState {

    <#
        .SYNOPSIS
        Get the ESXi state from vCenter Server

        .DESCRIPTION
        This cmdlet sets the configuration state of ESXi host to provided value. Possible states are "Connected", "Disconnected", "Maintenance" and "NotResponding"
        If putting in Maintenance mode, you need to provide the VsanDataMigrationMode which can be one of these values - "Full", "EnsureAccessibility", "NoDataMigration"
        Can only be used after you have run Get-vCenterServerConnection cmdlet
        Default timeout 5 hrs (18000 seconds)

        .EXAMPLE
        Set-ESXiState -esxiFqdn sfo01-m01-esx04.sfo.rainpole.io -state Connected
        The above example sets the ESXi hosts state to connected
        
        .EXAMPLE
        Set-ESXiState -esxiFqdn sfo01-m01-esx04.sfo.rainpole.io -state Maintenance -VsanDataMigrationMode Full
        The above example sets the ESXi hosts state to Maintenance with Full data migration. 
    
    #>
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $esxiFqdn,
        [Parameter (Mandatory = $true)] [ValidateSet ("Connected", "Disconnected", "Maintenance", "NotResponding")] [String]$state, 
        [Parameter (Mandatory = $false)] [ValidateSet ("Full", "EnsureAccessibility", "NoDataMigration")] [String]$vsanDataMigrationMode,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $timeout = 18000
    )
    
    if ($state -ieq (Get-ESXiState -esxiFqdn $esxiFqdn)) {
        Write-Warning "$esxiFqdn is already in $state state"
        return
    }
    if ($state -ieq "maintenance") {
        if ($PSBoundParameters.ContainsKey("vsanDataMigrationMode")) {
            Write-Host "Entering Maintenance state for $esxiFqdn"
            Set-VMHost -VMHost $esxiFqdn -State $state -VsanDataMigrationMode $vsanDataMigrationMode -Evacuate
        }
        else {
            Throw "You must provide a valid vsanDataMigrationMode value"
        }
    }
    else {
        Write-Host "Changing state for $esxiFqdn to $state"
        Set-VMHost -VMHost $esxiFqdn -State $state
    }
    $timeout = New-TimeSpan -Seconds $timeout
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    do {
        $currentState = Get-ESXiState -esxiFqdn $esxiFqdn
        if ($state -ieq $currentState) {
            Write-Host "Successfully changed state for $esxiFqdn to $state"
            break
        }
        else {
            Write-Host "Polling every 60 seconds for state to change to $state..."
        }
        Start-Sleep -Seconds 60
    } while ($stopwatch.elapsed -lt $timeout)
}

Export-ModuleMember -Function Set-ESXiState


Function Get-ESXiLockdownMode {

    <#
        .SYNOPSIS
        Get the ESXi state from vCenter Server

        .DESCRIPTION
        This cmdlet gets the lockdown mode value for all hosts in a cluster or a particular ESXi host within that cluster.
        If esxiFqdn is provided, only the value for that host is retrieved. 

        .EXAMPLE
        Get-ESXiLockdownMode -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01 -cluster sfo-m01-cl01
        The above example retreives the lockdown mode value for all ESXi hosts in the provided cluster

        .EXAMPLE
        Get-ESXiLockdownMode -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01 -cluster sfo-m01-cl01 -esxiFqdn sfo01-m01-esx01.sfo.rainpole.io
        The above example retreives the lockdown mode value for the provided ESXi host in the provided cluster

    #>
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $cluster,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $esxiFqdn
    )
    Try {
        $vcfVcenterDetails = Get-vCenterServerConnection -server $server -user $user -pass $pass -domain $domain
        if (Get-Cluster | Where-Object { $_.Name -eq $cluster }) {
            if ($PsBoundParameters.ContainsKey("esxiFqdn")) {
                $esxiHosts = Get-Cluster $cluster | Get-VMHost -Name $esxiFqdn
            }
            else {
                $esxiHosts = Get-Cluster $cluster | Get-VMHost | Sort-Object -Property Name
            }
            if (!$esxiHosts) { Write-Warning "No ESXi hosts found within $cluster cluster." }
        }
        else {
            Write-Error "Unable to locate Cluster $cluster in $($vcfVcenterDetails.fqdn) vCenter Server: PRE_VALIDATION_FAILED" -ErrorAction Stop
        }
        ForEach ($esxiHost in $esxiHosts) {
            $currentMode = (Get-VMHost -name $esxiHost).ExtensionData.Config.LockdownMode
            Write-Host "$esxiHost is in $currentMode mode"
        }
        if ($PsBoundParameters.ContainsKey("esxiFqdn")) {
            return $currentMode
        }
    }
    Catch {
        Debug-ExceptionWriter -object $_
    }
}

Export-ModuleMember -Function Get-ESXiLockdownMode

Function Set-ESXiLockdownMode {

    <#
        .SYNOPSIS
        Set the lockdown mode for all ESXi hosts in given cluster

        .DESCRIPTION
        This cmdlet sets the lockdown mode value for all hosts in a cluster. 

        .EXAMPLE
        Set-ESXiLockdownMode -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01 -cluster sfo-m01-cl01 -enable
        This example will enable the lockdown mode on all hosts in the provided cluster

         .EXAMPLE
        Set-ESXiLockdownMode -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01 -cluster sfo-m01-cl01 -disable
        This example will disable the lockdown mode on all hosts in the provided cluster
    #>
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $cluster, 
        [Parameter (Mandatory = $true, ParameterSetName = "enable")] [ValidateNotNullOrEmpty()] [Switch] $enable,
        [Parameter (Mandatory = $true, ParameterSetName = "disable")] [ValidateNotNullOrEmpty()] [Switch] $disable

    )
    Try {
        $vcfVcenterDetails = Get-vCenterServerConnection -server $server -user $user -pass $pass -domain $domain
        if (Get-Cluster | Where-Object { $_.Name -eq $cluster }) {
            $esxiHosts = Get-Cluster $cluster | Get-VMHost | Sort-Object -Property Name
            if (!$esxiHosts) { Write-Warning "No ESXi hosts found within $cluster cluster." }
        }
        else {
            Write-Error "Unable to locate Cluster $cluster in $($vcfVcenterDetails.fqdn) vCenter Server: PRE_VALIDATION_FAILED" -ErrorAction Stop
        }

        if ($PSBoundParameters.ContainsKey("enable")) {

            Write-Host -ForegroundColor Yellow "Enabling Lockdown Mode on all hosts in the $ClusterName cluster."
            ForEach ($esxiHost in $esxiHosts) {
                $currentMode = (Get-VMHost -name $esxiHost).ExtensionData.Config.LockdownMode
                if ($currentMode -eq "lockdownDisabled") {
                    ($esxiHost | Get-View).EnterLockdownMode()
                    Write-Host "Changing $esxiHost mode from $currentMode to lockdownNormal"
                    $newMode = (Get-VMHost -name $esxiHost).ExtensionData.Config.LockdownMode
                    if ($currentMode -eq $newMode) {
                        Write-Error "Unable to change $esxiHost mode from $currentMode to lockdownNormal. Currently it is in $newMode" -ErrorAction Stop
                    }
                }
                else {
                    Write-Host "$esxiHost is in already in lockdownNormal mode"
                }
            }
        } 
        
        if ($PSBoundParameters.ContainsKey("disable")) {
            Write-Host -ForegroundColor Yellow "Disabling Lockdown Mode on all hosts in the $ClusterName cluster."
            ForEach ($esxiHost in $esxiHosts) {
                $currentMode = (Get-VMHost -name $esxiHost).ExtensionData.Config.LockdownMode
                if ($currentMode -ne "lockdownDisabled") {
                    ($esxiHost | Get-View).ExitLockdownMode()
                    Write-Host "Changing $esxiHost mode from $currentMode to lockdownDisabled"
                    $newMode = (Get-VMHost -name $esxiHost).ExtensionData.Config.LockdownMode
                    if ($currentMode -eq $newMode) {
                        Write-Error "Unable to change $esxiHost mode from $currentMode to lockdownDisabled. Currently it is in $newMode" -ErrorAction Stop
                    }
                }
                else {
                    Write-Host "$esxiHost is already in lockdownDisabled mode"
                }
            }
        } 
    }
    Catch {
        Debug-ExceptionWriter -object $_
    }
}

Export-ModuleMember -Function Set-ESXiLockdownMode


Function Restart-ESXiHost {

    <#
        .SYNOPSIS
        Restart the provided ESXi host and poll for it to come back online

        .DESCRIPTION
        This cmdlet triggers a restart the provided ESXi host and polls for it to come back online. 
        Timeout value is in seconds.

        .EXAMPLE
        Restart-EsxiHost -esxiFqdn sfo01-m01-esx03.sfo.rainpole.io -user root -pass VMw@re123! -poll $true -timeout 1800 -pollPeriod 30
        This example restarts the provided esxi hosts and polls every 30 seconds till it comes back online. It will timeout after 1800 seconds. 
    #>
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $esxiFqdn,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [bool] $poll = $true,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $timeout = 1800,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $pollPeriod = 30
    )

    # Connect to ESXi host
    Connect-VIServer $esxiFqdn -User $user -password $pass -Force

    Write-Host "Restarting $esxiFqdn"
    $vmHost = Get-VMHost -Server $esxiFqdn
    if (!$vmHost) {
        Write-Error "Unable to find ESXi host with FQDN $esxiFqdn" -ErrorAction Stop
        return
    }
    
    # Get ESXi uptime before restart
    $ESXiUpTime = New-TimeSpan -Start $vmHost.ExtensionData.Summary.Runtime.BootTime.ToLocalTime() -End (Get-Date)
    
    Restart-VMHost $esxiFqdn
    Disconnect-VIServer -Server $esxiFqdn -Confirm:$false -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

    if ($poll) {
        Write-Host "Waiting for $esxiFqdn to reboot...Polling every $pollPeriod seconds"
        Start-Sleep 30
        $timeout = New-TimeSpan -Seconds $timeout
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        do {
            if ((Test-NetConnection -ComputerName $esxiFqdn -Port 443 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue).TcpTestSucceeded) {
                if (Connect-VIServer $esxiFqdn -User $user -Password $pass -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue) {
                    $vmHost = Get-VMHost -Server $esxiFqdn
                    $currentUpTime = New-TimeSpan -Start $vmHost.ExtensionData.Summary.Runtime.BootTime.ToLocalTime() -End (Get-Date)
                    if ($($ESXiUpTime.TotalSeconds) -gt $($currentUpTime.TotalSeconds)) {
                        Write-Host "ESXi $esxiFqdn, has been restarted."
                    }
                    else {
                        Write-Host "ESXi uptime - $($ESXiUpTime.TotalSeconds) | Current Uptime - $($currentUpTime.TotalSeconds) "
                    }
                    Disconnect-VIServer -Server $esxiFqdn -Confirm:$false -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null
                    return
                }
            }
            Write-Host "Waiting for $esxiFqdn to boot up..."
            Start-Sleep -Seconds $pollPeriod
        } while ($stopwatch.elapsed -lt $timeout)

        Write-Error "ESXi host $esxiFqdn) did not responded after $($timeout.TotalMinutes) seconds. Please check if ESXi is up and running." -ErrorAction Stop
    }
    else {
        Write-Host "Restart of $esxiFqdn triggered without polling for it to come back online. Monitor its progress in the vCenter"
    }        
}

Export-ModuleMember -Function Restart-EsxiHost


#TODO: Inprogress -- Incomplete
Function Install-EsxiCertificate {
    <#
        .SYNOPSIS
        Install ESXi certificate to a single ESXi host or a whole cluster

        .DESCRIPTION
        The Install-EsxiCertificate cmdlet will replace ESXi certificate for a single host or all hosts in a cluster
        (the behavior is controlled with parameter -cluster/-esxiFqdn). 
        You must provide the folder containing the signed certificate files
        Certificate names should be in format <FQDN>.crt e.g. sfo01-m01-esx01.sfo.rainpole.io.crt
        The workflow will put ESXi host in maintenance mode with full data migration, 
        will disconnect ESXi from the vCenter Server, replace the certificate, reboot the host,
        and once ESXi is up and running it will connect it vCenter server and exit maintenance mode.
        Timeout for putting ESXi host in maintenance is provided in seconds using -timeout Parameter. Default is 18000 seconds or 5 hrs. 

        .EXAMPLE
        Install-EsxiCertificate -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01 -esxiFqdn sfo01-m01-esx03.sfo.rainpole.io -certificateFolder F:\certificates
        This example will install certificate from the given folder to the ESXi host sfo01-m01-esx03.sfo.rainpole.io in domain sfo-m01 

        Install-EsxiCertificate -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -cluster sfo-m01-cl01
        This example will install certificates from the given folder to all ESXi hosts in cluster "sfo-m01-cl01" in Domain "sfo-m01"

    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $true, ParameterSetName = "cluster")] [ValidateNotNullOrEmpty()] [String]  $cluster,
        [Parameter (Mandatory = $true, ParameterSetName = "host")] [ValidateNotNullOrEmpty()] [String] $esxiFqdn,
        [Parameter (Mandatory = $true) ] [ValidateNotNullOrEmpty()] [String] $certificateFolder,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $certificateFileExt = ".cer",
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $timeout = 18000
    )

    Try {
        $vcfVcenterDetails = Get-vCenterServerConnection -server $server -user $user -pass $pass -domain $domain 
        if ($PsBoundParameters.ContainsKey("cluster")) {
            if (Get-Cluster | Where-Object { $_.Name -eq $cluster }) {
                $esxiHosts = Get-Cluster $cluster | Get-VMHost | Sort-Object -Property Name
                if (!$esxiHosts) { Write-Warning "No ESXi hosts found within $cluster cluster." }
            }
            else {
                Write-Error "Unable to locate Cluster $cluster in $($vcfVcenterDetails.fqdn) vCenter Server: PRE_VALIDATION_FAILED" -ErrorAction Stop
            }
        }
        else {
            $esxiHosts = Get-VMHost -Name $esxiFqdn
            if (!$esxiHosts) { Write-Error "No ESXi host '$esxiFqdn' found within workload domain '$domain'." -ErrorAction Stop }
        }
    
        # Certificate replacement starts here
        $replacedHosts = New-Object Collections.Generic.List[String]
        $skippedHosts = New-Object Collections.Generic.List[String]
        Foreach ($esxiHost in $esxiHosts) {
            $esxiFqdn = $esxiHost.Name
            $crtPath = "$certificateFolder\$esxiFqdn$certificateFileExt"

            if (!(Test-Path $crtPath -PathType Leaf )) {
                Write-Error "Could not find certificate in $crtPath. Skipping certificate replacement for $esxiFqdn. "
                $skippedHosts.Add($esxiFqdn)
                continue
            }

            if (Confirm-ESXiCertificateAlreadyInstalled -server $server -user $user -pass $pass -esxiFqdn $esxiFqdn -signedCertificate $crtPath) {
                $skippedHosts.Add($esxiFqdn)
                continue
            }
            else {
                $esxiCredential = (Get-VCFCredential -resourcename $esxiFqdn | Where-Object { $_.username -eq "root" })
                if ($esxiCredential) {
                    
                    Set-ESXiState -esxiFqdn $esxiFqdn -state "Maintenance" -VsanDataMigrationMode "Full" -timeout $timeout
                
                    Write-Host "Starting certificate replacement for $esxiFqdn"                                    

                    $esxCertificatePem = Get-Content $crtPath -Raw
                    Set-VIMachineCertificate -PemCertificate $esxCertificatePem -VMHost $esxifqdn
                    $replacedHosts.Add($esxiFqdn)
                    
                    Restart-ESXiHost -esxiFqdn $esxiFqdn -user $($esxiCredential.username) -pass $($esxiCredential.password)
                
                    # Connect to vCenter server, then connect ESXi host to it and exit maintenance mode
                    Write-Host "Exiting maintenance mode and connecting to vCenter"
                    $vcfVcenterDetails = Get-vCenterServerConnection -server $server -user $user -pass $pass -domain $domain 
                    if ($vcfVcenterDetails) { 
                        Set-ESXiState -esxiFqdn $esxiFqdn -state "Connected" -timeout $timeout
                        Start-Sleep 30
                        Set-ESXiState -esxiFqdn $esxiFqdn -state "Connected"
                    }
                    else {
                        Write-Error "Could not connect to vCenter Server $vcfVcenterDetails. Check the state of ESXi host in vCenter" -ErrorAction Stop
                        break
                    }
                }
                else {
                    Write-Error "Unable to get credentials for $esxiFqdn"
                    $skippedHosts.Add($esxiFqdn)
                }
            }
        }
        Write-Host "Certificates for following ESXi hosts has been replaced "
        Foreach ($replacedHost in $replacedHosts) {
            Write-Host "$replacedHost"
        }
        Write-Warning "Following ESXi hosts have been skipped"
        Foreach ($skippedHost in $skippedHosts) {
            Write-Host "$skippedHost"
        }
    }
    Catch {
        Debug-ExceptionWriter -object $_
    }
    Finally {
        Disconnect-VIServer $vcfVcenterDetails.fqdn -Confirm:$false -WarningAction SilentlyContinue
    }
}
Export-ModuleMember -Function Install-EsxiCertificate
