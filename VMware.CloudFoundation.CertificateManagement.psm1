# Copyright 2023 VMware, Inc.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# Note:
# This PowerShell module should be considered entirely experimental. It is still in development and not tested beyond lab
# scenarios. It is recommended you don't use it for any production environment without testing extensively!

# Allow communication with self-signed certificates when using Powershell Core. If you require all communications to be
# secure and do not wish to allow communication with self-signed certificates, remove lines 13-36 before importing the
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


Function Get-vCenterServerDetailHelper {
    <#
        .SYNOPSIS
        Helper function to get vCenter Server details using either domain or ESXi FQDN

        .DESCRIPTION
        The cmdlet connects to SDDC Manager using the -server, -user, and -password values
        - Validates that network connectivity and authentication is possible to SDDC Manager
        - Validates that network connectivity and authentication is possible to vCenter Server
        - Validates that the workload domain exists in the SDDC Manager inventory

        .EXAMPLE
        Get-vCenterServerDetailHelper -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -esxiFqdn sfo01-m01-esx01.sfo.rainpole.io
        This example retrieves the ESXi trusted thumbprints for esxi with FQDN sfo01-m01-esx01.sfo.rainpole.io

        .EXAMPLE 
        Get-vCenterServerDetailHelper -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01
    #>

    Param (
        [Parameter (Mandatory = $true, ParameterSetName = "esxifqdn")]
        [Parameter (Mandatory = $true, ParameterSetName = "domain")] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true, ParameterSetName = "esxifqdn")]
        [Parameter (Mandatory = $true, ParameterSetName = "domain")] [String]$user,
        [Parameter (Mandatory = $true, ParameterSetName = "esxifqdn")]
        [Parameter (Mandatory = $true, ParameterSetName = "domain")] [String]$pass,
        [Parameter (Mandatory = $true, ParameterSetName = "domain")] [String]$domain,  
        [Parameter (Mandatory = $true, ParameterSetName = "esxifqdn")] [String]$esxiFqdn

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

Export-ModuleMember -Function Get-vCenterServerDetailHelper

Function Get-EsxiTrustedCertificateThumbprint {
    <#
        .SYNOPSIS
        Retrieves ESXi host's trusted certificates thumbprint

        .DESCRIPTION
        The Get-EsxiTrustedCertificateThumbprint cmdlet retrieves the ESXi host's trusted thumbprints
        The cmdlet connects to SDDC Manager using the -server, -user, and -password values.
        - Validates that network connectivity and authentication is possible to SDDC Manager
        - Validates that network connectivity and authentication is possible to vCenter Server
        - Validates that the workload domain exists in the SDDC Manager inventory

        .EXAMPLE
        Get-EsxiTrustedCertificateThumbprint -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -esxiFqdn sfo01-m01-esx01.sfo.rainpole.io
        This example retrieves the ESXi trusted thumbprints for esxi with FQDN sfo01-m01-esx01.sfo.rainpole.io

    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$esxiFqdn
    )
    
    Try {
        $vcfVcenterDetails = Get-vCenterServerDetailHelper -server $server -user $user -pass $pass -esxiFqdn $esxiFqdn
        $esxiTrustedThumbprint = $(Get-VITrustedCertificate -Server $($vcfVcenterDetails.fqdn) -VMHost $esxiFqdn).Certificate.Thumbprint
        Disconnect-VIServer $vcfVcenterDetails.fqdn -Confirm:$false -WarningAction SilentlyContinue
        return $esxiTrustedThumbprint                       
    }
    Catch {
        Debug-ExceptionWriter -object $_
    }
}
Export-ModuleMember -Function Get-EsxiTrustedCertificateThumbprint


Function Get-vCenterTrustedCertificateThumbprint {
    <#
        .SYNOPSIS
        Retrieves vCenter Servers trusted certificates thumbprint

        .DESCRIPTION
        The Get-vCenterTrustedCertificateThumbprint cmdlet retrieves the ESXi host's trusted thumbprints
        The cmdlet connects to SDDC Manager using the -server, -user, and -password values.
        - Validates that network connectivity and authentication is possible to SDDC Manager
        - Validates that network connectivity and authentication is possible to vCenter Server
        - Validates that the workload domain exists in the SDDC Manager inventory

        .EXAMPLE
        Get-vCenterTrustedCertificateThumbprint -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01 -issuer rainpole
        This example retrieves the ESXi trusted thumbprints for esxi with FQDN sfo01-m01-esx01.sfo.rainpole.io

    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$issuer
    )
    
    Try {
        $vcfVcenterDetails = Get-vCenterServerDetailHelper -server $server -user $user -pass $pass -domain $domain
        $vcTrustedcert = Get-VITrustedCertificate -Server $($vcfVcenterDetails.fqdn) | Where-Object { $_.issuer -match $issuer }
        if ($vcTrustedcert) {
            $vcTrustedThumbprint = $vcTrustedcert.Certificate.Thumbprint
        }
        return $vcTrustedThumbprint                       
    }
    Catch {
        Debug-ExceptionWriter -object $_
    }
}
Export-ModuleMember -Function Get-vCenterTrustedCertificateThumbprint


Function Verify-SignedCertificateWithCA {
    <#
    Verify the signed certificate thumbprint with the CA thumbprint from vcenter

     .DESCRIPTION
    This cmdlet will get the thumbprint from the signed certificate and matches it with the CA thumbprint from vcenter. 
    You need to pass in the complete path for the certificate file. 

    .EXAMPLE
    Verify-SignedCertificateWithCA -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01 -issuer rainpole -signedCertificate F:\bncode\powershell-module-for-vmware-cloud-foundation-certificate-management\Root64.cer

    #>
    
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$domain,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$issuer,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$signedCertificate
    )

    $vcThumbprint = Get-vCenterTrustedCertificateThumbprint -server $server -user $user -pass $pass -domain $domain -issuer $issuer
    $crt = New-Object System.Security.Cryptography.X509Certificates.X509Certificate
    $crt.Import($signedCertificate)
    $signedCertThumbprint = $crt.GetCertHashString()

    if ($vcThumbprint -eq $signedCertThumbprint) {
        Write-Output "Signed Certificate thumbprint matches with the vCenter server CA Thumbprint"
    }
    else {
        Write-Error "Thumbprint of vCenter server CA = $vcThumbprint"
        Write-Error "Thumbprint of signed certificate = $signedCertThumbprint"
        Throw "Signed Certificate thumbprint DOESNT match with the vCenter server CA Thumbprint"
    }
}

Export-ModuleMember -Function Verify-SignedCertificateWithCA

Function Get-EsxiCSR {
    <#
        .SYNOPSIS
        Generate the ESXi Certificate Sign Request in a specified cluster or single ESXi host and saves it to file(s)

        .DESCRIPTION
        The Get-EsxiCSR cmdlet will generate the Certificate Sign Request from a cluster or infividual ESXi host and saves it to file(s)
        The cmdlet connects to SDDC Manager using the -server, -user, and -password values.
        - Validates that network connectivity and authentication is possible to SDDC Manager
        - Validates that the workload domain exists in the SDDC Manager inventory
        - Validates that network connectivity and authentication is possible to vCenter Server
        - Gathers the ESXi hosts from the cluster
        - Request ESXi CSR and save it in the working directory as FQDN.csr e.g. sfo01-m01-esx01.sfo.rainpole.io.csr
        - Defines possible country codes as per: https://www.digicert.com/kb/ssl-certificate-country-codes.htm

        .EXAMPLE
        Get-EsxiCSR -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01 -cluster sfo-m01-cl01 -Country US -Locality "Test Location" -Organization "VMware LTD" -OrganizationUnit "VCF Deployment" -StateOrProvince "California" -outputFolder F:\csr
        This example generates CSRs and stores them in the working directory for all ESXi hosts in the cluster "production" with the specified properties

    #>

    Param (
        [Parameter (Mandatory = $true, ParameterSetName = "cluster")]
        [Parameter (Mandatory = $true, ParameterSetName = "host")] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true, ParameterSetName = "cluster")]
        [Parameter (Mandatory = $true, ParameterSetName = "host")] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true, ParameterSetName = "cluster")]
        [Parameter (Mandatory = $true, ParameterSetName = "host")] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true, ParameterSetName = "cluster")]
        [Parameter (Mandatory = $true, ParameterSetName = "host")] [ValidateNotNullOrEmpty()] [String]$domain,
        [Parameter (Mandatory = $true, ParameterSetName = "cluster")] [ValidateNotNullOrEmpty()] [String]$cluster,
        [Parameter (Mandatory = $true, ParameterSetName = "host")] [ValidateNotNullOrEmpty()] [String]$hostname,
        [Parameter (Mandatory = $true, ParameterSetName = "cluster")]
        [Parameter (Mandatory = $true, ParameterSetName = "host")] [ValidateNotNullOrEmpty()] [String]$outputFolder,
        [Parameter (Mandatory = $true, ParameterSetName = "cluster")]
        [Parameter (Mandatory = $true, ParameterSetName = "host")] [ValidateSet ("US", "CA", "AX", "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AN", "AO", "AQ", "AR", "AS", "AT", "AU", `
                "AW", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BM", "BN", "BO", "BR", "BS", "BT", "BV", "BW", "BZ", "CA", "CC", "CF", "CH", "CI", "CK", `
                "CL", "CM", "CN", "CO", "CR", "CS", "CV", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", `
                "FM", "FO", "FR", "FX", "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM", "HN", `
                "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KR", "KW", "KY", "KZ", "LA", `
                "LC", "LI", "LK", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", `
                "MW", "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NT", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM", `
                "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW", "SA", "SB", "SC", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SR", "ST", `
                "SU", "SV", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TM", "TN", "TO", "TP", "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", `
                "VC", "VE", "VG", "VI", "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "COM", "EDU", "GOV", "INT", "MIL", "NET", "ORG", "ARPA")] [String]$Country,
        [Parameter (Mandatory = $true, ParameterSetName = "cluster")]
        [Parameter (Mandatory = $true, ParameterSetName = "host")] [ValidateNotNullOrEmpty()] [String]$Locality,
        [Parameter (Mandatory = $true, ParameterSetName = "cluster")]
        [Parameter (Mandatory = $true, ParameterSetName = "host")] [ValidateNotNullOrEmpty()] [String]$Organization,
        [Parameter (Mandatory = $true, ParameterSetName = "cluster")]
        [Parameter (Mandatory = $true, ParameterSetName = "host")] [ValidateNotNullOrEmpty()] [String]$OrganizationUnit,
        [Parameter (Mandatory = $true, ParameterSetName = "cluster")]
        [Parameter (Mandatory = $true, ParameterSetName = "host")] [ValidateNotNullOrEmpty()] [String]$StateOrProvince
    
    )
    
    Try {
        if (!(Test-Path $outputFolder)) {
            Write-Error "Please specify a valid directory to save the CSR files."
            return
        }
        $vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $domain 
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
            $esxiHosts = Get-VMHost -Name $hostname
            if (!$esxiHosts) { Write-Warning "No ESXi host '$hostname' found within workload domain '$domain'." }
        }

        if ($esxiHosts) {
            Foreach ($esxiHost in $esxiHosts) {
                $csrPath = "$outputFolder\$($esxiHost.Name).csr"
                $esxRequest = New-VIMachineCertificateSigningRequest -Server $($vcfVcenterDetails.fqdn) -VMHost $($esxiHost.Name) -Country "$Country" -Locality "$Locality" -Organization "$Organization" -OrganizationUnit "$OrganizationUnit" -StateOrProvince "$StateOrProvince" -CommonName $($esxiHost.Name)
                $esxRequest.CertificateRequestPEM | Out-File $csrPath -Force
                if (Test-Path $csrPath -PathType Leaf ) {
                    Write-Output "CSR for $($esxiHost.Name) has been generated and saved to $csrPath"
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
        # Disconnect from vCenter Server
        Disconnect-VIServer $vcfVcenterDetails.fqdn -Confirm:$false -WarningAction SilentlyContinue
    }
}
Export-ModuleMember -Function Get-EsxiCSR


Function Get-ESXiCertManagementMode {
    <#
        .SYNOPSIS
        Retrieves ESXi host's management mode

        .DESCRIPTION
        Get-ESXiCertManagementMode cmdlet retrieves the ESXi host's management mode 

        .EXAMPLE
        Get-ESXiCertManagementMode -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -esxiFqdn sfo01-m01-esx01.sfo.rainpole.io
        This example retrieves the ESXi trusted thumbprints for esxi with FQDN sfo01-m01-esx01.sfo.rainpole.io

    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$esxiFqdn
    )
    
    Try {
        $vcfVcenterDetails = Get-vCenterServerDetailHelper -server $server -user $user -pass $pass -esxiFqdn $esxiFqdn
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

Export-ModuleMember -Function Get-ESXiCertManagementMode

Function Set-ESXiCertManagementMode {

    <#
        .SYNOPSIS
        Sets the ESXi host's management mode to either custom or vmca

        .DESCRIPTION
        Set-ESXiCertManagementMode cmdlet sets the ESXi host's management mode 

        .EXAMPLE
        Set-ESXiCertManagementMode -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -esxiFqdn sfo01-m01-esx01.sfo.rainpole.io -mode custom
        This example sets the ESXi management mode to custom
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$esxiFqdn,
        [Parameter (Mandatory = $true)] [ValidateSet ("custom", "vmca")] [String]$mode

    )
    Try {
        $vcfVcenterDetails = Get-vCenterServerDetailHelper -server $server -user $user -pass $pass -esxiFqdn $esxiFqdn
        $entity = Connect-VIServer -Server $vcfVcenterDetails.fqdn -User $vcfVcenterDetails.ssoAdmin -Pass $vcfVcenterDetails.ssoAdminPass
        $certModeSetting = Get-AdvancedSetting "vpxd.certmgmt.mode" -Entity $entity
        if ($certModeSetting.value -ne $mode) {
            Set-AdvancedSetting $certModeSetting -Value $mode
            Write-Output "ESXi Certificate Management Mode is set to custom"
        }
        else {
            Write-Output "ESXi Certificate Management Mode already set to custom"
        }
    }
    Catch {
        Debug-ExceptionWriter -object $_
    }
    Finally {
        Disconnect-VIServer $vcfVcenterDetails.fqdn -Confirm:$false -WarningAction SilentlyContinue
    }
}
Export-ModuleMember -Function Set-ESXiCertManagementMode



Function Get-VsanHealthSummary {

    <#
    .SYNOPSIS
    Get the vSAN health summary from vCenter for given cluster 

    .DESCRIPTION
    Get the vSAN health summary from vCenter for given cluster. If any status is YELLOW or RED, a WARNING or ERROR will be raised

    .EXAMPLE
    Get-VsanHealthSummary -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01 -cluster sfo-m01-cl01 
    This example Gets the ESXi management mode to custom
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $cluster

    )
    Try {
        $vcfVcenterDetails = Get-vCenterServerDetailHelper -server $server -user $user -pass $pass -domain $domain
       
        $vSANClusterHealthSystem = Get-VSANView -Id "VsanVcClusterHealthSystem-vsan-cluster-health-system"
        $cluster_view = (Get-Cluster -Name $cluster).ExtensionData.MoRef
        $results = $vSANClusterHealthSystem.VsanQueryVcClusterHealthSummary($cluster_view, $null, $null, $true, $null, $null, 'defaultView')
        $healthCheckGroups = $results.groups

        foreach ($healthCheckGroup in $healthCheckGroups) {     
            $Health = @("Yellow", "Red")
            $output = $healthCheckGroup.grouptests | Where-Object TestHealth -in $Health | Select-Object TestHealth, @{l = "TestId"; e = { $_.testid.split(".") | Select-Object -last 1 } }, TestName, TestShortDescription, @{l = "Group"; e = { $healthCheckGroup.GroupName } }
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
                    Write-Error " $vCenter - vSAN Clustername $Cluster | vSAN Alarm Name - $healthCheckTestName | Alarm Description - $healthCheckTestShortDescription"
                }
            }
        }
        return $overallStatus
    }
    Catch {
        Debug-ExceptionWriter -object $_
    }
}

Export-ModuleMember -Function Get-VsanHealthSummary



Function get-ESXiMaintenanceMode {

}

Function Set-ESXiMaintenanceMode {

}

Function Set-ESXiLockdownMode {

    <#
    Set-ESXiLockdownMode -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01 -cluster sfo-m01-cl01 -enable
    #>
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $cluster, 
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch] $enable,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch] $disable

    )
    Try {
        $vcfVcenterDetails = Get-vCenterServerDetailHelper -server $server -user $user -pass $pass -domain $domain
        if (Get-Cluster | Where-Object { $_.Name -eq $cluster }) {
            $esxiHosts = Get-Cluster $cluster | Get-VMHost | Sort-Object -Property Name
            if (!$esxiHosts) { Write-Warning "No ESXi hosts found within $cluster cluster." }
        }
        else {
            Write-Error "Unable to locate Cluster $cluster in $($vcfVcenterDetails.fqdn) vCenter Server: PRE_VALIDATION_FAILED"
        }

        if ($PSBoundParameters.ContainsKey("enable")) {

            Write-Host -ForegroundColor Yellow "Enabling Lockdown Mode on all hosts in the $ClusterName cluster."
            ForEach ($esxiHost in $esxiHosts) {
                $currentMode = (Get-VMHost -name $esxiHost).ExtensionData.Config.LockdownMode
                if ($currentMode -eq "lockdownDisabled") {
                    ($esxiHost | Get-View).EnterLockdownMode()
                    Write-Output "Changing $esxiHost mode from $currentMode to lockdownNormal"
                }
                else {
                    Write-Output "$esxiHost is in already in lockdownNormal mode"
                }
            }
        } 
        
        if ($PSBoundParameters.ContainsKey("disable")) {
            Write-Host -ForegroundColor Yellow "Disabling Lockdown Mode on all hosts in the $ClusterName cluster."
            ForEach ($esxiHost in $esxiHosts) {
                $currentMode = (Get-VMHost -name $esxiHost).ExtensionData.Config.LockdownMode
                if ($currentMode -ne "lockdownDisabled") {
                    ($esxiHost | Get-View).ExitLockdownMode()
                    Write-Output "Changing $esxiHost mode from $currentMode to lockdownDisabled"
                }
                else {
                    Write-Output "$esxiHost is already in lockdownDisabled mode"
                }
            }
        } 

    }
    Catch {
        Debug-ExceptionWriter -object $_
    }

 
}

Export-ModuleMember -Function Set-ESXiLockdownMode
