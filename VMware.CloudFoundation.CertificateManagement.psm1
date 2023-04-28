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


Function Get-vCenterServerConnection {
    <#
        .SYNOPSIS
        Helper function to get vCenter Server details using either domain or ESXi FQDN

        .DESCRIPTION
        The cmdlet connects to SDDC Manager using the -server, -user, and -password values
        - Validates that network connectivity and authentication is possible to SDDC Manager
        - Validates that network connectivity and authentication is possible to vCenter Server
        - Validates that the workload domain exists in the SDDC Manager inventory

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
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $esxiFqdn
    )
    
    Try {
        $vcfVcenterDetails = Get-vCenterServerConnection -server $server -user $user -pass $pass -esxiFqdn $esxiFqdn
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
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $issuer
    )
    
    Try {
        $vcfVcenterDetails = Get-vCenterServerConnection -server $server -user $user -pass $pass -domain $domain
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
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $issuer,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $signedCertificate
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
            Write-Error "Please specify a valid directory to save the CSR files."
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
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $esxiFqdn
    )
    
    Try {
        $vcfVcenterDetails = Get-vCenterServerConnection -server $server -user $user -pass $pass -esxiFqdn $esxiFqdn
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
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $esxiFqdn,
        [Parameter (Mandatory = $true)] [ValidateSet ("custom", "vmca")] [String] $mode

    )
    Try {
        $vcfVcenterDetails = Get-vCenterServerConnection -server $server -user $user -pass $pass -esxiFqdn $esxiFqdn
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
        Get-vCenterServerConnection -server $server -user $user -pass $pass -domain $domain
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


Function Get-ESXiState {
    <#
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
    Can only be used after you have run Get-vCenterServerConnection 

    Set-ESXiState -esxiFqdn sfo01-m01-esx04.sfo.rainpole.io -state Connected
    Set-ESXiState -esxiFqdn sfo01-m01-esx04.sfo.rainpole.io -state Maintenance -VsanDataMigrationMode Full


    Set-VMHost -VMHost $($esxiHost.Name) -State Maintenance -VsanDataMigrationMode Full -Evacuate

    Default timeout 5 hrs (18000 seconds)

    
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
            Write-Output "Entering Maintenance state for $esxiFqdn"
            Set-VMHost -VMHost $esxiFqdn -State $state -VsanDataMigrationMode $vsanDataMigrationMode -Evacuate
        }
        else {
            Throw "You must provide a valid vsanDataMigrationMode value"
        }
    }
    else {
        Write-Output "Changing state for $esxiFqdn to $state"
        Set-VMHost -VMHost $esxiFqdn -State $state
    }
    $timeout = New-TimeSpan -Seconds $timeout
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    do {
        $currentState = Get-ESXiState -esxiFqdn $esxiFqdn
        if ($state -ieq $currentState) {
            Write-Output "Successfully changed state for $esxiFqdn to $state"
            break
        }
        else {
            Write-Output "Polling every 60 seconds for state to change to $state..."
        }
        Start-Sleep -Seconds 60
    } while ($stopwatch.elapsed -lt $timeout)
}

Export-ModuleMember -Function Set-ESXiState


Function Get-ESXiLockdownMode {

    <#
    Get-ESXiLockdownMode -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01 -cluster sfo-m01-cl01
    Get-ESXiLockdownMode -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01 -cluster sfo-m01-cl01 -esxiFqdn sfo01-m01-esx01.sfo.rainpole.io

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
            Write-Error "Unable to locate Cluster $cluster in $($vcfVcenterDetails.fqdn) vCenter Server: PRE_VALIDATION_FAILED"
        }
        ForEach ($esxiHost in $esxiHosts) {
            $currentMode = (Get-VMHost -name $esxiHost).ExtensionData.Config.LockdownMode
            Write-Output "$esxiHost is in $currentMode mode"
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
    Set-ESXiLockdownMode -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01 -cluster sfo-m01-cl01 -enable
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


Function Restart-ESXiHost {

    <#
    Restart-EsxiHost -esxiFqdn sfo01-m01-esx03.sfo.rainpole.io -user root -pass VMw@re123! -poll $true -timeout 1800 -pollPeriod 30
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

    Write-Output "Restarting $esxiFqdn"
    $vmHost = Get-VMHost -Server $esxiFqdn
    if (!$vmHost) {
        Write-Error "Unable to find ESXi host with FQDN $esxiFqdn"
        return
    }
    
    # Get ESXi uptime before restart
    $ESXiUpTime = New-TimeSpan -Start $vmHost.ExtensionData.Summary.Runtime.BootTime.ToLocalTime() -End (Get-Date)
    
    Restart-VMHost $esxiFqdn
    Disconnect-VIServer -Server $esxiFqdn -Confirm:$false -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

    if ($poll) {
        Write-Output "Waiting for $esxiFqdn to reboot...Polling every $pollPeriod seconds"
        Start-Sleep 30
        $timeout = New-TimeSpan -Seconds $timeout
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        do {
            if ((Test-NetConnection -ComputerName $esxiFqdn -Port 443 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue).TcpTestSucceeded) {
                if (Connect-VIServer $esxiFqdn -User $user -Password $pass -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue) {
                    $vmHost = Get-VMHost -Server $esxiFqdn
                    $currentUpTime = New-TimeSpan -Start $vmHost.ExtensionData.Summary.Runtime.BootTime.ToLocalTime() -End (Get-Date)
                    if ($($ESXiUpTime.TotalSeconds) -gt $($currentUpTime.TotalSeconds)) {
                        Write-Output "ESXi $esxiFqdn, has been restarted."
                    }
                    else {
                        Write-Output "ESXi uptime - $($ESXiUpTime.TotalSeconds) | Current Uptime - $($currentUpTime.TotalSeconds) "
                    }
                    Disconnect-VIServer -Server $esxiFqdn -Confirm:$false -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null
                    return
                }
            }
            Write-Output "Waiting for $esxiFqdn to boot up..."
            Start-Sleep -Seconds $pollPeriod
        } while ($stopwatch.elapsed -lt $timeout)

        Write-Error "ESXi host $esxiFqdn) did not responded after $($timeout.TotalMinutes) seconds. Please check if ESXi is up and running."
    }
    else {
        Write-Output "Restart of $esxiFqdn triggered without polling for it to come back online. Monitor its progress in the vCenter"
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
        (the behavior is controlled with parameter -cluster/-host). cmdlet expects to find pem encoded certificates 
        in the specified directory, certificate names should be in format <FQDN>.crt e.g. sfo01-m01-esx01.sfo.rainpole.io.crt
        The workflow will put ESXi host in maintenance mode with full data migration, 
        will detach ESXi from the vCenter Server, replace the certificate, reboot the host,
        once ESXi is up and running it will attach it vCenter Server and exit maintenance mode.
        The Request-EsxiAccountLockout cmdlet retrieves a list of ESXi hosts for a cluster displaying the currently
        configured account lockout policy (Advanced Settings Security.AccountLockFailures and
        Security.AccountUnlockTime). The cmdlet connects to SDDC Manager using the -server, -user, and -password
        values:
        - Validates that network connectivity and authentication is possible to SDDC Manager
        - Validates that the workload domain exists in the SDDC Manager inventory
        - Validates that network connectivity and authentication is possible to vCenter Server
        - Gathers the ESXi host or all hosts in a specified cluster
        - TODO Validates that certificate filename matches the CN and FQDN of the ESXi host
        - TODO Validates that certificate has been signed with the same CA as the vCenter Server or CA thumbprint is in vCenter Trusted Store
        - TODO Validates that needed advanced settings are set in vCenter Server
        - Replaces the ESXi certificate

        .EXAMPLE
        Install-EsxiCertificate -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01 -esxiFqdn sfo01-m01-esx03.sfo.rainpole.io
        This example will install certificate on an ESXi host esxi01.sfo.rainpole.io in Workload domain wld-1

        Install-EsxiCertificate -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -cluster sfo-m01-vc01
        This example will install certificate on all ESXi hosts in cluster "production" in Workload Domain "wld-1"

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
                Write-Error "Unable to locate Cluster $cluster in $($vcfVcenterDetails.fqdn) vCenter Server: PRE_VALIDATION_FAILED"
                Throw "Unable to locate Cluster $cluster in $($vcfVcenterDetails.fqdn) vCenter Server: PRE_VALIDATION_FAILED"
            }
        }
        else {
            $esxiHosts = Get-VMHost -Name $esxiFqdn
            if (!$esxiHosts) { Write-Error "No ESXi host '$esxiFqdn' found within workload domain '$domain'." }
        }
    
        # Certificate replacement starts here

        Foreach ($esxiHost in $esxiHosts) {
            $esxiFqdn = $esxiHost.Name
            $crtPath = "$certificateFolder\$esxiFqdn$certificateFileExt"

            if (Test-Path $crtPath -PathType Leaf ) {
                Write-Output "Certificate file for $esxiFqdn has been found: $crtPath"
            }
            else {
                Write-Error "Could not find certificate in $crtPath. Skipping certificate replacement for $esxiFqdn. "
                continue
            }

            $esxiCredential = (Get-VCFCredential -resourcename $esxiFqdn | Where-Object { $_.username -eq "root" })
            if ($esxiCredential) {
                Set-ESXiState -esxiFqdn $esxiFqdn -state "Maintenance" -VsanDataMigrationMode "Full" -timeout $timeout
                #Set-ESXiState -esxiFqdn $($esxiHost.Name) -state "Disconnected" -timeout 300
             
                Write-Output "Starting certificate replacement for $esxiFqdn"
                #Write-Output "ESXi credentials: $esxiFqdn -User $($esxiCredential.username) -Password $($esxiCredential.password)"
                                
                #TODO: uncomment later when testing actual cert replacement
                #$esxCertificatePem = Get-Content $crtPath -Raw
                #Set-VIMachineCertificate -PemCertificate $esxCertificatePem -VMHost $($esxiHost.Name) 
                
                Restart-ESXiHost -esxiFqdn $esxiFqdn -user $($esxiCredential.username) -pass $($esxiCredential.password)
             
                # TODO Check if certificate is changed - reuse above certificate check "if cert is already changed"

                # Connect to vCenter server, then connect ESXi host to it and exit maintenance mode
                Write-Output "Exitting maintenance mode and connect to vCenter"
                $vcfVcenterDetails = Get-vCenterServerConnection -server $server -user $user -pass $pass -domain $domain 
                if ($vcfVcenterDetails) { 
                    Set-ESXiState -esxiFqdn $esxiFqdn -state "Connected" -timeout $timeout
                    #Start-Sleep 30
                    #Set-ESXiState -esxiFqdn $esxiFqdn -state "Connected"
                }
                else {
                    Write-Error "Could not connect to vCenter Server $vcfVcenterDetails. Check the state of ESXi host in vCenter"
                    break
                }
            }
            else {
                Write-Error "Could not find credentials for $esxiFqdn."
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
Export-ModuleMember -Function Install-EsxiCertificate
