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


Function Get-vCenterServer {
    <#
        .SYNOPSIS
        Retrieves the vCenter Server details and connection object via SDDC Manager using either a domain or ESXi FQDN

        .DESCRIPTION
        The cmdlet connects to SDDC Manager using the -server, -user, and -password values
        - Validates that network connectivity and authentication is possible to SDDC Manager
        - Validates that network connectivity and authentication is possible to vCenter Server
        - Validates that the workload domain exists in the SDDC Manager inventory
        - Connect to vCenter Server and returns its details and connection in a single object

        .EXAMPLE
        Get-vCenterServer -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -esxiFqdn sfo01-m01-esx03.sfo.rainpole.io

        .EXAMPLE 
        Get-vCenterServer -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01
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
            } else {
                $esxiHost = Get-VCFHost -fqdn $esxiFqdn
                if (!$esxiHost) {
                    Throw "ESXi host not found. Please check the provided FQDN: $esxiFqdn."
                }
                $domain = $(Get-VCFWorkloadDomain -id $($esxiHost.domain.id)).name
            }
            if ($vcfvCenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $domain) {
                if (Test-VsphereConnection -server $($vcfvCenterDetails.fqdn)) {
                    if ($connection = Connect-VIServer -server $vcfvCenterDetails.fqdn -user $vcfvCenterDetails.ssoAdmin -pass $vcfvCenterDetails.ssoAdminPass) {
                        $vcfvCenterServerObject = New-Object -TypeName psobject
                        $vcfvCenterServerObject | Add-Member -NotePropertyName 'details' -NotePropertyValue $vcfvCenterDetails 
                        $vcfvCenterServerObject | Add-Member -NotePropertyName 'connection' -NotePropertyValue $connection 
                        return $vcfvCenterServerObject
                    }
                }
            } else {
                Throw "Unable to return vCenter Server details: PRE_VALIDATION_FAILED"
            }
        } else {
            Throw "Unable to obtain access token from SDDC Manager ($server), check credentials: PRE_VALIDATION_FAILED"
        }
    } else {
        Throw "Unable to connect to ($server): PRE_VALIDATION_FAILED"
    }
}
#TODO: Remove export for helper function
Export-ModuleMember -Function Get-vCenterServer

Function Get-EsxiCertificateThumbprint {
    <#
        .SYNOPSIS
        Retrieves an ESXi host's certificate thumbprint.

        .DESCRIPTION
        The Get-EsxiCertificateThumbprint cmdlet retrieves an ESXi host's certificate thumbprint.

        .EXAMPLE
        Get-EsxiCertificateThumbprint -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -esxiFqdn sfo01-m01-esx01.sfo.rainpole.io
        This example retrieves the ESXI host's certificate thumbprint for an ESXi host with the FQDN of sfo01-m01-esx01.sfo.rainpole.io.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $esxiFqdn
    )
    
    Try {
        $vCenterServer = Get-vCenterServer -server $server -user $user -pass $pass -esxiFqdn $esxiFqdn
        $esxiCertificateThumbprint = $(Get-VIMachineCertificate -Server $($vCenterServer.details.fqdn) -VMHost $esxiFqdn).Certificate.Thumbprint
        return $esxiCertificateThumbprint                       
    }
    Catch {
        Debug-ExceptionWriter -object $_
    } Finally {
        if ($vCenterServer) { Disconnect-VIServer -server $vCenterServer.details.fqdn -Confirm:$false -WarningAction SilentlyContinue }
    }
}
Export-ModuleMember -Function Get-EsxiCertificateThumbprint


Function Get-vCenterCertificateThumbprint {
    <#
        .SYNOPSIS
        Retrieves either all of the vCenter Server instance's certificate thumbprints or those which match the provided issuer name.

        .DESCRIPTION
        The Get-vCenterCertificateThumbprint cmdlet retrieves the vCenter Server instance's certificate thumbprints. By default, it retrieves all thumbprints.         
        If issuer is provided, then only the thumbprint of the matching certificate is returned.


        .EXAMPLE
        Get-vCenterCertificateThumbprint -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 
        This example retrieves the certificate thumbprints for the vCenter Server instance belonging to the domain sfo-m01.      

        .EXAMPLE
        Get-vCenterCertificateThumbprint -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -issuer rainpole
        This example retrieves the vCenter Server instance's certificate thumbprints for the vCenter Server instance belonging to domain sfo-m01 and a matching issuer of rainpole.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $issuer
    )
    
    Try {
        $vCenterServer = Get-vCenterServer -server $server -user $user -pass $pass -domain $domain
        $vcTrustedCert = Get-VITrustedCertificate -Server $vCenterServer.details.fqdn
        
        if ($vcTrustedCert) {
            if ($PsBoundParameters.ContainsKey("issuer")) {
                $vcTrustedCert = $vcTrustedCert | Where-Object { $_.issuer -match $issuer }
            }
            $vcCertificateThumbprint = $vcTrustedCert.Certificate.Thumbprint
        } else {
            Write-Error "Unable to retrieve certificates from vCenter Server instance $($vCenterServer.details.fqdn)." -ErrorAction Stop
        }
        return $vcCertificateThumbprint                       
    }
    Catch {
        Debug-ExceptionWriter -object $_
    } Finally {
        if ($vCenterServer) { Disconnect-VIServer -server $vCenterServer.details.fqdn -Confirm:$false -WarningAction SilentlyContinue }
    }
}
Export-ModuleMember -Function Get-vCenterCertificateThumbprint


Function Confirm-ESXiCertificateInstalled {
    <#
        Verify if the provided certificate is already on the ESXi host. 

        .DESCRIPTION
        This cmdlet will get the thumbprint from the provided signed certificate and matches it with the certificate thumbprint from ESXi host. 
        You need to pass in the complete path for the certificate file. 
        Returns true if certificate is already installed, else returns false.

        .EXAMPLE
        Confirm-ESXiCertificateInstalled -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -esxiFqdn sfo01-w02-esx01.sfo.rainpole.io -signedCertificate F:\certificates\sfo01-w02-esx01.sfo.rainpole.io.cer
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
        } else {
            Write-Error "Could not find certificate in $signedCertificate." -ErrorAction Stop
            return
        }
        $esxiCertificateThumbprint = Get-EsxiCertificateThumbprint -server $server -user $user -pass $pass -esxiFqdn $esxiFqdn
        $crt = New-Object System.Security.Cryptography.X509Certificates.X509Certificate
        $crt.Import($signedCertificate)
        $signedCertThumbprint = $crt.GetCertHashString()

        if ($esxiCertificateThumbprint -eq $signedCertThumbprint) {
            Write-Host "Signed certificate thumbprint matches with the ESXi host certificate thumbprint."
            Write-Warning "Certificate is already installed on ESXi host $esxiFqdn : SKIPPED"
            return $true
        } else {
            Write-Host "ESXi host's certificate thumbprint ($esxiCertificateThumbprint) does not match with the thumbprint of provided certificate ($signedCertThumbprint)"
            Write-Host "Provided certificate is not installed on ESXi host $esxiFqdn."
            return $false
        }
    }
    Catch {
        Debug-ExceptionWriter -object $_
    }
}
Export-ModuleMember -Function Confirm-ESXiCertificateInstalled

Function Confirm-CAInvCenterServer {
    <#
        Verify the root certificate thumbprint matches with one of the CA thumbprints from vCenter Server instance.

        .DESCRIPTION
        This cmdlet will get the thumbprint from the root certificate and matches it with the CA thumbprint from the vCenter Server instance.
        You need to pass in the complete path for the certificate file. 
        Returns true if thumbprint matches, else returns false.

        .EXAMPLE
        Confirm-CAInvCenterServer -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -issuer rainpole -signedCertificate F:\certificates\Root64.cer
        This command will match the thumbprint of provided root certificate file with the thumbprints on the vCenter Server instance matching the issuer "rainpole".
    #>
    
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $signedCertificate,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $issuer
    )
    
    Try {

        if ($PsBoundParameters.ContainsKey("issuer")) { 
            $vcThumbprints = Get-vCenterCertificateThumbprint -server $server -user $user -pass $pass -domain $domain -issuer $issuer
        } else {
            $vcThumbprints = Get-vCenterCertificateThumbprint -server $server -user $user -pass $pass -domain $domain
        }
        if (Test-Path $signedCertificate -PathType Leaf ) {
            Write-Host "Certificate file found - $signedCertificate."
        } else {
            Write-Error "Could not find certificate in $signedCertificate." -ErrorAction Stop
            return
        }
        $crt = New-Object System.Security.Cryptography.X509Certificates.X509Certificate
        $crt.Import($signedCertificate)
        $signedCertThumbprint = $crt.GetCertHashString()

        $match = $false
        foreach ($vcThumbprint in $vcThumbprints) { 
            if ($vcThumbprint -eq $signedCertThumbprint) {
                Write-Host "Signed certificate thumbprint matches with the vCenter Server certificate authority thumbprint."
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

Export-ModuleMember -Function Confirm-CAInvCenterServer

Function Request-EsxiCsr {
    <#
        .SYNOPSIS
        Requests a Certificate Signing Request (CSR) for an ESXi host or a for each ESXi host in a cluster and saves it to file(s) in a directory.

        .DESCRIPTION
        The Request-EsxiCsr cmdlet will generate the Certificate Sign Request from a cluster or infividual ESXi host and saves it to file(s) in provided output directory.
        The cmdlet connects to SDDC Manager using the -server, -user, and -password values.
        - Validates that network connectivity and authentication is possible to SDDC Manager
        - Validates that the workload domain exists in the SDDC Manager inventory
        - Validates that network connectivity and authentication is possible to vCenter Server
        - Gathers the ESXi hosts from the cluster
        - Request ESXi CSR and save it in the output directory as FQDN.csr e.g. sfo01-m01-esx01.sfo.rainpole.io.csr
        - Defines possible counTry codes as per: https://www.digicert.com/kb/ssl-certificate-counTry-codes.htm

        .EXAMPLE
        Request-EsxiCsr -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -cluster sfo-m01-cl01 -country US -locality "Test Location" -organization "VMware LTD" -organizationUnit "VCF Deployment" -stateOrProvince "California" -outputDirectory F:\csr
        This example generates CSRs and stores them in the provided output directory for all ESXi hosts in the cluster sfo-m01-cl01 with the specified fields

    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $true, ParameterSetName = "cluster")] [ValidateNotNullOrEmpty()] [String] $cluster,
        [Parameter (Mandatory = $true, ParameterSetName = "host")] [ValidateNotNullOrEmpty()] [String] $esxiFqdn,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$outputDirectory,
        [Parameter (Mandatory = $true)] [ValidateSet ("US", "CA", "AX", "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AN", "AO", "AQ", "AR", "AS", "AT", "AU", `
                "AW", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BM", "BN", "BO", "BR", "BS", "BT", "BV", "BW", "BZ", "CA", "CC", "CF", "CH", "CI", "CK", `
                "CL", "CM", "CN", "CO", "CR", "CS", "CV", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", `
                "FM", "FO", "FR", "FX", "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM", "HN", `
                "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KR", "KW", "KY", "KZ", "LA", `
                "LC", "LI", "LK", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", `
                "MW", "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NT", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM", `
                "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW", "SA", "SB", "SC", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SR", "ST", `
                "SU", "SV", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TM", "TN", "TO", "TP", "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", `
                "VC", "VE", "VG", "VI", "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "COM", "EDU", "GOV", "INT", "MIL", "NET", "ORG", "ARPA")] [String]$country,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $locality,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $organization,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $organizationUnit,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $stateOrProvince
    
    )
    
    Try {
        if (!(Test-Path $outputDirectory)) {
            Write-Error "Please specify a valid directory to save the CSR files." -ErrorAction Stop
            return
        }
        $vCenterServer = Get-vCenterServer -server $server -user $user -pass $pass -domain $domain 
        if ($PsBoundParameters.ContainsKey("cluster")) {
            if (Get-Cluster | Where-Object { $_.Name -eq $cluster }) {
                $esxiHosts = Get-Cluster $cluster | Get-VMHost | Sort-Object -Property Name
                if (!$esxiHosts) { Write-Warning "No ESXi hosts found within $cluster cluster." }
            } else {
                Write-Error "Unable to locate cluster $cluster in vCenter Server instance $($vCenterServer.details.fqdn): PRE_VALIDATION_FAILED"
                Throw "Unable to locate cluster $cluster in vCenter Server $($vCenterServer.details.fqdn): PRE_VALIDATION_FAILED"
            }
        } else {
            $esxiHosts = Get-VMHost -Name $esxiFqdn
            if (!$esxiHosts) { Write-Warning "No ESXi host $esxiFqdn found within workload domain $domain." }
        }

        if ($esxiHosts) {
            foreach ($esxiHost in $esxiHosts) {
                $csrPath = "$outputDirectory\$($esxiHost.Name).csr"
                $esxRequest = New-VIMachineCertificateSigningRequest -Server $vCenterServer.details.fqdn -VMHost $esxiHost.Name -CounTry "$counTry" -Locality "$locality" -Organization "$organization" -OrganizationUnit "$organizationUnit" -StateOrProvince "$stateOrProvince" -CommonName $esxiHost.Name
                $esxRequest.CertificateRequestPEM | Out-File $csrPath -Force
                if (Test-Path $csrPath -PathType Leaf ) {
                    Write-Host "CSR for $($esxiHost.Name) has been generated and saved to $csrPath."
                } else {
                    Write-Error "Unable to generate CSR for $($esxiHost.name)."
                    Throw "Unable to generate CSR for $($esxiHost.name)."
                }
            }
        }                        
    } Catch {
        Debug-ExceptionWriter -object $_
    } Finally {
        if ($vCenterServer) { Disconnect-VIServer -server $vCenterServer.details.fqdn -Confirm:$false -WarningAction SilentlyContinue }
    }
}
Export-ModuleMember -Function Request-EsxiCsr


Function Get-vCenterCertManagementMode {
    <#
        .SYNOPSIS
        Retrieves the certificate management mode value from the vCenter Server instance for a workload domain.

        .DESCRIPTION
        Get-vCenterCertManagementMode cmdlet retrieves the certificate management mode value from vCenter Server instance for a workload domain.

        .EXAMPLE
        Get-vCenterCertManagementMode -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01
        This example retrieves the certificate management mode value for the vCenter Server instance for the domain sfo-m01.

    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain
    )
    
    Try {
        $vCenterServer = Get-vCenterServer -server $server -user $user -pass $pass -domain $domain
        $certModeSetting = Get-AdvancedSetting "vpxd.certmgmt.mode" -Entity $vCenterServer.connection
        return $certModeSetting.value
    } Catch {
        Debug-ExceptionWriter -object $_
    } Finally {
        if ($vCenterServer) { Disconnect-VIServer -server $vCenterServer.details.fqdn -Confirm:$false -WarningAction SilentlyContinue }
    }
}    

Export-ModuleMember -Function Get-vCenterCertManagementMode

Function Set-vCenterCertManagementMode {

    <#
        .SYNOPSIS
        Sets the ESXi host's management mode in the vCenter Server to either custom or vmca.

        .DESCRIPTION
        Set-vCenterCertManagementMode cmdlet sets the ESXi host's management mode on the vCenter server belonging to given domain.

        .EXAMPLE
        Set-vCenterCertManagementMode -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -mode custom
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
        $vCenterServer = Get-vCenterServer -server $server -user $user -pass $pass -domain $domain
        $certModeSetting = Get-AdvancedSetting "vpxd.certmgmt.mode" -Entity $vCenterServer.connection
        if ($certModeSetting.value -ne $mode) {
            Set-AdvancedSetting $certModeSetting -Value $mode
            Write-Host "Certificate Management Mode is set to $mode on the vCenter Server instance $($vCenterServer.details.fqdn)."
        } else {
            Write-Warning "Certificate Management Mode already set to $mode on the vCenter Server instance $($vCenterServer.details.fqdn): SKIPPED"
        }
    } Catch {
        Debug-ExceptionWriter -object $_
    } Finally {
        if ($vCenterServer) { Disconnect-VIServer -server $vCenterServer.details.fqdn -Confirm:$false -WarningAction SilentlyContinue }
    }
}
Export-ModuleMember -Function Set-vCenterCertManagementMode



Function Get-vSANHealthSummary {

    <#
        .SYNOPSIS
        Get the vSAN health summary from vCenter Server for given cluster 

        .DESCRIPTION
        This function gets the vSAN health summary from vCenter Server for a given cluster. If any status is YELLOW or RED, a WARNING or ERROR will be raised

        .EXAMPLE
        Get-vSANHealthSummary -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -cluster sfo-m01-cl01 
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
        $vCenterServer = Get-vCenterServer -server $server -user $user -pass $pass -domain $domain
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
                    Write-Warning "$($vCenterServer.details.fqdn) - vSAN cluster $cluster | vSAN Alarm Name - $healthCheckTestName | Alarm Description - $healthCheckTestShortDescription" 
                }
                if ($healthCheckTestHealth -eq "red") {
                    $overallStatus = ($overallStatus, 2 | Measure-Object -Max).Maximum
                    Write-Error "vSAN status is RED. Please check vSAN health before continuing..."
                    Write-Error "$($vCenterServer.details.fqdn) - vSAN Clustername $cluster | vSAN Alarm Name - $healthCheckTestName | Alarm Description - $healthCheckTestShortDescription" 
                }
            }
        }
        return $overallStatus
    }
    Catch {
        Debug-ExceptionWriter -object $_
    }
    Finally {
        if ($vCenterServer) { Disconnect-VIServer -server $vCenterServer.details.fqdn -Confirm:$false -WarningAction SilentlyContinue }
    }
}

Export-ModuleMember -Function Get-vSANHealthSummary


Function Get-EsxiConnectionState {
    <#
        .SYNOPSIS
        Get the ESXi host connection state from vCenter Server.

        .DESCRIPTION
        This cmdlet gets the current connection state of the ESXi host. Possible outputs are "Connected", "Disconnected", "Maintenance" and "NotResponding"
        Can only be used after you have run Get-vCenterServer cmdlet

        .EXAMPLE
        Get-EsxiConnectionState -esxiFqdn sfo01-m01-esx04.sfo.rainpole.io
    #>
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $esxiFqdn
    )
    $response = Get-VMHost -name $esxiFqdn
    return $response.ConnectionState
}
#TODO: Remove export for helper function
Export-ModuleMember -Function Get-EsxiConnectionState


Function Set-EsxiConnectionState {

    <#
        .SYNOPSIS
        Set the ESXi state from vCenter Server

        .DESCRIPTION
        This cmdlet sets the connection state of the ESXi host to the provided value. One of "Connected", "Disconnected", "Maintenance", or "NotResponding".
        If setting the connection state to Maintenance, you must provide the VsanDataMigrationMode. One of "Full", "EnsureAccessibility", or "NoDataMigration".
         Can only be used after you have run Get-vCenterServer cmdlet
        Default timeout 5 hrs (18000 seconds)

        .EXAMPLE
        Set-EsxiConnectionState -esxiFqdn sfo01-m01-esx04.sfo.rainpole.io -state Connected
        This example example sets the ESXi hosts state to Connected.
        
        .EXAMPLE
        Set-EsxiConnectionState -esxiFqdn sfo01-m01-esx04.sfo.rainpole.io -state Maintenance -VsanDataMigrationMode Full
        This example sets the ESXi host state to Maintenance with a Full data migration. 
    
    #>


    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $esxiFqdn,
        [Parameter (Mandatory = $true)] [ValidateSet ("Connected", "Disconnected", "Maintenance", "NotResponding")] [String]$state, 
        [Parameter (Mandatory = $false)] [ValidateSet ("Full", "EnsureAccessibility", "NoDataMigration")] [String]$vsanDataMigrationMode,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $timeout = 18000
    )
    
    if ($state -ieq (Get-EsxiConnectionState -esxiFqdn $esxiFqdn)) {
        Write-Warning "ESXi host $esxiFqdn is already in the $state connection state: SKIPPED"
        return
    }
    if ($state -ieq "maintenance") {
        if ($PSBoundParameters.ContainsKey("vsanDataMigrationMode")) {
            Write-Host "Entering $state connection state for ESXi host $esxiFqdn."
            Set-VMHost -VMHost $esxiFqdn -State $state -VsanDataMigrationMode $vsanDataMigrationMode -Evacuate
        } else {
            Throw "You must provide a valid vsanDataMigrationMode value."
        }
    } else {
        Write-Host "Changing the connection state for ESXi host $esxiFqdn to $state."
        Set-VMHost -VMHost $esxiFqdn -State $state
    }
    $timeout = New-TimeSpan -Seconds $timeout
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    do {
        $currentState = Get-EsxiConnectionState -esxiFqdn $esxiFqdn
        if ($state -ieq $currentState) {
            Write-Host "Successfully changed the connection state for ESXi host $esxiFqdn to $state."
            break
        } else {
            Write-Host "Polling every 60 seconds for state to change to $state..."
        }
        Start-Sleep -Seconds 60
    } while ($stopwatch.elapsed -lt $timeout)
}

#TODO: Remove export for helper function
Export-ModuleMember -Function Set-EsxiConnectionState


Function Get-ESXiLockdownMode {

    <#
        .SYNOPSIS
        Get the ESXi lockdown mode state from vCenter Server.

        .DESCRIPTION
        This cmdlet gets the lockdown mode value for all hosts in a cluster or a particular ESXi host within that cluster.
        If esxiFqdn is provided, only the value for that host is returned. 

        .EXAMPLE
        Get-ESXiLockdownMode -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -cluster sfo-m01-cl01
        This example retreives the lockdown mode state for each ESXi host in a cluster.

        .EXAMPLE
        Get-ESXiLockdownMode -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -cluster sfo-m01-cl01 -esxiFqdn sfo01-m01-esx01.sfo.rainpole.io
        This example retreives the lockdown mode state for a specific ESXi host in a cluster.
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
        $vCenterServer = Get-vCenterServer -server $server -user $user -pass $pass -domain $domain
        if (Get-Cluster | Where-Object { $_.Name -eq $cluster }) {
            if ($PsBoundParameters.ContainsKey("esxiFqdn")) {
                $esxiHosts = Get-Cluster $cluster | Get-VMHost -Name $esxiFqdn
            } else {
                $esxiHosts = Get-Cluster $cluster | Get-VMHost | Sort-Object -Property Name
            }
            if (!$esxiHosts) { Write-Warning "No ESXi hosts found within cluster $cluster." }
        } else {
            Write-Error "Unable to locate cluster $cluster in $($vCenterServer.details.fqdn) vCenter Server: PRE_VALIDATION_FAILED" -ErrorAction Stop
        }
        
        foreach ($esxiHost in $esxiHosts) {
            $lockdownMode = (Get-VMHost -name $esxiHost).ExtensionData.Config.LockdownMode
            Write-Host "ESXi host $esxiHost lockdown mode is set to $lockdownMode."
        }
        if ($PsBoundParameters.ContainsKey("esxiFqdn")) {
            return $lockdownMode
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
        Set-ESXiLockdownMode -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -cluster sfo-m01-cl01 -enable
        This example will enable the lockdown mode on all hosts in the provided cluster

         .EXAMPLE
        Set-ESXiLockdownMode -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -cluster sfo-m01-cl01 -disable
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
        $vCenterServer = Get-vCenterServer -server $server -user $user -pass $pass -domain $domain
        if (Get-Cluster | Where-Object { $_.Name -eq $cluster }) {
            $esxiHosts = Get-Cluster $cluster | Get-VMHost | Sort-Object -Property Name
            if (!$esxiHosts) { Write-Warning "No ESXi hosts found within $cluster cluster." }
        } else {
            Write-Error "Unable to locate Cluster $cluster in $($vCenterServer.details.fqdn) vCenter Server: PRE_VALIDATION_FAILED" -ErrorAction Stop
        }

        if ($PSBoundParameters.ContainsKey("enable")) {

            Write-Host "Enabling lockdown mode for each ESXi host in $cluster cluster"
            foreach ($esxiHost in $esxiHosts) {
                $currentLockdownMode = (Get-VMHost -name $esxiHost).ExtensionData.Config.LockdownMode
                if ($currentLockdownMode -eq "lockdownDisabled") {
                    ($esxiHost | Get-View).EnterLockdownMode()
                    Write-Host "Changing lockdown mode for ESXi host $esxiHost from $currentLockdownMode to lockdownNormal."
                    $newLockdownMode = (Get-VMHost -name $esxiHost).ExtensionData.Config.LockdownMode
                    if ($lockdownMode -eq $newLockdownMode) {
                        Write-Error "Unable to change lockdown mode for ESXi host $esxiHost from $currentLockdownMode to lockdownNormal. Lockdown mode is set to $newLockdownMode." -ErrorAction Stop}
                } else {
                    Write-Warning "Lockdown mode for ESXi host $esxiHost is already set to lockdownNormal: SKIPPED"
                }
            }
        } 
        
        if ($PSBoundParameters.ContainsKey("disable")) {
            Write-Host "Disabling lockdown mode for each ESXi host in $cluster cluster."
            foreach ($esxiHost in $esxiHosts) {
                $currentLockdownMode = (Get-VMHost -name $esxiHost).ExtensionData.Config.LockdownMode
                if ($currentLockdownMode -ne "lockdownDisabled") {
                    ($esxiHost | Get-View).ExitLockdownMode()
                    Write-Host "Changing lockdown mode for ESXi host $esxiHost from $currentLockdownMode to lockdownDisabled."
                    $newLockdownMode = (Get-VMHost -name $esxiHost).ExtensionData.Config.LockdownMode
                    if ($currentLockdownMode -eq $newLockdownMode) {
                        Write-Error "Unable to change lockdown mode for ESXi host $esxiHost from $currentLockdownMode to lockdownDisabled. Lockdown mode is set to $newLockdownMode." -ErrorAction Stop
                    }
                } else {
                    Write-Warning "Lockdown mode for ESXi host $esxiHost is already set to lockdownDisabled: SKIPPED"
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
        Restart-EsxiHost -esxiFqdn sfo01-m01-esx03.sfo.rainpole.io -user root -pass VMw@re1! -poll $true -timeout 1800 -pollInterval 30
        This example restarts the provided esxi hosts and polls every 30 seconds till it comes back online. It will timeout after 1800 seconds. 
    #>
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $esxiFqdn,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [bool] $poll = $true,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $timeout = 1800,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $pollInterval = 30
    )

    # Connect to ESXi host
    Connect-VIServer $esxiFqdn -User $user -password $pass -Force
    Write-Host "Restarting $esxiFqdn"
    $vmHost = Get-VMHost -Server $esxiFqdn
    if (!$vmHost) {
        Write-Error "Unable to locate ESXi host with FQDN $esxiFqdn : PRE_VALIDATION_FAILED" -ErrorAction Stop
        return
    }
    
    # Get ESXi uptime before restart
    $esxiUptime = New-TimeSpan -Start $vmHost.ExtensionData.Summary.Runtime.BootTime.ToLocalTime() -End (Get-Date)
    
    Restart-VMHost $esxiFqdn
    Disconnect-VIServer -server $esxiFqdn -Confirm:$false -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

    if ($poll) {
        Write-Host "Waiting for ESXi host $esxiFqdn to reboot. Polling the connection every $pollInterval seconds."
        Start-Sleep -Seconds $pollInterval
        $timeout = New-TimeSpan -Seconds $timeout
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        do {
            if ((Test-NetConnection -ComputerName $esxiFqdn -Port 443 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue).TcpTestSucceeded) {
                if (Connect-VIServer $esxiFqdn -User $user -Password $pass -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue) {
                    $vmHost = Get-VMHost -Server $esxiFqdn
                    $currentUpTime = New-TimeSpan -Start $vmHost.ExtensionData.Summary.Runtime.BootTime.ToLocalTime() -End (Get-Date)
                    if ($($esxiUptime.TotalSeconds) -gt $($currentUpTime.TotalSeconds)) {
                        Write-Host "ESXi host $esxiFqdn has been restarted and is now accessible."
                    } else {
                        Write-Host "ESXi host $esxiFqdn uptime: $($esxiUptime.TotalSeconds) | Current Uptime - $($currentUpTime.TotalSeconds)"
                    }
                    Disconnect-VIServer -Server $esxiFqdn -Confirm:$false -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null
                    return
                }
            }
            Write-Host "Waiting for ESXi host $esxiFqdn to reboot and become accessible."
            Start-Sleep -Seconds $pollInterval
        } while ($stopwatch.elapsed -lt $timeout)

        Write-Error "ESXi host $esxiFqdn did not respond after $($timeout.TotalMinutes) seconds. Please verify that the  ESXi host is online and accessible." -ErrorAction Stop
    } else {
        Write-Warning "Restart of ESXi host $esxiFqdn triggered without polling connection state. Please monitor the connection state in the vSphere Client."
    }        
}

Export-ModuleMember -Function Restart-EsxiHost


Function Install-EsxiCertificate {
    <#
        .SYNOPSIS
        Install a certificate for an ESXi host or for each ESXi host in a cluster.

        .DESCRIPTION
        The Install-EsxiCertificate cmdlet will replace the certificate for an ESXi host or for each ESXi host in a cluster
        (the behavior is controlled with parameter -cluster/-esxiFqdn). 
        You must provide the directory containing the signed certificate files
        Certificate names should be in format <FQDN>.crt e.g. sfo01-m01-esx01.sfo.rainpole.io.crt
        The workflow will put ESXi host in maintenance mode with full data migration, 
        disconnect ESXi host from the vCenter Server, replace the certificate, reboot the ESXi host, and exits maintenance mode once the ESXi host is online.
        Timeout for putting ESXi host in maintenance is provided in seconds using -timeout Parameter. Default is 18000 seconds or 5 hrs. 

        .EXAMPLE
        Install-EsxiCertificate -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -esxiFqdn sfo01-m01-esx03.sfo.rainpole.io -certificateDirectory F:\certificates -certificateFileExt ".cer"
        This example will install the certificate to the ESXi host sfo01-m01-esx03.sfo.rainpole.io in domain sfo-m01 from the provided path.
        
        Install-EsxiCertificate -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -cluster sfo-m01-cl01 -certificateDirectory F:\certificates -certificateFileExt ".cer"
        This example will install certificates for each ESXi host in cluster sfo-m01-cl01 in domain sfo-m01 from the provided path.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $true, ParameterSetName = "cluster")] [ValidateNotNullOrEmpty()] [String] $cluster,
        [Parameter (Mandatory = $true, ParameterSetName = "host")] [ValidateNotNullOrEmpty()] [String] $esxiFqdn,
        [Parameter (Mandatory = $true) ] [ValidateNotNullOrEmpty()] [String] $certificateDirectory,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $certificateFileExt = ".cer",
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $timeout = 18000
    )

    Try {
        $vCenterServer = Get-vCenterServer -server $server -user $user -pass $pass -domain $domain 
        if ($PsBoundParameters.ContainsKey("cluster")) {
            if (Get-Cluster | Where-Object { $_.Name -eq $cluster }) {
                $esxiHosts = Get-Cluster $cluster | Get-VMHost | Sort-Object -Property Name
                if (!$esxiHosts) { Write-Warning "No ESXi hosts found in cluster $cluster." }
            } else {
                Write-Error "Unable to locate cluster $cluster in $($vCenterServer.details.fqdn) vCenter Server: PRE_VALIDATION_FAILED" -ErrorAction Stop
            }
        } else {
            $esxiHosts = Get-VMHost -Name $esxiFqdn
            if (!$esxiHosts) { Write-Error "No ESXi host $esxiFqdn found in workload domain $domain." -ErrorAction Stop }
        }
    
        # Certificate replacement starts here
        $replacedHosts = New-Object Collections.Generic.List[String]
        $skippedHosts = New-Object Collections.Generic.List[String]
        foreach ($esxiHost in $esxiHosts) {
            $esxiFqdn = $esxiHost.Name
            $crtPath = "$certificateDirectory\$esxiFqdn$certificateFileExt"

            if (!(Test-Path $crtPath -PathType Leaf )) {
                Write-Error "Certificate not found at $crtPath. Skipping certificate replacement for ESXi host $esxiFqdn."
                $skippedHosts.Add($esxiFqdn)
                continue
            }

            if (Confirm-ESXiCertificateInstalled -server $server -user $user -pass $pass -esxiFqdn $esxiFqdn -signedCertificate $crtPath) {
                $skippedHosts.Add($esxiFqdn)
                continue
            } else {
                $esxiCredential = (Get-VCFCredential -resourcename $esxiFqdn | Where-Object { $_.username -eq "root" })
                if ($esxiCredential) {
                    Set-EsxiConnectionState -esxiFqdn $esxiFqdn -state "Maintenance" -VsanDataMigrationMode "Full" -timeout $timeout
                    Write-Host "Starting certificate replacement for ESXi host $esxiFqdn."                   
                    $esxCertificatePem = Get-Content $crtPath -Raw
                    Set-VIMachineCertificate -PemCertificate $esxCertificatePem -VMHost $esxifqdn
                    $replacedHosts.Add($esxiFqdn)
                    Restart-ESXiHost -esxiFqdn $esxiFqdn -user $($esxiCredential.username) -pass $($esxiCredential.password)
                
                    # Connect to vCenter Server, set the ESXi host connection state, and exit maintenance mode.
                    Write-Host "Connecting to vCenter Server instance $($vCenterServer.details.fqdn) and exiting ESXi host $esxiFqdn from maintenance mode."
                    $vCenterServer = Get-vCenterServer -server $server -user $user -pass $pass -domain $domain 
                    if ($vCenterServer) { 
                        Set-EsxiConnectionState -esxiFqdn $esxiFqdn -state "Connected" -timeout $timeout
                        Start-Sleep -Seconds 30
                        Set-EsxiConnectionState -esxiFqdn $esxiFqdn -state "Connected"
                    } else {
                        Write-Error "Could not connect to vCenter Server instance $($vCenterServer.details.fqdn). Check the state of ESXi host $esxiFqdn in vCenter Server." -ErrorAction Stop
                        break
                    }
                } else {
                    Write-Error "Unable to get credentials for ESXI host $esxiFqdn from SDDC Manager."
                    $skippedHosts.Add($esxiFqdn)
                }
            }
        }
        Write-Host "--------------------------------------------------------------------------------"
		Write-Host "ESXi Host Certificate Replacement Summary :"
		Write-Host "--------------------------------------------------------------------------------"

        Write-Host "Succesfully completed certificate replacement for $($replacedHosts.Count) ESXi hosts:"
        foreach ($replacedHost in $replacedHosts) {
            Write-Host "$replacedHost"
        }
        Write-Warning "Skipped certificate replacement for $($skippedHosts.Count) ESXi hosts:"
        foreach ($skippedHost in $skippedHosts) {
            Write-Warning "$skippedHost : SKIPPED"
        }
		Write-Host "--------------------------------------------------------------------------------"
    }
    Catch {
        Debug-ExceptionWriter -object $_
    }
    Finally {
        if ($vCenterServer) { Disconnect-VIServer -server $vCenterServer.details.fqdn -Confirm:$false -WarningAction SilentlyContinue }
    }
}

Export-ModuleMember -Function Install-EsxiCertificate
