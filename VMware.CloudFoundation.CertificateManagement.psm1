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
############################# GENERATE SIGNED CERTIFICATE FUNCTIONS  ##################################################



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
        if (Test-Connection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $esxiHost = Get-VCFHost -fqdn $esxiFqdn
                if (!$esxiHost){
                    Write-Error "ESXi host not found. Please check the provided FQDN $esxiFqdn"
                    return 
                }
                $domain = $(Get-VCFWorkloadDomain -id $($esxiHost.domain.id)).name
                if ($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $domain) {
                    if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                        if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                            $esxiTrustedThumbprint = $(Get-VITrustedCertificate -Server $($vcfVcenterDetails.fqdn) -VMHost $esxiFqdn).Certificate.Thumbprint
                            return $esxiTrustedThumbprint
                        }
                        Disconnect-VIServer $vcfVcenterDetails.fqdn -Confirm:$false -WarningAction SilentlyContinue
                    }
                }
            }
        }
    }
    Catch {
        Debug-ExceptionWriter -object $_
    }
}
Export-ModuleMember -Function Get-EsxiTrustedCertificateThumbprint



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
        - Gathers the ESXi 
        - Request ESXi CSR and save it in the working directory as FQDN.csr e.g. sfo01-m01-esx01.sfo.rainpole.io.csr

        .EXAMPLE
        Get-EsxiCSR -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re123! -domain sfo-m01 -cluster sfo-m01-cl01 -Country US -Locality "Test Location" -Organization "VMware LTD" -OrganizationUnit "VCF Deployment" -StateOrProvince "California" -outputFolder F:\csr
        This example generates CSRs and stores them in the working directory for all ESXi hosts in the cluster "production" with the specified properties

    #>

    # Define possible country codes as per: https://www.digicert.com/kb/ssl-certificate-country-codes.htm
    #Set-Variable -Name "CertificateCountryCodes" -Option Constant -Value 

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
        if (!(Test-Path $outputFolder)){
            Write-Error "Please specify a valid directory to save the CSR files."
            return
        }
        if (Test-Connection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                if (Get-VCFWorkloadDomain | Where-Object { $_.name -eq $domain }) {
                    if (($vcfVcenterDetails = Get-vCenterServerDetail -server $server -user $user -pass $pass -domain $domain)) {
                        if (Test-VsphereConnection -server $($vcfVcenterDetails.fqdn)) {
                            if (Test-VsphereAuthentication -server $vcfVcenterDetails.fqdn -user $vcfVcenterDetails.ssoAdmin -pass $vcfVcenterDetails.ssoAdminPass) {
                                if ($PsBoundParameters.ContainsKey("cluster")) {
                                    if (Get-Cluster | Where-Object {$_.Name -eq $cluster}) {
                                        $esxiHosts = Get-Cluster $cluster | Get-VMHost | Sort-Object -Property Name
                                        if (!$esxiHosts) { Write-Warning "No ESXi hosts found within $cluster cluster." }
                                    }
                                    else {
                                        Write-Error "Unable to locate Cluster $cluster in $($vcfVcenterDetails.fqdn) vCenter Server: PRE_VALIDATION_FAILED"
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
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                else {
                    Write-Error "Unable to locate workload domain $domain in $server SDDC Manager Server: PRE_VALIDATION_FAILED"
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