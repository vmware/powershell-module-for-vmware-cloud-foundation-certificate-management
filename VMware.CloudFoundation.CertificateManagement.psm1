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
#####################################################  FUNCTIONS  #####################################################

Function Get-vCenterServer {
    <#
        .SYNOPSIS
        Retrieves the vCenter Server details and connection object from SDDC Manager using either a workload domain name or ESXi host FQDN.

        .DESCRIPTION
        The Get-vCenterServer retrieves the vCenter Server details and connection object from SDDC Manager using either a workload domain name or ESXi host FQDN.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values.
        - Validates that network connectivity and authentication is possible to SDDC Manager.
        - Validates that network connectivity and authentication is possible to vCenter Server.
        - Validates that the workload domain exists in the SDDC Manager inventory.
        - Connects to vCenter Server and returns its details and connection in a single object.

        .EXAMPLE
        Get-vCenterServer -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -esxiFqdn sfo01-m01-esx01.sfo.rainpole.io
        This example retrieves the vCenter Server details and connection object to which the ESXi host with the FQDN of sfo01-m01-esx01.sfo.rainpole.io belongs.

        .EXAMPLE
        Get-vCenterServer -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01
        This example retrieves the vCenter Server details and connection object belonging to the domain sfo-m01.

        .PARAMETER server
        The FQDN of the SDDC Manager appliance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER domain
        The name of the workload domain to retrieve the vCenter Server details from SDDC Manager for the connection object.

        .PARAMETER esxiFqdn
        The FQDN of the ESXi host to validate against the SDDC Manager inventory.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true, ParameterSetName = "domain")] [String] $domain,
        [Parameter (Mandatory = $true, ParameterSetName = "esxifqdn")] [String] $esxiFqdn
    )

    if (Test-VCFConnection -server $server) {
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

Function Get-EsxiCertificateThumbprint {
    <#
        .SYNOPSIS
        Retrieves an ESXi host's certificate thumbprint.

        .DESCRIPTION
        The Get-EsxiCertificateThumbprint cmdlet retrieves an ESXi host's certificate thumbprint.

        .EXAMPLE
        Get-EsxiCertificateThumbprint -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -esxiFqdn sfo01-m01-esx01.sfo.rainpole.io
        This example retrieves the ESXi host's certificate thumbprint for an ESXi host with the FQDN of sfo01-m01-esx01.sfo.rainpole.io.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER esxiFqdn
        The FQDN of the ESXi host to retrieve the certificate thumbprint.
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
        This example retrieves the vCenter Server instance's certificate thumbprints for the vCenter Server instance belonging to domain sfo-m01 and a matching issuer "rainpole".

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER domain
        The name of the workload domain to retrieve the vCenter Server instance's certificate thumbprints from.

        .PARAMETER issuer
        The name of the issuer to match with the vCenter Server instance's certificate thumbprints.
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


Function Test-EsxiCertMgmtChecks {

    <#
        .SYNOPSIS
        Run the checks required for ESXi Certificate Management for a given cluster or an ESXi host.

        .DESCRIPTION
        The Test-EsxiCertMgmtChecks runs the checks required for ESXi Certificate Management for a given cluster or an ESXi host.
        The following checks are run:
        - Check ESXi Certificate Mode
        - Check ESXi Lockdown Mode
        - Confirm CA In vCenter Server
        - Check vSAN Health Status

        .EXAMPLE
        Test-EsxiCertMgmtChecks -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -cluster sfo-m01-cl01 -issuer rainpole -signedCertificate F:\Certificates\Root64.cer
        This example runs the checks required for ESXi Certificate Management for the cluster belonging to the domain sfo-m01.

        .EXAMPLE
        Test-EsxiCertMgmtChecks -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -cluster sfo-m01-cl01 -esxiFqdn sfo01-m01-esx01.sfo.rainpole.io -issuer rainpole -signedCertificate F:\Certificates\Root64.cer
        This example runs the checks required for ESXi Certificate Management for an ESXi host belonging to the domain sfo-m01.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER domain
        The name of the workload domain to retrieve the vCenter Server instance's certificate thumbprints from.

        .PARAMETER cluster
        The name of the cluster in which the ESXi host is located.

        .PARAMETER esxiFqdn
        The FQDN of the ESXi host to verify the certificate thumbprint against.

        .PARAMETER signedCertificate
        The complete path for the signed certificate file.

        .PARAMETER issuer
        The name of the issuer to match with the vCenter Server instance's certificate thumbprints.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $cluster,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $esxiFqdn,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $signedCertificate,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $issuer
    )

    $errorMessage = @()
    $warningMessage = @()
    $statusMessage = @()

    Try {
		Write-Output "############## Running Prechecks for ESXi Certificate Management ###############"

		$status = "FAILED"
        $vCenterServer = Get-vCenterServer -server $server -user $user -pass $pass -domain $domain
        $mode = Get-EsxiCertificateMode -server $server -user $user -pass $pass -domain $domain
        if ($mode -ne "custom"){
            $msg = "Certificate Management Mode is not set to $mode on the vCenter Server instance $($vCenterServer.details.fqdn)."
            $errorMessage += $msg
        } else {
            $msg = "Certificate Management Mode is set to $mode on the vCenter Server instance $($vCenterServer.details.fqdn)."
            $statusMessage += $statusMessage
			$status = "PASSED"
        }

        Write-Output "Check ESXi Certificate Mode: $status"

		$status = "FAILED"
        if ($PsBoundParameters.ContainsKey("esxiFqdn")){
            $lockdownModes = Get-EsxiLockdownMode -server $server -user $user -pass $pass -domain $domain -cluster $cluster -esxiFqdn $esxiFqdn
        } else {
            $lockdownModes = Get-EsxiLockdownMode -server $server -user $user -pass $pass -domain $domain -cluster $cluster
        }

        foreach ($lockdownMode in $lockdownModes) {
            if ($lockdownMode -like "*lockdownDisabled*"){
                $statusMessage += $lockdownMode
				$status = "PASSED"
            } else {
                $errorMessage += $lockdownMode
            }
        }

		Write-Output "Check ESXi Lockdown Mode: $status"

		$status = "FAILED"
        $caStatus = Confirm-CAInvCenterServer -server sfo-vcf01.sfo.rainpole.io -user $user -pass $pass -domain $domain -issuer $issuer -signedCertificate $signedCertificate
        if ($caStatus -eq $true) {
            $msg = "Signed certificate thumbprint matches with the vCenter Server certificate authority thumbprint."
            $statusMessage += $msg
			$status = "PASSED"
        } elseif ($caStatus -eq $false) {
            $msg = "Signed certificate thumbprint does not match any of the vCenter Server certificate authority thumbprints."
            $errorMessage += $msg
        } else {
            $msg = "Error: Unable to Confirm CA In vCenter Server."
            $msg = $msg + $caStatus
            $errorMessage += $msg
        }

		Write-Output "Confirm CA In vCenter Server: $status"

		$status = "FAILED"
        $vsanStatus = Get-vSANHealthSummary -server sfo-vcf01.sfo.rainpole.io -user $user -pass $pass -domain $domain -cluster $cluster -errorAction SilentlyContinue -ErrorVariable errorMsg -WarningAction SilentlyContinue -WarningVariable warnMsg
        if ($warnMsg){
            $warningMessage += $warnMsg
            $status = "WARNING"
        }
        if ($errorMsg){
            $errorMessage += $errorMsg
        }
        if ($vsanStatus -eq 0){
            $status = "PASSED"
            $statusMessage += $vsanStatus
        }

        Write-Output "Check vSAN Health Status: $status"

		Write-Output "############## Finished Running Prechecks for ESXi Certificate Management ###############"

        if ($statusMessage){
            Write-Debug "############## Status of ESXi Certificate Management Prechecks : ###############"
			foreach ($msg in $statusMessage) {
				Write-Debug $msg
			}
        }

        if ($warningMessage){
			Write-Output "############## Warnings Raised While Running Prechecks for ESXi Certificate Management : ###############"
			foreach ($msg in $warningMessage) {
				Write-Warning $msg
			}
		}

		if ($errorMessage){
			Write-Output "############## Issues Found While Running Prechecks for ESXi Certificate Management : ###############"
			foreach ($msg in $errorMessage) {
				Write-Error $msg
			}
        }
    } Catch {
        Debug-ExceptionWriter -object $_
    }
}

Function Confirm-EsxiCertificateInstalled {
    <#
        .SYNOPSIS
        Verifies if the provided certificate is already on the ESXi host.

        .DESCRIPTION
        The Confirm-EsxiCertificateInstalled cmdlet will get the thumbprint from the provided signed certificate and matches it with the certificate thumbprint from ESXi host.
        You need to pass in the complete path for the certificate file.
        Returns true if certificate is already installed, else returns false.

        .EXAMPLE
        Confirm-EsxiCertificateInstalled -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -esxiFqdn sfo01-w01-esx01.sfo.rainpole.io -signedCertificate F:\certificates\sfo01-w01-esx01.sfo.rainpole.io.cer
        This example checks the thumbprint of the provided signed certificate with the thumbprint on ESXi host.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER esxiFqdn
        The FQDN of the ESXi host to verify the certificate thumbprint against.

        .PARAMETER signedCertificate
        The complete path for the signed certificate file.
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
            Write-Debug "Certificate file found - $signedCertificate"
        } else {
            Write-Error "Could not find certificate in $signedCertificate." -ErrorAction Stop
            return
        }
        $esxiCertificateThumbprint = Get-EsxiCertificateThumbprint -server $server -user $user -pass $pass -esxiFqdn $esxiFqdn
        $crt = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2($signedCertificate)
        $signedCertThumbprint = $crt.Thumbprint

        if ($esxiCertificateThumbprint -eq $signedCertThumbprint) {
            Write-Debug "Signed certificate thumbprint matches with the ESXi host certificate thumbprint."
            Write-Warning "Certificate is already installed on ESXi host $esxiFqdn : SKIPPED"
            return $true
        } else {
            Write-Debug "ESXi host's certificate thumbprint ($esxiCertificateThumbprint) does not match with the thumbprint of provided certificate ($signedCertThumbprint)"
            Write-Debug "Provided certificate is not installed on ESXi host $esxiFqdn."
            return $false
        }
    }
    Catch {
        Debug-ExceptionWriter -object $_
    }
}

Function Confirm-CAInvCenterServer {
    <#
        .SYNOPSIS
        Verifies the root certificate thumbprint matches with one of the CA thumbprints from vCenter Server instance.

        .DESCRIPTION
        The Confirm-CAInvCenterServer cmdlet gets the thumbprint from the root certificate and matches it with the CA thumbprint from the vCenter Server instance.
        You need to pass in the complete path for the certificate file.
        Returns true if thumbprint matches, else returns false.

        .EXAMPLE
        Confirm-CAInvCenterServer -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -issuer rainpole -signedCertificate F:\certificates\Root64.cer
        This example matches the thumbprint of provided root certificate file with the thumbprints on the vCenter Server instance matching the issuer "rainpole".

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER domain
        The name of the workload domain to retrieve the vCenter Server instance's certificate thumbprints from.

        .PARAMETER signedCertificate
        The complete path for the root certificate file.

        .PARAMETER issuer
        The name of the issuer to match with the thumbprint.
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
            Write-Output "Certificate file found - $signedCertificate."
        } else {
            Write-Error "Could not find certificate in $signedCertificate." -ErrorAction Stop
            return
        }

        $crt = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2($signedCertificate)
        $signedCertThumbprint = $crt.Thumbprint

        $match = $false
        foreach ($vcThumbprint in $vcThumbprints) {
            if ($vcThumbprint -eq $signedCertThumbprint) {
                Write-Output "Signed certificate thumbprint matches with the vCenter Server certificate authority thumbprint."
                $match = $true
                break
            }
        }
        if (!$match) {
            Write-Error "Signed certificate thumbprint does not match any of the vCenter Server certificate authority thumbprints."
        }
        return $match
    }
    Catch {
        Debug-ExceptionWriter -object $_
    }
}

Function Request-EsxiCsr {
    <#
        .SYNOPSIS
        Requests a certificate signing request (CSR) for an ESXi host or a for each ESXi host in a cluster and saves it to file(s) in a directory.

        .DESCRIPTION
        The Request-EsxiCsr cmdlet will generate the certificate signing request for ESXi host(s) and saves it to file(s) in an output directory.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values.
        - Validates that network connectivity and authentication is possible to SDDC Manager.
        - Validates that the workload domain exists in the SDDC Manager inventory.
        - Validates that network connectivity and authentication is possible to vCenter Server.
        - Gathers the ESXi hosts from the cluster.
        - Requests the ESXi host CSR and saves it in the output directory as <esxi-host-fqdn>.csr. e.g. sfo01-m01-esx01.sfo.rainpole.io.csr
        - Defines possible country codes. Reference: https://www.digicert.com/kb/ssl-certificate-country-codes.htm

        .EXAMPLE
        Request-EsxiCsr -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -cluster sfo-m01-cl01 -country US -locality "Palo Alto" -organization "VMware, Inc." -organizationUnit "Engineering" -stateOrProvince "California" -outputDirectory F:\csr
        This example generates CSRs and stores them in the provided output directory for all ESXi hosts in the cluster sfo-m01-cl01 with the specified fields.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER domain
        The name of the workload domain in which the cluster is located.

        .PARAMETER cluster
        The name of the cluster in which the ESXi host is located.

        .PARAMETER esxiFqdn
        The FQDN of the ESXi host to request certificate signing request (CSR) for.

        .PARAMETER country
        The country code for the certificate signing request (CSR).

        .PARAMETER locality
        The locality for the certificate signing request (CSR).

        .PARAMETER organization
        The organization for the certificate signing request (CSR).

        .PARAMETER organizationUnit
        The organization unit for the certificate signing request (CSR).

        .PARAMETER stateOrProvince
        The state or province for the certificate signing request (CSR).

        .PARAMETER outputDirectory
        The directory to save the certificate signing request (CSR) files.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $true, ParameterSetName = "cluster")] [ValidateNotNullOrEmpty()] [String] $cluster,
        [Parameter (Mandatory = $true, ParameterSetName = "host")] [ValidateNotNullOrEmpty()] [String] $esxiFqdn,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $outputDirectory,
        [Parameter (Mandatory = $true)] [ValidateSet ("US", "CA", "AX", "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AN", "AO", "AQ", "AR", "AS", "AT", "AU", `
                "AW", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BM", "BN", "BO", "BR", "BS", "BT", "BV", "BW", "BZ", "CA", "CC", "CF", "CH", "CI", "CK", `
                "CL", "CM", "CN", "CO", "CR", "CS", "CV", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", `
                "FM", "FO", "FR", "FX", "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM", "HN", `
                "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KR", "KW", "KY", "KZ", "LA", `
                "LC", "LI", "LK", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", `
                "MW", "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NT", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM", `
                "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW", "SA", "SB", "SC", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SR", "ST", `
                "SU", "SV", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TM", "TN", "TO", "TP", "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", `
                "VC", "VE", "VG", "VI", "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "COM", "EDU", "GOV", "INT", "MIL", "NET", "ORG", "ARPA")] [String] $country,
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
                $esxRequest = New-VIMachineCertificateSigningRequest -Server $vCenterServer.details.fqdn -VMHost $esxiHost.Name -Country "$country" -Locality "$locality" -Organization "$organization" -OrganizationUnit "$organizationUnit" -StateOrProvince "$stateOrProvince" -CommonName $esxiHost.Name
                $esxRequest.CertificateRequestPEM | Out-File $csrPath -Force
                if (Test-Path $csrPath -PathType Leaf ) {
                    Write-Output "CSR for $($esxiHost.Name) has been generated and saved to $csrPath."
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

Function Get-EsxiCertificateMode {
    <#
        .SYNOPSIS
        Retrieves the certificate management mode value from the vCenter Server instance for a workload domain.

        .DESCRIPTION
        The Get-EsxiCertificateMode cmdlet retrieves the certificate management mode value from vCenter Server instance for a workload domain.

        .EXAMPLE
        Get-EsxiCertificateMode -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01
        This example retrieves the certificate management mode value for the vCenter Server instance for the workload domain sfo-m01.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER domain
        The name of the workload domain to retrieve the certificate management mode value for.
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

Function Set-EsxiCertificateMode {
    <#
        .SYNOPSIS
        Sets the certificate management mode in vCenter Server for the ESXi hosts in a workload domain.

        .DESCRIPTION
        The Set-EsxiCertificateMode cmdlet sets the certificate management mode in vCenter Server for the ESXi hosts in a workload domain.

        .EXAMPLE
        Set-EsxiCertificateMode -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -mode custom
        This example sets the certificate management mode to custom in vCenter Server for the ESXi hosts in workload domain sfo-m01.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER domain
        The name of the workload domain to set the vCenter Server instance certificate management mode setting for.

        .PARAMETER mode
        The certificate management mode to set in vCenter Server. One of "custom" or "vmca".
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
            Set-AdvancedSetting $certModeSetting -Value $mode -confirm:$false
            Write-Output "Certificate Management Mode is set to $mode on the vCenter Server instance $($vCenterServer.details.fqdn)."
            Write-Output "Please restart the vCenter Server services for the change to take effect. See the vCenter Server Configuration documentation for information about restarting services."
        } else {
            Write-Warning "Certificate Management Mode already set to $mode on the vCenter Server instance $($vCenterServer.details.fqdn): SKIPPED"
        }
    } Catch {
        Debug-ExceptionWriter -object $_
    } Finally {
        if ($vCenterServer) { Disconnect-VIServer -server $vCenterServer.details.fqdn -Confirm:$false -WarningAction SilentlyContinue }
    }
}

Function Get-vSANHealthSummary {
    <#
        .SYNOPSIS
        Retrieves the vSAN health summary from vCenter Server for a cluster.

        .DESCRIPTION
        The Get-vSANHealthSummary cmdlet gets the vSAN health summary from vCenter Server for a cluster. If any status is YELLOW or RED, a WARNING or ERROR will be raised.

        .EXAMPLE
        Get-vSANHealthSummary -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -cluster sfo-m01-cl01
        This example gets the vSAN health summary for cluster sfo-m01-cl01.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER domain
        The name of the workload domain in which the cluster is located.

        .PARAMETER cluster
        The name of the cluster to retrieve the vSAN health summary for.
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

        if (!$vSANClusterHealthSystem) {
            Write-Error "Cannot run the Get-vSANHealthSummary cmdlet because the vSAN health service is not running."
            return 2
        }

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
                    Write-Error "vSAN status is RED. Please check the vSAN health before continuing."
                    Write-Error "$($vCenterServer.details.fqdn) - vSAN Clustername $cluster | vSAN Alarm Name - $healthCheckTestName | Alarm Description - $healthCheckTestShortDescription"
                }
            }
        }

        if ($overallStatus -eq 0){
            Write-Output "The vSAN health status for $cluster is GREEN."
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

Function Get-EsxiConnectionState {
    <#
        .SYNOPSIS
        Retrieves the ESXi host connection state from vCenter Server.

        .DESCRIPTION
        The Get-EsxiConnectionState cmdlet gets the connection state of an ESXi host. One of "Connected", "Disconnected", "Maintenance", or "NotResponding"
        Depends on a connection to a vCenter Server instance.

        .EXAMPLE
        Get-EsxiConnectionState -esxiFqdn sfo01-m01-esx01.sfo.rainpole.io
        This example gets an ESXi host's connection state.

        .PARAMETER esxiFqdn
        The FQDN of the ESXi host.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $esxiFqdn
    )

    $response = Get-VMHost -name $esxiFqdn
    return $response.ConnectionState
}

Function Set-EsxiConnectionState {
    <#
        .SYNOPSIS
        Sets the ESXi host connection state in vCenter Server.

        .DESCRIPTION
        The Set-EsxiConnectionState cmdlet sets the connection state of an ESXi host. One of "Connected", "Disconnected" or "Maintenance".
        If setting the connection state to Maintenance, you may provide the VsanDataMigrationMode for a vSAN environment. One of "Full", "EnsureAccessibility", or "NoDataMigration".
        Depends on a connection to a vCenter Server instance.

        .EXAMPLE
        Set-EsxiConnectionState -esxiFqdn sfo01-m01-esx01.sfo.rainpole.io -state Connected
        This example sets an ESXi host's connection state to Connected.

        .EXAMPLE
        Set-EsxiConnectionState -esxiFqdn sfo01-m01-esx01.sfo.rainpole.io -state Maintenance -vsanDataMigrationMode Full
        This example sets an ESXi host's connection state to Maintenance with a Full data migration.

        .PARAMETER esxiFqdn
        The FQDN of the ESXi host.

        .PARAMETER state
        The connection state to set the ESXi host to. One of "Connected", "Disconnected" or "Maintenance".

        .PARAMETER vsanDataMigrationMode
        The vSAN data migration mode to use when setting the ESXi host to Maintenance. One of "Full", "EnsureAccessibility", or "NoDataMigration".

        .PARAMETER timeout
        The timeout in seconds to wait for the ESXi host to reach the desired connection state. Default is 18000 seconds (5 hours).

        .PARAMETER pollInterval
        The poll interval in seconds to check the ESXi host connection state. Default is 60 seconds.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $esxiFqdn,
        [Parameter (Mandatory = $true)] [ValidateSet ("Connected", "Disconnected", "Maintenance")] [String] $state,
        [Parameter (Mandatory = $false)] [ValidateSet ("Full", "EnsureAccessibility", "NoDataMigration")] [String] $vsanDataMigrationMode,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $timeout = 18000,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $pollInterval = 60
    )

    if ($state -ieq (Get-EsxiConnectionState -esxiFqdn $esxiFqdn)) {
        Write-Warning "ESXi host $esxiFqdn is already in the $state connection state: SKIPPED"
        return
    }
    if ($state -ieq "maintenance") {
        if ($PSBoundParameters.ContainsKey("vsanDataMigrationMode")) {
            Write-Output "Entering $state connection state for ESXi host $esxiFqdn with vSAN data migration mode set to $vsanDataMigrationMode."
            Set-VMHost -VMHost $esxiFqdn -State $state -VsanDataMigrationMode $vsanDataMigrationMode -Evacuate -confirm:$false
        } else {
            Write-Output "Entering $state connection state for ESXi host $esxiFqdn."
            Set-VMHost -VMHost $esxiFqdn -State $state -Evacuate -confirm:$false
        }
    } else {
        Write-Output "Changing the connection state for ESXi host $esxiFqdn to $state."
        Set-VMHost -VMHost $esxiFqdn -State $state -confirm:$false
    }
    $timeout = New-TimeSpan -Seconds $timeout
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    do {
        $currentState = Get-EsxiConnectionState -esxiFqdn $esxiFqdn
        if ($state -ieq $currentState) {
            Write-Output "Successfully changed the connection state for ESXi host $esxiFqdn to $state."
            break
        } else {
            if ($state -ieq "Connected"){
                Set-VMHost -VMHost $esxiFqdn -State $state -confirm:$false -ErrorAction SilentlyContinue -ErrorVariable $errMsg -WarningAction SilentlyContinue
            }
            Write-Output "Polling the connection every $pollInterval seconds. Waiting for the connection state to change to $state."
        }
        Start-Sleep -Seconds $pollInterval
    } while ($stopwatch.elapsed -lt $timeout)
}

Function Get-EsxiLockdownMode {
    <#
        .SYNOPSIS
        Retrieves the ESXi host lockdown mode state from vCenter Server.

        .DESCRIPTION
        The Get-EsxiLockdownMode cmdlet gets the lockdown mode value for all ESXi hosts in a given cluster or for a given ESXi host within the cluster.
        If esxiFqdn is provided, only the value for that host is returned.

        .EXAMPLE
        Get-EsxiLockdownMode -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -cluster sfo-m01-cl01
        This example retrieves the lockdown mode for each ESXi host in a cluster.

        .EXAMPLE
        Get-EsxiLockdownMode -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -cluster sfo-m01-cl01 -esxiFqdn sfo01-m01-esx01.sfo.rainpole.io
        This example retrieves the lockdown mode state for an ESXi host in a given cluster.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER domain
        The name of the workload domain in which the cluster is located.

        .PARAMETER cluster
        The name of the cluster in which the ESXi host is located.

        .PARAMETER esxiFqdn
        The FQDN of the ESXi host to retrieve the lockdown mode state for.
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
            Write-Output "ESXi host $esxiHost lockdown mode is set to $lockdownMode."
        }
        if ($PsBoundParameters.ContainsKey("esxiFqdn")) {
            return $lockdownMode
        }
    }
    Catch {
        Debug-ExceptionWriter -object $_
    }
}

Function Set-EsxiLockdownMode {
    <#
        .SYNOPSIS
        Sets the lockdown mode for all ESXi hosts in a given cluster.

        .DESCRIPTION
        The Set-EsxiLockdownMode cmdlet sets the lockdown mode for all ESXi hosts in a given cluster.

        .EXAMPLE
        Set-EsxiLockdownMode -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -cluster sfo-m01-cl01 -enable
        This example will enable the lockdown mode for all ESXi hosts in a cluster.

        .EXAMPLE
        Set-EsxiLockdownMode -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -cluster sfo-m01-cl01 -disable
        This example will disable the lockdown mode for all ESXi hosts in a cluster.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER domain
        The name of the workload domain in which the cluster is located.

        .PARAMETER cluster
        The name of the cluster in which the ESXi host is located.

        .PARAMETER enable
        Enable lockdown mode for the ESXi host(s).

        .PARAMETER disable
        Disable lockdown mode for the ESXi host(s).
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

            Write-Output "Enabling lockdown mode for each ESXi host in $cluster cluster"
            foreach ($esxiHost in $esxiHosts) {
                $currentLockdownMode = (Get-VMHost -name $esxiHost).ExtensionData.Config.LockdownMode
                if ($currentLockdownMode -eq "lockdownDisabled") {
                    ($esxiHost | Get-View).EnterLockdownMode()
                    Write-Output "Changing lockdown mode for ESXi host $esxiHost from $currentLockdownMode to lockdownNormal."
                    $newLockdownMode = (Get-VMHost -name $esxiHost).ExtensionData.Config.LockdownMode
                    if ($lockdownMode -eq $newLockdownMode) {
                        Write-Error "Unable to change lockdown mode for ESXi host $esxiHost from $currentLockdownMode to lockdownNormal. Lockdown mode is set to $newLockdownMode." -ErrorAction Stop}
                } else {
                    Write-Warning "Lockdown mode for ESXi host $esxiHost is already set to lockdownNormal: SKIPPED"
                }
            }
        }

        if ($PSBoundParameters.ContainsKey("disable")) {
            Write-Output "Disabling lockdown mode for each ESXi host in $cluster cluster."
            foreach ($esxiHost in $esxiHosts) {
                $currentLockdownMode = (Get-VMHost -name $esxiHost).ExtensionData.Config.LockdownMode
                if ($currentLockdownMode -ne "lockdownDisabled") {
                    ($esxiHost | Get-View).ExitLockdownMode()
                    Write-Output "Changing lockdown mode for ESXi host $esxiHost from $currentLockdownMode to lockdownDisabled."
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

Function Restart-EsxiHost {
    <#
        .SYNOPSIS
        Restarts an ESXi host and poll for connection availability.

        .DESCRIPTION
        The Restart-EsxiHost cmdlet restarts an ESXi host and polls for connection availability.
        Timeout value is in seconds.

        .EXAMPLE
        Restart-EsxiHost -esxiFqdn sfo01-m01-esx01.sfo.rainpole.io -user root -pass VMw@re1! -poll $true -timeout 1800 -pollInterval 30
        This example restarts an ESXi host and polls the connection availability every 30 seconds. It will timeout after 1800 seconds.

        .PARAMETER esxiFqdn
        The FQDN of the ESXi host.

        .PARAMETER user
        The username to authenticate to the ESXi host.

        .PARAMETER pass
        The password to authenticate to the ESXi host.

        .PARAMETER poll
        Poll for connection availability after restarting the ESXi host. Default is true.

        .PARAMETER timeout
        The timeout value in seconds. Default is 1800 seconds.

        .PARAMETER pollInterval
        The poll interval in seconds. Default is 30 seconds.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $esxiFqdn,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [bool] $poll = $true,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $timeout = 1800,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $pollInterval = 30
    )

    # Connect to the ESXi host.
    Connect-VIServer $esxiFqdn -User $user -password $pass -Force
    $vmHost = Get-VMHost -Server $esxiFqdn
    if (!$vmHost) {
        Write-Error "Unable to locate ESXi host with FQDN $esxiFqdn : PRE_VALIDATION_FAILED" -ErrorAction Stop
        return
    } else {
        Write-Output "Restarting $esxiFqdn"
    }

    # Retrieves the ESXi host uptime before restart.
    $esxiUptime = New-TimeSpan -Start $vmHost.ExtensionData.Summary.Runtime.BootTime.ToLocalTime() -End (Get-Date)

    Restart-VMHost $esxiFqdn -server $esxiFqdn -Confirm:$false

    Disconnect-VIServer -server $esxiFqdn -Confirm:$false -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

    if ($poll) {
        Write-Output "Waiting for ESXi host $esxiFqdn to restart. Polling the connection every $pollInterval seconds."
        Start-Sleep -Seconds $pollInterval
        $timeout = New-TimeSpan -Seconds $timeout
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        do {
            if (Test-EsxiConnection -server $esxiFqdn) {
                if (Connect-VIServer $esxiFqdn -User $user -Password $pass -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue) {
                    $vmHost = Get-VMHost -Server $esxiFqdn
                    $currentUpTime = New-TimeSpan -Start $vmHost.ExtensionData.Summary.Runtime.BootTime.ToLocalTime() -End (Get-Date)
                    if ($($esxiUptime.TotalSeconds) -gt $($currentUpTime.TotalSeconds)) {
                        Write-Output "ESXi host $esxiFqdn has been restarted and is now accessible."
                    } else {
                        Write-Output "ESXi host $esxiFqdn uptime: $($esxiUptime.TotalSeconds) | Current Uptime - $($currentUpTime.TotalSeconds)"
                    }
                    Disconnect-VIServer -Server $esxiFqdn -Confirm:$false -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null
                    return
                }
            }
            Write-Output "Waiting for ESXi host $esxiFqdn to restart and become accessible."
            Start-Sleep -Seconds $pollInterval
        } while ($stopwatch.elapsed -lt $timeout)
        Write-Error "ESXi host $esxiFqdn did not respond after $($timeout.TotalMinutes) seconds. Please verify that the  ESXi host is online and accessible." -ErrorAction Stop
    } else {
        Write-Warning "Restart of ESXi host $esxiFqdn triggered without polling connection state. Please monitor the connection state in the vSphere Client."
    }
}

Function Install-EsxiCertificate {
    <#
        .SYNOPSIS
        Installs a certificate for an ESXi host or for each ESXi host in a cluster.

        .DESCRIPTION
        The Install-EsxiCertificate cmdlet will replace the certificate for an ESXi host or for each ESXi host in a cluster.
        You must provide the directory containing the signed certificate files.
        Certificate names should be in format <FQDN>.crt e.g. sfo01-m01-esx01.sfo.rainpole.io.crt.
        The workflow will put the ESXi host in maintenance mode with full data migration,
        disconnect the ESXi host from the vCenter Server, replace the certificate, restart the ESXi host,
        and the exit maintenance mode once the ESXi host is online.

        .EXAMPLE
        Install-EsxiCertificate -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -esxiFqdn sfo01-m01-esx01.sfo.rainpole.io -certificateDirectory F:\certificates -certificateFileExt ".cer"
        This example will install the certificate to the ESXi host sfo01-m01-esx01.sfo.rainpole.io in domain sfo-m01 from the provided path.

        .EXAMPLE
        Install-EsxiCertificate -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -domain sfo-m01 -cluster sfo-m01-cl01 -certificateDirectory F:\certificates -certificateFileExt ".cer"
        This example will install certificates for each ESXi host in cluster sfo-m01-cl01 in workload domain sfo-m01 from the provided path.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER domain
        The name of the workload domain in which the ESXi host is located.

        .PARAMETER cluster
        The name of the cluster in which the ESXi host is located.

        .PARAMETER esxiFqdn
        The FQDN of the ESXi host.

        .PARAMETER certificateDirectory
        The directory containing the signed certificate files.

        .PARAMETER certificateFileExt
        The file extension of the certificate files. One of ".crt", ".cer", ".pem", ".p7b", or ".p7c".

        .PARAMETER timeout
        The timeout in seconds for putting the ESXi host in maintenance mode. Default is 18000 seconds (5 hours).
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $true, ParameterSetName = "cluster")] [ValidateNotNullOrEmpty()] [String] $cluster,
        [Parameter (Mandatory = $true, ParameterSetName = "host")] [ValidateNotNullOrEmpty()] [String] $esxiFqdn,
        [Parameter (Mandatory = $true) ] [ValidateNotNullOrEmpty()] [String] $certificateDirectory,
        [Parameter (Mandatory = $true)] [ValidateSet(".crt", ".cer", ".pem", ".p7b", ".p7c")] [String] $certificateFileExt,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $timeout = 18000
    )

    Try {
        $vCenterServer = Get-vCenterServer -server $server -user $user -pass $pass -domain $domain
        if ($PsBoundParameters.ContainsKey("cluster")) {
            $clusterDetails = Get-VCFCluster -Name $cluster
            if ($clusterDetails) {
                $esxiHosts =  Get-VCFHost | Where-Object { $_.cluster.id -eq $clusterDetails.id } | Sort-Object -Property fqdn
                if (!$esxiHosts) { Write-Warning "No ESXi hosts found in cluster $cluster." }
            } else {
                Write-Error "Unable to locate cluster $cluster in $($vCenterServer.details.fqdn) vCenter Server: PRE_VALIDATION_FAILED" -ErrorAction Stop
            }
        } else {
            $esxiHosts = Get-VCFHost -fqdn $esxiFqdn
            if (!$esxiHosts) { Write-Error "No ESXi host $esxiFqdn found in workload domain $domain." -ErrorAction Stop }
        }

        # Certificate replacement starts here.
        $replacedHosts = New-Object Collections.Generic.List[String]
        $skippedHosts = New-Object Collections.Generic.List[String]
        foreach ($esxiHost in $esxiHosts) {
            $esxiFqdn = $esxiHost.fqdn
            $crtPath = "$certificateDirectory\$esxiFqdn$certificateFileExt"

            if (!(Test-Path $crtPath -PathType Leaf )) {
                Write-Error "Certificate not found at $crtPath. Skipping certificate replacement for ESXi host $esxiFqdn."
                $skippedHosts.Add($esxiFqdn)
                continue
            }

            if (Confirm-EsxiCertificateInstalled -server $server -user $user -pass $pass -esxiFqdn $esxiFqdn -signedCertificate $crtPath) {
                $skippedHosts.Add($esxiFqdn)
                continue
            } else {
                $esxiCredential = (Get-VCFCredential -resourcename $esxiFqdn | Where-Object { $_.username -eq "root" })
                if ($esxiCredential) {
                    if ($clusterDetails.primaryDatastoreType -ieq "vsan") {
                        Set-EsxiConnectionState -esxiFqdn $esxiFqdn -state "Maintenance" -VsanDataMigrationMode "Full" -timeout $timeout
                    } else {
                        Set-EsxiConnectionState -esxiFqdn $esxiFqdn -state "Maintenance" -timeout $timeout
                    }
                    Write-Output "Starting certificate replacement for ESXi host $esxiFqdn."
                    $esxCertificatePem = Get-Content $crtPath -Raw
                    Set-VIMachineCertificate -PemCertificate $esxCertificatePem -VMHost $esxiFqdn -ErrorAction Stop -Confirm:$false
                    $replacedHosts.Add($esxiFqdn)

                    # Disconnect ESXi host from vCenter Server prior to restarting an ESXi host.
                    Set-EsxiConnectionState -esxiFqdn $esxiFqdn -state "Disconnected" -timeout $timeout
                    Restart-ESXiHost -esxiFqdn $esxiFqdn -user $($esxiCredential.username) -pass $($esxiCredential.password)

                    # Connect to vCenter Server, set the ESXi host connection state, and exit maintenance mode.
                    Write-Output "Connecting to vCenter Server instance $($vCenterServer.details.fqdn) and exiting ESXi host $esxiFqdn from maintenance mode."
                    $vCenterServer = Get-vCenterServer -server $server -user $user -pass $pass -domain $domain
                    if ($vCenterServer) {
                        Set-EsxiConnectionState -esxiFqdn $esxiFqdn -state "Connected" -timeout $timeout
                        Start-Sleep -Seconds 30
                        Set-EsxiConnectionState -esxiFqdn $esxiFqdn -state "Connected"
                    } else {
                        Write-Error "Could not connect to vCenter Server instance $($vCenterServer.details.fqdn). Check the state of ESXi host $esxiFqdn using the Get-EsxiConnectionState cmdlet." -ErrorAction Stop
                        break
                    }
                } else {
                    Write-Error "Unable to get credentials for ESXi host $esxiFqdn from SDDC Manager."
                    $skippedHosts.Add($esxiFqdn)
                }
            }
        }
        Write-Output "--------------------------------------------------------------------------------"
		Write-Output "ESXi Host Certificate Replacement Summary:"
		Write-Output "--------------------------------------------------------------------------------"
        Write-Output "Succesfully completed certificate replacement for $($replacedHosts.Count) ESXi hosts:"
        foreach ($replacedHost in $replacedHosts) {
            Write-Output "$replacedHost"
        }
        Write-Warning "Skipped certificate replacement for $($skippedHosts.Count) ESXi hosts:"
        foreach ($skippedHost in $skippedHosts) {
            Write-Warning "$skippedHost : SKIPPED"
        }
		Write-Output "--------------------------------------------------------------------------------"
    }
    Catch {
        Debug-ExceptionWriter -object $_
    }
    Finally {
        if ($vCenterServer) { Disconnect-VIServer -server $vCenterServer.details.fqdn -Confirm:$false -WarningAction SilentlyContinue }
    }
}

Function Set-SddcCertificateAuthority {
    <#
        .SYNOPSIS
        Sets the certificate authority in SDDC Manager to use a Microsoft Certificate Authority.

        .DESCRIPTION
        The Set-SddcCertificateAuthority will configure Microsoft Certificate Authority as SDDC Manager's Certificate Authority.

        .EXAMPLE
        Set-SddcCertificateAuthority -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -certAuthorityFqdn rpl-ad01.rainpole.io -certAuthorityUser svc-vcf-ca -certAuthorityPass VMw@re1! -certAuthorityTemplate VMware
        This example will configure Microsoft Certificate Authority rpl-ad01.rainpole.io in SDDC Manger.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER certAuthorityFqdn
        The fully qualified domain name of the Microsoft Certificate Authority.

        .PARAMETER certAuthorityUser
        The username to authenticate to the Microsoft Certificate Authority.

        .PARAMETER certAuthorityPass
        The password to authenticate to the Microsoft Certificate Authority.

        .PARAMETER certAuthorityTemplate
        The Certificate Template Name to be used with the Microsoft Certificate Authority.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $certAuthorityFqdn,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $certAuthorityUser,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $certAuthorityPass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $certAuthorityTemplate
    )

    if (Test-VCFConnection -server $server) {
        if ((Test-EndpointConnection -server $certAuthorityFqdn -port 443) -eq "True" ) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
                $vcfVersion = Get-VCFManager | select version | Select-String -Pattern '\d+\.\d+' -AllMatches | ForEach-Object {$_.matches.groups[0].value}
                $caServerUrl = "https://$certAuthorityFqdn/certsrv"
                Try {
                    Write-Output "Starting configuration of a Microsoft Certificate Authority in SDDC Manager..."
                    Write-Output "Checking status of the Microsoft Certificate Authority configuration..."
                    $vcfCertCa = Get-VCFCertificateAuthority
                    if ($vcfCertCa.username -ne "$certAuthorityUser") {
                        Write-Output "Configuring the Microsoft Certificate Authority in SDDC Manager using $($certAuthorityUser)..."
                        Set-VCFMicrosoftCA -serverUrl $caServerUrl -username $certAuthorityUser -password $certAuthorityPass -templateName $certAuthorityTemplate | Out-Null
                        Write-Output "Configuration of the Microsoft Certificate Authority in SDDC Manager using ($($certAuthorityUser)): SUCCESSFUL."
                    } else {
                        Write-Warning "Configuration of the Microsoft Certificate Authority in SDDC Manager using ($($certAuthorityUser)), already exists: SKIPPED."
                    }
                    Write-Output "Configuration a Microsoft Certificate Authority in SDDC Manager completed."
                } Catch {
                    $ErrorMessage = $_.Exception.Message
                    Write-Output "Error was: $ErrorMessage."
                }
            } else {
                Write-Error "Unable to authenticate to SDDC Manager ($($server)): PRE_VALIDATION_FAILED."
            }
        } else {
            Write-Error "Unable to connect to Microsoft Certificate Authority ($certAuthorityFqdn)."
        }
    } else {
        Write-Error "Unable to connect to SDDC Manager ($($server)): PRE_VALIDATION_FAILED."
    }
}

Function gatherSddcInventory {
    Param (
        [Parameter (Mandatory = $true)] $domainType,
        [Parameter (Mandatory = $true)] $workloadDomain
    )

    # Gathers deployment details from SDDC Manager.
    $sddcMgr = Get-VCFManager
    $sddcMgrVersion = $sddcMgr.version.split(".")[0]

    $resourcesObject = @()
    
    # SDDC Manager
    if ($domainType -eq "Management") {
        $resourcesObject += [pscustomobject]@{
            'fqdn'       = $sddcMgr.fqdn
            'name'       = $sddcMgr.fqdn.split(".")[0]
            'resourceId' = $sddcMgr.id
            'type'       = "SDDC_MANAGER"
        }
    }

    # vRealize Suite Lifecycle Manager
    if ($domainType -eq "Management") {
        $vrslcmNode = Get-VCFvRSLCM
        if ($vrslcmNode.id -ne "") {
            $resourcesObject += [pscustomobject]@{
                'fqdn'       = $vrslcmNode.fqdn
                'name'       = $vrslcmNode.fqdn.split(".")[0]
                'resourceId' = $vrslcmNode.id
                'type'       = "VRSLCM"
            }
        }
    }

    # vCenter Server
    if (([float]$sddcMgrVersion -ge 4) -AND ($domainType -eq "Management")) {
        $domain = Get-VCFWorkloadDomain | Where-Object { $_.type -eq "MANAGEMENT" }
        $vCenterServer = Get-VCFvCenter | Where-Object { $_.domain.id -eq $domain.id }
    } else {
        $domain = Get-VCFWorkloadDomain | Where-Object { $_.name -eq $workloadDomain }
        $vCenterServer = Get-VCFvCenter | Where-Object { $_.domain.id -eq $domain.id }
    }

    foreach ($vCenter in $vCenterServer) {
        $resourcesObject += [pscustomobject]@{
            'fqdn'       = $vCenter.fqdn
            'name'       = $vCenter.fqdn.split(".")[0]
            'resourceId' = $vCenter.id
            'type'       = "VCENTER"
        }
    }

    # NSX
    if ([float]$sddcMgrVersion -ge 4) {
        $nsxtManager = Get-VCFNsxtCluster | Where-Object { $_.domains.id -eq $domain.id }
        $nsxtSans = @()
        foreach ($nodeFqdn in $nsxtManager.nodes.fqdn) {
            $nsxtSans += $nodeFqdn
        }
        $nsxtSans += $nsxtManager.vipFqdn
        $nsxtvip = $nsxtManager.vipfqdn

        foreach ($nsxManager in $nsxtManager) {
            $resourcesObject += [pscustomobject]@{
                'fqdn'       = $nsxtvip
                'name'       = $nsxtvip.split(".")[0]
                'resourceId' = $nsxManager.id
                'sans'       = $nsxtSans
                'type'       = "NSXT_MANAGER"
            }
        }

        foreach ($nsxNode in $nsxtManager.nodes) {
            $resourcesObject += [pscustomobject]@{
                'fqdn'       = $nsxNode.fqdn
                'name'       = $nsxNode.name
                'resourceId' = $nsxNode.id
                'type'       = "NSXT_MANAGER"
            }
        }
    }
    Return $resourcesObject
}

Function Request-SddcCsr {
    <#
        .SYNOPSIS
        Requests SDDC Manager to generate and store certificate signing request files.

        .DESCRIPTION
        The Request-SddcCsr will request SDDC Manager to generate certifiate signing request files for all components associated with the given workload domain.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values.
        - Validates that network connectivity and authentication is possible to SDDC Manager.
        - Validates that the workload domain exists in the SDDC Manager inventory.
        - Defines possible country codes. Reference: https://www.digicert.com/kb/ssl-certificate-country-codes.htm

        .EXAMPLE
        Request-SddcCsr -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -workloadDomain sfo-w01 -country US -keysize "3072" -locality "San Francisco" -organization "Rainpole" -organizationUnit "IT" -stateOrProvince "California" -email "admin@rainpole.io"
        This example will request SDDC Manager to generate certificate signing request files for all components associated with the given workload domain.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER workloadDomain
        The name of the workload domain in which the certficates signing request to be generated.

        .PARAMETER country
        The country code for the certificate signing request (CSR).

        .PARAMETER keySize
        The key size for the certificate signing request (CSR).

        .PARAMETER locality
        The locality for the certificate signing request (CSR).

        .PARAMETER organization
        The organization for the certificate signing request (CSR).

        .PARAMETER organizationUnit
        The organization unit for the certificate signing request (CSR).

        .PARAMETER stateOrProvince
        The state or province for the certificate signing request (CSR).

        .PARAMETER email
        The contact email for the certificate signing request (CSR).
    #>
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $workloadDomain,
        [Parameter (Mandatory = $true)] [ValidateSet ("US", "CA", "AX", "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AN", "AO", "AQ", "AR", "AS", "AT", "AU", `
                "AW", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BM", "BN", "BO", "BR", "BS", "BT", "BV", "BW", "BZ", "CA", "CC", "CF", "CH", "CI", "CK", `
                "CL", "CM", "CN", "CO", "CR", "CS", "CV", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", `
                "FM", "FO", "FR", "FX", "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM", "HN", `
                "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KR", "KW", "KY", "KZ", "LA", `
                "LC", "LI", "LK", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", `
                "MW", "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NT", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM", `
                "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW", "SA", "SB", "SC", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SR", "ST", `
                "SU", "SV", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TM", "TN", "TO", "TP", "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", `
                "VC", "VE", "VG", "VI", "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "COM", "EDU", "GOV", "INT", "MIL", "NET", "ORG", "ARPA")] [String] $country,
        [Parameter (Mandatory = $true)] [ValidateSet ("2048", "3072", "4096")] [String] $keySize,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $locality,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $organization,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $organizationUnit,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $stateOrProvince,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $email
    )

    if (Test-VCFConnection -server $server) {
        if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
            $domainType = Get-VCFWorkloadDomain -name $workloadDomain
            $resourcesObject = gatherSddcInventory -domainType $domainType.type -workloadDomain $workloadDomain

            # Create a temporary directory under current directory
            $createPathCounter = 0
			for ($createPathCounter -lt 4) {
				$randomOutput = -join (((48..57)+(65..90)+(97..122)) * 80 |Get-Random -Count 6 |%{[char]$_})
				$tempPath = Join-Path -Path $pwd -childPath $randomOutput
				if (!(Test-Path -Path $tempPath)) {
					Break
				} else {
					if ($createPathCounter -eq 3) {
						Write-Error "Unable to write to ($tempPath): PRE_VALIDATION_FAILED.."
                        Exit
					}
					$createPathCounter++
				}
			}
			New-Item -Path $tempPath -ItemType Directory | Out-NULL
            $tempPath = Join-Path $tempPath ""

            # Generate a temporay JSON configuration file
            $csrGenerationSpecJson =
            '{
            "csrGenerationSpec": {
                "country": "'+ $country + '",
                "email": "'+ $email + '",
                "keyAlgorithm": "'+ "RSA" + '",
                "keySize": "'+ $keySize + '",
                "locality": "'+ $locality + '",
                "organization": "'+ $organization + '",
                "organizationUnit": "'+ $organizationUnit + '",
                "state": "'+ $stateOrProvince + '"
                },
            '
            $resourcesBodyObject += [pscustomobject]@{
                resources = $resourcesObject
            }
            $resourcesBodyObject | ConvertTo-Json -Depth 10 | Out-File -FilePath $tempPath"temp.json"
            Get-Content $tempPath"temp.json" | Select-Object -Skip 1 | Set-Content $tempPath"temp1.json"
            $resouresJson = Get-Content $tempPath"temp1.json" -Raw
            $requestCsrSpecJson = $csrGenerationSpecJson + $resouresJson
            $requestCsrSpecJson | Out-File $tempPath"$($workloadDomain)-requestCsrSpec.json"
            Write-Output "Requesting certificate signing requests for components associated with workload domain ($($workloadDomain))..."
            $myTask = Request-VCFCertificateCSR -domainName $($workloadDomain) -json $tempPath"$($workloadDomain)-requestCsrSpec.json"
            Do {
                Write-Output "Checking status for the generation of certificate signing requests for components associated with workload domain ($($workloadDomain))..."
                Start-Sleep 6
                $response = Get-VCFTask $myTask.id
            } While ($response.status -eq "IN_PROGRESS")
            if ($response.status -eq "FAILED") {
                Write-Output "Workflow completed with status: $($response.status)." 
            } elseif ($response.status -eq "SUCCESSFUL") {
                Write-Output "Workflow completed with status: $($response.status)."
            } else {
                Write-Warning "Workflow completed with an unrecognized status: $($response.status). Please check before proceeding."
            }
            Write-Output "Generate certificate signing requests for components associated with workload domain $($workloadDomain)."

            # Remove the temporary directory.
			Remove-Item -Recurse -Force $tempPath | Out-NULL
        } else {
            Write-Error "Unable to authenticate to SDDC Manager ($($server)): PRE_VALIDATION_FAILED."
        }
    } else {
        Write-Error "Unable to connect to SDDC Manager ($($server)): PRE_VALIDATION_FAILED."
    }
}

Function Request-SddcCertificate {
    <#
        .SYNOPSIS
        Requests SDDC Manager to connect to certificate authority to sign the certificate signing request files and to store the signed certificates.

        .DESCRIPTION
        The Request-SddcCertificate will request SDDC Manager to connect to the certificate authority to sign the generated certificate signing request files for all components associated with the given workload domain

        .EXAMPLE
        Request-SddcCertificate -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -workloadDomain sfo-w01
        This example will connect to SDDC Manager to request to have the certificate signing request files for a given workload domain to be signed.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER workloadDomain
        The name of the workload domain in which the certficates signing request to be signed.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $workloadDomain
    )

    if (Test-VCFConnection -server $server) {
        if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
            $domainType = Get-VCFWorkloadDomain -name $workloadDomain
            $resourcesObject = gatherSddcInventory -domainType $domainType.type -workloadDomain $workloadDomain

            # Create a temporary directory under current directory
            $createPathCounter = 0
			for ($createPathCounter -lt 4) {
				$randomOutput = -join (((48..57)+(65..90)+(97..122)) * 80 |Get-Random -Count 6 |%{[char]$_})
				$tempPath = Join-Path -Path $pwd -childPath $randomOutput
				if (!(Test-Path -Path $tempPath)) {
					Break
				} else {
					if ($createPathCounter -eq 3) {
						Write-Error "Unable to write to $tempPath."
                        Exit
					}
					$createPathCounter++
				}
			}
			New-Item -Path $tempPath -ItemType Directory | Out-NULL
            $tempPath = Join-Path $tempPath ""

            # Generate a temporay JSON configuration file
            $caTypeJson = '{
                "caType": "Microsoft",
                '
                $resourcesBodyObject += [pscustomobject]@{
                    resources = $resourcesObject
                }
                $resourcesBodyObject | ConvertTo-Json -Depth 10 | Out-File -FilePath $tempPath"temp.json"
                Get-Content $tempPath"temp.json" | Select-Object -Skip 1 | Set-Content $tempPath"temp1.json"
                $resouresJson = Get-Content $tempPath"temp1.json" -Raw
                $requestCertificateSpecJson = $caTypeJson + $resouresJson
                $requestCertificateSpecJson | Out-File $tempPath"$($workloadDomain)-requestCertificateSpec.json"

                Write-Output "Requesting certificates for components associated with workload domain $($workloadDomain)."
                $myTask = Request-VCFCertificate -domainName $($workloadDomain) -json $tempPath"$($workloadDomain)-requestCertificateSpec.json"
                Do {
                    Write-Output "Checking status for the generation of signed certificates for components associated with workload domain ($($workloadDomain))..."
                    Start-Sleep 6
                    $response = Get-VCFTask $myTask.id
                } While ($response.status -eq "IN_PROGRESS")
                if ($response.status -eq "FAILED") {
                    Write-Error "Workflow completed with status: $($response.status)." 
                } elseif ($response.status -eq "SUCCESSFUL") {
                    Write-Output "Workflow completed with status: $($response.status)."
                } else {
                    Write-Warning "Workflow completed with an unrecognized status: $($response.status). Please check the state before proceeding."
                }
                Write-Output "Request signed certficates for the components associated with workload domain $($workloadDomain) completed with status: $($response.status)."

                # Remove the temporary directory.
			    Remove-Item -Recurse -Force $tempPath  | Out-NULL
        } else {
            Write-Error "Unable to authenticate to SDDC Manager ($($server)): PRE_VALIDATION_FAILED."
        }
    } else {
        Write-Error "Unable to connect to SDDC Manager ($($server)): PRE_VALIDATION_FAILED."
    }
}

Function Install-SddcCertificate {
    <#
        .SYNOPSIS
        Installs the signed certificates for all components associated with the given workload domain.

        .DESCRIPTION
        The Install-SddcCertificate will install the signed certificates for all components associated with the given workload domain.

        .EXAMPLE
        Install-SddcCertificate -server sfo-vcf01.sfo.rainpole.io -user administrator@vsphere.local -pass VMw@re1! -workloadDomain sfo-w01
        This example will connect to SDDC Manager to install the signed certificates for a given workload domain.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER workloadDomain
        The name of the workload domain in which the certficates signing request to be installed.
    #>
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $workloadDomain
    )

    if (Test-VCFConnection -server $server) {
        if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
            $domainType = Get-VCFWorkloadDomain -name $workloadDomain
            $resourcesObject = gatherSddcInventory -domainType $domainType.type -workloadDomain $workloadDomain

            # Create a temporary directory under current directory
            $createPathCounter = 0
			for ($createPathCounter -lt 4) {
				$randomOutput = -join (((48..57)+(65..90)+(97..122)) * 80 |Get-Random -Count 6 |%{[char]$_})
				$tempPath = Join-Path -Path $pwd -childPath $randomOutput
				if (!(Test-Path -Path $tempPath)) {
					Break
				} else {
					if ($createPathCounter -eq 3) {
						Write-Error "Unable to write to $tempPath."
                        Exit
					}
					$createPathCounter++
				}
			}
			New-Item -Path $tempPath -ItemType Directory | Out-NULL
            $tempPath = Join-Path $tempPath ""

            # Generate a temporay JSON configuration file
            $operationTypeJson = '{
                "operationType": "INSTALL",
                '
              $resourcesBodyObject += [pscustomobject]@{
                  resources = $resourcesObject
              }
              $resourcesBodyObject | ConvertTo-Json -Depth 10 | Out-File -FilePath $tempPath"temp.json"
              Get-Content $tempPath"temp.json" | Select-Object -Skip 1 | Set-Content $tempPath"temp1.json"
              $resouresJson = Get-Content $tempPath"temp1.json" -Raw
              $requestCertificateSpecJson = $operationTypeJson + $resouresJson
              $requestCertificateSpecJson | Out-File $tempPath"$($workloadDomain)-updateCertificateSpec.json"

              # Install Certificates
              Try {
                Write-Output "Installing signed certificates for components associated with workload domain $($workloadDomain). This process may take some time to complete (60 minutes or greater)..."
                $myTaskId = Set-VCFCertificate -domainName $($workloadDomain) -json $tempPath"$($workloadDomain)-updateCertificateSpec.json"
                $pollLoopCounter = 0
                Do {
                    if ($pollLoopCounter % 10 -eq 0) {
                        Write-Output "Checking status for the Installation of signed certificates for components associated with workload domain ($($workloadDomain))..."
                    }
                    $response = Get-VCFTask $myTaskId.id
                    if ($response.status -in "In Progress","IN_PROGRESS") {
                        if (($pollLoopCounter % 10 -eq 0) -AND ($pollLoopCounter -gt 9)) {
                            Write-Output "Installation of signed certificates is still in progress for workload domain ($($workloadDomain))..."
                        }
                        Start-Sleep 60
                        $pollLoopCounter ++
                    }
                } While ($response.status -in "In Progress","IN_PROGRESS")
                if ($response.status -eq "FAILED") {
                    Write-Error "Workflow completed with status: $($response.status)." 
                } elseif ($response.status -eq "SUCCESSFUL") {
                    Write-Output "Workflow completed with status: $($response.status)."
                } else {
                    Write-Warning "Workflow completed with an unrecognized status: $($response.status). Please review the state before proceeding."
                }
                Write-Output "Installation of signed certificates for components associated with workload domain $($workloadDomain) completed with status: $($response.status)."

                # Remove the temporary directory.
			    Remove-Item -Recurse -Force $tempPath  | Out-NULL
            } Catch {
                $ErrorMessage = $_.Exception.Message
                Write-Error "Error was: $ErrorMessage"
            }
        } else {
            Write-Error "Unable to authenticate to SDDC Manager ($($server)): PRE_VALIDATION_FAILED."
        }
    } else {
        Write-Error "Unable to connect to SDDC Manager ($($server)): PRE_VALIDATION_FAILED."
    }
}

###################################################  END FUNCTIONS  ###################################################
#######################################################################################################################

