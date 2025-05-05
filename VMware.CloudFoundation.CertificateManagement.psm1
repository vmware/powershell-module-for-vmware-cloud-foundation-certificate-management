# © Broadcom. All Rights Reserved.
# The term “Broadcom” refers to Broadcom Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-2

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# Allow communication with self-signed certificates when using Powershell Core. If you require all communications to be
# secure and do not wish to allow communication with self-signed certificates, remove lines 20-40 before importing the
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

##########################################################################
#Region     Non Exported Functions                                  ######
Function Get-Password {
    param (
        [string]$user,
        [string]$password
    )

    if ([string]::IsNullOrEmpty($password)) {
        $secureString = Read-Host -Prompt "Enter the password for $user" -AsSecureString
        $password = ConvertFrom-SecureString $secureString -AsPlainText
    }
    return $password
}

Function Get-VcenterService {
    <#
    .DESCRIPTION
    The Get-VcenterService retrieves the service's current status and health from vCenter and returns with an
    ordered hash object with the service name and health.

    .EXAMPLE
    Get-VcenterService -serviceName "certificateauthority"
    This example retrieves the status and health of the vCenter service named "certificateauthority"

    .PARAMETER serviceName
    The name of the vCenter service.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $serviceName
    )

    $serviceExists = Invoke-GetService -Service $serviceName -ErrorAction SilentlyContinue
    if ($serviceExists -eq $null) {
        Write-Error "Service $serviceName does not exist." -ErrorAction Stop
        Exit
    } else {
        return [ordered]@{
            name   = $serviceName
            status = $serviceExists.state
            health = $serviceExists.health
        }
    }
}

Function Restart-VcenterService {
    <#
    .DESCRIPTION
    The Restart-VcenterService restart the vCenter service taken from parameter value and returns a hash object
    with the service name, the service status, and the result from restart operation.

    .EXAMPLE
    Restart-VcenterService -serviceName "certificateauthority"
    This example restart the vCenter service named "certificateauthority"

    .PARAMETER serviceName
    The name of the vCenter service.
    #>
    param (
        [string]$serviceName
    )

    Invoke-RestartService -Service $serviceName | Out-Null

    for ($count = 0; $count -lt 16; $count++) {
        $serviceStatus = Get-VcenterService -Service $serviceName
        if ($serviceStatus.status -eq "STARTED" -and $serviceStatus.health -eq "HEALTHY") {
            return [ordered]@{
                name   = $serviceName
                status = "GREEN"
                result = "Successfully restarted service."
            }
        } elseif ($serviceStatus.status -eq "STARTING" -or $serviceStatus.status -eq "STOPPING") {
            # Service is still starting or stopped state; sleep for 20 seconds before retry.
            Sleep-Time -Seconds 20
        } elseif ($serviceStatus.status -eq "STARTED" -and $serviceStatus.health -eq "HEALTHY_WITH_WARNINGS") {
            return [ordered]@{
                name   = $serviceName
                status = "YELLOW"
                result = "Issues restarting service: the health state is HEALTHY_WITH_WARNINGS."
            }
        } elseif (($serviceStatus.status -eq "STARTED") -and ($serviceStatus.health -eq "DEGRADED")) {
            return [ordered]@{
                name   = $serviceName
                status = "RED"
                result = "Failed restarting service: the health state is DEGRADED."
            }
        } elseif ($serviceStatus.status -eq "STOPPED") {
            return [ordered]@{
                name   = $serviceName
                status = "RED"
                result = "Failed restarting service: the service status is STOPPED."
            }
        } elseif ($count -gt 14) {
            # Operation timed out
            return [ordered]@{
                name   = $serviceName
                status = "RED"
                result = "Failed restarting service: unable to retrieve service status. Operation timed out."
            }
        }
    }
}

#EndRegion  Non Exported Functions                                  ######
##########################################################################

#######################################################################################################################
#####################################################  FUNCTIONS  #####################################################

Function Get-vCenterServer {
    <#
        .SYNOPSIS
        Retrieves the vCenter details and connection object from SDDC Manager using either a workload domain
        name or ESX host FQDN.

        .DESCRIPTION
        The Get-vCenterServer retrieves the vCenter details and connection object from SDDC Manager using either
        a workload domain name or ESX host FQDN.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values.
        - Validates that network connectivity and authentication is possible to SDDC Manager.
        - Validates that network connectivity and authentication is possible to vCenter.
        - Validates that the workload domain exists in the SDDC Manager inventory.
        - Connects to vCenter and returns its details and connection in a single object.

        .EXAMPLE
        Get-vCenterServer -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -esxiFqdn [esx_host_fqdn]
        This example retrieves the vCenter details and connection object to which the ESX host with the fully qualified domain name belongs.

        .EXAMPLE
        Get-vCenterServer -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name]
        This example retrieves the vCenter details and connection object belonging to the domain.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager appliance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER domain
        The name of the workload domain to retrieve the vCenter details from SDDC Manager for the connection object.

        .PARAMETER esxiFqdn
        The fully qualified domain name of the ESX host to validate against the SDDC Manager inventory.
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
                    Throw "ESX host not found. Please check the provided FQDN: $esxiFqdn."
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
                Throw "Unable to return vCenter details: PRE_VALIDATION_FAILED"
            }
        } else {
            Throw "Unable to obtain access token from SDDC Manager ($server), check credentials: PRE_VALIDATION_FAILED"
        }
    } else {
        Throw "Unable to connect to ($server): PRE_VALIDATION_FAILED"
    }
}

Function Get-VcfCertificateThumbprint {
    <#
        .SYNOPSIS
        Retrieves certificate thumbprints for ESX hosts or vCenter instances.

        .DESCRIPTION
        The Get-VcfCertificateThumbprint cmdlet retrieves certificate thumbprints for ESX hosts or vCenter
        instances.

        .EXAMPLE
        Get-VcfCertificateThumbprint -esxi -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -esxiFqdn [esx_host_fqdn]
        This example retrieves the ESX host's certificate thumbprint for an ESX host.

        .EXAMPLE
        Get-VcfCertificateThumbprint -vcenter -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -issuer [issuer_name]
        This example retrieves the vCenter instance's certificate thumbprints for the vCenter instance belonging to domain and a matching issuer.

        .PARAMETER esxi
        Switch to retrieve the certificate thumbprint for an ESX host.

        .PARAMETER vcenter
        Switch to retrieve the certificate thumbprints for a vCenter instance.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER domain
        The name of the workload domain (only required when using the "vCenter" parameter).

        .PARAMETER issuer
        The name of the issuer to match with the vCenter instance's certificate thumbprints (only required when using the "vCenter" parameter).
    #>

    Param (
        [Parameter (Mandatory = $true, ParameterSetName = "ESX")] [ValidateNotNullOrEmpty()] [Switch] $esxi,
        [Parameter (Mandatory = $true, ParameterSetName = "vCenter")] [ValidateNotNullOrEmpty()] [Switch] $vcenter,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $false, ParameterSetName = "ESX")] [ValidateNotNullOrEmpty()] [String] $esxiFqdn,
        [Parameter (Mandatory = $false, ParameterSetName = "vCenter")] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $false, ParameterSetName = "vCenter")] [ValidateNotNullOrEmpty()] [String] $issuer
    )

    $pass = Get-Password -User $user -Password $pass

    Try {
        if ($PsBoundParameters.ContainsKey("esxi")) {
            $vCenterServer = Get-vCenterServer -server $server -user $user -pass $pass -esxiFqdn $esxiFqdn
            $esxiCertificateThumbprint = $(Get-VIMachineCertificate -Server $($vCenterServer.details.fqdn) -VMHost $esxiFqdn).Certificate.Thumbprint
            return $esxiCertificateThumbprint
        } else {
            $vCenterServer = Get-vCenterServer -server $server -user $user -pass $pass -domain $domain
            $vcTrustedCert = Get-VITrustedCertificate -Server $vCenterServer.details.fqdn

            if ($vcTrustedCert) {
                if ($PsBoundParameters.ContainsKey("issuer")) {
                    $vcTrustedCert = $vcTrustedCert | Where-Object { $_.issuer -match $issuer }
                }
                $vcCertificateThumbprint = $vcTrustedCert.Certificate.Thumbprint
                return $vcCertificateThumbprint
            } else {
                Write-Error "Unable to retrieve certificates from vCenter instance $($vCenterServer.details.fqdn)." -ErrorAction Stop
            }
        }
    } Catch {
        Debug-ExceptionWriter -object $_
    } Finally {
        if ($vCenterServer) { Disconnect-VIServer -server $vCenterServer.details.fqdn -Confirm:$false -WarningAction SilentlyContinue }
    }
}

Function Test-EsxiCertMgmtChecks {
    <#
        .SYNOPSIS
        Run the checks required for ESX Certificate Management for a given cluster or an ESX host.

        .DESCRIPTION
        The Test-EsxiCertMgmtChecks runs the checks required for ESX Certificate Management for a given cluster or an
        ESX host. The following checks are run:
        - Check ESX Certificate Mode
        - Check ESX Lockdown Mode
        - Confirm CA In vCenter
        - Check vSAN Health Status

        .EXAMPLE
        Test-EsxiCertMgmtChecks -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -cluster [cluster_name] -issuer [issuer_name] -signedCertificate [full_certificate_file_path]
        This example runs the checks required for ESX Certificate Management for the cluster belonging to the domain.

        .EXAMPLE
        Test-EsxiCertMgmtChecks -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -cluster [cluster_name] -esxiFqdn [esx_host_fqdn] -issuer [issuer_name] -signedCertificate [full_certificate_file_path]
        This example runs the checks required for ESX Certificate Management for an ESX host belonging to the domain.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER domain
        The name of the workload domain to retrieve the vCenter instance's certificate thumbprints from.

        .PARAMETER cluster
        The name of the cluster in which the ESX host is located.

        .PARAMETER esxiFqdn
        The fully qualified domain name of the ESX host to verify the certificate thumbprint against.

        .PARAMETER signedCertificate
        The complete path for the signed certificate file.

        .PARAMETER issuer
        The name of the issuer to match with the vCenter instance's certificate thumbprints.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $cluster,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $esxiFqdn,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $signedCertificate,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $issuer
    )

    $pass = Get-Password -User $user -Password $pass

    $errorMessage = @()
    $warningMessage = @()
    $statusMessage = @()

    Try {
        Write-Output "############## Running Prechecks for ESX Certificate Management ###############"

        $status = "FAILED"
        $vCenterServer = Get-vCenterServer -server $server -user $user -pass $pass -domain $domain
        $mode = Get-EsxiCertificateMode -server $server -user $user -pass $pass -domain $domain
        if ($mode -ne "custom") {
            $msg = "Certificate Management Mode is not set to $mode on the vCenter instance $($vCenterServer.details.fqdn)."
            $errorMessage += $msg
        } else {
            $msg = "Certificate Management Mode is set to $mode on the vCenter instance $($vCenterServer.details.fqdn)."
            $statusMessage += $statusMessage
            $status = "PASSED"
        }

        Write-Output "Check ESX Certificate Mode: $status"

        $status = "FAILED"
        if ($PsBoundParameters.ContainsKey("esxiFqdn")) {
            $lockdownModes = Get-EsxiLockdownMode -server $server -user $user -pass $pass -domain $domain -cluster $cluster -esxiFqdn $esxiFqdn
        } else {
            $lockdownModes = Get-EsxiLockdownMode -server $server -user $user -pass $pass -domain $domain -cluster $cluster
        }

        foreach ($lockdownMode in $lockdownModes) {
            if ($lockdownMode -like "*lockdownDisabled*") {
                $statusMessage += $lockdownMode
                $status = "PASSED"
            } else {
                $errorMessage += $lockdownMode
            }
        }

        Write-Output "Check ESX Lockdown Mode: $status"

        $status = "FAILED"
        $caStatus = Confirm-CAInvCenterServer -server $server -user $user -pass $pass -domain $domain -issuer $issuer -signedCertificate $signedCertificate
        if ($caStatus -eq $true) {
            $msg = "Signed certificate thumbprint matches with the vCenter certificate authority thumbprint."
            $statusMessage += $msg
            $status = "PASSED"
        } elseif ($caStatus -eq $false) {
            $msg = "Signed certificate thumbprint does not match any of the vCenter certificate authority thumbprints."
            $errorMessage += $msg
        } else {
            $msg = "Error: Unable to Confirm CA In vCenter."
            $msg = $msg + $caStatus
            $errorMessage += $msg
        }

        Write-Output "Confirm CA In vCenter: $status"

        $status = "FAILED"
        $vsanStatus = Get-vSANHealthSummary -server $server -user $user -pass $pass -domain $domain -cluster $cluster -errorAction SilentlyContinue -ErrorVariable errorMsg -WarningAction SilentlyContinue -WarningVariable warnMsg
        if ($warnMsg) {
            $warningMessage += $warnMsg
            $status = "WARNING"
        }
        if ($errorMsg) {
            $errorMessage += $errorMsg
        }
        if ($vsanStatus -eq 0) {
            $status = "PASSED"
            $statusMessage += $vsanStatus
        }

        Write-Output "Check vSAN Health Status: $status"

        Write-Output "############## Finished Running Prechecks for ESX Certificate Management ###############"

        if ($statusMessage) {
            Write-Debug "############## Status of ESX Certificate Management Prechecks : ###############"
            foreach ($msg in $statusMessage) {
                Write-Debug $msg
            }
        }

        if ($warningMessage) {
            Write-Output "############## Warnings Raised While Running Prechecks for ESX Certificate Management : ###############"
            foreach ($msg in $warningMessage) {
                Write-Warning $msg
            }
        }

        if ($errorMessage) {
            Write-Output "############## Issues Found While Running Prechecks for ESX Certificate Management : ###############"
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
        Verifies if the provided certificate is already on the ESX host.

        .DESCRIPTION
        The Confirm-EsxiCertificateInstalled cmdlet will get the thumbprint from the provided signed certificate and
        matches it with the certificate thumbprint from ESX host. You need to pass in the complete path for the
        certificate file. Returns true if certificate is already installed, else returns false.

        .EXAMPLE
        Confirm-EsxiCertificateInstalled -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -esxiFqdn [esx_host_fqdn] -signedCertificate [full_certificate_file_path]
        This example checks the thumbprint of the provided signed certificate with the thumbprint on ESX host.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER esxiFqdn
        The fully qualified domain name of the ESX host to verify the certificate thumbprint against.

        .PARAMETER signedCertificate
        The complete path for the signed certificate file.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $esxiFqdn,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $signedCertificate
    )

    $pass = Get-Password -User $user -Password $pass

    Try {
        if (Test-Path $signedCertificate -PathType Leaf ) {
            Write-Debug "Certificate file found - $signedCertificate"
        } else {
            Write-Error "Could not find certificate in $signedCertificate." -ErrorAction Stop
            return
        }
        $esxiCertificateThumbprint = Get-VcfCertificateThumbprint -esxi -server $server -user $user -pass $pass -esxiFqdn $esxiFqdn
        $crt = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2($signedCertificate)
        $signedCertThumbprint = $crt.Thumbprint

        if ($esxiCertificateThumbprint -eq $signedCertThumbprint) {
            Write-Debug "Signed certificate thumbprint matches with the ESX host certificate thumbprint."
            Write-Warning "Certificate is already installed on ESX host $esxiFqdn : SKIPPED"
            return $true
        } else {
            Write-Debug "ESX host's certificate thumbprint ($esxiCertificateThumbprint) does not match with the thumbprint of provided certificate ($signedCertThumbprint)"
            Write-Debug "Provided certificate is not installed on ESX host $esxiFqdn."
            return $false
        }
    } Catch {
        Debug-ExceptionWriter -object $_
    }
}

Function Confirm-CAInvCenterServer {
    <#
        .SYNOPSIS
        Verifies the root certificate thumbprint matches with one of the CA thumbprints from vCenter instance.

        .DESCRIPTION
        The Confirm-CAInvCenterServer cmdlet gets the thumbprint from the root certificate and matches it with the CA
        thumbprint from the vCenter instance.You need to pass in the complete path for the certificate file.
        Returns true if thumbprint matches, else returns false.

        .EXAMPLE
        Confirm-CAInvCenterServer -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -issuer [issuer_name] -signedCertificate [certificate_path]
        This example matches the thumbprint of provided root certificate file with the thumbprints on the vCenter instance matching the issuer.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER domain
        The name of the workload domain to retrieve the vCenter instance's certificate thumbprints from.

        .PARAMETER signedCertificate
        The complete path for the root certificate file.

        .PARAMETER issuer
        The name of the issuer to match with the thumbprint.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $signedCertificate,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $issuer
    )

    $pass = Get-Password -User $user -Password $pass

    Try {
        if ($PsBoundParameters.ContainsKey("issuer")) {
            $vcThumbprints = Get-VcfCertificateThumbprint -vcenter -server $server -user $user -pass $pass -domain $domain -issuer $issuer
        } else {
            $vcThumbprints = Get-VcfCertificateThumbprint -vcenter -server $server -user $user -pass $pass -domain $domain
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
                Write-Output "Signed certificate thumbprint matches with the vCenter certificate authority thumbprint."
                $match = $true
                break
            }
        }
        if (!$match) {
            Write-Error "Signed certificate thumbprint does not match any of the vCenter certificate authority thumbprints."
        }
        return $match
    } Catch {
        Debug-ExceptionWriter -object $_
    }
}

Function Get-EsxiCertificateMode {
    <#
        .SYNOPSIS
        Retrieves the certificate management mode value from the vCenter instance for a workload domain.

        .DESCRIPTION
        The Get-EsxiCertificateMode cmdlet retrieves the certificate management mode value from vCenter instance
        for a workload domain.

        .EXAMPLE
        Get-EsxiCertificateMode -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name]
        This example retrieves the certificate management mode value for the vCenter instance for the workload domain.

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
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain
    )

    $pass = Get-Password -User $user -Password $pass

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
        Sets the certificate management mode in vCenter for the ESX hosts in a workload domain.

        .DESCRIPTION
        The Set-EsxiCertificateMode cmdlet sets the certificate management mode in vCenter for the ESX hosts in
        a workload domain.

        .EXAMPLE
        Set-EsxiCertificateMode -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -mode custom
        This example sets the certificate management mode to custom in vCenter for the ESX hosts in workload domain.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER domain
        The name of the workload domain to set the vCenter instance certificate management mode setting for.

        .PARAMETER mode
        The certificate management mode to set in vCenter. One of "custom" or "vmca".
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $true)] [ValidateSet ("custom", "vmca")] [String] $mode
    )

    $pass = Get-Password -User $user -Password $pass

    Try {
        $vCenterServer = Get-vCenterServer -server $server -user $user -pass $pass -domain $domain
        $certModeSetting = Get-AdvancedSetting "vpxd.certmgmt.mode" -Entity $vCenterServer.connection
        if ($certModeSetting.value -ne $mode) {
            Set-AdvancedSetting $certModeSetting -Value $mode -confirm:$false
            # Restart "VMware Certificate Authority" and "VMware Certificate Management" services.
            Write-Output 'Restarting vCenter services ("VMware Certificate Authority" and "VMware Certificate Management") for the change to take effect.'
            $services = @("certificateauthority", "certificatemanagement")
            $failedServices = @()

            foreach ($service in $services) {
                $serviceStatus = Restart-VcenterService -serviceName $service
                if ($serviceStatus.status -ne "GREEN") {
                    $failedServices += $serviceStatus
                }
            }

            if ($failedServices.Count -gt 0) {
                $failedServicesErrorString = ""
                foreach ($failedItem in $failedServices) {
                    $failedServicesErrorString += "$($failedItem.name): $($failedItem.result). `n"
                }
                Write-Error "The following services failed to restart successfully:`n$failedServicesErrorString`nSet-EsxiCertificateMode operation Failed." -ErrorAction Stop
            } else {
                Write-Output 'vCenter services ("VMware Certificate Authority" and "VMware Certificate Management") restarted successfully.'
            }
        } else {
            Write-Warning "Certificate Management Mode already set to $mode on the vCenter instance $($vCenterServer.details.fqdn): SKIPPED"
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
        Retrieves the vSAN health summary from vCenter for a cluster.

        .DESCRIPTION
        The Get-vSANHealthSummary cmdlet gets the vSAN health summary from vCenter for a cluster.
        If any status is YELLOW or RED, a WARNING or ERROR will be raised.

        .EXAMPLE
        Get-vSANHealthSummary -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -cluster [cluster_name]
        This example gets the vSAN health summary for cluster.

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
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $cluster
    )

    $pass = Get-Password -User $user -Password $pass

    Try {
        $vCenterServer = Get-vCenterServer -server $server -user $user -pass $pass -domain $domain
        $vSANClusterHealthSystem = Get-VSANView -Id "VsanVcClusterHealthSystem-vsan-cluster-health-system"
        $overallStatus = 0
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

        if ($overallStatus -eq 0) {
            Write-Output "The vSAN health status for $cluster is GREEN."
        }
        return $overallStatus
    } Catch {
        Debug-ExceptionWriter -object $_
    } Finally {
        if ($vCenterServer) { Disconnect-VIServer -server $vCenterServer.details.fqdn -Confirm:$false -WarningAction SilentlyContinue }
    }
}

Function Get-EsxiConnectionState {
    <#
        .SYNOPSIS
        Retrieves the ESX host connection state from vCenter.

        .DESCRIPTION
        The Get-EsxiConnectionState cmdlet gets the connection state of an ESX host.
        One of "Connected", "Disconnected", "Maintenance", or "NotResponding"
        Depends on a connection to a vCenter instance.

        .EXAMPLE
        Get-EsxiConnectionState -esxiFqdn [esx_host_fqdn]
        This example gets an ESX host's connection state.

        .PARAMETER esxiFqdn
        The fully qualified domain name of the ESX host.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $esxiFqdn
    )

    $response = Get-VMHost -name $esxiFqdn
    return $response.ConnectionState
}

Function Get-EsxiHostVsanMaintenanceModePrecheck {
    <#
        .SYNOPSIS
        Checks for any issues when the ESX H=host enters a particular vSAN maintenance mode.

        .DESCRIPTION
        The Get-EsxiHostVsanMaintenanceModePrecheck cmdlet checks if there's any issues for the ESX host entering a particular vSAN maintenance mode.
        The cmdlet will halt the script if the pre check fails.

        .EXAMPLE
        Get-EsxiHostVsanMaintenanceModePrecheck -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -cluster [cluster_name] -vsanDataMigrationMode Full
        This example checks each ESX host within a cluster within the workload domain for any issues when entering a particular vSAN maintenance mode

        Get-EsxiHostVsanMaintenanceModePrecheck -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -host [esx_host_fqdn] -vsanDataMigrationMode Full
        This example checks each ESX host within a cluster within the workload domain for any issues when entering a particular vSAN maintenance mode

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER domain
        The name of the workload domain in which the cluster is located.

        .PARAMETER cluster
        The name of the cluster containing the ESX hosts.

        .PARAMETER esxiFqdn
        The name of the FQDN of an ESX host.

        .PARAMETER vsanDataMigrationMode
        The type of vSAN maintenance mode.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $true, ParameterSetName = "cluster")] [ValidateNotNullOrEmpty()] [String] $cluster,
        [Parameter (Mandatory = $true, ParameterSetName = "esxiFqdn")] [ValidateNotNullOrEmpty()] [String] $esxiFqdn,
        [Parameter (Mandatory = $true)] [ValidateSet ("Full", "EnsureAccessibility", "NoDataMigration")] [String] $vsanDataMigrationMode
    )

    if ($vsanDataMigrationMode -eq "Full") {
        $vsanMigrationMode = "evacuateAllData"
    } elseif ($vsanDataMigrationMode -eq "EnsureAccessibility") {
        $vsanMigrationMode = "ensureObjectAccessibility"
    } elseif ($vsanDataMigrationMode -eq "NoDataMigration") {
        $vsanMigrationMode = "noAction"
    } else {
        Write-Error "No validate vsan Data migration mode selected" -ErrorAction Stop
    }

    Try {
        $vCenterServer = Get-vCenterServer -server $server -user $user -pass $pass -domain $domain
        if ($PsBoundParameters.ContainsKey("cluster")) {
            $clusterDetails = Get-VCFCluster -Name $cluster
            if ($clusterDetails) {
                $esxiHosts = Get-VCFHost | Where-Object { $_.cluster.id -eq $clusterDetails.id } | Sort-Object -Property fqdn
                if (!$esxiHosts) { Write-Warning "No ESX hosts found in cluster $cluster." }
            } else {
                Write-Error "Unable to locate cluster $cluster in $($vCenterServer.details.fqdn) vCenter: PRE_VALIDATION_FAILED" -ErrorAction Stop
            }
        } else {
            $esxiHosts = Get-VCFHost -fqdn $esxiFqdn
            if (!$esxiHosts) { Write-Error "No ESX host $esxiFqdn found in workload domain $domain." -ErrorAction Stop }
        }

        foreach ($esxiHost in $esxiHosts) {
            $vsanReport = Get-VsanEnterMaintenanceModeReport -VMHost $esxiHost.fqdn -VsanDataMigrationMode $vsanMigrationMode

            if ($vsanReport.OverallStatus -ne "green") {
                Write-Error "ESX host($($esxiHost.fqdn)) vSAN Data Migration($vsanDataMigrationMode) Pre-check failed with error $($vsanReport.OverallStatus)" -ErrorAction Stop
            } else {
                Write-Output "ESX host($($esxiHost.fqdn)) vSAN Data Migration($vsanDataMigrationMode) Pre-check: $($vsanReport.OverallStatus)"
            }
        }
    } Catch {
        Debug-ExceptionWriter -object $_
    } Finally {
        if ($vCenterServer) { Disconnect-VIServer -server $vCenterServer.details.fqdn -Confirm:$false -WarningAction SilentlyContinue }
    }
}

Function Set-EsxiConnectionState {
    <#
        .SYNOPSIS
        Sets the ESX host connection state in vCenter.

        .DESCRIPTION
        The Set-EsxiConnectionState cmdlet sets the connection state of an ESX host.
        One of "Connected", "Disconnected" or "Maintenance".
                        If setting the connection state to Maintenance, provide the VsanDataMigrationMode for a vSAN environment.
        One of "Full", "EnsureAccessibility", or "NoDataMigration".
        Depends on a connection to a vCenter instance.

        .EXAMPLE
        Set-EsxiConnectionState -esxiFqdn [esx_host_fqdn] -state Connected
        This example sets an ESX host's connection state to Connected.

        .EXAMPLE
        Set-EsxiConnectionState -esxiFqdn [esx_host_fqdn] -state Maintenance -vsanDataMigrationMode Full
        This example sets an ESX host's connection state to Maintenance with a vSAN data migration mode set to Full data migration.

        .EXAMPLE
        Set-EsxiConnectionState -esxiFqdn [esx_host_fqdn] -state Maintenance -vsanDataMigrationMode EnsureAccessibility -migratePowerOffVMs
        This example sets an ESX host's connection state to Maintenance and will migrate any Power Off or Suspend VMs to other ESX hosts and
        will set vSAN data migration mode to Ensure Accessibility.

        .PARAMETER esxiFqdn
        The fully qualified domain name of the ESX host.

        .PARAMETER state
        The connection state to set the ESX host to. One of "Connected", "Disconnected" or "Maintenance".

        .PARAMETER migratePowerOffVMs
        This optional switch argument will determined if power off and suspended VMs will be migrated off the ESX host when setting the ESX host to Maintenance.

        .PARAMETER vsanDataMigrationMode
        The vSAN data migration mode to use when setting the ESX host to Maintenance. One of "Full", "EnsureAccessibility", or "NoDataMigration".

        .PARAMETER timeout
        The timeout in seconds to wait for the ESX host to reach the desired connection state. Default is 18000 seconds (5 hours).

        .PARAMETER pollInterval
        The poll interval in seconds to check the ESX host connection state. Default is 60 seconds.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $esxiFqdn,
        [Parameter (Mandatory = $true)] [ValidateSet ("Connected", "Disconnected", "Maintenance")] [String] $state,
        [Parameter (Mandatory = $false)] [Switch] $migratePowerOffVMs,
        [Parameter (Mandatory = $false)] [ValidateSet ("Full", "EnsureAccessibility", "NoDataMigration")] [String] $vsanDataMigrationMode,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $timeout = 18000,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $pollInterval = 60
    )

    if ($state -ieq (Get-EsxiConnectionState -esxiFqdn $esxiFqdn)) {
        Write-Warning "ESX host $esxiFqdn is already in the $state connection state: SKIPPED"
        return
    }
    if ($state -ieq "maintenance") {
        if ($PSBoundParameters.ContainsKey("vsanDataMigrationMode")) {
            if (($vsanDataMigrationMode -eq "EnsureAccessibility") -and !($migratePowerOffVMs.IsPresent)) {
                Write-Output "Entering $state connection state for ESX host $esxiFqdn with vSAN data migration mode set to $vsanDataMigrationMode."
                Write-Output "Power off VMs and suspended VMs are left on the ESX host $esxiFqdn."
                Set-VMHost -VMHost $esxiFqdn -State $state -VsanDataMigrationMode $vsanDataMigrationMode -confirm:$false
            } elseif (($vsanDataMigrationMode -eq "NoDataMigration") -and !($migratePowerOffVMs.IsPresent)) {
                Write-Output "Entering $state connection state for ESX host $esxiFqdn with vSAN data migration mode set to $vsanDataMigrationMode."
                Write-Output "Power off VMs and suspended VMs are left on the ESX host $esxiFqdn."
                Set-VMHost -VMHost $esxiFqdn -State $state -VsanDataMigrationMode $vsanDataMigrationMode -confirm:$false
            } else {
                Write-Output "Entering $state connection state for ESX host $esxiFqdn with vSAN data migration mode set to $vsanDataMigrationMode."
                Write-Output "Power off VMs and suspended VMs will be migrated off to other ESX hosts."
                Set-VMHost -VMHost $esxiFqdn -State $state -VsanDataMigrationMode $vsanDataMigrationMode -Evacuate -confirm:$false
            }
        } else {
            if ($migratePowerOffVMs.IsPresent) {
                Write-Output "Entering $state connection state for ESX host $esxiFqdn. (Power off VMs and suspended VMs will be migrated off to other ESX hosts)"
                Set-VMHost -VMHost $esxiFqdn -State $state -Evacuate -confirm:$false
            } else {
                Write-Output "Entering $state connection state for ESX host $esxiFqdn. (Power off VMs and suspended VMs are left on the ESX host)"
                Set-VMHost -VMHost $esxiFqdn -State $state -confirm:$false
            }
        }
    } else {
        Write-Output "Changing the connection state for ESX host $esxiFqdn to $state."
        Set-VMHost -VMHost $esxiFqdn -State $state -confirm:$false
    }
    $timeout = New-TimeSpan -Seconds $timeout
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    do {
        $currentState = Get-EsxiConnectionState -esxiFqdn $esxiFqdn
        if ($state -ieq $currentState) {
            Write-Output "Successfully changed the connection state for ESX host $esxiFqdn to $state."
            break
        } else {
            if ($state -ieq "Connected") {
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
        Retrieves the ESX host lockdown mode state from a vCenter instance.

        .DESCRIPTION
        The Get-EsxiLockdownMode cmdlet gets the lockdown mode value for all ESX hosts in a given cluster or for a
        given ESX host within the cluster. If -esxiFqdn is provided, only the value for that host is returned.

        .EXAMPLE
        Get-EsxiLockdownMode -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -cluster [cluster_name]
        This example retrieves the lockdown mode for each ESX host in a cluster.

        .EXAMPLE
        Get-EsxiLockdownMode -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -cluster [cluster_name] -esxiFqdn [esx_host_fqdn]
        This example retrieves the lockdown mode state for an ESX host in cluster.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER domain
        The name of the workload domain in which the cluster is located.

        .PARAMETER cluster
        The name of the cluster in which the ESX host is located.

        .PARAMETER esxiFqdn
        The fully qualified domain name of the ESX host to retrieve the lockdown mode state for.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $cluster,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $esxiFqdn
    )

    $pass = Get-Password -User $user -Password $pass

    Try {
        $vCenterServer = Get-vCenterServer -server $server -user $user -pass $pass -domain $domain
        if (Get-Cluster | Where-Object { $_.Name -eq $cluster }) {
            if ($PsBoundParameters.ContainsKey("esxiFqdn")) {
                $esxiHosts = Get-Cluster $cluster | Get-VMHost -Name $esxiFqdn
            } else {
                $esxiHosts = Get-Cluster $cluster | Get-VMHost | Sort-Object -Property Name
            }
            if (!$esxiHosts) { Write-Warning "No ESX hosts found within cluster $cluster." }
        } else {
            Write-Error "Unable to locate cluster $cluster in $($vCenterServer.details.fqdn) vCenter: PRE_VALIDATION_FAILED" -ErrorAction Stop
        }

        foreach ($esxiHost in $esxiHosts) {
            $lockdownMode = (Get-VMHost -name $esxiHost).ExtensionData.Config.LockdownMode
            Write-Output "ESX host $esxiHost lockdown mode is set to $lockdownMode."
        }
        if ($PsBoundParameters.ContainsKey("esxiFqdn")) {
            return $lockdownMode
        }
    } Catch {
        Debug-ExceptionWriter -object $_
    }
}

Function Set-EsxiLockdownMode {
    <#
        .SYNOPSIS
        Sets the lockdown mode for all ESX hosts in a given cluster.

        .DESCRIPTION
        The Set-EsxiLockdownMode cmdlet sets the lockdown mode for all ESX hosts in a given cluster.

        .EXAMPLE
        Set-EsxiLockdownMode -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -cluster [cluster_name] -enable
        This example will enable the lockdown mode for all ESX hosts in a cluster.

        .EXAMPLE
        Set-EsxiLockdownMode -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -cluster [cluster_name] -disable
        This example will disable the lockdown mode for all ESX hosts in a cluster.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER domain
        The name of the workload domain in which the cluster is located.

        .PARAMETER cluster
        The name of the cluster in which the ESX host is located.

        .PARAMETER enable
        Enable lockdown mode for the ESX host(s).

        .PARAMETER disable
        Disable lockdown mode for the ESX host(s).
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $cluster,
        [Parameter (Mandatory = $true, ParameterSetName = "enable")] [ValidateNotNullOrEmpty()] [Switch] $enable,
        [Parameter (Mandatory = $true, ParameterSetName = "disable")] [ValidateNotNullOrEmpty()] [Switch] $disable
    )

    $pass = Get-Password -User $user -Password $pass

    Try {
        $vCenterServer = Get-vCenterServer -server $server -user $user -pass $pass -domain $domain
        if (Get-Cluster | Where-Object { $_.Name -eq $cluster }) {
            $esxiHosts = Get-Cluster $cluster | Get-VMHost | Sort-Object -Property Name
            if (!$esxiHosts) { Write-Warning "No ESX hosts found within $cluster cluster." }
        } else {
            Write-Error "Unable to locate Cluster $cluster in $($vCenterServer.details.fqdn) vCenter: PRE_VALIDATION_FAILED" -ErrorAction Stop
        }

        if ($PSBoundParameters.ContainsKey("enable")) {

            Write-Output "Enabling lockdown mode for each ESX host in $cluster cluster"
            foreach ($esxiHost in $esxiHosts) {
                $currentLockdownMode = (Get-VMHost -name $esxiHost).ExtensionData.Config.LockdownMode
                if ($currentLockdownMode -eq "lockdownDisabled") {
                    ($esxiHost | Get-View).EnterLockdownMode()
                    Write-Output "Changing lockdown mode for ESX host $esxiHost from $currentLockdownMode to lockdownNormal."
                    $newLockdownMode = (Get-VMHost -name $esxiHost).ExtensionData.Config.LockdownMode
                    if ($lockdownMode -eq $newLockdownMode) {
                        Write-Error "Unable to change lockdown mode for ESX host $esxiHost from $currentLockdownMode to lockdownNormal. Lockdown mode is set to $newLockdownMode." -ErrorAction Stop
                    }
                } else {
                    Write-Warning "Lockdown mode for ESX host $esxiHost is already set to lockdownNormal: SKIPPED"
                }
            }
        }

        if ($PSBoundParameters.ContainsKey("disable")) {
            Write-Output "Disabling lockdown mode for each ESX host in $cluster cluster."
            foreach ($esxiHost in $esxiHosts) {
                $currentLockdownMode = (Get-VMHost -name $esxiHost).ExtensionData.Config.LockdownMode
                if ($currentLockdownMode -ne "lockdownDisabled") {
                    ($esxiHost | Get-View).ExitLockdownMode()
                    Write-Output "Changing lockdown mode for ESX host $esxiHost from $currentLockdownMode to lockdownDisabled."
                    $newLockdownMode = (Get-VMHost -name $esxiHost).ExtensionData.Config.LockdownMode
                    if ($currentLockdownMode -eq $newLockdownMode) {
                        Write-Error "Unable to change lockdown mode for ESX host $esxiHost from $currentLockdownMode to lockdownDisabled. Lockdown mode is set to $newLockdownMode." -ErrorAction Stop
                    }
                } else {
                    Write-Warning "Lockdown mode for ESX host $esxiHost is already set to lockdownDisabled: SKIPPED"
                }
            }
        }
    } Catch {
        Debug-ExceptionWriter -object $_
    }
}

Function Restart-EsxiHost {
    <#
        .SYNOPSIS
        Restarts an ESX host and poll for connection availability.

        .DESCRIPTION
        The Restart-EsxiHost cmdlet restarts an ESX host and polls for connection availability.
        Timeout value is in seconds.

        .EXAMPLE
        Restart-EsxiHost -esxiFqdn [esx_host_fqdn] -user [admin_username] -pass [admin_password] -poll $true -timeout 1800 -pollInterval 30
        This example restarts an ESX host and polls the connection availability every 30 seconds. It will timeout after 1800 seconds.

        .PARAMETER esxiFqdn
        The fully qualified domain name of the ESX host.

        .PARAMETER user
        The username to authenticate to the ESX host.

        .PARAMETER pass
        The password to authenticate to the ESX host.

        .PARAMETER poll
        Poll for connection availability after restarting the ESX host. Default is true.

        .PARAMETER timeout
        The timeout value in seconds. Default is 1800 seconds.

        .PARAMETER pollInterval
        The poll interval in seconds. Default is 30 seconds.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $esxiFqdn,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [bool] $poll = $true,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $timeout = 1800,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $pollInterval = 30
    )

    $pass = Get-Password -User $user -Password $pass

    # Connect to the ESX host.
    Connect-VIServer $esxiFqdn -User $user -password $pass -Force
    $vmHost = Get-VMHost -Server $esxiFqdn
    if (!$vmHost) {
        Write-Error "Unable to locate ESX host with FQDN $esxiFqdn : PRE_VALIDATION_FAILED" -ErrorAction Stop
        return
    } else {
        Write-Output "Restarting $esxiFqdn"
    }

    # Retrieves the ESX host uptime before restart.
    $esxiUptime = New-TimeSpan -Start $vmHost.ExtensionData.Summary.Runtime.BootTime.ToLocalTime() -End (Get-Date)

    Restart-VMHost $esxiFqdn -server $esxiFqdn -Confirm:$false

    Disconnect-VIServer -server $esxiFqdn -Confirm:$false -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null

    if ($poll) {
        Write-Output "Waiting for ESX host $esxiFqdn to restart. Polling the connection every $pollInterval seconds."
        Start-Sleep -Seconds $pollInterval
        $timeout = New-TimeSpan -Seconds $timeout
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        do {
            if (Test-EsxiConnection -server $esxiFqdn) {
                if (Connect-VIServer $esxiFqdn -User $user -Password $pass -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue) {
                    $vmHost = Get-VMHost -Server $esxiFqdn
                    $currentUpTime = New-TimeSpan -Start $vmHost.ExtensionData.Summary.Runtime.BootTime.ToLocalTime() -End (Get-Date)
                    if ($($esxiUptime.TotalSeconds) -gt $($currentUpTime.TotalSeconds)) {
                        Write-Output "ESX host $esxiFqdn has been restarted and is now accessible."
                    } else {
                        Write-Output "ESX host $esxiFqdn uptime: $($esxiUptime.TotalSeconds) | Current Uptime - $($currentUpTime.TotalSeconds)"
                    }
                    Disconnect-VIServer -Server $esxiFqdn -Confirm:$false -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null
                    return
                }
            }
            Write-Output "Waiting for ESX host $esxiFqdn to restart and become accessible."
            Start-Sleep -Seconds $pollInterval
        } while ($stopwatch.elapsed -lt $timeout)
        Write-Error "ESX host $esxiFqdn did not respond after $($timeout.TotalMinutes) seconds. Please verify that the  ESX host is online and accessible." -ErrorAction Stop
    } else {
        Write-Warning "Restart of ESX host $esxiFqdn triggered without polling connection state. Please monitor the connection state in the vSphere Client."
    }
}

Function Install-EsxiCertificate {
    <#
        .SYNOPSIS
        Installs a certificate for an ESX host or for each ESX host in a cluster.

        .DESCRIPTION
        The Install-EsxiCertificate cmdlet will replace the certificate for an ESX host or for each ESX host
        in a cluster. You must provide the directory containing the signed certificate files.
        Certificate names should be in format <esx_host_fqdn>.crt.
        The workflow will put the ESX host in maintenance mode with full data migration,
        disconnect the ESX host from the vCenter, replace the certificate, restart the ESX host,
        and the exit maintenance mode once the ESX host is online.

        .EXAMPLE
        Install-EsxiCertificate -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -esxiFqdn [esx_host_fqdn] -certificateDirectory [certificate_directory_path] -certificateFileExt ".cer"
        This example will install the certificate to the ESX host in the workload domain from the provided path.

        .EXAMPLE
        Install-EsxiCertificate -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -cluster [cluster_name] -certificateDirectory [certificate_directory_path] -certificateFileExt ".cer"
        This example will install certificates for each ESX host in cluster in the workload domain from the provided path.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER domain
        The name of the workload domain in which the ESX host is located.

        .PARAMETER cluster
        The name of the cluster in which the ESX host is located.

        .PARAMETER esxiFqdn
        The fully qualified domain name of the ESX host.

        .PARAMETER certificateDirectory
        The directory containing the signed certificate files.

        .PARAMETER certificateFileExt
        The file extension of the certificate files. One of ".crt", ".cer", ".pem", ".p7b", or ".p7c".

        .PARAMETER timeout
        The timeout in seconds for putting the ESX host in maintenance mode. Default is 18000 seconds (5 hours).

        .PARAMETER migratePowerOffVMs
        This optional switch argument will determined if power off and suspended VMs will be migrated off the ESX host when setting the ESX host to Maintenance.

        .PARAMETER vsanDataMigrationMode
        The vSAN data migration mode to use when setting the ESX host to Maintenance. One of "Full" or "EnsureAccessibility".

        .PARAMETER uploadPrivateKey
        Option to upload of a custom Private Key for the ESX host.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $true, ParameterSetName = "cluster")] [ValidateNotNullOrEmpty()] [String] $cluster,
        [Parameter (Mandatory = $true, ParameterSetName = "host")] [ValidateNotNullOrEmpty()] [String] $esxiFqdn,
        [Parameter (Mandatory = $true) ] [ValidateNotNullOrEmpty()] [String] $certificateDirectory,
        [Parameter (Mandatory = $false)] [Switch] $migratePowerOffVMs,
        [Parameter (Mandatory = $false)] [ValidateSet ("Full", "EnsureAccessibility")] [String] $vsanDataMigrationMode,
        [Parameter (Mandatory = $true)] [ValidateSet(".crt", ".cer", ".pem", ".p7b", ".p7c")] [String] $certificateFileExt,
        [Parameter (Mandatory = $false, ParameterSetName = "esxi")] [Switch] $uploadPrivateKey,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $timeout = 18000
    )

    Try {
        $vCenterServer = Get-vCenterServer -server $server -user $user -pass $pass -domain $domain
        if ($PsBoundParameters.ContainsKey("cluster")) {
            $clusterDetails = Get-VCFCluster -Name $cluster
            if ($clusterDetails) {
                $esxiHosts = Get-VCFHost | Where-Object { $_.cluster.id -eq $clusterDetails.id } | Sort-Object -Property fqdn
                if (!$esxiHosts) { Write-Warning "No ESX hosts found in cluster $cluster." }
            } else {
                Write-Error "Unable to locate cluster $cluster in $($vCenterServer.details.fqdn) vCenter: PRE_VALIDATION_FAILED" -ErrorAction Stop
            }
        } else {
            $esxiHosts = Get-VCFHost -fqdn $esxiFqdn
            if (!$esxiHosts) { Write-Error "No ESX host $esxiFqdn found in workload domain $domain." -ErrorAction Stop }
        }

        $version = Get-VCFManager -version
        $vcfVersion = $version.Split('.')[0] + "." + $version.Split('.')[1]

        if ($vcfVersion -ge "5.2") {
            # get session ID
            $url = "https://$($vCenterServer.details.fqdn)/sdk/vim25/8.0.3.0/SessionManager/SessionManager/Login"
            $sessionId = (Invoke-WebRequest -Uri "$url" -Body ( @{'userName' = "$($vCenterServer.details.ssoAdmin)"; 'password' = "$($vCenterServer.details.ssoAdminPass)" } | ConvertTo-Json ) -Method:POST -ContentType:'application/json').Headers.'vmware-api-session-id'
            if ($sessionId[0].length -eq 40) {
                $sessionId = $sessionId[0]
            } else {
                Write-Error "Unable to retrieve session ID from $($vcenter.details.fqdn)'s API: PRE_VALIDATION_FAILED" -ErrorAction Stop
            }
        } else {
            # Perform ESX host vSAN data migration pre-check.
            if ($PsBoundParameters.ContainsKey("cluster")) {
                Write-Output "Performing Data Migration Pre-check on the cluster $cluster"
                Get-EsxiHostVsanMaintenanceModePrecheck -server $server -user $user -pass $pass -domain $domain -cluster $cluster -vsanDataMigrationMode $vsanDataMigrationMode
            } else {
                Write-Output "Performing Data Migration Pre-check on the ESX host $esxiFqdn"
                Get-EsxiHostVsanMaintenanceModePrecheck -server $server -user $user -pass $pass -domain $domain -esxiFqdn $esxiFqdn -vsanDataMigrationMode $vsanDataMigrationMode
            }
        }

        # Certificate replacement starts here.
        $replacedHosts = New-Object Collections.Generic.List[String]
        $skippedHosts = New-Object Collections.Generic.List[String]

        foreach ($esxiHost in $esxiHosts) {
            $esxiFqdn = $esxiHost.fqdn
            $crtPath = Join-Path -Path $certificateDirectory -childPath $esxiFqdn$certificateFileExt

            if (!(Test-Path $crtPath -PathType Leaf )) {
                Write-Error "Certificate not found at $crtPath. Skipping certificate replacement for ESX host $esxiFqdn."
                $skippedHosts.Add($esxiFqdn)
                continue
            }

            if ($vcfVersion -ge "5.2") {
                $keyPath = Join-Path -Path $certificateDirectory -childPath ($esxiFqdn + ".key")
                if (!(Test-Path $keyPath -PathType Leaf) -and ($PSBoundParameters.ContainsKey("uploadPrivateKey"))) {
                    Write-Error "Private key not found at $keyPath. Skipping certificate replacement for ESX host $esxiFqdn."
                    $skippedHosts.Add($esxiFqdn)
                    continue
                }
            }

            if (Confirm-EsxiCertificateInstalled -server $server -user $user -pass $pass -esxiFqdn $esxiFqdn -signedCertificate $crtPath) {
                $skippedHosts.Add($esxiFqdn)
                continue
            } elseif ($vcfVersion -ge "5.2") {
                Write-Output "Starting certificate replacement for ESX host $esxiFqdn."
                $esxCertificatePem = Get-Content $crtPath -Raw
                $esxiConfig = Get-View -ViewType HostSystem -Filter @{"Name" = "$esxiFqdn" }
                $esxiHostConfig = Get-View -Id $esxiConfig.ConfigManager.CertificateManager
                $esxiHostConfigMoid = $esxiConfig.ConfigManager.CertificateManager.value

                if ($PSBoundParameters.ContainsKey("uploadPrivateKey")) {
                    $esxCertificateKey = Get-Content $keyPath -Raw
                    $url = "https://$($vCenterServer.details.fqdn)/sdk/vim25/8.0.3.0/HostCertificateManager/$esxiHostConfigMoid/ProvisionServerPrivateKey"
                    # Install ESX Private Key
                    $body = @{'key' = "$esxCertificateKey" } | ConvertTo-Json
                    $respond = Invoke-WebRequest -Headers @{'vmware-api-session-id' = "$sessionId" } -Uri $url -Body $body -Method:POST -ContentType:'application/json'
                    if (!($respond.StatusCode -eq 204)) {
                        Write-Error "Upload private key to ESX host $esxiFqdn failed. " -ErrorAction Stop
                    }
                }
                # Install ESX Certificate
                $esxiHostConfig.InstallServerCertificate($esxCertificatePem)

                # trigger refresh on affected services
                $url = "https://$($vCenterServer.details.fqdn)/sdk/vim25/8.0.3.0/HostCertificateManager/$esxiHostConfigMoid/NotifyAffectedServices"
                $respond = Invoke-WebRequest -Headers @{'vmware-api-session-id' = "$sessionId" } -Uri $url -Method:POST -ContentType:'application/json'
                $replacedHosts.Add($esxiFqdn)
            } else {
                $esxiCredential = (Get-VCFCredential -resourcename $esxiFqdn | Where-Object { $_.username -eq "root" })
                if ($esxiCredential) {
                    if ($clusterDetails.primaryDatastoreType -ieq "vsan" -or $esxiHost.datastoreType -ieq "vsan" ) {
                        if (($vsanDataMigrationMode -eq "EnsureAccessibility") -and !($migratePowerOffVMs.IsPresent)) {
                            Set-EsxiConnectionState -esxiFqdn $esxiFqdn -state "Maintenance" -vsanDataMigrationMode $vsanDataMigrationMode -timeout $timeout
                        } elseif (($vsanDataMigrationMode -eq "EnsureAccessibility") -and ($migratePowerOffVMs.IsPresent)) {
                            Set-EsxiConnectionState -esxiFqdn $esxiFqdn -state "Maintenance" -vsanDataMigrationMode $vsanDataMigrationMode -migratePowerOffVMs -timeout $timeout
                        } else {
                            Set-EsxiConnectionState -esxiFqdn $esxiFqdn -state "Maintenance" -vsanDataMigrationMode "Full" -migratePowerOffVMs -timeout $timeout
                        }
                    } else {
                        Set-EsxiConnectionState -esxiFqdn $esxiFqdn -state "Maintenance" -timeout $timeout
                    }
                    Write-Output "Starting certificate replacement for ESX host $esxiFqdn."
                    $esxCertificatePem = Get-Content $crtPath -Raw
                    Set-VIMachineCertificate -PemCertificate $esxCertificatePem -VMHost $esxiFqdn -ErrorAction Stop -Confirm:$false
                    $replacedHosts.Add($esxiFqdn)

                    # Disconnect ESX host from vCenter prior to restarting an ESX host.
                    Set-EsxiConnectionState -esxiFqdn $esxiFqdn -state "Disconnected" -timeout $timeout
                    Restart-ESXiHost -esxiFqdn $esxiFqdn -user $($esxiCredential.username) -pass $($esxiCredential.password)

                    # Connect to vCenter, set the ESX host connection state, and exit maintenance mode.
                    Write-Output "Connecting to vCenter instance $($vCenterServer.details.fqdn) and exiting ESX host $esxiFqdn from maintenance mode."
                    $vCenterServer = Get-vCenterServer -server $server -user $user -pass $pass -domain $domain
                    if ($vCenterServer) {
                        Set-EsxiConnectionState -esxiFqdn $esxiFqdn -state "Connected" -timeout $timeout
                        Start-Sleep -Seconds 30
                        Set-EsxiConnectionState -esxiFqdn $esxiFqdn -state "Connected"
                    } else {
                        Write-Error "Could not connect to vCenter instance $($vCenterServer.details.fqdn). Check the state of ESX host $esxiFqdn using the Get-EsxiConnectionState cmdlet." -ErrorAction Stop
                        break
                    }
                } else {
                    Write-Error "Unable to get credentials for ESX host $esxiFqdn from SDDC Manager."
                    $skippedHosts.Add($esxiFqdn)
                }
            }
        }
        Write-Output "--------------------------------------------------------------------------------"
        Write-Output "ESX Host Certificate Replacement Summary:"
        Write-Output "--------------------------------------------------------------------------------"
        Write-Output "Succesfully completed certificate replacement for $($replacedHosts.Count) ESX hosts:"
        foreach ($replacedHost in $replacedHosts) {
            Write-Output "$replacedHost"
        }
        Write-Warning "Skipped certificate replacement for $($skippedHosts.Count) ESX hosts:"
        foreach ($skippedHost in $skippedHosts) {
            Write-Warning "$skippedHost : SKIPPED"
        }
        Write-Output "--------------------------------------------------------------------------------"
    } Catch {
        Debug-ExceptionWriter -object $_
    } Finally {
        if ($vCenterServer) { Disconnect-VIServer -server $vCenterServer.details.fqdn -Confirm:$false -WarningAction SilentlyContinue }
    }
}

Function Set-VcfCertificateAuthority {
    <#
        .SYNOPSIS
        Sets the certificate authority in SDDC Manager to use a Microsoft Certificate Authority or an
        OpenSSL Certificate Authority.

        .DESCRIPTION
        The Set-VcfCertificateAuthority will configure Microsoft Certificate Authority or
        OpenSSL Certificate Authority as SDDC Manager's Certificate Authority.

        .EXAMPLE
        Set-VcfCertificateAuthority -certAuthority Microsoft -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -certAuthorityFqdn [certificate_authority_fqdn] -certAuthorityUser [certificate_authority_username] -certAuthorityPass [certificate_authority_password] -certAuthorityTemplate [certificate_authority_template_name]
        This example will configure Microsoft Certificate Authority in SDDC Manager.

        Set-VcfCertificateAuthority -certAuthority OpenSSL -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -commonName []common_name] -organization [organization] -organizationUnit [organization_unit] -locality [locality] -state [state] -country [country]
        This example will configure an OpenSSL Certificate Authority in SDDC Manager.

        .PARAMETER certAuthority
        The type of Certificate Authority to be configured Microsoft or OpenSSL

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

        .PARAMETER commonName
        Specifies the common name for the OpenSSL Certificate Authority.

        .PARAMETER organization
        Specifies the organization name for the OpenSSL Certificate Authority.

        .PARAMETER organizationUnit
        Specifies the organization unit for the OpenSSL Certificate Authority.

        .PARAMETER locality
        Specifies the locality for the OpenSSL Certificate Authority.

        .PARAMETER state
        Specifies the state for the OpenSSL Certificate Authority.

        .PARAMETER country
        Specifies the country for the OpenSSL Certificate Authority.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateSet ("Microsoft", "OpenSSL")] [String] $certAuthority,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true, ParameterSetName = "microsoft")] [ValidateNotNullOrEmpty()] [String] $certAuthorityFqdn,
        [Parameter (Mandatory = $true, ParameterSetName = "microsoft")] [ValidateNotNullOrEmpty()] [String] $certAuthorityUser,
        [Parameter (Mandatory = $true, ParameterSetName = "microsoft")] [ValidateNotNullOrEmpty()] [String] $certAuthorityPass,
        [Parameter (Mandatory = $true, ParameterSetName = "microsoft")] [ValidateNotNullOrEmpty()] [String] $certAuthorityTemplate,
        [Parameter (Mandatory = $true, ParameterSetName = "openssl")] [ValidateNotNullOrEmpty()] [String] $commonName,
        [Parameter (Mandatory = $true, ParameterSetName = "openssl")] [ValidateNotNullOrEmpty()] [String] $organization,
        [Parameter (Mandatory = $true, ParameterSetName = "openssl")] [ValidateNotNullOrEmpty()] [String] $organizationUnit,

        [Parameter (Mandatory = $true, ParameterSetName = "openssl")] [ValidateNotNullOrEmpty()] [String] $locality,
        [Parameter (Mandatory = $true, ParameterSetName = "openssl")] [ValidateNotNullOrEmpty()] [String] $state,
        [Parameter (Mandatory = $true, ParameterSetName = "openssl")] [ValidateSet ("US", "CA", "AX", "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AN", "AO", "AQ", "AR", "AS", "AT", "AU", `
                "AW", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BM", "BN", "BO", "BR", "BS", "BT", "BV", "BW", "BZ", "CA", "CC", "CF", "CH", "CI", "CK", `
                "CL", "CM", "CN", "CO", "CR", "CS", "CV", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", `
                "FM", "FO", "FR", "FX", "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM", "HN", `
                "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KR", "KW", "KY", "KZ", "LA", `
                "LC", "LI", "LK", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", `
                "MW", "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NT", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM", `
                "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW", "SA", "SB", "SC", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SR", "ST", `
                "SU", "SV", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TM", "TN", "TO", "TP", "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", `
                "VC", "VE", "VG", "VI", "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "COM", "EDU", "GOV", "INT", "MIL", "NET", "ORG", "ARPA")] [String] $country
    )

    $pass = Get-Password -User $user -Password $pass

    if (Test-VCFConnection -server $server) {
        if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
            if ($certAuthority -eq "OpenSSL") {
                if (Test-EndpointConnection -server $commonName -port 443) {
                    Try {
                        Write-Output "Starting configuration of the OpenSSL Certificate Authority in SDDC Manager..."
                        Write-Output "Checking status of the OpenSSL Certificate Authority configuration..."
                        if ((Get-VCFCertificateAuthority).id -eq "OpenSSL") {
                            $vcfCommonName = (Get-VCFCertificateAuthority -caType OpenSSL).commonName
                            Write-Output "OpenSSL Certificate Authority is currently configured on SDDC Manager using $($vcfCommonName)."
                        } else {
                            Write-Output "OpenSSL Certificate Authority is currently not configured on SDDC Manager."
                        }
                        if ($vcfCommonName -ne $commonName) {
                            Write-Output "Configuring the OpenSSL Certificate Authority in SDDC Manager using $($commonName)..."
                            Set-VCFOpensslCa -commonName $commonName -organization $organization -organizationUnit $organizationUnit -locality $locality -state $state -country $country
                            Write-Output "Configuration of the OpenSSL Certificate Authority in SDDC Manager using $($commonName): SUCCESSFUL."
                        } else {
                            Write-Warning "Configuration of the OpenSSL Certificate Authority in SDDC Manager using $($commonName), already exists: SKIPPED."
                        }
                        Write-Output "Configuration the OpenSSL Certificate Authority in SDDC Manager completed."
                    } Catch {
                        $ErrorMessage = $_.Exception.Message
                        Write-Output "Error was: $ErrorMessage."
                    }
                } else {
                    Write-Error "Unable to connect to Openssl Certificate Authority ($commonName)."
                }
            } else {
                if (Test-EndpointConnection -server $certAuthorityFqdn -port 443) {
                    $caServerUrl = "https://$certAuthorityFqdn/certsrv"
                    Try {
                        Write-Output "Starting configuration of the Microsoft Certificate Authority in SDDC Manager..."
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
                    Write-Error "Unable to connect to Microsoft Certificate Authority ($certAuthorityFqdn)."
                }
            }
        } else {
            Write-Error "Unable to authenticate to SDDC Manager ($($server)): PRE_VALIDATION_FAILED."
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

    # Aria Suite Lifecycle
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

    # vCenter
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

Function Request-VcfCsr {
    <#
        .SYNOPSIS
        Requests SDDC Manager to generate and store certificate signing request (CSR) files or requests a certificate
        signing request for either an ESX host or a for each ESX host in a cluster and saves it to file(s) in a
        directory.

        .DESCRIPTION
        The Request-VcfCsr will request SDDC Manager to generate certificate signing request files for all components
        associated with the given domain when used with -sddcManager switch. The Request-VcfCsr cmdlet will generate
        the certificate signing request for ESX host(s) and saves it to file(s) in an output directory when used with
        the -esxi switch.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values.
        - Validates that network connectivity and authentication is possible to SDDC Manager.
        - Validates that the workload domain exists in the SDDC Manager inventory.
        - Validates that network connectivity and authentication is possible to vCenter.
        When used with -esxi switch, this cmdlet
        - Gathers the ESX hosts from the cluster
        - Requests the ESX host CSR and saves it in the output directory as <esxi-host-fqdn>.csr. e.g. sfo01-m01-esx01.sfo.rainpole.io.csr
        - Defines possible country codes. Reference: https://www.digicert.com/kb/ssl-certificate-country-codes.htm

        .EXAMPLE
        Request-VcfCsr -esxi -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -cluster [cluster_name] -country [country] -locality [locality] -organization [organization] -organizationUnit [organization_unit] -stateOrProvince [state_or_province] -outputDirectory [output_path]
        This example generates CSRs and stores them in the provided output directory for all ESX hosts in the cluster with the specified fields.

        .EXAMPLE
        Request-VcfCsr -sddcManager -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -country [country] -keysize [keysize] -locality [locality] -organization [organization] -organizationUnit [organization_unit] -stateOrProvince [state_or_province] -email [email_address]
        This example will request SDDC Manager to generate certificate signing request files for all components associated with the given workload domain.

        .PARAMETER esxi
        Switch to request and save certificate signing request files for ESX hosts.

        .PARAMETER sddcManager
        Switch to request and store certificate signing request files on SDDC Manager.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER domain
        The name of the workload domain in which the cluster is located.

        .PARAMETER cluster
        The name of the cluster in which the ESX host is located. (Only required when using -esxi parameter)

        .PARAMETER esxiFqdn
        The fully qualified domain name of the ESX host to request certificate signing request (CSR) for. (Only required when using -esxi parameter)

        .PARAMETER country
        The country code for the certificate signing request (CSR).

        .PARAMETER locality
        The locality for the certificate signing request (CSR).

        .PARAMETER keySize
        The key size for the certificate signing request (CSR). (Only required when using -sddcManager parameter)

        .PARAMETER organization
        The organization for the certificate signing request (CSR).

        .PARAMETER organizationUnit
        The organization unit for the certificate signing request (CSR).

        .PARAMETER stateOrProvince
        The state or province for the certificate signing request (CSR).

        .PARAMETER outputDirectory
        The directory to save the certificate signing request (CSR) files. (Only required when using -esxi parameter)

        .PARAMETER email
        The contact email for the certificate signing request (CSR). (Only required when using -sddcManager parameter)
    #>

    Param (
        [Parameter (Mandatory = $true, ParameterSetName = "esxi")] [ValidateNotNullOrEmpty()] [Switch] $esxi,
        [Parameter (Mandatory = $true, ParameterSetName = "sddc")] [ValidateNotNullOrEmpty()] [Switch] $sddcManager,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $false, ParameterSetName = "esxi")][ValidateNotNullOrEmpty()] [String] $cluster,
        [Parameter (Mandatory = $false, ParameterSetName = "esxi")] [ValidateNotNullOrEmpty()] [String] $esxiFqdn,
        [Parameter (Mandatory = $true, ParameterSetName = "esxi")] [ValidateNotNullOrEmpty()] [String] $outputDirectory,
        [Parameter (Mandatory = $true, ParameterSetName = "sddc")] [ValidateSet ("2048", "3072", "4096")] [String] $keySize,
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
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $stateOrProvince,
        [Parameter (Mandatory = $true, ParameterSetName = "sddc")] [ValidateNotNullOrEmpty()] [String] $email
    )

    $pass = Get-Password -User $user -Password $pass

    if ($PSBoundParameters.ContainsKey("esxi")) {
        if (!$PSBoundParameters.ContainsKey("cluster") -and !$PSBoundParameters.ContainsKey("esxiFqdn")) {
            Write-Error "Please provide either -cluster or -esxiFqdn paramater."
        } elseif ($PSBoundParameters.ContainsKey("cluster") -and $PSBoundParameters.ContainsKey("esxiFqdn")) {
            Write-Error "Only one of -esxiFqdn or -cluster parameter can be provided at a time."
        } elseif ($PSBoundParameters.ContainsKey("cluster")) {
            Request-EsxiCsr -server $server -user $user -pass $pass -domain $domain -cluster $cluster -country $country -locality $locality -organization $organization -organizationUnit $organizationUnit -stateOrProvince $stateOrProvince -outputDirectory $outputDirectory
        } else {
            Request-EsxiCsr -server $server -user $user -pass $pass -domain $domain -esxiFqdn $esxiFqdn -country $country -locality $locality -organization $organization -organizationUnit $organizationUnit -stateOrProvince $stateOrProvince -outputDirectory $outputDirectory
        }
    } else {
        Request-SddcCsr -server $server -user $user -pass $pass -keysize $keySize -workloadDomain $domain -country $country -locality $locality -organization $organization -organizationUnit $organizationUnit -stateOrProvince $stateOrProvince -email $email
    }
}

Function Request-EsxiCsr {
    <#
        .SYNOPSIS
        Requests a certificate signing request (CSR) for an ESX host or a for each ESX host in a cluster and saves it
        to file(s) in a directory.

        .DESCRIPTION
        The Request-EsxiCsr cmdlet will generate the certificate signing request for ESX host(s) and saves it to
        file(s) in an output directory.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values.
        - Validates that network connectivity and authentication is possible to SDDC Manager.
        - Validates that the workload domain exists in the SDDC Manager inventory.
        - Validates that network connectivity and authentication is possible to vCenter.
        - Gathers the ESX hosts from the cluster.
        - Requests the ESX host CSR and saves it in the output directory as <esxi-host-fqdn>.csr. e.g. sfo01-m01-esx01.sfo.rainpole.io.csr
        - Defines possible country codes. Reference: https://www.digicert.com/kb/ssl-certificate-country-codes.htm

        .EXAMPLE
        Request-EsxiCsr -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -cluster [cluster_name] -country [country] -locality [locality] -organization [organization] -organizationUnit [organization_unit] -stateOrProvince [state_or_province] -outputDirectory [output_path]
        This example generates CSRs and stores them in the provided output directory for all ESX hosts in the cluster with the specified fields.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER domain
        The name of the workload domain in which the cluster is located.

        .PARAMETER cluster
        The name of the cluster in which the ESX host is located.

        .PARAMETER esxiFqdn
        The fully qualified domain name of the ESX host to request certificate signing request (CSR) for.

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
                if (!$esxiHosts) { Write-Warning "No ESX hosts found within $cluster cluster." }
            } else {
                Write-Error "Unable to locate cluster $cluster in vCenter instance $($vCenterServer.details.fqdn): PRE_VALIDATION_FAILED"
                Throw "Unable to locate cluster $cluster in vCenter $($vCenterServer.details.fqdn): PRE_VALIDATION_FAILED"
            }
        } else {
            $esxiHosts = Get-VMHost -Name $esxiFqdn
            if (!$esxiHosts) { Write-Warning "No ESX host $esxiFqdn found within workload domain $domain." }
        }

        if ($esxiHosts) {
            foreach ($esxiHost in $esxiHosts) {
                $csrPath = Join-Path -Path $outputDirectory -childPath "$($esxiHost.Name).csr"
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

Function Request-SddcCsr {
    <#
        .SYNOPSIS
        Requests SDDC Manager to generate and store certificate signing request files.

        .DESCRIPTION
        The Request-SddcCsr will request SDDC Manager to generate certificate signing request files for all components
        associated with the given workload domain.
        The cmdlet connects to the SDDC Manager using the -server, -user, and -password values.
        - Validates that network connectivity and authentication is possible to SDDC Manager.
        - Validates that the workload domain exists in the SDDC Manager inventory.
        - Defines possible country codes. Reference: https://www.digicert.com/kb/ssl-certificate-country-codes.htm

        .EXAMPLE
        Request-SddcCsr -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -workloadDomain [workload_domain_name] -country [country] -keysize [keysize] -locality [locality] -organization [organization] -organizationUnit [organization_unit] -stateOrProvince [state_or_province] -email [email_address]
        This example will request SDDC Manager to generate certificate signing request files for all components associated with the given workload domain.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER workloadDomain
        The name of the workload domain in which the certificate is requested to be generated.

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
            for ($createPathCounter = 0; $createPathCounter -lt 4; $createPathCounter++) {
                $randomOutput = -join (((48..57) + (65..90) + (97..122)) * 80 | Get-Random -Count 6 | % { [char]$_ })
                $tempPath = Join-Path -Path $pwd -childPath $randomOutput
                if (!(Test-Path -Path $tempPath)) {
                    Break
                } else {
                    if ($createPathCounter -eq 3) {
                        Write-Error "Unable to write to ($tempPath): PRE_VALIDATION_FAILED.."
                        Exit
                    }
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

Function Request-VcfSignedCertificate {
    <#
        .SYNOPSIS
        Requests SDDC Manager to connect to certificate authority to sign the certificate signing request files and to
        store the signed certificates.

        .DESCRIPTION
        The Request-VcfSignedCertificate will request SDDC Manager to connect to the certificate authority to sign the
        generated certificate signing request files for all components associated with the given workload domain

        .EXAMPLE
        Request-VcfSignedCertificate -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -workloadDomain [workload_domain_name] -certAuthority Microsoft
        This example will connect to SDDC Manager to request to have the certificate signing request files for a given workload domain to be signed by Microsoft CA.

        .EXAMPLE
        Request-VcfSignedCertificate -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -workloadDomain [workload_domain_name] -certAuthority OpenSSL
        This example will connect to SDDC Manager to request to have the certificate signing request files for a given workload domain to be signed by OpenSSL CA.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER workloadDomain
        The name of the workload domain in which the certificate is requested to be signed.

        .PARAMETER certAuthority
        The type of Certificate Authority to be used for signing certificates. One of: Microsoft, OpenSSL.

    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $workloadDomain,
        [Parameter (Mandatory = $true)] [ValidateSet ("Microsoft", "OpenSSL")] [String] $certAuthority
    )

    $pass = Get-Password -User $user -Password $pass

    if (Test-VCFConnection -server $server) {
        if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
            $domainType = Get-VCFWorkloadDomain -name $workloadDomain
            $resourcesObject = gatherSddcInventory -domainType $domainType.type -workloadDomain $workloadDomain

            # Create a temporary directory under current directory
            for ($createPathCounter = 0; $createPathCounter -lt 4; $createPathCounter++) {
                $randomOutput = -join (((48..57) + (65..90) + (97..122)) * 80 | Get-Random -Count 6 | % { [char]$_ })
                $tempPath = Join-Path -Path $pwd -childPath $randomOutput
                if (!(Test-Path -Path $tempPath)) {
                    Break
                } else {
                    if ($createPathCounter -eq 3) {
                        Write-Error "Unable to write to $tempPath."
                        Exit
                    }
                }
            }
            New-Item -Path $tempPath -ItemType Directory | Out-NULL
            $tempPath = Join-Path $tempPath ""

            # Generate a temporay JSON configuration file
            $requestCertificateSpec = [pscustomobject]@{
                caType    = $certAuthority
                resources = $resourcesObject
            }

            $requestCertificateSpec | ConvertTo-Json -Depth 10 | Out-File $tempPath"$($workloadDomain)-requestCertificateSpec.json"

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
            Remove-Item -Recurse -Force $tempPath | Out-NULL
        } else {
            Write-Error "Unable to authenticate to SDDC Manager ($($server)): PRE_VALIDATION_FAILED."
        }
    } else {
        Write-Error "Unable to connect to SDDC Manager ($($server)): PRE_VALIDATION_FAILED."
    }
}

Function Install-VcfCertificate {
    <#
        .SYNOPSIS
        Installs the signed certificates for all components associated with the given workload domain, or an ESX Host
        or for each ESX host in a given cluster.

        .DESCRIPTION
        The Install-VcfCertificate will install the signed certificates for all components associated with the given
        workload domain when used with the -sddcManager switch. The Install-VcfCertificate cmdlet will replace the
        certificate for an ESX host or for each ESX host in a cluster when used with the -esxi switch.
        When used with the -esxi switch:
            - You must provide the directory containing the signed certificate files.
            - Certificate names should be in format <esx_host_fqdn>.crt.
            - The workflow will put the ESX host in maintenance mode with full data migration,
            disconnect the ESX host from the vCenter, replace the certificate, restart the ESX host,
            and the exit maintenance mode once the ESX host is online.

        .EXAMPLE
        Install-VcfCertificate -sddcManager -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name]
        This example will connect to SDDC Manager to install the signed certificates for a given workload domain.

        .EXAMPLE
        Install-VcfCertificate -esxi -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -esxiFqdn [esx_host_fqdn] -migratePowerOffVMs -vsanDataMigrationMode EnsureAccessibility -certificateDirectory [certificate_directory_path] -certificateFileExt ".cer"
        This example will install the certificate to the ESX host in the workload domain using the provided path.
        For VMware Cloud Foundation version 5.1 and earlier, the ESX hosts will enter maintenance mode with vSAN data migration Mode set to 'EnsureAccessibility'.
        Any powered off virtual machines will be migrated off the ESX hosts prior to entering maintenance mode.

        .EXAMPLE
        Install-VcfCertificate -esxi -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -cluster [cluster_name] -certificateDirectory [certificate_directory_path] -certificateFileExt ".cer"
        This example will install certificates for each ESX host in the  cluster within the workload domain, using the provided path.
        For VMware Cloud Foundation 5.2 or later, the vsanDataMigrationMode option is no longer applicable.
        For VMware Cloud Foundation 5.1 and earlier, by default the ESX hosts will enter maintenance mode with vSAN data migration Mode set to 'Full data migration'.
        Any powered off virtual machines will not be migrated off the ESX hosts prior to entering maintenance mode.

        .EXAMPLE
        Install-VcfCertificate -esxi -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -domain [workload_domain_name] -cluster [cluster_name] -certificateDirectory [certificate_directory_path] -certificateFileExt ".cer" -uploadPrivateKey
        This example will install private keys and certificates for each ESX host in the cluster within the workload domain, using the provided path.
        The 'uploadprivatekey' parameter is only validated for VMware Cloud Foundation version is 5.2 or later.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER domain
        The name of the domain in which the certificate is requested to be installed or in which the ESX hosts are located.

        .PARAMETER cluster
        The name of the cluster in which the ESX host is located. (Only required when -esxi switch is used)

        .PARAMETER esxiFqdn
        The fully qualified domain name of the ESX host. (Only required when -esxi switch is used)

        .PARAMETER certificateDirectory
        The directory containing the signed certificate files. (Only required when -esxi switch is used)

        .PARAMETER certificateFileExt
        The file extension of the certificate files. One of ".crt", ".cer", ".pem", ".p7b", or ".p7c". (Only required when -esxi switch is used)

        .PARAMETER timeout
        The timeout in seconds for putting the ESX host in maintenance mode. Default is 18000 seconds (5 hours). (Only required when -esxi switch is used)

        .PARAMETER esxi
        Switch to indicate that the certificate is to be installed on an ESX host.

        .PARAMETER sddcManager
        Switch to indicate that the certificate is to be installed for all components associated with the given workload domain, excluding ESX hosts.

        .PARAMETER migratePowerOffVMs
        Option to decide if power off virtual machines and suspended virtual machines will be migrated to other ESX hosts when the ESX host goes into maintenance mode.

        .PARAMETER uploadPrivateKey
        Option to upload of a custom Private Key for the ESX host.

        .PARAMETER vsanDataMigrationMode
        The vSAN data migration mode to use when setting the ESX host to Maintenance. One of "Full" or "EnsureAccessibility".

        .PARAMETER NoConfirmation
        The cmdlet will not ask for confirmation.
    #>

    Param (
        [Parameter (Mandatory = $true, ParameterSetName = "esxi")] [ValidateNotNullOrEmpty()] [Switch] $esxi,
        [Parameter (Mandatory = $true, ParameterSetName = "sddc")] [ValidateNotNullOrEmpty()] [Switch] $sddcManager,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $server,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $user,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String] $pass,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String] $domain,
        [Parameter (Mandatory = $false, ParameterSetName = "esxi")] [ValidateNotNullOrEmpty()] [String] $cluster,
        [Parameter (Mandatory = $false, ParameterSetName = "esxi")] [ValidateNotNullOrEmpty()] [String] $esxiFqdn,
        [Parameter (Mandatory = $false, ParameterSetName = "esxi")] [Switch] $migratePowerOffVMs,
        [Parameter (Mandatory = $false, ParameterSetName = "esxi")] [Switch] $uploadPrivateKey,
        [Parameter (Mandatory = $false, ParameterSetName = "esxi")] [ValidateSet ("Full", "EnsureAccessibility")] [String] $vsanDataMigrationMode,
        [Parameter (Mandatory = $true, ParameterSetName = "esxi") ] [ValidateNotNullOrEmpty()] [String] $certificateDirectory,
        [Parameter (Mandatory = $true, ParameterSetName = "esxi")] [ValidateSet(".crt", ".cer", ".pem", ".p7b", ".p7c")] [String] $certificateFileExt,
        [Parameter (Mandatory = $false)] [Switch] $NoConfirmation,
        [Parameter (Mandatory = $false, ParameterSetName = "esxi")] [ValidateNotNullOrEmpty()] [String] $timeout = 18000
    )

    $pass = Get-Password -User $user -Password $pass

    if ($PSBoundParameters.ContainsKey("esxi")) {
        # VCF version checks
        if (Test-VCFConnection -server $server) {
            if (Test-VCFAuthentication -server $server -user $user -pass $pass) {
            } else {
                Throw "Unable to return vCenter details: PRE_VALIDATION_FAILED"
            }
        } else {
            Throw "Unable to obtain access token from SDDC Manager ($server), check credentials: PRE_VALIDATION_FAILED"
        }

        $version = Get-VCFManager -version
        $vcfVersion = $version.Split('.')[0] + "." + $version.Split('.')[1]

        if ($vcfVersion -ge "5.2") {
            # VCF version >= 5.2
            if (!$PSBoundParameters.ContainsKey("cluster") -and !$PSBoundParameters.ContainsKey("esxiFqdn")) {
                Write-Error "Please provide either -cluster or -esxiFqdn paramater."
            } elseif ($PSBoundParameters.ContainsKey("cluster") -and $PSBoundParameters.ContainsKey("esxiFqdn")) {
                Write-Error "Only one of -esxiFqdn or -cluster parameter can be provided at a time."
            } elseif ($PSBoundParameters.ContainsKey("cluster")) {
                if ($PSBoundParameters.ContainsKey("uploadPrivateKey")) {
                    Install-EsxiCertificate -server $server -user $user -pass $pass -domain $domain -cluster $cluster -certificateDirectory $certificateDirectory -certificateFileExt $certificateFileExt -uploadPrivateKey
                } else {
                    Install-EsxiCertificate -server $server -user $user -pass $pass -domain $domain -cluster $cluster -certificateDirectory $certificateDirectory -certificateFileExt $certificateFileExt
                }
            } else {
                if ($PSBoundParameters.ContainsKey("uploadPrivateKey")) {
                    Install-EsxiCertificate -server $server -user $user -pass $pass -domain $domain -esxiFqdn $esxiFqdn -certificateDirectory $certificateDirectory -certificateFileExt $certificateFileExt -uploadPrivateKey
                } else {
                    Install-EsxiCertificate -server $server -user $user -pass $pass -domain $domain -esxiFqdn $esxiFqdn -certificateDirectory $certificateDirectory -certificateFileExt $certificateFileExt
                }
            }
        } else {
            # VCF version < 5.2
            if ($PSBoundParameters.ContainsKey("uploadPrivateKey")) {
                Write-Error "upload Private key is only supported for VCF version 5.2 and later.  Please remove this parameter and try again." -ErrorAction Stop
            }

            # Warning Message on using EnsureAccessibility instead of Full Migration
            if (!($PSBoundParameters.ContainsKey("NoConfirmation")) -and ($vsanDataMigrationMode -eq "EnsureAccessibility")) {
                $warningMessage = "Please ensure sufficient backups of the cluster exists.  Please ensure the ESX`n"
                $warningMessage += " hosts activities are minimumized during certificate replacement process. `n"
                $warningMessage += "Please enter yes to confirm: "
                $proceed = Read-Host $warningMessage
                if (($proceed -match "no") -or ($proceed -match "yes")) {
                    if ($proceed -match "no") {
                        return "Stopping script execution. (confirmation is $proceed)."
                    }
                } else {
                    return "None of the options is selected. Default is 'No', hence stopping script execution."
                }
            }

            if (!$PSBoundParameters.ContainsKey("cluster") -and !$PSBoundParameters.ContainsKey("esxiFqdn")) {
                Write-Error "Please provide either -cluster or -esxiFqdn paramater."
            } elseif ($PSBoundParameters.ContainsKey("cluster") -and $PSBoundParameters.ContainsKey("esxiFqdn")) {
                Write-Error "Only one of -esxiFqdn or -cluster parameter can be provided at a time."
            } elseif ($PSBoundParameters.ContainsKey("cluster")) {
                if ($vsanDataMigrationMode.IsPresent) {
                    if ($migratePowerOffVMs.IsPresent) {
                        Install-EsxiCertificate -server $server -user $user -pass $pass -domain $domain -cluster $cluster -certificateDirectory $certificateDirectory -certificateFileExt $certificateFileExt -vsanDataMigrationMode $vsanDataMigrationMode -migratePowerOffVMs
                    } else {
                        Install-EsxiCertificate -server $server -user $user -pass $pass -domain $domain -cluster $cluster -certificateDirectory $certificateDirectory -certificateFileExt $certificateFileExt -vsanDataMigrationMode $vsanDataMigrationMode
                    }
                } else {
                    Install-EsxiCertificate -server $server -user $user -pass $pass -domain $domain -cluster $cluster -certificateDirectory $certificateDirectory -certificateFileExt $certificateFileExt -vsanDataMigrationMode Full -migratePowerOffVMs
                }
            } else {
                if ($vsanDataMigrationMode.IsPresent) {
                    if ($migratePowerOffVMs.IsPresent) {
                        Install-EsxiCertificate -server $server -user $user -pass $pass -domain $domain -esxiFqdn $esxiFqdn -certificateDirectory $certificateDirectory -certificateFileExt $certificateFileExt -vsanDataMigrationMode $vsanDataMigrationMode -migratePowerOffVMs
                    } else {
                        Install-EsxiCertificate -server $server -user $user -pass $pass -domain $domain -esxiFqdn $esxiFqdn -certificateDirectory $certificateDirectory -certificateFileExt $certificateFileExt -vsanDataMigrationMode $vsanDataMigrationMode
                    }
                } else {
                    Install-EsxiCertificate -server $server -user $user -pass $pass -domain $domain -esxiFqdn $esxiFqdn -certificateDirectory $certificateDirectory -certificateFileExt $certificateFileExt -vsanDataMigrationMode Full -migratePowerOffVMs
                }
                if (!$PSBoundParameters.ContainsKey("cluster") -and !$PSBoundParameters.ContainsKey("esxiFqdn")) {
                    Write-Error "Please provide either -cluster or -esxiFqdn paramater."
                } elseif ($PSBoundParameters.ContainsKey("cluster") -and $PSBoundParameters.ContainsKey("esxiFqdn")) {
                    Write-Error "Only one of -esxiFqdn or -cluster parameter can be provided at a time."
                } elseif ($PSBoundParameters.ContainsKey("cluster")) {
                    if ($vsanDataMigrationMode.IsPresent) {
                        if ($migratePowerOffVMs.IsPresent) {
                            Install-EsxiCertificate -server $server -user $user -pass $pass -domain $domain -cluster $cluster -certificateDirectory $certificateDirectory -certificateFileExt $certificateFileExt -vsanDataMigrationMode $vsanDataMigrationMode -migratePowerOffVMs
                        } else {
                            Install-EsxiCertificate -server $server -user $user -pass $pass -domain $domain -cluster $cluster -certificateDirectory $certificateDirectory -certificateFileExt $certificateFileExt -vsanDataMigrationMode $vsanDataMigrationMode
                        }
                    } else {
                        Install-EsxiCertificate -server $server -user $user -pass $pass -domain $domain -cluster $cluster -certificateDirectory $certificateDirectory -certificateFileExt $certificateFileExt -vsanDataMigrationMode Full -migratePowerOffVMs
                    }
                } else {
                    if ($vsanDataMigrationMode.IsPresent) {
                        if ($migratePowerOffVMs.IsPresent) {
                            Install-EsxiCertificate -server $server -user $user -pass $pass -domain $domain -esxiFqdn $esxiFqdn -certificateDirectory $certificateDirectory -certificateFileExt $certificateFileExt -vsanDataMigrationMode $vsanDataMigrationMode -migratePowerOffVMs
                        } else {
                            Install-EsxiCertificate -server $server -user $user -pass $pass -domain $domain -esxiFqdn $esxiFqdn -certificateDirectory $certificateDirectory -certificateFileExt $certificateFileExt -vsanDataMigrationMode $vsanDataMigrationMode
                        }
                    } else {
                        Install-EsxiCertificate -server $server -user $user -pass $pass -domain $domain -esxiFqdn $esxiFqdn -certificateDirectory $certificateDirectory -certificateFileExt $certificateFileExt -vsanDataMigrationMode Full -migratePowerOffVMs
                    }
                }
            }
        }
    } else {
        Install-SddcCertificate -server $server -user $user -pass $pass -workloadDomain $domain
    }
}

Function Install-SddcCertificate {
    <#
        .SYNOPSIS
        Installs the signed certificates for all components associated with the given workload domain.

        .DESCRIPTION
        The Install-SddcCertificate will install the signed certificates for all components associated with the given
        workload domain.

        .EXAMPLE
        Install-SddcCertificate -server [sddc_manager_fqdn] -user [admin_username] -pass [admin_password] -workloadDomain [workload_domain_name]
        This example will connect to SDDC Manager to install the signed certificates for a given workload domain.

        .PARAMETER server
        The fully qualified domain name of the SDDC Manager instance.

        .PARAMETER user
        The username to authenticate to the SDDC Manager instance.

        .PARAMETER pass
        The password to authenticate to the SDDC Manager instance.

        .PARAMETER workloadDomain
        The name of the workload domain in which the certificate is requested to be installed.
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
            for ($createPathCounter = 0; $createPathCounter -lt 4; $createPathCounter++) {
                $randomOutput = -join (((48..57) + (65..90) + (97..122)) * 80 | Get-Random -Count 6 | % { [char]$_ })
                $tempPath = Join-Path -Path $pwd -childPath $randomOutput
                if (!(Test-Path -Path $tempPath)) {
                    Break
                } else {
                    if ($createPathCounter -eq 3) {
                        Write-Error "Unable to write to $tempPath."
                        Exit
                    }
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
                    if ($response.status -in "In Progress", "IN_PROGRESS") {
                        if (($pollLoopCounter % 10 -eq 0) -AND ($pollLoopCounter -gt 9)) {
                            Write-Output "Installation of signed certificates is still in progress for workload domain ($($workloadDomain))..."
                        }
                        Start-Sleep 60
                        $pollLoopCounter ++
                    }
                } While ($response.status -in "In Progress", "IN_PROGRESS")
                if ($response.status -eq "FAILED") {
                    Write-Error "Workflow completed with status: $($response.status)."
                } elseif ($response.status -eq "SUCCESSFUL") {
                    Write-Output "Workflow completed with status: $($response.status)."
                } else {
                    Write-Warning "Workflow completed with an unrecognized status: $($response.status). Please review the state before proceeding."
                }
                Write-Output "Installation of signed certificates for components associated with workload domain $($workloadDomain) completed with status: $($response.status)."

                # Remove the temporary directory.
                Remove-Item -Recurse -Force $tempPath | Out-NULL
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

