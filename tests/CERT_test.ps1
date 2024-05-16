Describe 'Test Suite' {
    BeforeAll {
        $useLiveData = $true

        Function Start-SetupLogFile ($path) {
            if (!$path) {
                $path = Get-Location
            }
            $scriptName = Split-Path $MyInvocation.ScriptName -leaf
            $filetimeStamp = Get-Date -Format "MM-dd-yyyy_hh_mm_ss"
            $logfilename = $scriptName + '-' + $filetimeStamp + '.log'
            $Global:logFile = Join-Path $path.Path 'logs' $logfilename
            $logFolder = Join-Path $path.Path 'logs'
            $logFolderExists = Test-Path $logFolder
            if (!$logFolderExists) {
                New-Item -ItemType Directory -Path $logFolder | Out-Null
            }
            New-Item -type File -Path $logFile | Out-Null
            $logContent = '[' + $filetimeStamp + '] INFO Beginning of Log File'
            Add-Content -Path $logFile $logContent | Out-Null
        }

        Function Write-LogToFile {
            Param (
                [Parameter (Mandatory = $true)] [AllowEmptyString()] [String]$Message,
                [Parameter (Mandatory = $false)] [ValidateSet("INFO", "ERROR", "WARNING", "EXCEPTION")] [String]$Type = "INFO",
                [Parameter (Mandatory = $false)] [String]$Colour,
                [Parameter (Mandatory = $false)] [String]$Skipnewline,
                [Parameter (Mandatory = $false)] [bool]$LogOnConsole = $false
            )

            $timeStamp = Get-Date -Format "MM-dd-yyyy_HH:mm:ss"
            if ($LogOnConsole) {
                if (!$Colour) {
                    $Colour = "White"
                }
                Write-Host -NoNewline -ForegroundColor White " [$timeStamp]"
                if ($Skipnewline) {
                    Write-Host -NoNewline -ForegroundColor $Colour " $Type $Message"
                } else {
                    Write-Host -ForegroundColor $Colour " $Type $Message"
                }
            }
            $logContent = '[' + $timeStamp + '] ' + $Type + ' ' + $Message
            Add-Content -Path $logFile $logContent
        }

        Function Get-Index {
            param(
                [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()] $output,
                [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()] $server,
                [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()] $user,
                [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()] $type,
                [bool] $useLiveData = $false
            )

            $flag = $false
            if ($useLiveData) {
                $index = 0
                # Loop through each item in the output.
                foreach ($item in $output) {
                    if ($user -and $type) {
                        if ($item.'System' -match $server -and $item.'User' -match $user -and $item.'Type' -match $type) {
                            $flag = $true
                            break
                        }
                    } else {
                        if ($user) {
                            # If the system matches the server and user, break the loop.
                            if ($item.'System' -match $server -and $item.'User' -match $user) {
                                $flag = $true
                                break
                            }
                        } elseif ($type) {
                            if ($item.'System' -match $server -and $item.'Type' -match $type) {
                                $flag = $true
                                break
                            }
                        } else {
                            # If the system matches the server, break the loop.
                            if ($item.'System' -match $server) {
                                $flag = $true
                                break
                            }
                        }
                    }
                    # Increment the index by 1.
                    $index = $index + 1
                }
            } else {
                $index = $output.'Index'
            }
            if (-Not $flag) {
                Write-LogToFile -Type ERROR -message "$server or $user is not matching in the $output"
            } else {
                return $index
            }
        }

        Start-SetupLogFile
        $inputData = Get-Content -Raw 'InputData.json' | ConvertFrom-Json
        $server = $inputData.'SDDC Manager'
        $sddcManagerUser = $inputData.'User'
        $sddcManagerPass = $inputData.'Password'
        $certAuthorityFqdn = $inputData.'certAuthorityFqdn'
        $certAuthorityUser = $inputData.'certAuthorityUser'
        $certAuthorityPass = $inputData.'certAuthorityPass'
        $certAuthorityTemplate = $inputData.'certAuthorityTemplate'
        $commonName = $inputData.'commonName'
        $organization = $inputData.'organization'
        $organizationUnit = $inputData.'organizationUnit'
        $locality = $inputData.'locality'
        $state = $inputData.'state'
        $country = $inputData.'country'
        $outputDirectory = $inputData.'outputDirectory'
        $email = $inputData.'email'
        $keysize = $inputData.'keysize'
        $domain = $inputData.'Domains'[0]
        $esxiServer = $inputData.$domain.'ESXi Hosts'[0]
        $cluster = $inputData.$domain.'Clusters'[0]
    }

    # VCF Certificate Management
    Describe 'VMware Cloud Foundation Certificate Management Test Suite' -Tag "VCFCertificateManagementSuite" {

        Describe 'Microsoft Certificate Authority Test Suite' -Tag "MicrosoftCertificate" {

            Describe 'Set the certificate authority in SDDC Manager' -Tag "SetMicrosoftCertificateAuthority" {
                # Expect a success.
                It 'Expect Success' -Tag "Positive" {
                    Try {
                        Write-LogToFile -message "Start of 'Configuring of Certificate Authority' Positive Testcase"

                        # Configure the Certificate Authority for SDDC Manager
                        $config = Set-VCFCertificateAuthority -certAuthority 'Microsoft' -server $server -user $sddcManagerUser -pass $sddcManagerPass -certAuthorityFqdn $certAuthorityFqdn -certAuthorityUser $certAuthorityUser -certAuthorityPass $certAuthorityPass -certAuthorityTemplate $certAuthorityTemplate
                        Write-LogToFile -message "Update Result: $config"

                        $config -match "Configuration a Microsoft Certificate Authority in SDDC Manager completed."

                    } Catch {
                        Write-LogToFile -Type ERROR -message "An error occurred: $_"
                        $false | Should -Be $true
                    } Finally {
                        Write-LogToFile -message "End of 'Configuring of Certificate Authority' Positive Testcase"
                    }
                }

                # Expect a failure.
                It 'Expect Failure' -Tag "Negative" {
                    Try {
                        Write-LogToFile -message "Start of 'Configuring of Certificate Authority' Negative Testcase"

                        #set $certAuthorityTemplate to an invalid value
                        $certAuthorityFqdn = 'rpl-ad01.rainpole.io'

                        # Configure the Certificate Authority for SDDC Manager
                        $config = Set-VCFCertificateAuthority -certAuthority 'Microsoft' -server $server -user $sddcManagerUser -pass $sddcManagerPass -certAuthorityFqdn $certAuthorityFqdn -certAuthorityUser $certAuthorityUser -certAuthorityPass $certAuthorityPass -certAuthorityTemplate $certAuthorityTemplate
                        $null | Should -Be $config

                        } Catch {
                            # Output the caught exception.
                            Write-LogToFile -message "Caught Exception: $_"

                            # If an error was thrown, fail the test.
                            $false | Should -Be $true
                        } Finally {
                            Write-LogToFile -message "End of 'Configuring of Certificate Authority' Negative Testcase"
                            $certAuthorityFqdn = $inputData.'certAuthorityFqdn'
                        }
                    }
            }

            Describe 'Request-VCFCsr for SDDC Manager' -Tag "RequestVCFCsrSDDCMicrosoft" {
                    # Expect a success.
                    It 'Expect Success' -Tag "Positive" {
                        Try {
                            Write-LogToFile -message "Start of Request-VCFCsr for SDDC Positive Testcase"

                            # Request-VCF certificate
                            $config = Request-VCFCsr -sddcManager -server $server -user $sddcManagerUser -pass $sddcManagerPass -domain $inputData.'Domains'[1] -country $country -keysize $keysize -locality $locality -organization $organization -organizationUnit $organizationUnit -stateOrProvince $state -email $email
                            Write-LogToFile -message "Update Result: $config"

                            $config -match "Workflow completed with status: Successful."  | Should -Not -BeNullorEmpty

                        } Catch {
                            Write-LogToFile -Type ERROR -message "An error occurred: $_"
                            $false | Should -Be $true
                        } Finally {
                            Write-LogToFile -message "End of Request-VCFCsr for SDDC Positive Testcase"
                        }
                    }

                    # Expect a failure.
                    It 'Expect Failure' -Tag "Negative" {
                        Try {
                            Write-LogToFile -message "Start of Request-VCFCsr for SDDC Negative Testcase"

                            #set $sddcManagerPass to an invalid value
                            $sddcManagerPass = "VMw@re"

                            #Request-VCF certificate
                            $config = Request-VCFCsr -sddcManager -server $server -user $sddcManagerUser -pass $sddcManagerPass -domain $inputData.'Domains'[1] -country $country -keysize $keysize -locality $locality -organization $organization -organizationUnit $organizationUnit -stateOrProvince $state -email $email

                            } Catch {
                                # Output the caught error.
                                Write-LogToFile -Type ERROR -message "An error occurred: $_"
                                $true | Should -Be $true
                            } Finally {
                                Write-LogToFile -message "End of Request-VCFCsr for SDDC Negative Testcase"
                                $sddcManagerPass = $inputData.'Password'
                            }
                        }
            }

            Describe 'Request-VCFSignedCertificate for SDDC' -Tag "RequestVCFSignedCsrSDDCMicrosoft" {
            # Expect a success.
            It 'Expect Success' -Tag "Positive" {
                Try {
                    Write-LogToFile -message "Start of Request-VCFSignedCertificate for SDDC Positive Testcase"

                    # Request-VCF signed certificate
                    $config = Request-VCFSignedCertificate -server $server -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $inputData.'Domains'[1] -certAuthority Microsoft
                    Write-LogToFile -message "Update Result: $config"

                    $config -match "Workflow completed with status: Successful."  | Should -Not -BeNullorEmpty

                } Catch {
                    Write-LogToFile -Type ERROR -message "An error occurred: $_"
                    $false | Should -Be $true
                } Finally {
                    Write-LogToFile -message "End of Request-VCFSignedCertificate for SDDC Positive Testcase"
                }
            }

            # Expect a failure.
            It 'Expect Failure' -Tag "Negative" {
                Try {
                    Write-LogToFile -message "Start of Request-VCFSignedCertificate for SDDC Negative Testcase"

                    #set $sddcManagerPass to an invalid value
                    $sddcManagerPass = "VMw@re"

                    # Request-VCF signed certificate
                    $config = Request-VCFSignedCertificate -server $server -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $inputData.'Domains'[1] -certAuthority Microsoft

                    } Catch {
                        # Output the caught error.
                        Write-LogToFile -Type ERROR -message "An error occurred: $_"
                        $true | Should -Be $true
                    } Finally {
                        Write-LogToFile -message "End of Request-VCFSignedCertificate for SDDC Negative Testcase"
                        $sddcManagerPass = $inputData.'Password'
                    }
                }
            }

            Describe 'InstallVCFCertificate for SDDC' -Tag "InstallVCFCertificateSDDCMicrosoft" {

                # Expect a success.
                It 'Expect Success' -Tag "Positive" {
                    Try {
                        Write-LogToFile -message "Installing VCFCertificate for SDDC Positive Testcase"

                        # Install VCF certificate
                        $config = Install-VCFCertificate -sddcManager -server $server -user $sddcManagerUser -pass $sddcManagerPass -domain $inputData.'Domains'[1]
                        Start-Sleep -Seconds 1500
                        Write-LogToFile -message "Update Result: $config"

                        $config -match "Installation of signed certificates for components associated with workload domain completed with status: Successful."  | Should -Not -BeNullorEmpty

                    } Catch {
                        Write-LogToFile -Type ERROR -message "An error occurred: $_"
                        $false | Should -Be $true
                    } Finally {
                        Write-LogToFile -message "End of Installation of VCFCertificate for SDDC Positive Testcase"
                    }
                }

                # Expect a failure.
                It 'Expect Failure' -Tag "Negative" {
                    Try {
                        Write-LogToFile -message " Installing VCFCertificate for SDDC Negative Testcase"

                        #set $sddcManagerPass to an invalid value
                        $sddcManagerPass = "VMw@re1!"

                        # Configure the Certificate Authority for SDDC Manager
                        $config = Install-VCFCertificate -sddcManager -server $server -user $sddcManagerUser -pass $sddcManagerPass -domain $inputData.'Domains'[1]

                        } Catch {
                            # Output the caught error.
                            Write-LogToFile -Type ERROR -message "An error occurred: $_"
                            $true | Should -Be $true
                        } Finally {
                            Write-LogToFile -message "End of Installation VCFCertificate for SDDC Negative Testcase"
                            $sddcManagerPass = $inputData.'Password'
                        }
                    }
            }

        }

        Describe 'Openssl Certificate Authority Test Suite' -Tag "OpensslCertificate" {

            Describe 'Configuring OpenSSL Certificate Authority for SDDC Manager' -Tag "SetOpenSSLCertificateAuthority" {
                # Expect a success.
                It 'Expect Success' -Tag "Positive" {
                    Try {
                        Write-LogToFile -message "Start of 'Configuring OpenSSL Certificate Authority' Positive Testcase"

                        # Configure the Certificate Authority for SDDC Manager
                        $config = Set-VCFCertificateAuthority -certAuthority OpenSSL -server $server -user $sddcManagerUser -pass $sddcManagerPass -commonName $commonName -organization $organization -organizationUnit $organizationUnit -locality $locality -state $state -country $country
                        Write-LogToFile -message "Update Result: $config"

                        $config -match "Configuration the OpenSSL Certificate Authority in SDDC Manager completed."  | Should -Not -BeNullorEmpty

                    } Catch {
                        Write-LogToFile -Type ERROR -message "An error occurred: $_"
                        $false | Should -Be $true
                    } Finally {
                        Write-LogToFile -message "End of 'Configuring OpenSSL Certificate Authority' Positive Testcase"
                    }
                }

                # Expect a failure.
                It 'Expect Failure' -Tag "Negative" {
                    Try {
                        Write-LogToFile -message "Start of 'Configuring OpenSSL Certificate Authority' Negative Testcase"

                        #set $certAuthorityTemplate to an invalid value
                        $commonName= "sfo-vc01.sfo.rainpole.io"

                        # Configure the Certificate Authority for SDDC Manager
                        $config = Set-VCFCertificateAuthority -certAuthority OpenSSL -server $server -user $sddcManagerUser -pass $sddcManagerPass -commonName $commonName -organization $organization -organizationUnit $organizationUnit -locality $locality -state $state -country $country
                        $null | Should -Be $config

                        } Catch {
                            # Output the caught exception.
                            Write-LogToFile -message "Caught Exception: $_"

                            # If an error was thrown, fail the test.
                            $false | Should -Be $true
                        } Finally {
                            Write-LogToFile -message "End of 'Configuring OpenSSL Certificate Authority' Negative Testcase"
                            $commonName = $inputData.'commonName'
                        }
                }
            }

            Describe 'Request-VCFCsr for SDDC' -Tag "RequestVCFCsrSDDCOpenssl" {
                # Expect a success.
                It 'Expect Success' -Tag "Positive" {
                    Try {
                        Write-LogToFile -message "Start of Request-VCFCsr for SDDC Positive Testcase"

                        # Request-VCF certificate
                        $config = Request-VCFCsr -sddcManager -server $server -user $sddcManagerUser -pass $sddcManagerPass -domain $inputData.'Domains'[1] -country $country -keysize $keysize -locality $locality -organization $organization -organizationUnit $organizationUnit -stateOrProvince $state -email $email
                        Write-LogToFile -message "Update Result: $config"

                        $config -match "Workflow completed with status: Successful."  | Should -Not -BeNullorEmpty

                    } Catch {
                        Write-LogToFile -Type ERROR -message "An error occurred: $_"
                        $false | Should -Be $true
                    } Finally {
                        Write-LogToFile -message "End of Request-VCFCsr for SDDC Positive Testcase"
                    }
                }

                # Expect a failure.
                It 'Expect Failure' -Tag "Negative" {
                    Try {
                        Write-LogToFile -message "Start of Request-VCFCsr for SDDC Negative Testcase"

                        #set $$sddcManagerPass to an invalid value
                        $sddcManagerPass = "VMw@re"

                        # Request-VCF certificate
                        $config = Request-VCFCsr -sddcManager -server $server -user $sddcManagerUser -pass $sddcManagerPass -domain $inputData.'Domains'[1] -country $country -keysize $keysize -locality $locality -organization $organization -organizationUnit $organizationUnit -stateOrProvince $state -email $email
                        $null | Should -Be $config

                        } Catch {
                            # Output the caught error.
                            Write-LogToFile -Type ERROR -message "An error occurred: $_"
                            $true | Should -Be $true
                        } Finally {
                            Write-LogToFile -message "End of Request-VCFCsr for SDDC Negative Testcase"
                            $sddcManagerPass = $inputData.'Password'
                        }
                }
            }

            Describe 'Request-VCFSignedCertificate for SDDC' -Tag "RequestVCFSignedCsrSDDCOpenssl" {
                # Expect a success.
                It 'Expect Success' -Tag "Positive" {
                    Try {
                        Write-LogToFile -message "Start of Request-VCFSignedCertificate for SDDC Positive Testcase"

                        # Request-VCF signed certificate
                        $config = Request-VCFSignedCertificate -server $server -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $inputData.'Domains'[1] -certAuthority OpenSSL
                        Write-LogToFile -message "Update Result: $config"

                        $config -match "Workflow completed with status: Successful."  | Should -Not -BeNullorEmpty

                    } Catch {
                        Write-LogToFile -Type ERROR -message "An error occurred: $_"
                        $false | Should -Be $true
                    } Finally {
                        Write-LogToFile -message "End of Request-VCFSignedCertificate for SDDC Positive Testcase"
                    }
                }

                # Expect a failure.
                It 'Expect Failure' -Tag "Negative" {
                    Try {
                        Write-LogToFile -message "Start of Request-VCFSignedCertificate for SDDC Negative Testcase"

                        #set $sddcManagerPass to an invalid value
                        $sddcManagerPass = "VMw@re"

                        # Request-VCF signed certificate
                        $config = Request-VCFSignedCertificate -server $server -user $sddcManagerUser -pass $sddcManagerPass -workloadDomain $inputData.'Domains'[1] -certAuthority OpenSSL

                        } Catch {
                            # Output the caught error.
                            Write-LogToFile -Type ERROR -message "An error occurred: $_"
                            $true | Should -Be $true
                        } Finally {
                            Write-LogToFile -message "End of Request-VCFSignedCertificate for SDDC Negative Testcase"
                            $sddcManagerPass = $inputData.'Password'
                        }
                    }
            }


            Describe 'Install-VCFCertificate for SDDC' -Tag "InstallVCFCertificateSDDCOpenssl" {
                # Expect a success.
                It 'Expect Success' -Tag "Positive" {
                    Try {
                        Write-LogToFile -message "Installing VCFCertificate for SDDC Positive Testcase"

                        # Instal vcf certificate
                        $config = Install-VCFCertificate -sddcManager -server $server -user $sddcManagerUser -pass $sddcManagerPass -domain $inputData.'Domains'[1]
                        Start-Sleep -Seconds 1500
                        Write-LogToFile -message "Update Result: $config"

                        $config -match "Installation of signed certificates for components associated with workload domain sfo-m01 completed with status: Successful."  | Should -Not -BeNullorEmpty

                    } Catch {
                        Write-LogToFile -Type ERROR -message "An error occurred: $_"
                        $false | Should -Be $true
                    } Finally {
                        Write-LogToFile -message "End of Installation of VCFCertificate for SDDC Positive Testcase"
                    }
                }

                # Expect a failure.
                It 'Expect Failure' -Tag "Negative" {
                    Try {
                        Write-LogToFile -message " Installing VCFCertificate for SDDC Negative Testcase"

                        #set $sddcManagerPass to an invalid value
                        $sddcManagerPass = "VMw@re1!"

                        # Install VCF certificate
                        $config = Install-VCFCertificate -sddcManager -server $server -user $sddcManagerUser -pass $sddcManagerPass -domain $inputData.'Domains'[1]
                        $null | Should -Be $config

                    } Catch {
                            # Output the caught error.
                            Write-LogToFile -Type ERROR -message "An error occurred: $_"
                            $true | Should -Be $true
                        } Finally {
                            Write-LogToFile -message "End of Installation VCFCertificate for SDDC Negative Testcase"
                            $sddcManagerPass = $inputData.'Password'
                        }
                }
            }
        }
    }
}
