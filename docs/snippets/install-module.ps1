Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name VMware.PowerCLI -MinimumVersion 13.1.0
Install-Module -Name PowerVCF -MinimumVersion 2.4.0
Install-Module -Name PowerValidatedSolutions -MinimumVersion 2.6.0
Install-Module -Name VMware.CloudFoundation.CertificateManagement
