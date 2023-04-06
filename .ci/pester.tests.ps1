BeforeAll {
    Import-Module -Name "$PSScriptRoot/../VMware.CloudFoundation.CertificateManagement.psd1" -Force -ErrorAction Stop
}

Describe -Tag:('ModuleValidation') 'Module Baseline Validation' {

    It 'is present' {
        $module = Get-Module VMware.CloudFoundation.CertificateManagement
        $module | Should -Be $true
    }

    It ('passes Test-ModuleManifest') {
        Test-ModuleManifest -Path:("$PSScriptRoot/../VMware.CloudFoundation.CertificateManagement.psd1") | Should -Not -BeNullOrEmpty
        $? | Should -Be $true
    }
}
