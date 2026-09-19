#Requires -Modules Pester
# Tenant guard: the collector reuses existing sessions (including Az contexts cached on disk), so it
# must refuse to collect when those sessions belong to a tenant other than the intended one.
# All service cmdlets are stubbed; no tenant is contacted.

BeforeAll {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdminSecOps.Collector.psd1') -Force
    $script:mod = Get-Module AdminSecOps.Collector
    function global:Get-MgContext { $null }
    function global:Get-AzContext { [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Stub signature for mocking.')] param($ErrorAction) $null }
    function global:Get-ConnectionInformation { [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Stub signature for mocking.')] param($ErrorAction) @() }
    & $script:mod { Initialize-AsoContext -PackagePath $env:TEMP | Out-Null }
    $script:tenantA = '11111111-1111-4111-8111-111111111111'
    $script:tenantB = '22222222-2222-4222-8222-222222222222'
}

AfterAll {
    Remove-Item -Path 'function:global:Get-MgContext', 'function:global:Get-AzContext', 'function:global:Get-ConnectionInformation' -ErrorAction SilentlyContinue
}

Describe 'Assert-AsoSessionTenant' {
    BeforeEach {
        $a = $script:tenantA
        $b = $script:tenantB
        Mock -ModuleName AdminSecOps.Collector Get-MgContext { [pscustomobject]@{ TenantId = $a; Account = 'reader@contoso.example'; Scopes = @('Policy.Read.All') } }.GetNewClosure()
        Mock -ModuleName AdminSecOps.Collector Get-ConnectionInformation { @([pscustomobject]@{ State = 'Connected'; IsEopSession = $false; TenantID = $a; UserPrincipalName = 'reader@contoso.example' }) }.GetNewClosure()
        Mock -ModuleName AdminSecOps.Collector Get-AzContext { [pscustomobject]@{ Account = [pscustomobject]@{ Id = 'someone@other.example' }; Tenant = [pscustomobject]@{ Id = $b } } }.GetNewClosure()
    }

    It 'passes when every session matches -TenantId' {
        $t = $script:tenantA
        { & $script:mod { param($t) Assert-AsoSessionTenant -Module Entra, Exchange -TenantId $t } $t } | Should -Not -Throw
    }

    It 'refuses when a session (a cached Azure context) belongs to another tenant' {
        $t = $script:tenantA
        { & $script:mod { param($t) Assert-AsoSessionTenant -Module Entra, Azure -TenantId $t } $t } | Should -Throw '*Refusing to collect: Azure is signed in to a different tenant*'
    }

    It 'refuses without -TenantId when sessions span tenants' {
        { & $script:mod { Assert-AsoSessionTenant -Module Entra, Azure } } | Should -Throw '*belong to different tenants*'
    }

    It 'compares tenant IDs case-insensitively' {
        $t = $script:tenantA.ToUpperInvariant()
        { & $script:mod { param($t) Assert-AsoSessionTenant -Module Entra -TenantId $t } $t } | Should -Not -Throw
    }

    It 'ignores services not used by the selected modules' {
        $t = $script:tenantA
        { & $script:mod { param($t) Assert-AsoSessionTenant -Module Entra -TenantId $t } $t } | Should -Not -Throw
    }

    It 'warns but proceeds with a single tenant and no -TenantId' {
        $warnings = & $script:mod { Assert-AsoSessionTenant -Module Entra, Exchange 3>&1 } | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }
        @($warnings).Count | Should -Be 1
        "$($warnings[0])" | Should -BeLike '*No -TenantId was specified*'
    }
}
