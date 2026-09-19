#Requires -Modules Pester
# Live-mode data access wrappers, exercised with mocked service cmdlets (no tenant is contacted).
# Verifies GET-only calls, paging, throttling retry and error mapping of the live code path.

BeforeAll {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdminSecOps.Collector.psd1') -Force
    $script:mod = Get-Module AdminSecOps.Collector
    # Stubs shadow the real cmdlets (functions take precedence) so nothing is ever sent to a service.
    function global:Invoke-MgGraphRequest { [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Stub signature for mocking.')] param($Method, $Uri, $OutputType, $ErrorAction) throw 'stub not mocked' }
    function global:Get-MgContext { $null }
    function global:Invoke-AzRestMethod { [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Stub signature for mocking.')] param($Method, $Path, $Uri, $ErrorAction) throw 'stub not mocked' }
    function global:Get-OrganizationConfig { [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Stub signature for mocking.')] param($ErrorAction) [pscustomobject]@{ AuditDisabled = $false; OAuth2ClientProfileEnabled = $true; CustomerLockBoxEnabled = $null; MailTipsExternalRecipientsTipsEnabled = $true; Extra = 'ignored' } }
    & $script:mod { Initialize-AsoContext -PackagePath $env:TEMP | Out-Null }
}

AfterAll {
    Remove-Item -Path 'function:global:Invoke-MgGraphRequest', 'function:global:Get-MgContext', 'function:global:Invoke-AzRestMethod', 'function:global:Get-OrganizationConfig' -ErrorAction SilentlyContinue
}

Describe 'Microsoft Graph wrapper (live path, mocked)' {
    It 'uses GET, requests JSON and follows @odata.nextLink' {
        Mock -ModuleName AdminSecOps.Collector Invoke-MgGraphRequest -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/v1.0/groupSettings' } -MockWith {
            '{"value":[{"id":"1"}],"@odata.nextLink":"https://graph.microsoft.com/v1.0/groupSettings?$skiptoken=2"}'
        }
        Mock -ModuleName AdminSecOps.Collector Invoke-MgGraphRequest -ParameterFilter { $Uri -like '*skiptoken=2' } -MockWith { '{"value":[{"id":"2"},{"id":"3"}]}' }
        $items = & $script:mod { @(Invoke-AsoGraphGetAll -Uri 'https://graph.microsoft.com/v1.0/groupSettings') }
        @($items | ForEach-Object id) | Should -Be @('1', '2', '3')
        Should -Invoke -ModuleName AdminSecOps.Collector Invoke-MgGraphRequest -Times 2 -Exactly -ParameterFilter { $Method -eq 'GET' -and $OutputType -eq 'Json' }
    }

    It 'retries after 429 throttling' {
        $script:calls = 0
        Mock -ModuleName AdminSecOps.Collector Start-Sleep { }
        Mock -ModuleName AdminSecOps.Collector Invoke-MgGraphRequest {
            $script:calls++
            if ($script:calls -eq 1) { throw [System.Net.Http.HttpRequestException]::new('Response status code does not indicate success: TooManyRequests (Too Many Requests).') }
            '{"isEnabled":true}'
        }
        $r = & $script:mod { Invoke-AsoGraphGet -Uri 'v1.0/policies/identitySecurityDefaultsEnforcementPolicy' }
        $r.isEnabled | Should -BeTrue
        Should -Invoke -ModuleName AdminSecOps.Collector Start-Sleep -Times 1 -Exactly
        Should -Invoke -ModuleName AdminSecOps.Collector Invoke-MgGraphRequest -Times 2 -Exactly
    }

    It 'maps 403 to Unauthorized' {
        Mock -ModuleName AdminSecOps.Collector Invoke-MgGraphRequest { throw [System.Net.Http.HttpRequestException]::new('Response status code does not indicate success: Forbidden (Forbidden).') }
        $status = & $script:mod {
            try { Invoke-AsoGraphGet -Uri 'v1.0/directory/onPremisesSynchronization' | Out-Null; 'no error' }
            catch { (Resolve-AsoErrorStatus -ErrorObject $_).Status }
        }
        $status | Should -Be 'Unauthorized'
    }
}

Describe 'Azure Resource Manager wrapper (live path, mocked)' {
    It 'uses GET with -Path, then -Uri for nextLink' {
        Mock -ModuleName AdminSecOps.Collector Invoke-AzRestMethod -ParameterFilter { $Path } -MockWith {
            [pscustomobject]@{ StatusCode = 200; Content = '{"value":[{"name":"a"}],"nextLink":"https://management.azure.com/subscriptions?api-version=2022-12-01&$skiptoken=2"}'; Headers = @{} }
        }
        Mock -ModuleName AdminSecOps.Collector Invoke-AzRestMethod -ParameterFilter { $Uri } -MockWith {
            [pscustomobject]@{ StatusCode = 200; Content = '{"value":[{"name":"b"}]}'; Headers = @{} }
        }
        $items = & $script:mod { @(Invoke-AsoArmGetAll -Path '/subscriptions?api-version=2022-12-01') }
        @($items | ForEach-Object name) | Should -Be @('a', 'b')
        Should -Invoke -ModuleName AdminSecOps.Collector Invoke-AzRestMethod -Times 2 -Exactly -ParameterFilter { $Method -eq 'GET' }
    }

    It 'maps ARM AuthorizationFailed to Unauthorized' {
        Mock -ModuleName AdminSecOps.Collector Invoke-AzRestMethod { [pscustomobject]@{ StatusCode = 403; Content = '{"error":{"code":"AuthorizationFailed","message":"The client does not have authorization."}}'; Headers = @{} } }
        $mapped = & $script:mod {
            try { Invoke-AsoArmGet -Path '/subscriptions/x/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01' | Out-Null; $null }
            catch { Resolve-AsoErrorStatus -ErrorObject $_ }
        }
        $mapped.Status | Should -Be 'Unauthorized'
        $mapped.Message | Should -Match 'does not have authorization'
    }
}

Describe 'Exchange Online wrapper (live path, stubbed cmdlet)' {
    It 'projects cmdlet output onto the requested properties' {
        $o = & $script:mod { @(Invoke-AsoExoCommand -Name 'Get-OrganizationConfig' -Property @('AuditDisabled', 'OAuth2ClientProfileEnabled', 'CustomerLockBoxEnabled'))[0] }
        $o.AuditDisabled | Should -BeFalse
        $o.OAuth2ClientProfileEnabled | Should -BeTrue
        $o.PSObject.Properties['Extra'] | Should -BeNullOrEmpty
    }

    It 'reports an unavailable cmdlet (e.g. no Defender for Office 365) as CommandNotAvailable' {
        $code = & $script:mod {
            try { Invoke-AsoExoCommand -Name 'Get-AtpPolicyForO365' -Property @('EnableSafeDocs') | Out-Null; 'none' }
            catch { (Resolve-AsoErrorStatus -ErrorObject $_).Code }
        }
        $code | Should -Be 'COMMAND_NOT_AVAILABLE'
    }
}

Describe 'Local Windows host (live, read-only)' -Skip:(-not ($IsWindows)) {
    It 'reads registry values read-only and returns null for missing values' {
        & $script:mod { Get-AsoRegistryValue -SubKey 'SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'CurrentBuild' } | Should -Not -BeNullOrEmpty
        & $script:mod { Get-AsoRegistryValue -SubKey 'SOFTWARE\AdminSecOps\DoesNotExist' -Name 'Nothing' } | Should -BeNullOrEmpty
    }

    It 'collects windows.hosts from this computer' {
        $out = Join-Path ([System.IO.Path]::GetTempPath()) ("aso-live-win-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
        try {
            $r = Invoke-AdminSecOpsCollection -Module Windows -OutputPath $out -SkipConnect -NoZip
            $e = Get-Content -Raw -LiteralPath (Join-Path $r.PackagePath 'evidence/windows/hosts.json') | ConvertFrom-Json -AsHashtable
            $e.status | Should -BeIn @('Success', 'Partial')
            $e.data.Count | Should -Be 1
            $e.data[0].hostName | Should -Not -BeNullOrEmpty
            $e.data[0].Keys | Should -Contain 'defender'
            $e.data[0].firewallProfiles.GetType().IsArray | Should -BeTrue
        }
        finally {
            if (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Recurse -Force }
        }
    }
}
