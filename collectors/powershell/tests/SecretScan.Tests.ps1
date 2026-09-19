#Requires -Modules Pester
# The local secret scanner must mirror packages/core/src/sensitive.ts and block evidence the engine
# would reject.

BeforeAll {
    $script:repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdminSecOps.Collector.psd1') -Force
    $script:mod = Get-Module AdminSecOps.Collector
    function script:Find([string] $Json) { & $script:mod { param($j) Test-AsoJsonTextSensitive -Json $j } $Json }
    $script:tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("aso-scan-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    [void][System.IO.Directory]::CreateDirectory($script:tempRoot)
}

AfterAll {
    if ($script:tempRoot -and (Test-Path -LiteralPath $script:tempRoot)) { [System.IO.Directory]::Delete($script:tempRoot, $true) }
}

Describe 'Parity with packages/core/src/sensitive.ts' {
    It 'uses exactly the same forbidden property names' {
        $ts = Get-Content -Raw -LiteralPath (Join-Path $script:repoRoot 'packages/core/src/sensitive.ts')
        $block = [regex]::Match($ts, 'FORBIDDEN_PROPERTY_NAMES = \[(?<list>[\s\S]*?)\] as const').Groups['list'].Value
        $tsNames = @([regex]::Matches($block, "'([^']+)'") | ForEach-Object { $_.Groups[1].Value }) | Sort-Object
        $tsNames.Count | Should -BeGreaterThan 30
        $psNames = & $script:mod { $script:AsoForbiddenPropertyNames } | Sort-Object
        $psNames | Should -Be $tsNames
    }

    It 'uses the same secret value rule ids' {
        $ts = Get-Content -Raw -LiteralPath (Join-Path $script:repoRoot 'packages/core/src/sensitive.ts')
        $tsIds = @([regex]::Matches($ts, "id: '([a-z0-9-]+)'") | ForEach-Object { $_.Groups[1].Value }) | Sort-Object
        $psIds = & $script:mod { $script:AsoSecretValuePatterns | ForEach-Object Id } | Sort-Object
        $psIds | Should -Be $tsIds
    }
}

Describe 'Find-AsoSensitiveContent' {
    It 'blocks <Case>' -ForEach @(
        @{ Case = 'passwordCredentials hint'; Json = '{"data":[{"passwordCredentials":[{"keyId":"k","hint":"Xq7"}]}]}'; Rule = 'forbidden-property' }
        @{ Case = 'secretText'; Json = '{"data":{"secretText":"abc"}}'; Rule = 'forbidden-property' }
        @{ Case = 'cpassword property'; Json = '{"data":{"cpassword":"j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"}}'; Rule = 'forbidden-property' }
        @{ Case = 'cpassword in a string value'; Json = '{"data":{"xml":"<Properties cpassword=\"abc\" />"}}'; Rule = 'gpp-cpassword' }
        @{ Case = 'JWT'; Json = '{"data":{"note":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL2dyYXBoIn0.c2lnbmF0dXJl"}}'; Rule = 'jwt' }
        @{ Case = 'LAPS password attribute'; Json = '{"data":{"ms-Mcs-AdmPwd":"P@ss"}}'; Rule = 'forbidden-property' }
        @{ Case = 'Windows LAPS password attribute'; Json = '{"data":{"msLAPS-Password":"{}"}}'; Rule = 'forbidden-property' }
        @{ Case = 'access_token'; Json = '{"access_token":"abc"}'; Rule = 'forbidden-property' }
        @{ Case = 'mail body'; Json = '{"data":{"body":{"content":"hello"}}}'; Rule = 'forbidden-property' }
        @{ Case = 'storage connection string'; Json = '{"data":{"cs":"DefaultEndpointsProtocol=https;AccountName=x;AccountKey=abcdefghijklmnopqrstuvwxyz0123=="}}'; Rule = 'storage-account-key' }
        @{ Case = 'PEM private key'; Json = '{"data":{"k":"-----BEGIN PRIVATE KEY-----\nMIIE"}}'; Rule = 'pem-private-key' }
        @{ Case = 'SAS signature'; Json = '{"data":{"u":"https://x.blob.core.windows.net/c?sv=2022&sig=abcdefghijklmnopqrstuvwxyz0123"}}'; Rule = 'sas-signature' }
    ) {
        $findings = Find $Json
        $findings.Count | Should -BeGreaterThan 0
        $findings[0].Rule | Should -Be $Rule
        ($findings | ForEach-Object Path) -join ' ' | Should -Match '^\$'
    }

    It 'allows legitimate metadata (<Case>)' -ForEach @(
        @{ Case = 'pwdLastSet'; Json = '{"data":{"pwdLastSet":"2026-01-01T00:00:00Z"}}' }
        @{ Case = 'passwordCredentials metadata'; Json = '{"data":{"passwordCredentials":[{"keyId":"k","endDateTime":"2027-01-01T00:00:00Z"}]}}' }
        @{ Case = 'null hint'; Json = '{"data":{"hint":null}}' }
        @{ Case = 'empty cpassword attribute value'; Json = '{"data":{"cpassword":""}}' }
        @{ Case = 'LAPS expiration timestamp'; Json = '{"data":{"windowsLapsExpiration":"2026-01-01T00:00:00Z","legacyLapsExpiration":null}}' }
    ) {
        (Find $Json).Count | Should -Be 0
    }

    It 'never includes the offending value in a finding' {
        $findings = Find '{"data":{"secretText":"TOP-SECRET-VALUE"}}'
        ($findings | ConvertTo-Json -Depth 5) | Should -Not -Match 'TOP-SECRET-VALUE'
    }
}

Describe 'Evidence writing is blocked on sensitive content' {
    It 'writes the dataset as Failed with SENSITIVE_CONTENT_BLOCKED and no data' {
        $pkg = Join-Path $script:tempRoot 'blocked'
        [void][System.IO.Directory]::CreateDirectory($pkg)
        $status = & $script:mod {
            param($pkg)
            Initialize-AsoContext -PackagePath $pkg | Out-Null
            $state = New-AsoDatasetState -Entry (Get-AsoCatalogEntry -Id 'entra.applications')
            $state.Status = 'Success'
            $state.Data = [object[]]@([ordered]@{ id = '1'; appId = '00000000-0000-0000-0000-000000000001'; displayName = 'x'; passwordCredentials = @([ordered]@{ keyId = 'k'; hint = 'abc' }); keyCredentials = @() })
            Write-AsoEnvelope -State $state -CollectedAt '2026-09-01T10:00:00.0000000Z'
        } $pkg
        $status | Should -Be 'Failed'
        $text = Get-Content -Raw -LiteralPath (Join-Path $pkg 'evidence/entra/applications.json')
        $text | Should -Not -Match '"hint"'
        $e = $text | ConvertFrom-Json
        $e.status | Should -Be 'Failed'
        $e.data | Should -BeNullOrEmpty
        $e.errors[0].code | Should -Be 'SENSITIVE_CONTENT_BLOCKED'
    }

    It 'drops forbidden properties already when normalising cmdlet output' {
        $plain = & $script:mod { ConvertTo-AsoPlainObject -InputObject ([pscustomobject]@{ Name = 'x'; cpassword = 'abc' }) -Property @('Name', 'cpassword') }
        $plain.PSObject.Properties.Name | Should -Be @('Name')
    }

    It 'refuses to request secret directory attributes' {
        & $script:mod { Initialize-AsoContext -PackagePath $env:TEMP | Out-Null }
        { & $script:mod { Invoke-AsoAdCommand -Name 'Get-ADComputer' -Parameters @{ Filter = '*'; Properties = @('ms-Mcs-AdmPwd') } -Property @('Name') } } | Should -Throw '*must never be requested*'
        { & $script:mod { Invoke-AsoAdCommand -Name 'Get-ADComputer' -Parameters @{ Filter = '*'; Properties = @('msLAPS-Password') } -Property @('Name') } } | Should -Throw '*must never be requested*'
        { & $script:mod { Invoke-AsoAdCommand -Name 'Get-ADUser' -Parameters @{ Filter = '*'; Properties = @('*') } -Property @('Name') } } | Should -Throw '*must never be requested*'
    }

    It 'refuses commands that are not on the allow-list' {
        & $script:mod { Initialize-AsoContext -PackagePath $env:TEMP | Out-Null }
        { & $script:mod { Invoke-AsoExoCommand -Name 'Set-Mailbox' -Property @('Name') } } | Should -Throw '*not on the read-only allow-list*'
        { & $script:mod { Invoke-AsoAdCommand -Name 'Set-ADUser' -Property @('Name') } } | Should -Throw '*not on the read-only allow-list*'
        { & $script:mod { Invoke-AsoWindowsCommand -Name 'Set-MpPreference' -Property @('Name') } } | Should -Throw '*not on the read-only allow-list*'
    }
}
