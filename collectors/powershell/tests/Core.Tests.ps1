#Requires -Modules Pester
# Unit tests of the collector framework: conversions, JSON, envelope and manifest writing, hashing,
# status mapping and replay keys.

BeforeAll {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdminSecOps.Collector.psd1') -Force
    $script:mod = Get-Module AdminSecOps.Collector
    function script:InModule([scriptblock] $Block, [object[]] $Arguments = @()) { & $script:mod $Block @Arguments }
    $script:tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("aso-core-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    [void][System.IO.Directory]::CreateDirectory($script:tempRoot)
}

AfterAll {
    if ($script:tempRoot -and (Test-Path -LiteralPath $script:tempRoot)) { [System.IO.Directory]::Delete($script:tempRoot, $true) }
}

Describe 'FILETIME conversion' {
    It 'converts <Value> to <Expected>' -ForEach @(
        @{ Value = [long]0; Expected = $null }
        @{ Value = [long]9223372036854775807; Expected = $null }
        @{ Value = [long]-1; Expected = $null }
        @{ Value = $null; Expected = $null }
        @{ Value = [long]133000000000000000; Expected = '2022-06-18T04:26:40.0000000Z' }
        @{ Value = '133000000000000000'; Expected = '2022-06-18T04:26:40.0000000Z' }
        @{ Value = [long]116444736000000000; Expected = '1970-01-01T00:00:00.0000000Z' }
    ) {
        InModule { param($v) ConvertFrom-AsoFileTime -Value $v } @(, $Value) | Should -Be $Expected
    }
}

Describe 'Timestamp conversion' {
    It 'normalises <Value> to UTC round-trip format' -ForEach @(
        @{ Value = '2026-09-01T10:00:00Z'; Expected = '2026-09-01T10:00:00.0000000Z' }
        @{ Value = '2026-09-01T12:00:00+02:00'; Expected = '2026-09-01T10:00:00.0000000Z' }
        @{ Value = '0001-01-01T00:00:00Z'; Expected = $null }
        @{ Value = ''; Expected = $null }
        @{ Value = 'not a date'; Expected = $null }
    ) {
        InModule { param($v) ConvertTo-AsoTimestamp -Value $v } @(, $Value) | Should -Be $Expected
    }

    It 'converts DateTime of any kind to UTC' {
        $utc = [DateTime]::SpecifyKind([DateTime]::new(2026, 1, 2, 3, 4, 5), [DateTimeKind]::Utc)
        InModule { param($v) ConvertTo-AsoTimestamp -Value $v } @(, $utc) | Should -Be '2026-01-02T03:04:05.0000000Z'
        InModule { param($v) ConvertTo-AsoTimestamp -Value $v } @(, $utc.ToLocalTime()) | Should -Be '2026-01-02T03:04:05.0000000Z'
    }

    It 'produces timestamps accepted by the engine schema' {
        $ts = InModule { ConvertTo-AsoTimestamp -Value ([DateTime]::UtcNow) }
        $ts | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$'
    }
}

Describe 'JSON serialisation' {
    It 'keeps single-element and empty arrays as arrays' {
        $json = InModule {
            $state = [pscustomobject]@{ Items = [object[]]@('one') }
            ConvertTo-AsoJson -InputObject ([ordered]@{ one = [object[]]@('x'); none = [object[]]@(); strings = (ConvertTo-AsoStringArray -Value 'a'); empty = (ConvertTo-AsoStringArray -Value $null); fromList = $state.Items }) -Compress
        }
        $json | Should -Be '{"one":["x"],"none":[],"strings":["a"],"empty":[],"fromList":["one"]}'
    }

    It 'serialises a top-level single-element dataset as an array in the envelope' {
        $envelopeJson = InModule {
            Initialize-AsoContext -PackagePath $env:TEMP | Out-Null
            $entry = Get-AsoCatalogEntry -Id 'windows.hosts'
            $state = New-AsoDatasetState -Entry $entry
            $state.Status = 'Success'
            $state.Data = [object[]]@([ordered]@{ hostName = 'h' })
            ConvertTo-AsoJson -InputObject (New-AsoEnvelopeObject -State $state -CollectedAt '2026-09-01T10:00:00.0000000Z') -Compress
        }
        $envelopeJson | Should -Match '"data":\[\{"hostName":"h"\}\]'
    }

    It 'serialises an empty dataset as [] not null' {
        $envelopeJson = InModule {
            Initialize-AsoContext -PackagePath $env:TEMP | Out-Null
            $state = New-AsoDatasetState -Entry (Get-AsoCatalogEntry -Id 'entra.guestUsers')
            $state.Status = 'Success'
            $state.Data = [object[]]@()
            ConvertTo-AsoJson -InputObject (New-AsoEnvelopeObject -State $state -CollectedAt '2026-09-01T10:00:00.0000000Z') -Compress
        }
        $envelopeJson | Should -Match '"data":\[\]'
    }

    It 'nulls data when the status is not usable' {
        $envelopeJson = InModule {
            Initialize-AsoContext -PackagePath $env:TEMP | Out-Null
            $state = New-AsoDatasetState -Entry (Get-AsoCatalogEntry -Id 'entra.guestUsers')
            $state.Status = 'Unauthorized'
            $state.Data = [object[]]@('x')
            ConvertTo-AsoJson -InputObject (New-AsoEnvelopeObject -State $state -CollectedAt '2026-09-01T10:00:00.0000000Z') -Compress
        }
        $envelopeJson | Should -Match '"data":null'
    }

    It 'returns property lists as arrays without nesting' {
        $result = InModule {
            $o = [pscustomobject]@{ a = @(1, 2); b = 'x'; c = $null }
            [pscustomobject]@{ A = (Get-AsoList $o 'a').Count; B = (Get-AsoList $o 'b').Count; C = (Get-AsoList $o 'c').Count; Missing = (Get-AsoList $o 'nope').Count }
        }
        $result.A | Should -Be 2
        $result.B | Should -Be 1
        $result.C | Should -Be 0
        $result.Missing | Should -Be 0
    }
}

Describe 'Envelope writer, hashing and UTF-8 without BOM' {
    BeforeAll {
        $script:pkg = Join-Path $script:tempRoot 'pkg1'
        [void][System.IO.Directory]::CreateDirectory($script:pkg)
        $script:written = InModule {
            param($pkg)
            $ctx = Initialize-AsoContext -PackagePath $pkg
            $state = New-AsoDatasetState -Entry (Get-AsoCatalogEntry -Id 'entra.securityDefaults')
            $state.Status = 'Success'
            $state.Data = [ordered]@{ isEnabled = $true; note = 'caf' + [char]0x00E9 }
            $status = Write-AsoEnvelope -State $state -CollectedAt '2026-09-01T10:00:00.0000000Z'
            [pscustomobject]@{ Status = $status; File = $ctx.Files[0]; AssessmentId = $ctx.AssessmentId }
        } @($script:pkg)
        $script:path = Join-Path $script:pkg 'evidence/entra/securityDefaults.json'
    }

    It 'writes the envelope at evidence/<module>/<dataset>.json' {
        Test-Path -LiteralPath $script:path | Should -BeTrue
        $script:written.File.path | Should -Be 'evidence/entra/securityDefaults.json'
    }

    It 'writes UTF-8 without a byte order mark' {
        $bytes = [System.IO.File]::ReadAllBytes($script:path)
        ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) | Should -BeFalse
        $bytes[0] | Should -Be ([byte][char]'{')
        [System.Text.Encoding]::UTF8.GetString($bytes) | Should -Match ('caf' + [char]0x00E9)
    }

    It 'records the lower-case SHA-256 and size of the written bytes' {
        $expected = (Get-FileHash -LiteralPath $script:path -Algorithm SHA256).Hash.ToLowerInvariant()
        $script:written.File.sha256 | Should -Be $expected
        $script:written.File.sha256 | Should -Match '^[a-f0-9]{64}$'
        $script:written.File.sizeBytes | Should -Be (Get-Item -LiteralPath $script:path).Length
    }

    It 'writes a complete envelope' {
        $e = Get-Content -Raw -LiteralPath $script:path | ConvertFrom-Json -AsHashtable
        $e.schemaVersion | Should -Be '1.0'
        $e.datasetId | Should -Be 'entra.securityDefaults'
        $e.assessmentId | Should -Be $script:written.AssessmentId
        $e.collector.name | Should -Be 'AdminSecOps.Collector'
        $e.collector.module | Should -Be 'Entra'
        $e.collector.moduleVersion | Should -Be '0.1.0'
        $e.source.system | Should -Be 'MicrosoftGraph'
        $e.source.operations.GetType().IsArray | Should -BeTrue
        $e.status | Should -Be 'Success'
        $e.errors.Count | Should -Be 0
        $e.data.isEnabled | Should -BeTrue
    }
}

Describe 'Manifest writer' {
    It 'writes a manifest matching the contract' {
        $pkg = Join-Path $script:tempRoot 'pkg2'
        [void][System.IO.Directory]::CreateDirectory($pkg)
        $manifestPath = InModule {
            param($pkg)
            $ctx = Initialize-AsoContext -PackagePath $pkg -Label 'Unit test' -TenantId '11111111-2222-4333-8444-555555555555'
            $state = New-AsoDatasetState -Entry (Get-AsoCatalogEntry -Id 'windows.hosts')
            $state.Status = 'NotApplicable'
            [void](Write-AsoEnvelope -State $state -CollectedAt '2026-09-01T10:00:00.0000000Z')
            $ctx.Modules.Add([ordered]@{ name = 'Windows'; version = '0.1.0'; status = 'Skipped'; startedAt = $null; completedAt = $null; prerequisites = @(); errors = @(); warnings = @() })
            Write-AsoManifest -Options @{ modules = [string[]]@('Windows'); replayMode = $false }
        } @($pkg)
        $m = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json -AsHashtable
        $m.manifestVersion | Should -Be '1.0'
        $m.product | Should -Be 'AdminSecOps'
        $m.collector.name | Should -Be 'AdminSecOps.Collector'
        $m.collector.powershellVersion | Should -Not -BeNullOrEmpty
        $m.environment.label | Should -Be 'Unit test'
        $m.environment.tenantId | Should -Be '11111111-2222-4333-8444-555555555555'
        $m.environment.Contains('adForestName') | Should -BeTrue
        $m.options.modules | Should -Be @('Windows')
        $m.modules.Count | Should -Be 1
        $m.files.Count | Should -Be 1
        $m.files[0].status | Should -Be 'NotApplicable'
        $m.files[0].schemaVersion | Should -Be '1.0'
        $m.files[0].module | Should -Be 'Windows'
    }
}

Describe 'ZIP packaging' {
    It 'uses forward-slash entry names and includes every file' {
        $pkg = Join-Path $script:tempRoot 'pkg3'
        [void][System.IO.Directory]::CreateDirectory((Join-Path $pkg 'evidence/entra'))
        Set-Content -LiteralPath (Join-Path $pkg 'evidence-manifest.json') -Value '{}' -NoNewline
        Set-Content -LiteralPath (Join-Path $pkg 'evidence/entra/organization.json') -Value '{}' -NoNewline
        $zip = Join-Path $script:tempRoot 'pkg3.zip'
        InModule { param($p, $z) Compress-AsoPackage -PackagePath $p -ZipPath $z } @($pkg, $zip) | Out-Null
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::OpenRead($zip)
        try { $names = @($archive.Entries | ForEach-Object FullName) }
        finally { $archive.Dispose() }
        $names | Should -Contain 'evidence-manifest.json'
        $names | Should -Contain 'evidence/entra/organization.json'
        @($names | Where-Object { $_ -match '\\' }) | Should -BeNullOrEmpty
        $names[0] | Should -Be 'evidence-manifest.json'
    }
}

Describe 'Status mapping' {
    It 'maps <Case> to <Expected>' -ForEach @(
        @{ Case = 'HTTP 403'; Status = 403; Code = 'Authorization_RequestDenied'; Message = 'Insufficient privileges to complete the operation.'; Expected = 'Unauthorized' }
        @{ Case = 'HTTP 401'; Status = 401; Code = 'InvalidAuthenticationToken'; Message = 'Access token is empty.'; Expected = 'Unauthorized' }
        @{ Case = 'ARM AuthorizationFailed'; Status = 403; Code = 'AuthorizationFailed'; Message = 'The client does not have authorization.'; Expected = 'Unauthorized' }
        @{ Case = 'Entra P1 missing (signInActivity)'; Status = 403; Code = 'Authentication_RequestFromNonPremiumTenantOrB2CTenant'; Message = 'Neither tenant is B2C or tenant doesn''t have premium license'; Expected = 'NotApplicable' }
        @{ Case = 'PIM licence'; Status = 400; Code = 'AadPremiumLicenseRequired'; Message = 'The tenant needs to have Microsoft Entra ID P2 or Microsoft Entra ID Governance license.'; Expected = 'NotApplicable' }
        @{ Case = 'PIM licence (message only)'; Status = 400; Code = 'BadRequest'; Message = 'The tenant needs an AAD Premium 2 license.'; Expected = 'NotApplicable' }
        @{ Case = 'Intune not provisioned'; Status = 400; Code = 'BadRequest'; Message = 'Request not applicable to target tenant.'; Expected = 'NotApplicable' }
        @{ Case = 'HTTP 500'; Status = 500; Code = 'InternalServerError'; Message = 'Something failed.'; Expected = 'Failed' }
        @{ Case = 'HTTP 404'; Status = 404; Code = 'Request_ResourceNotFound'; Message = 'Resource does not exist.'; Expected = 'Failed' }
    ) {
        $mapped = InModule { param($s, $c, $m) Resolve-AsoErrorStatus -ErrorObject (New-AsoServiceException -StatusCode $s -ErrorCode $c -Message $m) } @($Status, $Code, $Message)
        $mapped.Status | Should -Be $Expected
    }

    It 'maps access denied exceptions from AD/registry to Unauthorized' {
        $mapped = InModule { Resolve-AsoErrorStatus -ErrorObject ([System.UnauthorizedAccessException]::new('Access is denied.')) }
        $mapped.Status | Should -Be 'Unauthorized'
    }

    It 'maps generic exceptions to Failed' {
        (InModule { Resolve-AsoErrorStatus -ErrorObject ([System.InvalidOperationException]::new('boom')) }).Status | Should -Be 'Failed'
    }

    It 'keeps messages free of tokens' {
        $jwt = 'eyJhbGciOiJIUzI1NiJ9abcdef.eyJzdWIiOiIxMjM0NTY3ODkwIn0abcdef.signature'
        $msg = InModule { param($t) New-AsoMessage -Code 'X' -Message "failed with $t" } @($jwt)
        $msg.message | Should -Not -Match 'eyJ'
    }
}

Describe 'Replay keys' {
    It 'derives readable keys from request URLs' {
        InModule { Get-AsoReplayKey -Request 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' } | Should -Be 'v1.0_policies_authorizationPolicy'
        InModule { Get-AsoReplayKey -Request '/subscriptions?api-version=2022-12-01' } | Should -Be 'subscriptions'
    }

    It 'shortens long keys deterministically' {
        $long = 'https://graph.microsoft.com/v1.0/' + ('x' * 300)
        $a = InModule { param($r) Get-AsoReplayKey -Request $r } @($long)
        $b = InModule { param($r) Get-AsoReplayKey -Request $r } @($long)
        $a | Should -Be $b
        $a.Length | Should -BeLessOrEqual 120
    }
}

Describe 'Plain object normalisation' {
    It 'normalises cmdlet-like values to JSON-compatible values' {
        $o = [pscustomobject]@{
            When   = [DateTime]::SpecifyKind([DateTime]::new(2026, 1, 1), [DateTimeKind]::Utc)
            Span   = [TimeSpan]::FromDays(42)
            Kind   = [System.DayOfWeek]::Monday
            Sid    = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
            Bytes  = [byte[]](1, 2, 3)
            Many   = [System.Collections.Generic.List[string]]::new([string[]]@('a', 'b'))
            Secret = 'must not be copied'
        }
        $plain = InModule { param($x) ConvertTo-AsoPlainObject -InputObject $x -Property @('When', 'Span', 'Kind', 'Sid', 'Bytes', 'Many', 'Secret', 'Missing') } @($o)
        $plain.When | Should -Be '2026-01-01T00:00:00.0000000Z'
        $plain.Span | Should -Be '42.00:00:00'
        $plain.Kind | Should -Be 'Monday'
        $plain.Sid | Should -Be 'S-1-5-32-544'
        $plain.Bytes | Should -Be 'AQID'
        $plain.Many | Should -Be @('a', 'b')
        $plain.PSObject.Properties['Secret'] | Should -BeNullOrEmpty
        $plain.Missing | Should -BeNullOrEmpty
    }
}
