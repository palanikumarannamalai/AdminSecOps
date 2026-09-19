#Requires -Modules Pester
# Authentication-library isolation: Exchange runs in a child process and contributes its evidence to
# the parent's package. The child process launch and all sign-ins are mocked; nothing is contacted.

BeforeAll {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdminSecOps.Collector.psd1') -Force
    $script:mod = Get-Module AdminSecOps.Collector
    $script:exchangeCount = & $script:mod { @(Get-AsoCatalogEntry -Module 'Exchange').Count }
}

Describe 'Test-AsoIsolationRequired' {
    It 'isolates Exchange only in live mode when combined with Graph or Azure modules' {
        & $script:mod { Test-AsoIsolationRequired -Module Entra, Exchange -Mode Live } | Should -BeTrue
        & $script:mod { Test-AsoIsolationRequired -Module Exchange, Azure -Mode Live } | Should -BeTrue
        & $script:mod { Test-AsoIsolationRequired -Module Exchange -Mode Live } | Should -BeFalse
        & $script:mod { Test-AsoIsolationRequired -Module Entra, Azure -Mode Live } | Should -BeFalse
        & $script:mod { Test-AsoIsolationRequired -Module Entra, Exchange -Mode Replay } | Should -BeFalse
    }
}

Describe 'Invoke-AsoIsolatedModule (parent side)' {
    BeforeEach {
        $script:pkg = Join-Path ([System.IO.Path]::GetTempPath()) ("aso-iso-" + [guid]::NewGuid())
        [void][System.IO.Directory]::CreateDirectory($script:pkg)
        $p = $script:pkg
        & $script:mod { param($p) Initialize-AsoContext -PackagePath $p | Out-Null } $p
    }
    AfterEach { Remove-Item -LiteralPath $script:pkg -Recurse -Force -ErrorAction SilentlyContinue }

    It 'merges the child handoff, fills missing datasets as Failed and removes handoff files' {
        Mock -ModuleName AdminSecOps.Collector Start-AsoIsolatedProcess {
            $req = Get-Content -LiteralPath $InputPath -Raw | ConvertFrom-Json
            $handoff = [ordered]@{
                assessmentId = $req.assessmentId
                moduleRecord = [ordered]@{ name = 'Exchange'; version = '0.1.0'; status = 'CompletedWithErrors'; startedAt = $null; completedAt = $null; prerequisites = @(); errors = @(); warnings = @() }
                files        = @([ordered]@{ path = 'evidence/exchange/transportConfig.json'; datasetId = 'exchange.transportConfig'; module = 'Exchange'; sha256 = ('a' * 64); sizeBytes = 10; schemaVersion = '1.0'; status = 'Success'; collectedAt = '2026-09-19T00:00:00.0000000Z' })
                log          = @([ordered]@{ time = '2026-09-19T00:00:00Z'; level = 'Info'; module = 'Exchange'; dataset = $null; message = 'child log line' })
                environment  = [ordered]@{ primaryDomain = 'contoso.example' }
            }
            [System.IO.File]::WriteAllText($req.outputPath, ($handoff | ConvertTo-Json -Depth 10))
            0
        }
        $r = & $script:mod { Invoke-AsoIsolatedModule -Name Exchange -TenantId '11111111-1111-4111-8111-111111111111' }
        $r.Status | Should -Be 'CompletedWithErrors'
        $files = & $script:mod { @((Get-AsoContext).Files | Where-Object { $_.module -eq 'Exchange' }) }
        $files.Count | Should -Be $script:exchangeCount
        @($files | Where-Object { $_.status -eq 'Success' }).Count | Should -Be 1
        @($files | Where-Object { $_.status -eq 'Failed' }).Count | Should -Be ($script:exchangeCount - 1)
        (& $script:mod { (Get-AsoContext).Environment.primaryDomain }) | Should -Be 'contoso.example'
        # Regression (live validation): ConvertFrom-Json turns ISO strings into DateTime; the merged
        # manifest entry must keep the round-trip ISO-8601 UTC format required by the evidence schema.
        $merged = @($files | Where-Object { $_.status -eq 'Success' })[0]
        $merged.collectedAt | Should -Be '2026-09-19T00:00:00.0000000Z'
        $merged.collectedAt | Should -BeOfType [string]
        (& $script:mod { @((Get-AsoContext).Log | Where-Object { $_.message -eq 'child log line' }).Count }) | Should -Be 1
        @(Get-ChildItem -LiteralPath $script:pkg -Filter '.isolated-*' -Force).Count | Should -Be 0
    }

    It 'records every dataset as Failed when the child process produces nothing' {
        Mock -ModuleName AdminSecOps.Collector Start-AsoIsolatedProcess { 1 }
        $r = & $script:mod { Invoke-AsoIsolatedModule -Name Exchange }
        $r.Status | Should -Be 'Failed'
        $files = & $script:mod { @((Get-AsoContext).Files | Where-Object { $_.module -eq 'Exchange' }) }
        @($files | Where-Object { $_.status -eq 'Failed' }).Count | Should -Be $script:exchangeCount
    }

    It 'rejects a handoff for a different assessment' {
        Mock -ModuleName AdminSecOps.Collector Start-AsoIsolatedProcess {
            $req = Get-Content -LiteralPath $InputPath -Raw | ConvertFrom-Json
            [System.IO.File]::WriteAllText($req.outputPath, (@{ assessmentId = [guid]::NewGuid().ToString(); files = @(); log = @() } | ConvertTo-Json))
            0
        }
        $r = & $script:mod { Invoke-AsoIsolatedModule -Name Exchange }
        $r.Status | Should -Be 'Failed'
    }
}

Describe 'Invoke-AsoIsolatedModuleChild (child side)' {
    BeforeEach {
        $script:pkg = Join-Path ([System.IO.Path]::GetTempPath()) ("aso-isoc-" + [guid]::NewGuid())
        [void][System.IO.Directory]::CreateDirectory($script:pkg)
    }
    AfterEach { Remove-Item -LiteralPath $script:pkg -Recurse -Force -ErrorAction SilentlyContinue }

    It 'runs the module with the parent assessment ID and writes a handoff' {
        $id = [guid]::NewGuid().ToString()
        $inPath = Join-Path $script:pkg '.isolated-Exchange-input.json'
        $outPath = Join-Path $script:pkg '.isolated-Exchange-output.json'
        [System.IO.File]::WriteAllText($inPath, (@{ module = 'Exchange'; assessmentId = $id; packagePath = $script:pkg; label = 'x'; tenantId = '11111111-1111-4111-8111-111111111111'; useDeviceCode = $false; servicePlans = @('ATP_ENTERPRISE'); servicePlansResolved = $true; outputPath = $outPath } | ConvertTo-Json))
        Mock -ModuleName AdminSecOps.Collector Connect-AsoService { }
        Mock -ModuleName AdminSecOps.Collector Assert-AsoSessionTenant { }
        Mock -ModuleName AdminSecOps.Collector Invoke-AsoModule {
            & (Get-Module AdminSecOps.Collector) {
                $c = Get-AsoContext
                $c.Modules.Add([ordered]@{ name = 'Exchange'; status = 'Completed' })
                $c.Files.Add([ordered]@{ path = 'evidence/exchange/transportConfig.json'; datasetId = 'exchange.transportConfig'; module = 'Exchange'; status = 'Success' })
            }
        }
        & $script:mod { param($p) Invoke-AsoIsolatedModuleChild -InputPath $p } $inPath
        $h = Get-Content -LiteralPath $outPath -Raw | ConvertFrom-Json
        $h.assessmentId | Should -Be $id
        $h.moduleRecord.status | Should -Be 'Completed'
        @($h.files).Count | Should -Be 1
        (& $script:mod { (Get-AsoContext).ServicePlans.Contains('ATP_ENTERPRISE') }) | Should -BeTrue
    }

    It 'reports a tenant guard refusal as a failed module instead of throwing' {
        $inPath = Join-Path $script:pkg '.isolated-Exchange-input.json'
        $outPath = Join-Path $script:pkg '.isolated-Exchange-output.json'
        [System.IO.File]::WriteAllText($inPath, (@{ module = 'Exchange'; assessmentId = [guid]::NewGuid().ToString(); packagePath = $script:pkg; outputPath = $outPath; tenantId = '11111111-1111-4111-8111-111111111111' } | ConvertTo-Json))
        Mock -ModuleName AdminSecOps.Collector Connect-AsoService { }
        Mock -ModuleName AdminSecOps.Collector Assert-AsoSessionTenant { throw 'Refusing to collect: wrong tenant' }
        & $script:mod { param($p) Invoke-AsoIsolatedModuleChild -InputPath $p } $inPath
        $h = Get-Content -LiteralPath $outPath -Raw | ConvertFrom-Json
        $h.moduleRecord.status | Should -Be 'Failed'
        $h.moduleRecord.errors[0].message | Should -BeLike '*wrong tenant*'
    }

    It 'refuses a handoff path outside the package folder' {
        $inPath = Join-Path $script:pkg '.isolated-Exchange-input.json'
        [System.IO.File]::WriteAllText($inPath, (@{ module = 'Exchange'; assessmentId = [guid]::NewGuid().ToString(); packagePath = $script:pkg; outputPath = (Join-Path ([System.IO.Path]::GetTempPath()) 'elsewhere.json') } | ConvertTo-Json))
        { & $script:mod { param($p) Invoke-AsoIsolatedModuleChild -InputPath $p } $inPath } | Should -Throw '*inside the package folder*'
    }
}
