#Requires -Modules Pester
# The PowerShell dataset catalogue must match the TypeScript dataset registry exactly.

BeforeAll {
    $script:repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdminSecOps.Collector.psd1') -Force
    $script:mod = Get-Module AdminSecOps.Collector
    $script:catalog = & $script:mod { $script:AsoCatalog }

    # Parse id/module pairs from packages/schemas/src/datasets/*.ts
    $script:tsDatasets = @{}
    foreach ($file in Get-ChildItem -LiteralPath (Join-Path $script:repoRoot 'packages/schemas/src/datasets') -Filter '*.ts') {
        $text = Get-Content -Raw -LiteralPath $file.FullName
        foreach ($m in [regex]::Matches($text, "defineDataset\(\{\s*id:\s*'([^']+)',\s*module:\s*'([^']+)'")) {
            $script:tsDatasets[$m.Groups[1].Value] = $m.Groups[2].Value
        }
    }
}

Describe 'Dataset catalogue' {
    It 'finds the TypeScript dataset definitions' {
        $script:tsDatasets.Count | Should -BeGreaterThan 50
    }

    It 'has exactly one collector entry for every TypeScript dataset' {
        $psIds = @($script:catalog | ForEach-Object Id)
        ($psIds | Sort-Object) | Should -Be (@($script:tsDatasets.Keys) | Sort-Object)
        ($psIds | Select-Object -Unique).Count | Should -Be $psIds.Count
    }

    It 'uses the same module as the TypeScript definition for <_>' -ForEach @(
        'entra.organization', 'm365.sharePointSettings', 'exchange.atpPolicy', 'intune.settings', 'azure.keyVaults',
        'ad.users', 'adcs.certificateTemplates', 'gpo.groupPolicyObjects', 'gpo.sysvolPasswordArtifacts', 'windows.hosts'
    ) {
        $id = $_
        ($script:catalog | Where-Object Id -EQ $id).Module | Should -Be $script:tsDatasets[$id]
    }

    It 'maps every dataset to the module declared in TypeScript' {
        foreach ($entry in $script:catalog) {
            $entry.Module | Should -Be $script:tsDatasets[$entry.Id] -Because $entry.Id
        }
    }

    It 'names an existing Get-Aso* collector function for every dataset' {
        foreach ($entry in $script:catalog) {
            $entry.Function | Should -Match '^Get-Aso[A-Za-z0-9]+$' -Because $entry.Id
            (& $script:mod { param($n) Get-Command -Name $n -CommandType Function -ErrorAction SilentlyContinue } $entry.Function) | Should -Not -BeNullOrEmpty -Because $entry.Function
        }
    }

    It 'uses package paths the engine accepts' {
        foreach ($entry in $script:catalog) {
            "evidence/$($entry.Module.ToLowerInvariant())/$($entry.Name).json" | Should -Match '^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*){0,5}$'
        }
    }

    It 'never records tokens or secrets in operations' {
        foreach ($entry in $script:catalog) {
            ($entry.Operations -join ' ') | Should -Not -Match '(?i)(bearer|access_token|client_secret|sig=|AccountKey=)'
        }
    }
}

Describe 'Get-AdminSecOpsPermission' {
    It 'returns one entry per dataset' {
        @(Get-AdminSecOpsPermission).Count | Should -Be $script:catalog.Count
    }

    It 'explains least privilege per module' {
        $summary = @(Get-AdminSecOpsPermission -Summary)
        $summary.Count | Should -Be 9
        ($summary | Where-Object Module -EQ 'Entra').RoleOrRights | Should -Match 'Global Reader'
        ($summary | Where-Object Module -EQ 'Exchange').RoleOrRights | Should -Match 'View-Only Organization Management'
        ($summary | Where-Object Module -EQ 'Azure').RoleOrRights | Should -Match 'Reader'
        ($summary | Where-Object Module -EQ 'Windows').RoleOrRights | Should -Match 'Local administrator'
        ($summary | Where-Object Module -EQ 'Entra').GraphDelegatedScope | Should -Contain 'Policy.Read.All'
    }

    It 'only requests read scopes from Microsoft Graph' {
        $scopes = & $script:mod { $script:AsoGraphScopes }
        $scopes.Count | Should -Be 16
        # Team.ReadBasic.All is read-only; ReadWrite never matches.
        @($scopes | Where-Object { $_ -notmatch '\.Read(Basic)?(\.|$)' }) | Should -BeNullOrEmpty
        @($scopes | Where-Object { $_ -match 'Write' }) | Should -BeNullOrEmpty
    }

    It 'filters by module' {
        @(Get-AdminSecOpsPermission -Module AD | Where-Object Module -NE 'AD') | Should -BeNullOrEmpty
    }
}

Describe 'Test-AdminSecOpsPrerequisite' {
    It 'reports checks per module without connecting' {
        $checks = @(Test-AdminSecOpsPrerequisite -Module Windows, Entra)
        $checks.Count | Should -BeGreaterThan 2
        ($checks | Where-Object Check -EQ 'PowerShell 7.2 or later' | Select-Object -First 1).Satisfied | Should -BeTrue
        @($checks | Where-Object { $_.Module -notin 'Windows', 'Entra' }) | Should -BeNullOrEmpty
        ($checks | Where-Object { $_.Module -eq 'Windows' -and $_.Check -like 'Running elevated*' }).Required | Should -BeFalse
    }
}
