#Requires -Modules Pester
# Static proof that collector code is read-only: every .ps1/.psm1 of the module is parsed with the
# PowerShell AST and checked for state-changing commands, non-GET HTTP methods and write APIs.

BeforeDiscovery {
    $script:moduleRoot = Split-Path -Parent $PSScriptRoot
    $script:sourceFiles = @(Get-ChildItem -LiteralPath $script:moduleRoot -Recurse -File -Include '*.ps1', '*.psm1' |
            Where-Object { $_.FullName -notlike (Join-Path $script:moduleRoot 'tests*') } |
            ForEach-Object { @{ Path = $_.FullName; Name = $_.FullName.Substring($script:moduleRoot.Length + 1) } })
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'ReadOnlyAnalyzer.ps1')
    $script:moduleRoot = Split-Path -Parent $PSScriptRoot
    $script:allFiles = @(Get-ChildItem -LiteralPath $script:moduleRoot -Recurse -File -Include '*.ps1', '*.psm1' |
            Where-Object { $_.FullName -notlike (Join-Path $script:moduleRoot 'tests*') } | ForEach-Object { $_.FullName })
    $script:moduleFunctions = Get-ModuleFunctionName -Path $script:allFiles
}

Describe 'Read-only static analysis' {
    It 'finds collector source files' {
        $script:allFiles.Count | Should -BeGreaterThan 10
    }

    It '<Name> contains no state-changing commands, non-GET requests or write APIs' -ForEach $script:sourceFiles {
        $violations = Get-ReadOnlyViolation -Path $Path -ModuleFunctionName $script:moduleFunctions
        $report = ($violations | ForEach-Object { "$($_.File):$($_.Line) $($_.Rule) :: $($_.Text)" }) -join [Environment]::NewLine
        $report | Should -BeNullOrEmpty
    }

    It 'module functions use the Aso / AdminSecOps noun prefix so they cannot shadow service cmdlets' {
        $bad = @($script:moduleFunctions | Where-Object { $_ -notmatch '^[A-Za-z]+-(Aso|AdminSecOps)' })
        $bad | Should -BeNullOrEmpty
    }

    It 'service allow-lists contain only Get-* cmdlets' {
        Import-Module (Join-Path $script:moduleRoot 'AdminSecOps.Collector.psd1') -Force
        $lists = & (Get-Module AdminSecOps.Collector) { @($script:AsoExoAllowList) + @($script:AsoAdAllowList) + @($script:AsoGpoAllowList) + @($script:AsoWindowsAllowList) }
        $lists.Count | Should -BeGreaterThan 20
        @($lists | Where-Object { $_ -notmatch '^Get-' }) | Should -BeNullOrEmpty
    }
}

Describe 'The analyzer detects violations (it is not vacuous)' {
    It 'flags <Rule>' -ForEach @(
        @{ Rule = 'ForbiddenVerb:Set-Mailbox'; Text = 'Set-Mailbox -Identity x -ForwardingSmtpAddress y' }
        @{ Rule = 'ForbiddenVerb:New-MgUser'; Text = 'New-MgUser -DisplayName x' }
        @{ Rule = 'ForbiddenVerb:Remove-ADUser'; Text = 'Remove-ADUser -Identity x' }
        @{ Rule = 'ForbiddenVerb:Update-MgPolicyAuthorizationPolicy'; Text = 'Update-MgPolicyAuthorizationPolicy -BodyParameter @{}' }
        @{ Rule = 'ForbiddenVerb:Grant-CsTeamsPolicy'; Text = 'Grant-CsTeamsPolicy -Identity x' }
        @{ Rule = 'NonGetHttpMethod'; Text = 'Invoke-MgGraphRequest -Method POST -Uri "v1.0/users"' }
        @{ Rule = 'NonGetHttpMethod'; Text = '$p = @{ Method = ''PATCH''; Uri = ''x'' }' }
        @{ Rule = 'ForbiddenCommand:Invoke-RestMethod'; Text = 'Invoke-RestMethod -Uri https://example.test' }
        @{ Rule = 'ForbiddenCommand:Invoke-Expression'; Text = 'Invoke-Expression "Get-Date"' }
        @{ Rule = 'ForbiddenMethod:WriteAllText'; Text = '[System.IO.File]::WriteAllText("a", "b")' }
        @{ Rule = 'ForbiddenMethod:SetValue'; Text = '$key.SetValue("x", 1)' }
        @{ Rule = 'RegistryOpenedWritable'; Text = '[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM", $true)' }
        @{ Rule = 'DynamicInvocation'; Text = '$c = "Set-ADUser"; & $c -Identity x' }
        @{ Rule = 'ForbiddenCommand:Out-File'; Text = 'Get-Date | Out-File x.txt' }
        @{ Rule = 'RestrictedCommand:Invoke-MgGraphRequest'; Text = 'Invoke-MgGraphRequest -Method GET -Uri x' }
    ) {
        $violations = Get-ReadOnlyViolation -ScriptText $Text -FileName 'entra.ps1'
        @($violations | Where-Object { $_.Rule -eq $Rule }).Count | Should -BeGreaterThan 0
    }

    It 'allows Update-AzConfig only in Connect.ps1 with -Scope Process' {
        Get-ReadOnlyViolation -ScriptText 'Update-AzConfig -EnableLoginByWam $false -Scope Process' -FileName 'Connect.ps1' | Should -BeNullOrEmpty
        @(Get-ReadOnlyViolation -ScriptText 'Update-AzConfig -EnableLoginByWam $false -Scope CurrentUser' -FileName 'Connect.ps1').Count | Should -Be 1
        @(Get-ReadOnlyViolation -ScriptText 'Update-AzConfig -EnableLoginByWam $false' -FileName 'Connect.ps1').Count | Should -Be 1
        @(Get-ReadOnlyViolation -ScriptText 'Update-AzConfig -EnableLoginByWam $false -Scope Process' -FileName 'azure.ps1').Count | Should -Be 1
    }

    It 'accepts read-only code' {
        $violations = Get-ReadOnlyViolation -ScriptText 'Get-ADUser -Filter * -Properties pwdLastSet | Select-Object Name; [System.IO.File]::ReadAllText("x")' -FileName 'ad.ps1'
        $violations | Should -BeNullOrEmpty
    }
}
