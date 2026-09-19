# PSScriptAnalyzer settings for the AdminSecOps collectors (used by scripts/Invoke-PSScriptAnalyzer.ps1).
#
# Policy: every default rule at Error and Warning severity is enforced and the build fails on any
# finding. Nothing is excluded globally. Where a rule does not fit a specific function, the
# function carries a [Diagnostics.CodeAnalysis.SuppressMessageAttribute] with a written
# justification next to the code, so every exception is reviewed in context:
#   - PSUseShouldProcessForStateChangingFunctions is suppressed only on New-Aso* / Set-Aso* helpers
#     that build or change in-memory objects (envelopes, messages, dataset state). They change no
#     system state, so -WhatIf/-Confirm would be meaningless. The static read-only test
#     (tests/ReadOnly.Tests.ps1) independently proves no state-changing command is used.
#   - PSReviewUnusedParameter is suppressed only on test stubs whose signatures mirror real cmdlets
#     so Pester parameter filters can be applied.
@{
    Severity            = @('Error', 'Warning')
    IncludeDefaultRules = $true
    ExcludeRules        = @()
    Rules               = @{
        # The module declares PowerShellVersion 7.2; flag syntax that would not parse there.
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('7.2')
        }
    }
}
