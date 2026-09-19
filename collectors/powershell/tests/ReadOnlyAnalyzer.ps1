# Static read-only analysis of collector source code using the PowerShell AST.
# Used by ReadOnly.Tests.ps1. Returns violations as objects (file, line, rule, text).

$script:ForbiddenVerbs = @(
    'Set', 'New', 'Remove', 'Add', 'Enable', 'Disable', 'Grant', 'Revoke', 'Update', 'Clear', 'Reset',
    'Start', 'Stop', 'Restart', 'Suspend', 'Resume', 'Install', 'Uninstall', 'Register', 'Unregister',
    'Publish', 'Unpublish', 'Move', 'Copy', 'Rename', 'Send', 'Submit', 'Approve', 'Deny', 'Lock', 'Unlock',
    'Mount', 'Dismount', 'Protect', 'Unprotect', 'Block', 'Unblock', 'Export', 'Save', 'Sync', 'Push',
    'Restore', 'Backup', 'Initialize', 'Edit', 'Merge', 'Join', 'Split', 'Invoke', 'Out', 'Write', 'Set'
)
# Commands with a forbidden verb that are harmless (no state outside the process) or read-only.
$script:AllowedCommands = @(
    'Set-StrictMode', 'Start-Sleep', 'Out-Null', 'Out-String', 'Export-ModuleMember', 'Join-Path', 'Split-Path',
    'Write-Verbose', 'Write-Output', 'Write-Warning', 'Write-Debug', 'Write-Information', 'Write-Error'
)
# Only these files may call these commands.
$script:RestrictedCommands = @{
    'Invoke-MgGraphRequest' = @('DataAccess.ps1')
    'Invoke-AzRestMethod'   = @('DataAccess.ps1')
    'Resolve-DnsName'       = @('DataAccess.ps1')
    'Add-Type'              = @('Output.ps1')
    'Connect-MgGraph'       = @('Connect.ps1')
    'Connect-ExchangeOnline' = @('Connect.ps1')
    'Connect-AzAccount'     = @('Connect.ps1')
}
$script:AlwaysForbiddenCommands = @(
    'Invoke-RestMethod', 'Invoke-WebRequest', 'Invoke-Expression', 'iex', 'Invoke-Command', 'Invoke-Item',
    'Invoke-CimMethod', 'Invoke-WmiMethod', 'Start-Process', 'Start-Job', 'Set-Content', 'Add-Content',
    'Out-File', 'Set-ItemProperty', 'New-ItemProperty', 'Remove-ItemProperty', 'Set-Item', 'Remove-Item',
    'New-Item', 'Copy-Item', 'Move-Item', 'Rename-Item', 'Set-Acl', 'Invoke-MgGraphRequestBatch', 'curl', 'wget', 'irm', 'iwr'
)
# .NET methods that change state. Allowed only in core/Output.ps1 (package writing).
$script:ForbiddenMethods = @(
    'WriteAllText', 'WriteAllBytes', 'WriteAllLines', 'AppendAllText', 'AppendAllLines', 'AppendText', 'CreateText',
    'CreateDirectory', 'Delete', 'DeleteValue', 'DeleteSubKey', 'DeleteSubKeyTree', 'SetValue', 'CreateSubKey',
    'SetAccessControl', 'SetAttributes', 'CommitChanges', 'SetInfo', 'Put', 'PutEx', 'InvokeSet', 'MoveTo', 'CopyTo',
    'Move', 'Copy', 'Encrypt', 'Decrypt', 'OpenWrite', 'CreateEntry', 'ExtractToDirectory', 'SetPassword', 'ChangePassword'
)
# Dynamic invocations (& $var) are allowed only for these variables (script blocks passed as parameters,
# or the allow-listed command resolved in DataAccess.ps1).
$script:AllowedDynamicInvocations = @{ 'ScriptBlock' = '*'; 'Read' = '*'; 'command' = 'DataAccess.ps1' }
# Other dynamic invocations by exact expression: the dataset collector named in the catalogue (checked by
# Catalog.Tests.ps1 to be a module Get-Aso* function) and the module loader dot-sourcing its own files.
$script:AllowedDynamicExpressions = @{ '$Entry.Function' = 'Collection.ps1'; '$file.FullName' = 'AdminSecOps.Collector.psm1' }
$script:WriteExemptFiles = @('Output.ps1')

function Get-ReadOnlyViolation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Path')] [string[]] $Path,
        [Parameter(Mandatory, ParameterSetName = 'Text')] [string] $ScriptText,
        [Parameter(ParameterSetName = 'Text')] [string] $FileName = 'Synthetic.ps1',
        [string[]] $ModuleFunctionName = @()
    )
    $sources = [System.Collections.Generic.List[object]]::new()
    if ($PSCmdlet.ParameterSetName -eq 'Path') {
        foreach ($p in $Path) {
            $tokens = $null; $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$tokens, [ref]$errors)
            $sources.Add([pscustomobject]@{ Name = (Split-Path -Leaf $p); Ast = $ast; Errors = $errors })
        }
    }
    else {
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($ScriptText, [ref]$tokens, [ref]$errors)
        $sources.Add([pscustomobject]@{ Name = $FileName; Ast = $ast; Errors = $errors })
    }

    $violations = [System.Collections.Generic.List[object]]::new()
    $add = {
        param($file, $node, $rule)
        $violations.Add([pscustomobject]@{ File = $file; Line = $node.Extent.StartLineNumber; Rule = $rule; Text = ($node.Extent.Text -split "`n")[0].Trim() })
    }

    foreach ($src in $sources) {
        $file = $src.Name
        foreach ($e in @($src.Errors)) { if ($e) { $violations.Add([pscustomobject]@{ File = $file; Line = $e.Extent.StartLineNumber; Rule = 'ParseError'; Text = $e.Message }) } }

        # Commands
        foreach ($cmd in $src.Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
            $name = $cmd.GetCommandName()
            if (-not $name) {
                $first = $cmd.CommandElements[0]
                $varName = if ($first -is [System.Management.Automation.Language.VariableExpressionAst]) { $first.VariablePath.UserPath } else { $null }
                $allowed = $varName -and $script:AllowedDynamicInvocations.ContainsKey($varName) -and ($script:AllowedDynamicInvocations[$varName] -eq '*' -or $script:AllowedDynamicInvocations[$varName] -eq $file)
                if ($first -is [System.Management.Automation.Language.ScriptBlockExpressionAst]) { $allowed = $true }
                if ($script:AllowedDynamicExpressions.ContainsKey($first.Extent.Text) -and $script:AllowedDynamicExpressions[$first.Extent.Text] -eq $file) { $allowed = $true }
                if (-not $allowed) { & $add $file $cmd 'DynamicInvocation' }
                continue
            }
            if ($script:AlwaysForbiddenCommands -contains $name) { & $add $file $cmd "ForbiddenCommand:$name"; continue }
            # Update-AzConfig changes only the local Az client, and is allowed solely in Connect.ps1 with
            # an explicit '-Scope Process' (so nothing persists beyond the collector process).
            if ($name -eq 'Update-AzConfig') {
                $scopeIndex = [array]::FindIndex([object[]]$cmd.CommandElements, [Predicate[object]] { param($e) $e -is [System.Management.Automation.Language.CommandParameterAst] -and $e.ParameterName -eq 'Scope' })
                $scopeValue = if ($scopeIndex -ge 0 -and $scopeIndex + 1 -lt $cmd.CommandElements.Count) { $cmd.CommandElements[$scopeIndex + 1].Extent.Text } else { $null }
                if ($file -ne 'Connect.ps1' -or $scopeValue -ne 'Process') { & $add $file $cmd 'ForbiddenCommand:Update-AzConfig (only Connect.ps1 with -Scope Process)' }
                continue
            }
            if ($script:RestrictedCommands.ContainsKey($name)) {
                if ($script:RestrictedCommands[$name] -notcontains $file) { & $add $file $cmd "RestrictedCommand:$name" }
            }
            elseif ($ModuleFunctionName -contains $name -or $script:AllowedCommands -contains $name) {
                # Module-internal functions are analysed through their own bodies.
            }
            elseif ($name -match '^([A-Za-z]+)-') {
                $verb = $Matches[1]
                if ($script:ForbiddenVerbs -contains $verb -and -not ($script:WriteExemptFiles -contains $file -and $name -in 'New-Item')) {
                    & $add $file $cmd "ForbiddenVerb:$name"
                }
            }
            # HTTP method must be GET wherever a -Method parameter is used.
            for ($i = 0; $i -lt $cmd.CommandElements.Count; $i++) {
                $el = $cmd.CommandElements[$i]
                if ($el -is [System.Management.Automation.Language.CommandParameterAst] -and $el.ParameterName -eq 'Method') {
                    $arg = if ($el.Argument) { $el.Argument } elseif ($i + 1 -lt $cmd.CommandElements.Count) { $cmd.CommandElements[$i + 1] } else { $null }
                    $value = if ($arg -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $arg.Value } else { $null }
                    if ($value -ne 'GET') { & $add $file $cmd 'NonGetHttpMethod' }
                }
            }
            if ($name -in 'Invoke-MgGraphRequest', 'Invoke-AzRestMethod') {
                $hasMethod = @($cmd.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'Method' }).Count -gt 0
                $splat = @($cmd.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.VariableExpressionAst] -and $_.Splatted }).Count -gt 0
                if (-not $hasMethod -and -not $splat) { & $add $file $cmd 'HttpMethodNotExplicit' }
            }
        }

        # Hashtables used for splatting: Method = 'GET' only.
        foreach ($ht in $src.Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.HashtableAst] }, $true)) {
            foreach ($pair in $ht.KeyValuePairs) {
                $key = $pair.Item1
                if ($key -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $key.Value -eq 'Method') {
                    $valueText = $pair.Item2.Extent.Text.Trim().Trim("'", '"')
                    if ($valueText -ne 'GET') { & $add $file $ht 'NonGetHttpMethod' }
                }
            }
        }

        # .NET methods that write or change state.
        if ($script:WriteExemptFiles -notcontains $file) {
            foreach ($m in $src.Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)) {
                $member = if ($m.Member -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $m.Member.Value } else { $null }
                if (-not $member) { & $add $file $m 'DynamicMethodName'; continue }
                if ($script:ForbiddenMethods -contains $member) { & $add $file $m "ForbiddenMethod:$member" }
                if ($member -eq 'OpenSubKey') {
                    $args2 = @($m.Arguments)
                    $ok = $args2.Count -ge 2 -and $args2[1].Extent.Text -eq '$false'
                    if (-not $ok) { & $add $file $m 'RegistryOpenedWritable' }
                }
                if ($member -eq 'Open' -and $m.Expression -is [System.Management.Automation.Language.TypeExpressionAst] -and $m.Expression.TypeName.FullName -match 'IO\.File$') { & $add $file $m 'FileOpen' }
            }
        }

        # Strings that look like write HTTP verbs passed to a request.
        foreach ($s in $src.Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -or $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst] }, $true)) {
            if ($s.Value -match '(?i)-Method\s+[''"]?(POST|PATCH|PUT|DELETE|MERGE)\b') { & $add $file $s 'NonGetHttpMethodInString' }
        }
    }
    return , $violations.ToArray()
}

function Get-ModuleFunctionName {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string[]] $Path)
    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $Path) {
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$tokens, [ref]$errors)
        foreach ($f in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) { $names.Add($f.Name) }
    }
    return , $names.ToArray()
}
