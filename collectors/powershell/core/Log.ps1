# Structured, in-memory collection log. Written to logs/collection-log.json at the end of a run.
# Log messages describe what was done (module, dataset, operation, counts, error codes). They never
# contain response bodies, tokens or evidence values.

function Write-AsoLog {
    [CmdletBinding()]
    param(
        [ValidateSet('Debug', 'Info', 'Warning', 'Error')] [string] $Level = 'Info',
        [string] $Module,
        [string] $Dataset,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Message,
        [string] $Target
    )
    $entry = [ordered]@{
        timestamp = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        level     = $Level
        module    = if ($Module) { $Module } else { $null }
        dataset   = if ($Dataset) { $Dataset } else { $null }
        message   = Protect-AsoLogText -Text $Message -MaxLength 1000
        target    = if ($Target) { Protect-AsoLogText -Text $Target -MaxLength 500 } else { $null }
    }
    $ctx = $script:AsoContext
    if ($null -ne $ctx) { $ctx.Log.Add($entry) }
    $prefix = if ($Dataset) { "[$Dataset] " } elseif ($Module) { "[$Module] " } else { '' }
    switch ($Level) {
        'Warning' { Write-Verbose "WARNING: $prefix$($entry.message)" }
        'Error' { Write-Verbose "ERROR: $prefix$($entry.message)" }
        default { Write-Verbose "$prefix$($entry.message)" }
    }
}
