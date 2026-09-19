# JSON helpers shared by live and replay code paths.

$script:AsoJsonHasDateKind = $null -ne (Get-Command -Name ConvertFrom-Json).Parameters['DateKind']

function ConvertFrom-AsoJson {
    <#
    .SYNOPSIS
    Parses JSON into PSCustomObjects without converting date strings to DateTime (where the
    PowerShell version supports -DateKind String). Timestamps are normalised later by
    ConvertTo-AsoTimestamp, which accepts both strings and DateTime values.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Json, [switch] $AsHashtable)
    if ([string]::IsNullOrWhiteSpace($Json)) { return $null }
    $params = @{ InputObject = $Json; Depth = 100; NoEnumerate = $true }
    if ($AsHashtable) { $params['AsHashtable'] = $true }
    if ($script:AsoJsonHasDateKind) { $params['DateKind'] = 'String' }
    return , (ConvertFrom-Json @params)
}

function ConvertTo-AsoJson {
    <#
    .SYNOPSIS
    Serialises evidence with enough depth for every dataset. Arrays must already be real arrays
    (use @() / [object[]] when building objects) so that single-element and empty arrays are kept.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowNull()] $InputObject, [switch] $Compress)
    return (ConvertTo-Json -InputObject $InputObject -Depth 30 -Compress:$Compress)
}
