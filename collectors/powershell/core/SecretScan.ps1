# Local secret scanner. Mirrors packages/core/src/sensitive.ts so that the collector refuses to
# write evidence the engine would reject. Keep both lists in sync (tests/SecretScan.Tests.ps1
# parses sensitive.ts and fails when they differ).

$script:AsoForbiddenPropertyNames = @(
    'password', 'passwd', 'passwordhash', 'passwordvalue', 'secret', 'secrettext', 'clientsecret', 'hint',
    'accesstoken', 'refreshtoken', 'idtoken', 'bearertoken', 'sastoken', 'privatekey', 'privatekeypem',
    'accountkey', 'primarykey', 'secondarykey', 'connectionstring', 'cpassword', 'nthash', 'lmhash',
    'unicodepwd', 'userpassword', 'msmcsadmpwd', 'mslapspassword', 'mslapsencryptedpassword',
    'mslapsencryptedpasswordhistory', 'dbcspwd', 'supplementalcredentials', 'cookie', 'setcookie',
    'authorization', 'body', 'uniquebody', 'bodypreview', 'messagebody', 'mimecontent'
)
$script:AsoForbiddenNameSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$script:AsoForbiddenPropertyNames, [StringComparer]::Ordinal)

$script:AsoSecretValuePatterns = @(
    [pscustomobject]@{ Id = 'jwt'; Description = 'JSON Web Token (access or ID token)'; Regex = [regex]::new('eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*') }
    [pscustomobject]@{ Id = 'pem-private-key'; Description = 'PEM-encoded private key'; Regex = [regex]::new('-----BEGIN (?:RSA |EC |DSA |ENCRYPTED |OPENSSH )?PRIVATE KEY-----') }
    [pscustomobject]@{ Id = 'storage-account-key'; Description = 'Azure Storage connection string containing an account key'; Regex = [regex]::new('AccountKey=[A-Za-z0-9+/=]{20,}', 'IgnoreCase') }
    [pscustomobject]@{ Id = 'sas-signature'; Description = 'Shared access signature'; Regex = [regex]::new('[?&]sig=[A-Za-z0-9%+/=]{20,}', 'IgnoreCase') }
    [pscustomobject]@{ Id = 'gpp-cpassword'; Description = 'Group Policy Preferences cpassword value'; Regex = [regex]::new('cpassword="[^"]+"', 'IgnoreCase') }
)

function ConvertTo-AsoNormalizedPropertyName {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Name)
    return ($Name.ToLowerInvariant() -replace '[-_.\s]', '')
}

function Test-AsoForbiddenPropertyName {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Name)
    return $script:AsoForbiddenNameSet.Contains((ConvertTo-AsoNormalizedPropertyName -Name $Name))
}

function Find-AsoSensitiveContent {
    <#
    .SYNOPSIS
    Walks a parsed JSON value (hashtables / arrays from ConvertFrom-Json -AsHashtable, or
    PSCustomObjects) and reports forbidden property names and secret-looking values.
    Findings contain only the JSON path and rule, never the value.
    #>
    [CmdletBinding()]
    param([AllowNull()] $InputObject, [int] $MaxFindings = 50)
    $findings = [System.Collections.Generic.List[object]]::new()
    $stack = [System.Collections.Generic.Stack[object]]::new()
    $stack.Push([pscustomobject]@{ Value = $InputObject; Path = '$' })
    while ($stack.Count -gt 0 -and $findings.Count -lt $MaxFindings) {
        $item = $stack.Pop()
        $value = $item.Value
        $path = $item.Path
        if ($null -eq $value) { continue }
        if ($value -is [string]) {
            foreach ($rule in $script:AsoSecretValuePatterns) {
                if ($rule.Regex.IsMatch($value)) {
                    $findings.Add([pscustomobject]@{ Path = $path; Rule = $rule.Id; Description = $rule.Description })
                    break
                }
            }
            continue
        }
        if ($value -is [ValueType]) { continue }
        if ($value -is [System.Collections.IDictionary]) {
            foreach ($key in @($value.Keys)) {
                $child = $value[$key]
                $childPath = "$path.$key"
                if ((Test-AsoForbiddenPropertyName -Name ([string]$key)) -and $null -ne $child -and -not ($child -is [string] -and $child.Length -eq 0)) {
                    $findings.Add([pscustomobject]@{ Path = $childPath; Rule = 'forbidden-property'; Description = "Property name '$key' is not permitted in evidence" })
                    continue
                }
                $stack.Push([pscustomobject]@{ Value = $child; Path = $childPath })
            }
            continue
        }
        if ($value -is [System.Management.Automation.PSCustomObject]) {
            foreach ($prop in $value.PSObject.Properties) {
                $child = $prop.Value
                $childPath = "$path.$($prop.Name)"
                if ((Test-AsoForbiddenPropertyName -Name $prop.Name) -and $null -ne $child -and -not ($child -is [string] -and $child.Length -eq 0)) {
                    $findings.Add([pscustomobject]@{ Path = $childPath; Rule = 'forbidden-property'; Description = "Property name '$($prop.Name)' is not permitted in evidence" })
                    continue
                }
                $stack.Push([pscustomobject]@{ Value = $child; Path = $childPath })
            }
            continue
        }
        if ($value -is [System.Collections.IEnumerable]) {
            $index = 0
            foreach ($child in $value) {
                $stack.Push([pscustomobject]@{ Value = $child; Path = "$path[$index]" })
                $index++
            }
            continue
        }
    }
    return , $findings.ToArray()
}

function Test-AsoJsonTextSensitive {
    <#
    .SYNOPSIS
    Parses JSON text and returns the sensitive-content findings (empty array when clean).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Json)
    $parsed = ConvertFrom-Json -InputObject $Json -AsHashtable -Depth 100 -NoEnumerate
    return , (Find-AsoSensitiveContent -InputObject $parsed)
}
