# Group Policy datasets: GPO metadata, links and flattened security settings parsed from
# Get-GPOReport -ReportType Xml, and a SYSVOL scan for Group Policy Preferences cpassword artifacts.

$script:AsoGppFileNames = @('Groups.xml', 'Services.xml', 'ScheduledTasks.xml', 'DataSources.xml', 'Drives.xml', 'Printers.xml')
# Registry value names whose data could be a credential; their values are never recorded.
$script:AsoSensitiveRegistryNamePattern = '(?i)(pass(word|wd)?|pwd|secret|token|credential|privatekey|apikey|connectionstring)'
$script:AsoAuditValueText = @{ 0 = 'No Auditing'; 1 = 'Success'; 2 = 'Failure'; 3 = 'Success and Failure' }

function ConvertFrom-AsoXmlText {
    <# Parses XML with DTD processing prohibited and no external resolution. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Xml)
    $settings = [System.Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $stringReader = [System.IO.StringReader]::new($Xml)
    $reader = [System.Xml.XmlReader]::Create($stringReader, $settings)
    try {
        $doc = [System.Xml.XmlDocument]::new()
        $doc.XmlResolver = $null
        $doc.Load($reader)
        return , $doc
    }
    finally {
        $reader.Dispose()
        $stringReader.Dispose()
    }
}

function Get-AsoXmlChildText {
    [CmdletBinding()]
    [OutputType([string])]
    param($Node, [Parameter(Mandatory)] [string] $LocalName)
    if ($null -eq $Node) { return $null }
    foreach ($child in $Node.ChildNodes) {
        if ($child.LocalName -eq $LocalName) { return [string]$child.InnerText }
    }
    return $null
}

function Get-AsoXmlChild {
    [CmdletBinding()]
    param($Node, [Parameter(Mandatory)] [string] $LocalName)
    $out = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $Node) {
        foreach ($child in $Node.ChildNodes) { if ($child.LocalName -eq $LocalName) { $out.Add($child) } }
    }
    return , [object[]]$out.ToArray()
}

function ConvertTo-AsoGpoSettingValue {
    <# SettingNumber -> number, SettingBoolean -> bool, SettingString -> string. #>
    [CmdletBinding()]
    param($Node)
    $number = Get-AsoXmlChildText -Node $Node -LocalName 'SettingNumber'
    if ($null -ne $number) { return (ConvertTo-AsoNumber $number) }
    $bool = Get-AsoXmlChildText -Node $Node -LocalName 'SettingBoolean'
    if ($null -ne $bool) { return (ConvertTo-AsoBool $bool) }
    $text = Get-AsoXmlChildText -Node $Node -LocalName 'SettingString'
    if ($null -ne $text) { return $text }
    return $null
}

function ConvertFrom-AsoGpoReport {
    <#
    .SYNOPSIS
    Parses one GPO XML report into links and flattened settings (see the schema naming convention).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Xml, $State, [string] $Target)
    $doc = ConvertFrom-AsoXmlText -Xml $Xml
    $root = $doc.DocumentElement
    $links = [System.Collections.Generic.List[object]]::new()
    foreach ($l in (Get-AsoXmlChild -Node $root -LocalName 'LinksTo')) {
        $links.Add([ordered]@{
                somPath  = [string](Get-AsoXmlChildText -Node $l -LocalName 'SOMPath')
                enabled  = [bool](ConvertTo-AsoBool (Get-AsoXmlChildText -Node $l -LocalName 'Enabled'))
                enforced = [bool](ConvertTo-AsoBool (Get-AsoXmlChildText -Node $l -LocalName 'NoOverride'))
            })
    }
    $settings = [System.Collections.Generic.List[object]]::new()
    $redacted = 0
    foreach ($scope in 'Computer', 'User') {
        foreach ($scopeNode in (Get-AsoXmlChild -Node $root -LocalName $scope)) {
            foreach ($extData in (Get-AsoXmlChild -Node $scopeNode -LocalName 'ExtensionData')) {
                foreach ($ext in (Get-AsoXmlChild -Node $extData -LocalName 'Extension')) {
                    foreach ($node in $ext.ChildNodes) {
                        switch ($node.LocalName) {
                            'SecurityOptions' {
                                $name = Get-AsoXmlChildText -Node $node -LocalName 'KeyName'
                                if (-not $name) { $name = Get-AsoXmlChildText -Node $node -LocalName 'SystemAccessPolicyName' }
                                if ($name) { $settings.Add([ordered]@{ scope = $scope; category = 'SecurityOptions'; name = $name; value = ConvertTo-AsoGpoSettingValue -Node $node }) }
                            }
                            'Account' {
                                $name = Get-AsoXmlChildText -Node $node -LocalName 'Name'
                                if ($name) { $settings.Add([ordered]@{ scope = $scope; category = 'AccountPolicy'; name = $name; value = ConvertTo-AsoGpoSettingValue -Node $node }) }
                            }
                            'UserRightsAssignment' {
                                $name = Get-AsoXmlChildText -Node $node -LocalName 'Name'
                                $members = [System.Collections.Generic.List[string]]::new()
                                foreach ($m in (Get-AsoXmlChild -Node $node -LocalName 'Member')) {
                                    $mName = Get-AsoXmlChildText -Node $m -LocalName 'Name'
                                    if (-not $mName) { $mName = Get-AsoXmlChildText -Node $m -LocalName 'SID' }
                                    if ($mName) { $members.Add($mName) }
                                }
                                if ($name) { $settings.Add([ordered]@{ scope = $scope; category = 'UserRightsAssignment'; name = $name; value = [string[]]$members.ToArray() }) }
                            }
                            'Audit' {
                                $name = Get-AsoXmlChildText -Node $node -LocalName 'Name'
                                $s = [bool](ConvertTo-AsoBool (Get-AsoXmlChildText -Node $node -LocalName 'SuccessAttempts'))
                                $f = [bool](ConvertTo-AsoBool (Get-AsoXmlChildText -Node $node -LocalName 'FailureAttempts'))
                                $text = if ($s -and $f) { 'Success and Failure' } elseif ($s) { 'Success' } elseif ($f) { 'Failure' } else { 'No Auditing' }
                                if ($name) { $settings.Add([ordered]@{ scope = $scope; category = 'AuditPolicy'; name = $name; value = $text }) }
                            }
                            'AuditSetting' {
                                $name = Get-AsoXmlChildText -Node $node -LocalName 'SubcategoryName'
                                $v = ConvertTo-AsoNumber (Get-AsoXmlChildText -Node $node -LocalName 'SettingValue')
                                $text = if ($null -ne $v -and $script:AsoAuditValueText.ContainsKey([int]$v)) { $script:AsoAuditValueText[[int]$v] } else { $null }
                                if ($name) { $settings.Add([ordered]@{ scope = $scope; category = 'AuditPolicy'; name = $name; value = $text }) }
                            }
                            'Policy' {
                                $name = Get-AsoXmlChildText -Node $node -LocalName 'Name'
                                $stateText = Get-AsoXmlChildText -Node $node -LocalName 'State'
                                if ($name) { $settings.Add([ordered]@{ scope = $scope; category = 'RegistryPolicy'; name = $name; value = $stateText }) }
                            }
                            'RegistrySetting' {
                                $keyPath = Get-AsoXmlChildText -Node $node -LocalName 'KeyPath'
                                foreach ($val in (Get-AsoXmlChild -Node $node -LocalName 'Value')) {
                                    $valueName = Get-AsoXmlChildText -Node $val -LocalName 'Name'
                                    $full = if ($valueName) { "$keyPath\$valueName" } else { $keyPath }
                                    $data = $null
                                    if ($valueName -match $script:AsoSensitiveRegistryNamePattern) {
                                        $redacted++
                                    }
                                    else {
                                        $num = Get-AsoXmlChildText -Node $val -LocalName 'Number'
                                        $data = if ($null -ne $num) { ConvertTo-AsoNumber $num } else { Get-AsoXmlChildText -Node $val -LocalName 'String' }
                                    }
                                    if ($keyPath) { $settings.Add([ordered]@{ scope = $scope; category = 'RegistryValue'; name = $full; value = $data }) }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if ($redacted -gt 0 -and $State) {
        Add-AsoDatasetWarning -State $State -Code 'REGISTRY_VALUE_WITHHELD' -Message "$redacted registry value(s) whose name suggests a credential were recorded without their data." -Target $Target
    }
    [pscustomobject]@{
        Links    = [object[]]$links.ToArray()
        Settings = [object[]]$settings.ToArray()
    }
}

function Get-AsoGpoGroupPolicyObject {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $items = Invoke-AsoAdPerDomain -State $State -ScriptBlock {
        param($domain)
        $gpos = @(Invoke-AsoGpoCommand -Name 'Get-GPO' -Parameters @{ All = $true; Domain = $domain } -Property @('Id', 'DisplayName', 'GpoStatus', 'CreationTime', 'ModificationTime', 'WmiFilter') -ReplayKey "Get-GPO_$domain")
        foreach ($g in $gpos) {
            $id = ([string]$g.Id).Trim('{}')
            $parsed = [pscustomobject]@{ Links = [object[]]@(); Settings = [object[]]@() }
            try {
                $xml = Get-AsoGpoReportXml -Guid $id -Domain $domain
                $parsed = ConvertFrom-AsoGpoReport -Xml $xml -State $State -Target "$domain $id"
            }
            catch {
                $mapped = Resolve-AsoErrorStatus -ErrorObject $_
                Add-AsoDatasetError -State $State -Code $mapped.Code -Message "The report of GPO $id could not be read or parsed; links and settings are missing. $($mapped.Message)" -Target "$domain $id"
            }
            [ordered]@{
                id           = $id
                displayName  = [string]$g.DisplayName
                domain       = $domain
                gpoStatus    = [string]$g.GpoStatus
                createdTime  = ConvertTo-AsoTimestamp $g.CreationTime
                modifiedTime = ConvertTo-AsoTimestamp $g.ModificationTime
                wmiFilter    = ConvertTo-AsoString $g.WmiFilter
                links        = $parsed.Links
                settings     = $parsed.Settings
            }
        }
    }
    if (-not $State.Status) { $State.Data = $items }
}

function Get-AsoGpoSysvolPasswordArtifact {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $scanned = [System.Collections.Generic.List[int]]::new()
    $artifacts = Invoke-AsoAdPerDomain -State $State -ScriptBlock {
        param($domain)
        $root = Get-AsoSysvolPolicyRoot -Domain $domain
        $rootFull = [System.IO.Path]::GetFullPath($root).TrimEnd('\', '/')
        $files = @(Get-AsoSysvolPreferenceFile -Root $root -FileName $script:AsoGppFileNames)
        $scanned.Add($files.Count)
        foreach ($file in $files) {
            $hasCpassword = $false
            try { $hasCpassword = Test-AsoFileContainsCpassword -Path $file.FullName }
            catch {
                Add-AsoDatasetError -State $State -Code 'FILE_UNREADABLE' -Message 'A Group Policy Preferences file could not be read.' -Target $file.Name
                continue
            }
            if (-not $hasCpassword) { continue }
            $relative = $file.FullName.Substring($rootFull.Length).TrimStart('\', '/') -replace '/', '\'
            $first = ($relative -split '\\')[0]
            $gpoId = if ($first -match '^\{?([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}?$') { $Matches[1].ToUpperInvariant() } else { $null }
            [ordered]@{
                domain       = $domain
                gpoId        = $gpoId
                relativePath = $relative
                fileName     = $file.Name
            }
        }
    }
    if (-not $State.Status) {
        $total = 0
        foreach ($n in $scanned) { $total += $n }
        $State.Data = [ordered]@{
            filesScanned = [long]$total
            artifacts    = [object[]]$artifacts
        }
    }
}
