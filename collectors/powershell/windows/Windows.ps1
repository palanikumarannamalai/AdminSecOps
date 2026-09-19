# Local Windows host security configuration (the host running the collector only).
# Read-only: CIM queries, Get-* cmdlets and read-only registry access. Every value is null when unreadable.

function Get-AsoSafeValue {
    <# Runs a read and returns $null (with a warning) when it fails, so one unreadable value never fails the host. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State, [Parameter(Mandatory)] [string] $What, [Parameter(Mandatory)] [scriptblock] $Read)
    try {
        return , (& $Read)
    }
    catch {
        Add-AsoDatasetWarning -State $State -Code 'VALUE_UNREADABLE' -Message "$What could not be read: $($_.Exception.Message)"
        return $null
    }
}

function Read-AsoHostRegistryValue {
    <#
    .SYNOPSIS
    Reads a local HKLM value. Returns $null when absent or unreadable (unreadable adds a warning).
    With -Detailed returns @{ Readable; Value } so "not configured" and "unreadable" can be told apart.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State, [Parameter(Mandatory)] [string] $SubKey, [Parameter(Mandatory)] [string] $Name, [switch] $Detailed)
    $readable = $true
    $value = $null
    try { $value = Get-AsoRegistryValue -SubKey $SubKey -Name $Name }
    catch {
        $readable = $false
        Add-AsoDatasetWarning -State $State -Code 'VALUE_UNREADABLE' -Message "Registry value HKLM\$SubKey\$Name could not be read: $($_.Exception.Message)"
    }
    if ($Detailed) { return [pscustomobject]@{ Readable = $readable; Value = $value } }
    return $value
}

function Get-AsoWindowsHost {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $os = @(Invoke-AsoWindowsCommand -Name 'Get-CimInstance' -Parameters @{ ClassName = 'Win32_OperatingSystem' } -Property @('Caption', 'Version', 'BuildNumber', 'ProductType') -ReplayKey 'Win32_OperatingSystem')[0]
    if ($null -eq $os) { throw 'Win32_OperatingSystem returned no instance.' }
    $cs = Get-AsoSafeValue -State $State -What 'Win32_ComputerSystem' -Read { @(Invoke-AsoWindowsCommand -Name 'Get-CimInstance' -Parameters @{ ClassName = 'Win32_ComputerSystem' } -Property @('Name', 'DNSHostName', 'Domain', 'PartOfDomain') -ReplayKey 'Win32_ComputerSystem')[0] }
    $productType = ConvertTo-AsoNumber $os.ProductType
    $hostName = if ($cs -and $cs.DNSHostName) { [string]$cs.DNSHostName } elseif ($cs -and $cs.Name) { [string]$cs.Name } else { 'localhost' }
    if ($cs -and (ConvertTo-AsoBool $cs.PartOfDomain) -and $cs.Domain) { $hostName = "$hostName.$($cs.Domain)".ToLowerInvariant() }

    $firewall = Get-AsoSafeValue -State $State -What 'Firewall profiles' -Read {
        [object[]]@(Invoke-AsoWindowsCommand -Name 'Get-NetFirewallProfile' -Parameters @{ PolicyStore = 'ActiveStore' } -Property @('Name', 'Enabled', 'DefaultInboundAction') | ForEach-Object {
                [ordered]@{
                    name                 = [string]$_.Name
                    enabled              = ConvertTo-AsoBool $_.Enabled
                    defaultInboundAction = ConvertTo-AsoString $_.DefaultInboundAction
                }
            })
    }
    if ($null -eq $firewall) { $firewall = [object[]]@() } else { $firewall = [object[]]@($firewall) }

    $smb = Get-AsoSafeValue -State $State -What 'SMB server configuration' -Read { @(Invoke-AsoWindowsCommand -Name 'Get-SmbServerConfiguration' -Property @('EnableSMB1Protocol', 'RequireSecuritySignature'))[0] }

    $tsPolicy = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $deny = Read-AsoHostRegistryValue -State $State -SubKey $tsPolicy -Name 'fDenyTSConnections'
    if ($null -eq $deny) { $deny = Read-AsoHostRegistryValue -State $State -SubKey 'SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' }
    $nla = Read-AsoHostRegistryValue -State $State -SubKey $tsPolicy -Name 'UserAuthentication'
    if ($null -eq $nla) { $nla = Read-AsoHostRegistryValue -State $State -SubKey 'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' }
    $denyN = ConvertTo-AsoNumber $deny
    $nlaN = ConvertTo-AsoNumber $nla

    $lsaKey = 'SYSTEM\CurrentControlSet\Control\Lsa'
    $sbl = Read-AsoHostRegistryValue -State $State -SubKey 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Detailed
    $sblEnabled = if ($sbl.Readable) { (ConvertTo-AsoNumber $sbl.Value) -eq 1 } else { $null }

    $dg = Get-AsoSafeValue -State $State -What 'Win32_DeviceGuard' -Read { @(Invoke-AsoWindowsCommand -Name 'Get-CimInstance' -Parameters @{ Namespace = 'root\Microsoft\Windows\DeviceGuard'; ClassName = 'Win32_DeviceGuard' } -Property @('SecurityServicesRunning', 'VirtualizationBasedSecurityStatus') -ReplayKey 'Win32_DeviceGuard')[0] }
    $running = $null
    if ($dg) { $running = @(ConvertTo-AsoStringArray $dg.SecurityServicesRunning) -contains '1' }

    $mp = $null
    try {
        $mp = @(Invoke-AsoWindowsCommand -Name 'Get-MpComputerStatus' -Property @('AntivirusEnabled', 'RealTimeProtectionEnabled', 'IsTamperProtected', 'AntivirusSignatureAge'))[0]
    }
    catch {
        Add-AsoDatasetWarning -State $State -Code 'DEFENDER_UNAVAILABLE' -Message "Microsoft Defender status is not available: $($_.Exception.Message)"
    }

    $State.Data = [object[]]@(
        [ordered]@{
            hostName           = $hostName
            osCaption          = ConvertTo-AsoString $os.Caption
            osVersion          = ConvertTo-AsoString $os.Version
            osBuild            = ConvertTo-AsoString $os.BuildNumber
            isServer           = ($null -ne $productType -and $productType -ne 1)
            isDomainController = ($productType -eq 2)
            domainJoined       = if ($cs) { ConvertTo-AsoBool $cs.PartOfDomain } else { $null }
            firewallProfiles   = $firewall
            smb                = [ordered]@{
                smb1ServerEnabled             = if ($smb) { ConvertTo-AsoBool $smb.EnableSMB1Protocol } else { $null }
                serverRequireSecuritySignature = if ($smb) { ConvertTo-AsoBool $smb.RequireSecuritySignature } else { $null }
            }
            rdp                = [ordered]@{
                enabled     = if ($null -ne $denyN) { $denyN -eq 0 } else { $null }
                nlaRequired = if ($null -ne $nlaN) { $nlaN -eq 1 } else { $null }
            }
            lsa                = [ordered]@{
                runAsPPL                  = ConvertTo-AsoNumber (Read-AsoHostRegistryValue -State $State -SubKey $lsaKey -Name 'RunAsPPL')
                lmCompatibilityLevel      = ConvertTo-AsoNumber (Read-AsoHostRegistryValue -State $State -SubKey $lsaKey -Name 'LmCompatibilityLevel')
                wdigestUseLogonCredential = ConvertTo-AsoNumber (Read-AsoHostRegistryValue -State $State -SubKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential')
            }
            credentialGuard    = [ordered]@{
                running   = $running
                vbsStatus = if ($dg) { ConvertTo-AsoNumber $dg.VirtualizationBasedSecurityStatus } else { $null }
            }
            powershell         = [ordered]@{
                scriptBlockLoggingEnabled = $sblEnabled
            }
            defender           = [ordered]@{
                available                 = ($null -ne $mp)
                antivirusEnabled          = if ($mp) { ConvertTo-AsoBool $mp.AntivirusEnabled } else { $null }
                realTimeProtectionEnabled = if ($mp) { ConvertTo-AsoBool $mp.RealTimeProtectionEnabled } else { $null }
                isTamperProtected         = if ($mp) { ConvertTo-AsoBool $mp.IsTamperProtected } else { $null }
                antivirusSignatureAgeDays = if ($mp) { ConvertTo-AsoNumber $mp.AntivirusSignatureAge } else { $null }
            }
        }
    )
}
