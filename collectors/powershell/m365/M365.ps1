# Microsoft 365 (SharePoint Online / OneDrive and Microsoft Teams) settings via Microsoft Graph v1.0 (GET only).

$script:AsoTeamsFanoutLimit = 200

function ConvertTo-AsoStringList {
    <# Returns a string array for a Graph string collection, or $null when the property was not returned. #>
    [CmdletBinding()]
    param($InputObject, [Parameter(Mandatory)] [string] $Name)
    if ($null -eq (Get-AsoPropertyValue $InputObject $Name)) { return $null }
    return , [object[]]@((Get-AsoList $InputObject $Name) | ForEach-Object { [string]$_ })
}

function Get-AsoM365SharePointSetting {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $s = Invoke-AsoGraphGet -Uri "$script:AsoGraphBase/admin/sharepoint/settings"
    # The documented response example wraps the settings in "value".
    $inner = Get-AsoPropertyValue $s 'value'
    if ($inner -is [System.Collections.IDictionary] -or $inner -is [System.Management.Automation.PSCustomObject]) { $s = $inner }
    $idle = Get-AsoPropertyValue $s 'idleSessionSignOut'
    $State.Data = [ordered]@{
        sharingCapability                               = [string](Get-AsoPropertyValue $s 'sharingCapability')
        sharingDomainRestrictionMode                    = ConvertTo-AsoString (Get-AsoPropertyValue $s 'sharingDomainRestrictionMode')
        isResharingByExternalUsersEnabled               = ConvertTo-AsoBool (Get-AsoPropertyValue $s 'isResharingByExternalUsersEnabled')
        isLegacyAuthProtocolsEnabled                    = ConvertTo-AsoBool (Get-AsoPropertyValue $s 'isLegacyAuthProtocolsEnabled')
        isUnmanagedSyncAppForTenantRestricted           = ConvertTo-AsoBool (Get-AsoPropertyValue $s 'isUnmanagedSyncAppForTenantRestricted')
        sharingAllowedDomainList                        = ConvertTo-AsoStringList $s 'sharingAllowedDomainList'
        sharingBlockedDomainList                        = ConvertTo-AsoStringList $s 'sharingBlockedDomainList'
        isRequireAcceptingUserToMatchInvitedUserEnabled = ConvertTo-AsoBool (Get-AsoPropertyValue $s 'isRequireAcceptingUserToMatchInvitedUserEnabled')
        idleSessionSignOut                              = if ($null -eq $idle) { $null } else {
            [ordered]@{
                isEnabled             = ConvertTo-AsoBool (Get-AsoPropertyValue $idle 'isEnabled')
                warnAfterInSeconds    = ConvertTo-AsoNumber (Get-AsoPropertyValue $idle 'warnAfterInSeconds')
                signOutAfterInSeconds = ConvertTo-AsoNumber (Get-AsoPropertyValue $idle 'signOutAfterInSeconds')
            }
        }
    }
}

function Get-AsoM365TeamsAppSetting {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $s = Invoke-AsoGraphGet -Uri "$script:AsoGraphBase/teamwork/teamsAppSettings"
    $State.Data = [ordered]@{
        allowUserRequestsForAppAccess                     = ConvertTo-AsoBool (Get-AsoPropertyValue $s 'allowUserRequestsForAppAccess')
        isUserPersonalScopeResourceSpecificConsentEnabled = ConvertTo-AsoBool (Get-AsoPropertyValue $s 'isUserPersonalScopeResourceSpecificConsentEnabled')
    }
}

function ConvertTo-AsoTeamSettingSet {
    [CmdletBinding()]
    param($InputObject, [Parameter(Mandatory)] [string[]] $Name)
    if ($null -eq $InputObject) { return $null }
    $out = [ordered]@{}
    foreach ($n in $Name) { $out[$n] = ConvertTo-AsoBool (Get-AsoPropertyValue $InputObject $n) }
    return $out
}

function Get-AsoM365TeamsTeamSetting {
    <#
    .SYNOPSIS
    Per-team member and guest settings (owner-chosen, not tenant policy). Lists teams, then reads each
    team (bounded). A team that cannot be read keeps null settings and marks the dataset Partial.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $select = 'id,displayName,visibility,isArchived,memberSettings,guestSettings'
    $teams = @(Invoke-AsoGraphGetAll -Uri "$script:AsoGraphBase/teams?`$select=id,displayName,visibility" -State $State)
    $out = [System.Collections.Generic.List[object]]::new()
    $read = 0
    foreach ($t in $teams) {
        $id = [string](Get-AsoPropertyValue $t 'id')
        $team = $null
        if ($id -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,199}$') {
            Add-AsoDatasetError -State $State -Code 'FANOUT_ITEM_INVALID' -Message 'A team could not be requested (invalid identifier).'
        }
        elseif ($read -ge $script:AsoTeamsFanoutLimit) {
            if ($read -eq $script:AsoTeamsFanoutLimit) {
                Add-AsoDatasetError -State $State -Code 'FANOUT_LIMIT' -Message "Stopped after $read team settings request(s) (collection limit); results are incomplete."
                $read++
            }
        }
        else {
            $read++
            try {
                $team = Invoke-AsoGraphGet -Uri "$script:AsoGraphBase/teams/$([uri]::EscapeDataString($id))?`$select=$select"
            }
            catch {
                $mapped = Resolve-AsoErrorStatus -ErrorObject $_
                Add-AsoDatasetError -State $State -Code 'FANOUT_ITEM_FAILED' -Message "The team settings could not be read. $($mapped.Message)" -Target $id
            }
        }
        if ($null -ne $team -and ($null -eq (Get-AsoPropertyValue $team 'memberSettings') -or $null -eq (Get-AsoPropertyValue $team 'guestSettings'))) {
            Add-AsoDatasetError -State $State -Code 'TEAM_SETTINGS_MISSING' -Message 'Microsoft Graph returned a team without its member or guest settings.' -Target $id
        }
        $source = if ($null -ne $team) { $team } else { $t }
        $out.Add([ordered]@{
                id             = $id
                displayName    = ConvertTo-AsoString (Get-AsoPropertyValue $source 'displayName')
                visibility     = ConvertTo-AsoString (Get-AsoPropertyValue $source 'visibility')
                isArchived     = ConvertTo-AsoBool (Get-AsoPropertyValue $team 'isArchived')
                memberSettings = ConvertTo-AsoTeamSettingSet (Get-AsoPropertyValue $team 'memberSettings') @('allowCreateUpdateChannels', 'allowDeleteChannels', 'allowAddRemoveApps', 'allowCreateUpdateRemoveTabs', 'allowCreateUpdateRemoveConnectors')
                guestSettings  = ConvertTo-AsoTeamSettingSet (Get-AsoPropertyValue $team 'guestSettings') @('allowCreateUpdateChannels', 'allowDeleteChannels')
            })
    }
    $State.Data = [object[]]$out.ToArray()
}
