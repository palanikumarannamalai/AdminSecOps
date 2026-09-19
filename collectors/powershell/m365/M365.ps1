# Microsoft 365 (SharePoint Online / OneDrive) tenant settings via Microsoft Graph v1.0 (GET only).

function Get-AsoM365SharePointSetting {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $s = Invoke-AsoGraphGet -Uri "$script:AsoGraphBase/admin/sharepoint/settings"
    $State.Data = [ordered]@{
        sharingCapability                     = [string](Get-AsoPropertyValue $s 'sharingCapability')
        sharingDomainRestrictionMode          = ConvertTo-AsoString (Get-AsoPropertyValue $s 'sharingDomainRestrictionMode')
        isResharingByExternalUsersEnabled     = ConvertTo-AsoBool (Get-AsoPropertyValue $s 'isResharingByExternalUsersEnabled')
        isLegacyAuthProtocolsEnabled          = ConvertTo-AsoBool (Get-AsoPropertyValue $s 'isLegacyAuthProtocolsEnabled')
        isUnmanagedSyncAppForTenantRestricted = ConvertTo-AsoBool (Get-AsoPropertyValue $s 'isUnmanagedSyncAppForTenantRestricted')
    }
}
