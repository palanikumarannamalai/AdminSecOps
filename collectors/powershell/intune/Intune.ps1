# Microsoft Intune datasets via Microsoft Graph v1.0 (GET only).

$script:AsoIntunePlans = @('INTUNE_A', 'INTUNE_EDU', 'INTUNE_SMBIZ', 'INTUNE_A_VL', 'Intune_Defender', 'INTUNE_P1')

function Get-AsoIntuneSetting {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    if (-not (Assert-AsoLicence -State $State -ServicePlan $script:AsoIntunePlans -Feature 'Microsoft Intune')) { return }
    $dm = Invoke-AsoGraphGet -Uri "$script:AsoGraphBase/deviceManagement?`$select=settings"
    $s = Get-AsoPropertyValue $dm 'settings'
    if ($null -eq $s) {
        # Live validation: the deviceManagement singleton may ignore $select and omit settings.
        $dm = Invoke-AsoGraphGet -Uri "$script:AsoGraphBase/deviceManagement"
        $s = Get-AsoPropertyValue $dm 'settings'
    }
    if ($null -eq $s) { throw 'deviceManagement did not return settings (with or without $select).' }
    $State.Data = [ordered]@{
        secureByDefault                     = [bool](ConvertTo-AsoBool (Get-AsoPropertyValue $s 'secureByDefault'))
        deviceComplianceCheckinThresholdDays = ConvertTo-AsoNumber (Get-AsoPropertyValue $s 'deviceComplianceCheckinThresholdDays')
        isScheduledActionEnabled            = ConvertTo-AsoBool (Get-AsoPropertyValue $s 'isScheduledActionEnabled')
    }
}

function Get-AsoIntuneDeviceOverview {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    if (-not (Assert-AsoLicence -State $State -ServicePlan $script:AsoIntunePlans -Feature 'Microsoft Intune')) { return }
    $o = Invoke-AsoGraphGet -Uri "$script:AsoGraphBase/deviceManagement/managedDeviceOverview"
    $os = Get-AsoPropertyValue $o 'deviceOperatingSystemSummary'
    $State.Data = [ordered]@{
        enrolledDeviceCount = Get-AsoCount (Get-AsoPropertyValue $o 'enrolledDeviceCount')
        windowsCount        = Get-AsoCount (Get-AsoPropertyValue $os 'windowsCount')
        macOSCount          = Get-AsoCount (Get-AsoPropertyValue $os 'macOSCount')
        iosCount            = Get-AsoCount (Get-AsoPropertyValue $os 'iosCount')
        androidCount        = Get-AsoCount (Get-AsoPropertyValue $os 'androidCount')
    }
}

function Get-AsoIntuneCompliancePolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    if (-not (Assert-AsoLicence -State $State -ServicePlan $script:AsoIntunePlans -Feature 'Microsoft Intune')) { return }
    $items = @(Invoke-AsoGraphGetAll -Uri "$script:AsoGraphBase/deviceManagement/deviceCompliancePolicies?`$expand=assignments" -State $State)
    $State.Data = [object[]]@($items | ForEach-Object {
            $p = $_
            $assignments = [object[]]@((Get-AsoList $p 'assignments') | ForEach-Object {
                    $target = Get-AsoPropertyValue $_ 'target'
                    [ordered]@{
                        targetType = [string](Get-AsoOdataPropertyValue $target '@odata.type')
                        groupId    = ConvertTo-AsoString (Get-AsoPropertyValue $target 'groupId')
                    }
                })
            [ordered]@{
                id                   = [string](Get-AsoPropertyValue $p 'id')
                displayName          = [string](Get-AsoPropertyValue $p 'displayName')
                odataType            = [string](Get-AsoOdataPropertyValue $p '@odata.type')
                lastModifiedDateTime = ConvertTo-AsoTimestamp (Get-AsoPropertyValue $p 'lastModifiedDateTime')
                assignments          = $assignments
                settings             = [ordered]@{
                    bitLockerEnabled         = ConvertTo-AsoBool (Get-AsoPropertyValue $p 'bitLockerEnabled')
                    secureBootEnabled        = ConvertTo-AsoBool (Get-AsoPropertyValue $p 'secureBootEnabled')
                    codeIntegrityEnabled     = ConvertTo-AsoBool (Get-AsoPropertyValue $p 'codeIntegrityEnabled')
                    storageRequireEncryption = ConvertTo-AsoBool (Get-AsoFirstPropertyValue -InputObject $p -Name @('storageRequireEncryption', 'storageRequireDeviceEncryption'))
                    passwordRequired         = ConvertTo-AsoBool (Get-AsoFirstPropertyValue -InputObject $p -Name @('passwordRequired', 'passcodeRequired'))
                    defenderEnabled          = ConvertTo-AsoBool (Get-AsoPropertyValue $p 'defenderEnabled')
                    rtpEnabled               = ConvertTo-AsoBool (Get-AsoPropertyValue $p 'rtpEnabled')
                    antivirusRequired        = ConvertTo-AsoBool (Get-AsoPropertyValue $p 'antivirusRequired')
                    firewallEnabled          = ConvertTo-AsoBool (Get-AsoFirstPropertyValue -InputObject $p -Name @('firewallEnabled', 'activeFirewallRequired'))
                    tpmRequired              = ConvertTo-AsoBool (Get-AsoPropertyValue $p 'tpmRequired')
                    osMinimumVersion         = ConvertTo-AsoString (Get-AsoPropertyValue $p 'osMinimumVersion')
                }
            }
        })
}
