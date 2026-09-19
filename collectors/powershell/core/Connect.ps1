# Interactive, read-only sign-in. Credentials and tokens are never requested by, stored by or
# written by the collector: the Microsoft sign-in experience of each module handles authentication
# and keeps tokens in that module's own in-memory cache.

function Get-AsoGraphConnectionState {
    [CmdletBinding()]
    param()
    if (-not (Get-Command -Name Get-MgContext -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ Connected = $false; TenantId = $null; Scopes = [string[]]@(); Detail = 'Microsoft.Graph.Authentication is not loaded.' }
    }
    $mg = Get-MgContext
    if ($null -eq $mg) {
        return [pscustomobject]@{ Connected = $false; TenantId = $null; Scopes = [string[]]@(); Detail = 'Not connected to Microsoft Graph.' }
    }
    # Only the tenant ID and granted scope names are read from the context; never token data.
    return [pscustomobject]@{ Connected = $true; TenantId = [string]$mg.TenantId; Scopes = ConvertTo-AsoStringArray -Value $mg.Scopes; Detail = 'Connected to Microsoft Graph.' }
}

function Get-AsoExchangeConnectionState {
    [CmdletBinding()]
    param()
    if (-not (Get-Command -Name Get-ConnectionInformation -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ Connected = $false; Detail = 'ExchangeOnlineManagement is not loaded.' }
    }
    $connections = @(Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object { [string]$_.State -eq 'Connected' -and -not $_.IsEopSession })
    if ($connections.Count -eq 0) { return [pscustomobject]@{ Connected = $false; Detail = 'Not connected to Exchange Online.' } }
    return [pscustomobject]@{ Connected = $true; Detail = 'Connected to Exchange Online.' }
}

function Get-AsoAzureConnectionState {
    [CmdletBinding()]
    param()
    if (-not (Get-Command -Name Get-AzContext -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ Connected = $false; TenantId = $null; Detail = 'Az.Accounts is not loaded.' }
    }
    $az = Get-AzContext -ErrorAction SilentlyContinue
    if ($null -eq $az -or $null -eq $az.Account) { return [pscustomobject]@{ Connected = $false; TenantId = $null; Detail = 'Not connected to Azure.' } }
    return [pscustomobject]@{ Connected = $true; TenantId = [string]$az.Tenant.Id; Detail = 'Connected to Azure.' }
}

function Import-AsoOptionalModule {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Name)
    if (Get-Module -Name $Name) { return $true }
    if (-not (Get-Module -ListAvailable -Name $Name)) { return $false }
    try {
        Import-Module -Name $Name -ErrorAction Stop -Verbose:$false | Out-Null
        return $true
    }
    catch {
        Write-AsoLog -Level Warning -Message "Module $Name could not be imported: $($_.Exception.Message)"
        return $false
    }
}

function Connect-AsoService {
    <#
    .SYNOPSIS
    Signs in interactively to the services needed by the selected modules, only when no existing
    session is present. Never used in replay mode or with -SkipConnect.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string[]] $Module, [string] $TenantId)

    $needsGraph = @($Module | Where-Object { $_ -in 'Entra', 'M365', 'Intune' }).Count -gt 0
    if ($needsGraph -and (Import-AsoOptionalModule -Name 'Microsoft.Graph.Authentication')) {
        $state = Get-AsoGraphConnectionState
        if (-not $state.Connected) {
            Write-AsoLog -Message 'Signing in to Microsoft Graph with read-only delegated scopes.'
            $params = @{ Scopes = $script:AsoGraphScopes; NoWelcome = $true; ErrorAction = 'Stop' }
            if ($TenantId) { $params['TenantId'] = $TenantId }
            try { Connect-MgGraph @params | Out-Null }
            catch { Write-AsoLog -Level Error -Message "Microsoft Graph sign-in failed: $($_.Exception.Message)" }
            $state = Get-AsoGraphConnectionState
        }
        if ($state.Connected) {
            $missing = @($script:AsoGraphScopes | Where-Object { $state.Scopes -notcontains $_ })
            if ($missing.Count -gt 0) {
                Write-AsoLog -Level Warning -Message "The Microsoft Graph session does not list these scopes; related datasets may be Unauthorized: $($missing -join ', ')"
            }
        }
    }
    if ($Module -contains 'Exchange' -and (Import-AsoOptionalModule -Name 'ExchangeOnlineManagement')) {
        if (-not (Get-AsoExchangeConnectionState).Connected) {
            Write-AsoLog -Message 'Signing in to Exchange Online.'
            try { Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop | Out-Null }
            catch { Write-AsoLog -Level Error -Message "Exchange Online sign-in failed: $($_.Exception.Message)" }
        }
    }
    if ($Module -contains 'Azure' -and (Import-AsoOptionalModule -Name 'Az.Accounts')) {
        if (-not (Get-AsoAzureConnectionState).Connected) {
            Write-AsoLog -Message 'Signing in to Azure.'
            $params = @{ ErrorAction = 'Stop' }
            if ($TenantId) { $params['Tenant'] = $TenantId }
            try { Connect-AzAccount @params | Out-Null }
            catch { Write-AsoLog -Level Error -Message "Azure sign-in failed: $($_.Exception.Message)" }
        }
    }
}
