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
    # Only the tenant ID, account name and granted scope names are read from the context; never token data.
    return [pscustomobject]@{ Connected = $true; TenantId = [string]$mg.TenantId; Account = [string]$mg.Account; Scopes = ConvertTo-AsoStringArray -Value $mg.Scopes; Detail = 'Connected to Microsoft Graph.' }
}

function Get-AsoExchangeConnectionState {
    [CmdletBinding()]
    param()
    if (-not (Get-Command -Name Get-ConnectionInformation -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ Connected = $false; Detail = 'ExchangeOnlineManagement is not loaded.' }
    }
    $connections = @(Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object { [string]$_.State -eq 'Connected' -and -not $_.IsEopSession })
    if ($connections.Count -eq 0) { return [pscustomobject]@{ Connected = $false; TenantId = $null; TenantIds = [string[]]@(); Account = $null; Detail = 'Not connected to Exchange Online.' } }
    $tenants = [string[]]@($connections | ForEach-Object { [string]$_.TenantID } | Where-Object { $_ } | Sort-Object -Unique)
    return [pscustomobject]@{
        Connected = $true
        TenantId  = if ($tenants.Count -eq 1) { $tenants[0] } else { $null }
        TenantIds = $tenants
        Account   = [string]$connections[0].UserPrincipalName
        Detail    = 'Connected to Exchange Online.'
    }
}

function Get-AsoAzureConnectionState {
    [CmdletBinding()]
    param()
    if (-not (Get-Command -Name Get-AzContext -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ Connected = $false; TenantId = $null; Detail = 'Az.Accounts is not loaded.' }
    }
    $az = Get-AzContext -ErrorAction SilentlyContinue
    if ($null -eq $az -or $null -eq $az.Account) { return [pscustomobject]@{ Connected = $false; TenantId = $null; Detail = 'Not connected to Azure.' } }
    return [pscustomobject]@{ Connected = $true; TenantId = [string]$az.Tenant.Id; Account = [string]$az.Account.Id; Detail = 'Connected to Azure.' }
}

function Assert-AsoSessionTenant {
    <#
    .SYNOPSIS
    Refuses to collect when the signed-in sessions do not belong to the intended tenant.
    .DESCRIPTION
    Existing sessions (Connect-MgGraph / Connect-ExchangeOnline / Connect-AzAccount, including
    contexts cached by Az.Accounts on disk) are reused, so the collector must verify which tenant
    it is about to read. When -TenantId is given, every session used by the selected modules must
    belong to that tenant. Without -TenantId, all sessions must belong to one tenant. Violations
    throw before any evidence is collected. The account and tenant in use are always displayed.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string[]] $Module, [string] $TenantId)

    $sessions = [System.Collections.Generic.List[object]]::new()
    $usesGraph = @($Module | Where-Object { $_ -in 'Entra', 'M365', 'Intune', 'Exchange', 'Azure' }).Count -gt 0
    if ($usesGraph -and (Get-Command -Name Get-MgContext -ErrorAction SilentlyContinue)) {
        $graph = Get-AsoGraphConnectionState
        if ($graph.Connected) { $sessions.Add([pscustomobject]@{ Service = 'Microsoft Graph'; TenantIds = [string[]]@($graph.TenantId); Account = $graph.Account }) }
    }
    if ($Module -contains 'Exchange' -and (Get-Command -Name Get-ConnectionInformation -ErrorAction SilentlyContinue)) {
        $exo = Get-AsoExchangeConnectionState
        if ($exo.Connected) { $sessions.Add([pscustomobject]@{ Service = 'Exchange Online'; TenantIds = $exo.TenantIds; Account = $exo.Account }) }
    }
    if ($Module -contains 'Azure' -and (Get-Command -Name Get-AzContext -ErrorAction SilentlyContinue)) {
        $az = Get-AsoAzureConnectionState
        if ($az.Connected) { $sessions.Add([pscustomobject]@{ Service = 'Azure'; TenantIds = [string[]]@($az.TenantId); Account = $az.Account }) }
    }

    foreach ($s in $sessions) {
        Write-Information -MessageData ("{0}: account {1}, tenant {2}" -f $s.Service, $s.Account, ($s.TenantIds -join ', ')) -InformationAction Continue
        Write-AsoLog -Message ("{0} session tenant: {1}" -f $s.Service, ($s.TenantIds -join ', '))
    }

    $all = [string[]]@($sessions | ForEach-Object { $_.TenantIds } | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)
    if ($TenantId) {
        $expected = $TenantId.ToLowerInvariant()
        $wrong = @($sessions | Where-Object { @($_.TenantIds | Where-Object { $_ -and $_.ToLowerInvariant() -ne $expected }).Count -gt 0 })
        if ($wrong.Count -gt 0) {
            throw ("Refusing to collect: {0} signed in to a different tenant than -TenantId {1}. Sign out (Disconnect-MgGraph / Disconnect-ExchangeOnline / Disconnect-AzAccount) or sign in to the intended tenant, then retry." -f (($wrong | ForEach-Object { "$($_.Service) is" }) -join ' and '), $TenantId)
        }
    }
    elseif ($all.Count -gt 1) {
        throw ("Refusing to collect: the signed-in sessions belong to different tenants ({0}). Specify -TenantId and sign in to that tenant only." -f ($all -join ', '))
    }
    elseif ($all.Count -eq 1) {
        Write-Warning ("No -TenantId was specified. Evidence will be collected from tenant {0}. Pass -TenantId to enforce the intended tenant." -f $all[0])
    }
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
    param([Parameter(Mandatory)] [string[]] $Module, [string] $TenantId, [switch] $UseDeviceCode)

    # Sign-in uses the system browser (or a device code) instead of the Windows account broker (WAM):
    # WAM needs a parent console window and fails in background or non-interactive hosts.
    # Settings are changed for this process only.

    # Exchange Online must be signed in BEFORE Microsoft.Graph.Authentication is loaded: Graph ships an
    # older MSAL broker assembly and, when it loads first, Connect-ExchangeOnline fails with
    # "Method not found ... BrokerExtension.WithBroker" (observed in live validation).
    if ($Module -contains 'Exchange' -and (Import-AsoOptionalModule -Name 'ExchangeOnlineManagement')) {
        if (-not (Get-AsoExchangeConnectionState).Connected) {
            $preloaded = @(Get-Module -Name 'Microsoft.Graph.Authentication', 'Az.Accounts' | ForEach-Object Name)
            if ($preloaded.Count -gt 0) {
                Write-AsoLog -Level Warning -Message ("{0} was loaded before Exchange Online in this PowerShell session; Exchange sign-in may fail with an MSAL 'Method not found' error. Run the collector in a new PowerShell session without importing those modules first." -f ($preloaded -join ' and '))
            }
            Write-AsoLog -Message 'Signing in to Exchange Online.'
            $params = @{ ShowBanner = $false; ErrorAction = 'Stop' }
            $cmd = Get-Command -Name Connect-ExchangeOnline
            if ($UseDeviceCode -and $cmd.Parameters.ContainsKey('Device')) { $params['Device'] = $true }
            elseif ($cmd.Parameters.ContainsKey('DisableWAM')) { $params['DisableWAM'] = $true }
            try { Connect-ExchangeOnline @params | Out-Null }
            catch { Write-AsoLog -Level Error -Message "Exchange Online sign-in failed: $($_.Exception.Message)" }
            if (-not (Get-AsoExchangeConnectionState).Connected) { Write-AsoLog -Level Error -Message 'Exchange Online sign-in did not complete; the Exchange module will be skipped.' }
        }
    }

    $needsGraph = @($Module | Where-Object { $_ -in 'Entra', 'M365', 'Intune' }).Count -gt 0
    if ($needsGraph -and (Import-AsoOptionalModule -Name 'Microsoft.Graph.Authentication')) {
        $state = Get-AsoGraphConnectionState
        if (-not $state.Connected) {
            Write-AsoLog -Message 'Signing in to Microsoft Graph with read-only delegated scopes.'
            # Set-MgGraphOption is not used: it persists to the user profile, and the collector must
            # not change the operator's configuration. Use -UseDeviceCode where browser sign-in fails.
            # ContextScope Process keeps the Graph token cache in memory (not persisted to the user profile).
            $params = @{ Scopes = $script:AsoGraphScopes; NoWelcome = $true; ContextScope = 'Process'; ErrorAction = 'Stop' }
            if ($TenantId) { $params['TenantId'] = $TenantId }
            if ($UseDeviceCode) { $params['UseDeviceCode'] = $true }
            try { Connect-MgGraph @params | Out-Null }
            catch { Write-AsoLog -Level Error -Message "Microsoft Graph sign-in failed: $($_.Exception.Message)" }
            $state = Get-AsoGraphConnectionState
            if (-not $state.Connected) { Write-AsoLog -Level Error -Message 'Microsoft Graph sign-in did not complete; Graph-based modules will be skipped.' }
        }
        if ($state.Connected) {
            $missing = @($script:AsoGraphScopes | Where-Object { $state.Scopes -notcontains $_ })
            if ($missing.Count -gt 0) {
                Write-AsoLog -Level Warning -Message "The Microsoft Graph session does not list these scopes; related datasets may be Unauthorized: $($missing -join ', ')"
            }
        }
    }

    if ($Module -contains 'Azure' -and (Import-AsoOptionalModule -Name 'Az.Accounts')) {
        # Az.Accounts persists contexts and tokens to the user profile by default. For this process
        # only: stop persisting, and ignore a cached context that belongs to a different tenant than
        # -TenantId (the saved context on disk is left untouched).
        try { Disable-AzContextAutosave -Scope Process -ErrorAction Stop | Out-Null } catch { Write-AsoLog -Level Warning -Message "Could not disable Az context autosave for this process: $($_.Exception.Message)" }
        $azState = Get-AsoAzureConnectionState
        if ($TenantId -and $azState.Connected -and $azState.TenantId -and $azState.TenantId -ne $TenantId) {
            Write-AsoLog -Message 'Ignoring a cached Azure context from another tenant for this process.'
            Clear-AzContext -Scope Process -Force -ErrorAction SilentlyContinue | Out-Null
        }
        if (-not (Get-AsoAzureConnectionState).Connected) {
            Write-AsoLog -Message 'Signing in to Azure.'
            if (Get-Command -Name Update-AzConfig -ErrorAction SilentlyContinue) {
                try { Update-AzConfig -EnableLoginByWam $false -Scope Process -ErrorAction Stop | Out-Null } catch { Write-AsoLog -Level Warning -Message "Could not disable WAM for Azure: $($_.Exception.Message)" }
            }
            $params = @{ ErrorAction = 'Stop' }
            if ($TenantId) { $params['Tenant'] = $TenantId }
            if ($UseDeviceCode) { $params['UseDeviceAuthentication'] = $true }
            try { Connect-AzAccount @params | Out-Null }
            catch { Write-AsoLog -Level Error -Message "Azure sign-in failed: $($_.Exception.Message)" }
            if (-not (Get-AsoAzureConnectionState).Connected) { Write-AsoLog -Level Error -Message 'Azure sign-in did not complete; the Azure module will be skipped.' }
        }
    }
}
