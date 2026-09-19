# Active Directory Certificate Services configuration stored in the Configuration partition.
# Only CA registration objects and certificate templates are read; no certificates, keys or CA data.

function Get-AsoAdConfigurationNamingContext {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $ctx = Get-AsoContext
    if (-not $ctx.Cache.ContainsKey('ad:configNC')) {
        $forest = Get-AsoAdForestInfo
        $rootDse = @(Invoke-AsoAdCommand -Name 'Get-ADRootDSE' -Parameters @{ Server = $forest.RootDomain } -Property @('schemaNamingContext', 'configurationNamingContext'))[0]
        if ($null -eq $rootDse -or -not $rootDse.configurationNamingContext) { throw 'The configuration naming context could not be determined.' }
        $ctx.Cache['ad:configNC'] = [string]$rootDse.configurationNamingContext
    }
    return $ctx.Cache['ad:configNC']
}

function Get-AsoCertificateNotAfter {
    <# Parses a DER certificate (base64) and returns NotAfter as ISO-8601 UTC; no key material exists in a CA certificate attribute. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [string] $Base64)
    if (-not $Base64) { return $null }
    try {
        $bytes = [Convert]::FromBase64String($Base64)
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
        try { return (ConvertTo-AsoTimestamp -Value $cert.NotAfter) }
        finally { $cert.Dispose() }
    }
    catch {
        return $null
    }
}

function Get-AsoAdcsCertificateAuthority {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $configNC = Get-AsoAdConfigurationNamingContext
    $forest = Get-AsoAdForestInfo
    $params = @{
        SearchBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
        LDAPFilter = '(objectClass=pKIEnrollmentService)'
        Properties = @('dNSHostName', 'certificateTemplates', 'cACertificate')
        Server     = $forest.RootDomain
    }
    $cas = @(Invoke-AsoAdCommand -Name 'Get-ADObject' -Parameters $params -Property @('Name', 'dNSHostName', 'certificateTemplates', 'cACertificate') -ReplayKey 'Get-ADObject_EnrollmentServices')
    if ($cas.Count -eq 0) {
        Add-AsoDatasetWarning -State $State -Code 'NO_ENTERPRISE_CA' -Message 'No enterprise certification authority is registered in Active Directory.'
    }
    $State.Data = [object[]]@($cas | ForEach-Object {
            $certs = ConvertTo-AsoStringArray $_.cACertificate
            $notAfter = $null
            foreach ($c in $certs) {
                $na = Get-AsoCertificateNotAfter -Base64 $c
                if ($na -and (-not $notAfter -or $na -gt $notAfter)) { $notAfter = $na }
            }
            [ordered]@{
                name                  = [string]$_.Name
                dnsHostName           = ConvertTo-AsoString $_.dNSHostName
                certificateTemplates  = [string[]]@((ConvertTo-AsoStringArray $_.certificateTemplates) | Sort-Object)
                caCertificateNotAfter = $notAfter
            }
        })
}

function Get-AsoAdcsCertificateTemplate {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)
    $configNC = Get-AsoAdConfigurationNamingContext
    $forest = Get-AsoAdForestInfo
    $attrs = @('displayName', 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', 'msPKI-RA-Signature', 'pKIExtendedKeyUsage', 'msPKI-Certificate-Application-Policy', 'msPKI-Template-Schema-Version', 'nTSecurityDescriptor')
    $params = @{
        SearchBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
        LDAPFilter = '(objectClass=pKICertificateTemplate)'
        Properties = $attrs
        Server     = $forest.RootDomain
    }
    $templates = @(Invoke-AsoAdCommand -Name 'Get-ADObject' -Parameters $params -Property (@('Name') + $attrs) -ReplayKey 'Get-ADObject_CertificateTemplates')
    $State.Data = [object[]]@($templates | ForEach-Object {
            $t = $_
            $aces = [System.Collections.Generic.List[object]]::new()
            foreach ($rule in (Get-AsoList $t 'nTSecurityDescriptor')) {
                $rights = [string](Get-AsoPropertyValue $rule 'ActiveDirectoryRights')
                $aces.Add([ordered]@{
                        principalSid      = ConvertTo-AsoString (Get-AsoPropertyValue $rule 'SecurityIdentifier')
                        principalName     = [string](Get-AsoPropertyValue $rule 'IdentityReference')
                        accessControlType = [string](Get-AsoPropertyValue $rule 'AccessControlType')
                        rights            = [string[]]@($rights -split ',\s*' | Where-Object { $_ })
                        objectType        = ConvertTo-AsoString (Get-AsoPropertyValue $rule 'ObjectType')
                    })
            }
            $schemaVersion = ConvertTo-AsoNumber $t.'msPKI-Template-Schema-Version'
            [ordered]@{
                name                 = [string]$t.Name
                displayName          = ConvertTo-AsoString $t.displayName
                schemaVersion        = $schemaVersion
                certificateNameFlag  = [long](ConvertTo-AsoNumber $t.'msPKI-Certificate-Name-Flag')
                enrollmentFlag       = [long](ConvertTo-AsoNumber $t.'msPKI-Enrollment-Flag')
                raSignature          = [long](ConvertTo-AsoNumber $t.'msPKI-RA-Signature')
                extendedKeyUsage     = ConvertTo-AsoStringArray $t.pKIExtendedKeyUsage
                applicationPolicies  = ConvertTo-AsoStringArray $t.'msPKI-Certificate-Application-Policy'
                permissions          = [object[]]$aces.ToArray()
            }
        })
}
