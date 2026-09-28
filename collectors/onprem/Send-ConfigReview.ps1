#Requires -Version 7.2
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ConfigPath)
$ErrorActionPreference='Stop'
if (-not $IsWindows) { throw 'The agent requires Windows and the Windows account used for setup.' }
$config=Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$origin=[uri]$config.origin
if ($origin.Scheme -ne 'https' -or $origin.UserInfo -or $origin.AbsolutePath -ne '/' -or $origin.Query -or $origin.Fragment) { throw 'Agent destination must be an HTTPS origin.' }
$credential=Import-Clixml -LiteralPath (Join-Path (Split-Path -Parent $ConfigPath) 'upload-credential.xml')
$token=$credential.GetNetworkCredential().Password
if ($token -notmatch '^[\w-]{43}$') { throw 'Invalid upload credential. Enroll again.' }
# No remote commands are fetched. Only the fixed local collection entry point can run.
$result=& (Join-Path $PSScriptRoot 'Collect-ConfigReview.ps1') -TenantId ([guid]$config.tenantId) -OutputPath $config.outputPath -Module $config.modules -IncludeDomainControllerSettings:([bool]$config.includeDomainControllerSettings)
if (-not $result.ZipPath -or -not (Test-Path -LiteralPath $result.ZipPath -PathType Leaf)) { throw 'Collection did not produce an evidence ZIP.' }
if ((Get-Item -LiteralPath $result.ZipPath).Length -gt 20MB) { throw 'Evidence ZIP exceeds the hosted 20 MB limit; upload a smaller scoped collection.' }
try {
    $response=Invoke-RestMethod -Uri ($origin.AbsoluteUri.TrimEnd('/')+'/api/onprem/ingest') -Method Post -Headers @{Authorization='Bearer '+$token} -ContentType 'application/zip' -InFile $result.ZipPath -MaximumRedirection 0 -TimeoutSec 300
    Write-Output ('Assessment saved: '+$response.assessmentId)
} catch {
    # Do not print request headers, credentials or raw response bodies.
    $status=if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
    throw "Upload failed (HTTP $status). Check credential expiry, revocation, network and package limits. The local package is retained for review."
} finally { $token=$null;$credential=$null }
