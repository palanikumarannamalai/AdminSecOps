#Requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [uri]$Origin='https://configreview.apps.palanikumar.net/',
    [Parameter(Mandatory)][string]$DataPath,
    [ValidateSet('AD','ADCS','GPO','Windows')][string[]]$Module=@('AD','ADCS','GPO','Windows'),
    [switch]$IncludeDomainControllerSettings,
    [switch]$RegisterDailyTask
)
$ErrorActionPreference='Stop'
if (-not $IsWindows) { throw 'Windows is required for protected credential storage and scheduled collection.' }
if ($Origin.Scheme -ne 'https' -or $Origin.UserInfo -or $Origin.AbsolutePath -ne '/' -or $Origin.Query -or $Origin.Fragment) { throw 'Use an HTTPS origin without a path, query or credentials.' }
$directory=[IO.Path]::GetFullPath($DataPath)
if (Test-Path -LiteralPath $directory) { throw 'Choose a new private data directory. Existing directories are not overwritten.' }
$null=New-Item -ItemType Directory -Path $directory
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$acl=[Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true,$false)
foreach($sid in @($identity.User,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'),[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))){
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
}
Set-Acl -LiteralPath $directory -AclObject $acl
$secureToken=Read-Host 'Paste the upload credential from your ConfigReview workspace' -AsSecureString
$credential=[pscredential]::new('ConfigReviewUpload',$secureToken)
$credential | Export-Clixml -LiteralPath (Join-Path $directory 'upload-credential.xml')
$config=[ordered]@{origin=$Origin.AbsoluteUri;tenantId=$TenantId.ToString();outputPath=(Join-Path $directory 'evidence');modules=$Module;includeDomainControllerSettings=[bool]$IncludeDomainControllerSettings}
$configPath=Join-Path $directory 'agent.json'
$config | ConvertTo-Json | Set-Content -LiteralPath $configPath -Encoding utf8
if ($RegisterDailyTask) {
    # InteractiveToken intentionally requires this account to be signed in. No password is requested or stored by this installer.
    if ($PSScriptRoot.Contains('"') -or $configPath.Contains('"')) { throw 'Double quotes are not allowed in installation paths.' }
    $action=New-ScheduledTaskAction -Execute (Join-Path $PSHOME 'pwsh.exe') -Argument ('-NoProfile -NonInteractive -File "'+(Join-Path $PSScriptRoot 'Send-ConfigReview.ps1')+'" -ConfigPath "'+$configPath+'"')
    $trigger=New-ScheduledTaskTrigger -Daily -At '09:00'
    $principal=New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
    $settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
    $taskName='ConfigReview-'+$TenantId.ToString()+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
    Write-Output ('Task created: '+$taskName+'. Runs only while this Windows account is signed in.')
}
Write-Output ('Configuration saved: '+$configPath)
Write-Output 'Credential is protected with Windows DPAPI for this account. Review local evidence retention and renew the upload credential within 30 days.'
