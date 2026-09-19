#Requires -Version 7.2
# AdminSecOps.Collector - read-only evidence collectors for Microsoft security assessments.
# Strict mode 1.0 catches uninitialised variables; property-level strictness is deliberately not used
# because Microsoft APIs omit properties that are null.
Set-StrictMode -Version 1.0

$moduleRoot = $PSScriptRoot
$folders = @('core', 'entra', 'm365', 'exchange', 'intune', 'azure', 'ad', 'adcs', 'gpo', 'windows')
foreach ($folder in $folders) {
    $path = Join-Path -Path $moduleRoot -ChildPath $folder
    foreach ($file in (Get-ChildItem -LiteralPath $path -Filter '*.ps1' -File | Sort-Object -Property Name)) {
        . $file.FullName
    }
}

Export-ModuleMember -Function @('Invoke-AdminSecOpsCollection', 'Get-AdminSecOpsPermission', 'Test-AdminSecOpsPrerequisite')
