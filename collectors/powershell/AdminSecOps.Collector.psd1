@{
    RootModule           = 'AdminSecOps.Collector.psm1'
    ModuleVersion        = '0.2.0'
    GUID                 = '51822c08-c2b0-4339-b16f-c6ee6ed6fb0b'
    Author               = 'AdminSecOps'
    CompanyName          = 'AdminSecOps'
    Copyright            = '(c) AdminSecOps. All rights reserved.'
    Description          = 'Read-only evidence collectors for AdminSecOps security assessments of Microsoft Entra ID, Microsoft 365, Exchange Online, Intune, Azure, Active Directory, AD CS, Group Policy and Windows hosts. Produces a verifiable evidence package (manifest, SHA-256 hashes, JSON evidence) and never collects secrets.'
    PowerShellVersion    = '7.2'
    CompatiblePSEditions = @('Core')
    FunctionsToExport    = @('Invoke-AdminSecOpsCollection', 'Get-AdminSecOpsPermission', 'Test-AdminSecOpsPrerequisite')
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags         = @('Security', 'Assessment', 'Entra', 'ActiveDirectory', 'Microsoft365', 'Azure', 'ReadOnly')
            ExternalModuleDependencies = @()
        }
    }
}
