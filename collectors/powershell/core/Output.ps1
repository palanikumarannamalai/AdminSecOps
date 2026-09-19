# Package output: the ONLY file in the collector that writes to disk. Everything written here is
# inside the package directory chosen by the operator (or the ZIP next to it).
# tests/ReadOnly.Tests.ps1 allows file-system writes only in this file.

function Initialize-AsoPackageDirectory {
    <#
    .SYNOPSIS
    Creates <OutputPath>/AdminSecOps-Assessment-<yyyyMMdd-HHmmss>/ with evidence/ and logs/.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $OutputPath, [Parameter(Mandatory)] [string] $Timestamp)
    if (-not (Test-Path -LiteralPath $OutputPath -PathType Container)) {
        [void][System.IO.Directory]::CreateDirectory($OutputPath)
    }
    $root = (Resolve-Path -LiteralPath $OutputPath).ProviderPath
    $name = "AdminSecOps-Assessment-$Timestamp"
    $path = Join-Path -Path $root -ChildPath $name
    $suffix = 1
    while (Test-Path -LiteralPath $path) {
        $path = Join-Path -Path $root -ChildPath "$name-$suffix"
        $suffix++
    }
    [void][System.IO.Directory]::CreateDirectory($path)
    [void][System.IO.Directory]::CreateDirectory((Join-Path -Path $path -ChildPath 'evidence'))
    [void][System.IO.Directory]::CreateDirectory((Join-Path -Path $path -ChildPath 'logs'))
    return $path
}

function Write-AsoTextFile {
    <# Writes UTF-8 text WITHOUT a byte order mark. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Path, [Parameter(Mandatory)] [AllowEmptyString()] [string] $Text)
    $dir = [System.IO.Path]::GetDirectoryName($Path)
    if ($dir -and -not [System.IO.Directory]::Exists($dir)) { [void][System.IO.Directory]::CreateDirectory($dir) }
    [System.IO.File]::WriteAllText($Path, $Text, [System.Text.UTF8Encoding]::new($false))
}

function Remove-AsoHandoffFile {
    <# Deletes a transient isolation handoff file inside the package folder (never evidence). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Deletes only transient handoff files created by this run inside the package folder.')]
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Path)
    $leaf = [System.IO.Path]::GetFileName($Path)
    if ($leaf -notlike '.isolated-*.json') { throw "Refusing to delete '$leaf': not an isolation handoff file." }
    if ([System.IO.File]::Exists($Path)) { [System.IO.File]::Delete($Path) }
}

function Get-AsoFileSha256 {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Write-AsoEnvelope {
    <#
    .SYNOPSIS
    Builds the evidence envelope for a dataset state, runs the local secret scan, writes the file
    (UTF-8 without BOM), hashes it after writing and registers it for the manifest.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State, [Parameter(Mandatory)] [string] $CollectedAt)
    $ctx = Get-AsoContext
    $entry = $State.Entry
    $relative = "evidence/$($entry.Module.ToLowerInvariant())/$($entry.Name).json"

    $envelope = New-AsoEnvelopeObject -State $State -CollectedAt $CollectedAt
    $json = ConvertTo-AsoJson -InputObject $envelope
    $findings = Test-AsoJsonTextSensitive -Json $json
    if ($findings.Count -gt 0) {
        $paths = ($findings | Select-Object -First 5 | ForEach-Object { "$($_.Path) ($($_.Rule))" }) -join ', '
        Write-AsoLog -Level Error -Module $entry.Module -Dataset $entry.Id -Message "Evidence blocked by the local secret scan at $paths. The dataset is written as Failed without data."
        $State.Status = 'Failed'
        $State.Data = $null
        $State.Errors.Clear()
        $State.Errors.Add((New-AsoMessage -Code 'SENSITIVE_CONTENT_BLOCKED' -Message "The collected data contained secret-like content ($($findings.Count) location(s): $paths) and was discarded before writing."))
        $envelope = New-AsoEnvelopeObject -State $State -CollectedAt $CollectedAt
        $json = ConvertTo-AsoJson -InputObject $envelope
    }

    $full = Join-Path -Path $ctx.PackagePath -ChildPath ($relative.Replace('/', [System.IO.Path]::DirectorySeparatorChar))
    Write-AsoTextFile -Path $full -Text $json
    $sha = Get-AsoFileSha256 -Path $full
    $size = (Get-Item -LiteralPath $full).Length
    $ctx.Files.Add([ordered]@{
            path          = $relative
            datasetId     = $entry.Id
            module        = $entry.Module
            sha256        = $sha
            sizeBytes     = [long]$size
            schemaVersion = $script:AsoSchemaVersion
            status        = $envelope.status
            collectedAt   = $CollectedAt
        })
    return $envelope.status
}

function New-AsoEnvelopeObject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory object only.')]
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State, [Parameter(Mandatory)] [string] $CollectedAt)
    $ctx = Get-AsoContext
    $entry = $State.Entry
    $usable = $State.Status -in 'Success', 'Partial'
    $envelope = [ordered]@{
        schemaVersion = $script:AsoSchemaVersion
        datasetId     = $entry.Id
        assessmentId  = $ctx.AssessmentId
        collector     = [ordered]@{
            name          = $script:AsoCollectorName
            version       = $script:AsoCollectorVersion
            module        = $entry.Module
            moduleVersion = $script:AsoCollectorVersion
        }
        collectedAt   = $CollectedAt
        source        = [ordered]@{
            system     = $entry.System
            operations = [string[]]@($entry.Operations)
            apiVersion = $entry.ApiVersion
        }
        status        = $State.Status
        errors        = [object[]]$State.Errors.ToArray()
        warnings      = [object[]]$State.Warnings.ToArray()
        data          = $null
    }
    # Assigned separately: an if-expression would unroll single-element and empty arrays.
    if ($usable) { $envelope['data'] = $State.Data }
    return $envelope
}

function Write-AsoManifest {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [hashtable] $Options)
    $ctx = Get-AsoContext
    $manifest = [ordered]@{
        manifestVersion = $script:AsoManifestVersion
        product         = 'AdminSecOps'
        assessmentId    = $ctx.AssessmentId
        createdAt       = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        collector       = [ordered]@{
            name              = $script:AsoCollectorName
            version           = $script:AsoCollectorVersion
            powershellVersion = $PSVersionTable.PSVersion.ToString()
            platform          = [string]$PSVersionTable.Platform
        }
        environment     = $ctx.Environment
        options         = $Options
        modules         = [object[]]$ctx.Modules.ToArray()
        files           = [object[]]$ctx.Files.ToArray()
    }
    $json = ConvertTo-AsoJson -InputObject $manifest
    $findings = Test-AsoJsonTextSensitive -Json $json
    if ($findings.Count -gt 0) {
        throw 'The evidence manifest failed the local secret scan; the package was not completed.'
    }
    $path = Join-Path -Path $ctx.PackagePath -ChildPath 'evidence-manifest.json'
    Write-AsoTextFile -Path $path -Text $json
    return $path
}

function Write-AsoLogFile {
    [CmdletBinding()]
    param()
    $ctx = Get-AsoContext
    $log = [ordered]@{
        assessmentId = $ctx.AssessmentId
        collector    = $script:AsoCollectorName
        version      = $script:AsoCollectorVersion
        entries      = [object[]]$ctx.Log.ToArray()
    }
    $json = ConvertTo-AsoJson -InputObject $log
    $findings = Test-AsoJsonTextSensitive -Json $json
    if ($findings.Count -gt 0) {
        # Never write a log that looks like it contains secrets; keep only the structure.
        $log.entries = @([ordered]@{ timestamp = [DateTime]::UtcNow.ToString('o'); level = 'Error'; module = $null; dataset = $null; message = 'Log content was withheld because it failed the local secret scan.'; target = $null })
        $json = ConvertTo-AsoJson -InputObject $log
    }
    Write-AsoTextFile -Path (Join-Path -Path $ctx.PackagePath -ChildPath (Join-Path 'logs' 'collection-log.json')) -Text $json
}

function Compress-AsoPackage {
    <#
    .SYNOPSIS
    Creates a ZIP of the package directory using System.IO.Compression with forward-slash entry
    names (the engine rejects backslashes and unusual characters in package paths).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $PackagePath, [Parameter(Mandatory)] [string] $ZipPath)
    Add-Type -AssemblyName System.IO.Compression
    $root = (Resolve-Path -LiteralPath $PackagePath).ProviderPath.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $files = @(Get-ChildItem -LiteralPath $root -Recurse -File | Sort-Object -Property FullName)
    $manifestFirst = @($files | Where-Object { $_.Name -eq 'evidence-manifest.json' -and $_.DirectoryName -eq $root }) + @($files | Where-Object { -not ($_.Name -eq 'evidence-manifest.json' -and $_.DirectoryName -eq $root) })
    if (Test-Path -LiteralPath $ZipPath) { throw "The ZIP file '$ZipPath' already exists." }
    $stream = [System.IO.File]::Open($ZipPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    try {
        $zip = [System.IO.Compression.ZipArchive]::new($stream, [System.IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            foreach ($file in $manifestFirst) {
                $relative = $file.FullName.Substring($root.Length + 1).Replace('\', '/')
                if ($relative -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*){0,5}$') {
                    throw "Refusing to add an unsafe path to the evidence ZIP: $relative"
                }
                $zipEntry = $zip.CreateEntry($relative, [System.IO.Compression.CompressionLevel]::Optimal)
                $zipEntry.LastWriteTime = [DateTimeOffset]::new($file.LastWriteTimeUtc)
                $out = $zipEntry.Open()
                try {
                    $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
                    $out.Write($bytes, 0, $bytes.Length)
                }
                finally { $out.Dispose() }
            }
        }
        finally { $zip.Dispose() }
    }
    finally { $stream.Dispose() }
    return $ZipPath
}
