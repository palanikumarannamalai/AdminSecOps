# Collector architecture

The collectors are a PowerShell 7 module, `collectors/powershell/AdminSecOps.Collector.psd1`,
that produces an evidence package conforming to the contract in [EVIDENCE-MODEL.md](EVIDENCE-MODEL.md).
Operational usage (commands, permissions, replay) is documented in
[collectors/powershell/README.md](../collectors/powershell/README.md).

## Design goals

1. **Read-only by construction.** Collectors never change configuration.
2. **Least privilege.** Delegated read scopes and read-only roles; elevated collection is opt-in.
3. **Metadata only.** No credentials, tokens, keys, secrets or content (see PRIVACY.md).
4. **One dataset failing never aborts a run.** Each dataset gets an honest status.
5. **Offline testable.** The same transformation code runs against recorded responses.

## Layout

```
collectors/powershell/
  AdminSecOps.Collector.psd1/.psm1   module (exports 3 public commands)
  core/
    Catalog.ps1        dataset catalogue (mirror of packages/schemas datasets; parity-tested)
    Collection.ps1     Invoke-AdminSecOpsCollection, Get-AdminSecOpsPermission, Test-AdminSecOpsPrerequisite
    Connect.ps1        interactive sign-in only when no session exists; never stores tokens
    Context.ps1        run context, timestamp/FILETIME conversion, status mapping, licence detection
    DataAccess.ps1     the ONLY data-access layer: read-only wrappers + replay
    SecretScan.ps1     pre-write secret scan mirroring packages/core/src/sensitive.ts
    Output.ps1         the ONLY file-writing code: envelopes, manifest, hashes, ZIP
    Json.ps1, Log.ps1, Prerequisites.ps1
  entra/ m365/ exchange/ intune/ azure/ ad/ adcs/ gpo/ windows/   one function per dataset
  tests/               Pester tests, read-only AST analyzer, replay scenario (replay/contoso)
```

## Data flow for one dataset

```
catalog entry -> collector function -> DataAccess wrapper (live API or replay file)
   -> projection to the dataset schema (explicit property selection, secrets dropped)
   -> status mapping (Success / Partial / Failed / Unauthorized / NotCollected / NotApplicable)
   -> secret scan (blocks the dataset with SENSITIVE_CONTENT_BLOCKED if anything matches)
   -> envelope written as UTF-8 without BOM -> SHA-256 + size recorded in the manifest
```

After all modules run, `evidence-manifest.json` is written, followed by a ZIP built with
`System.IO.Compression` using forward-slash entry names.

## Read-only enforcement

- Graph: `Invoke-AsoGraphGet` / `Invoke-AsoGraphGetAll` call `Invoke-MgGraphRequest -Method GET`
  only, follow `@odata.nextLink`, and honour `Retry-After` on 429.
- Azure: `Invoke-AsoArmGet` uses `Invoke-AzRestMethod -Method GET` only.
- Exchange, AD, GPO, Windows: `Invoke-AsoAllowListedCommand` accepts only allow-listed
  `Get-*`/`Resolve-DnsName` commands.
- `tests/ReadOnlyAnalyzer.ps1` parses every collector file with the PowerShell AST and fails
  the test suite on forbidden verbs (`Set-`, `New-`, `Remove-`, `Add-`, `Enable-`, `Disable-`,
  `Grant-`, `Revoke-`, `Update-`, ...), non-GET HTTP methods or file writes outside `Output.ps1`.
  Negative tests prove the analyzer detects violations.

## Status semantics

| Status | When |
|---|---|
| Success | Dataset fully collected |
| Partial | Some pages/objects failed (e.g. one subscription returned 403) |
| Unauthorized | 401/403 or insufficient privileges |
| NotApplicable | Licence/feature absent (e.g. no Entra ID P2 for PIM, no Defender for Office 365) |
| NotCollected | Optional dataset not requested (`ad.domainControllerSettings` without `-IncludeDomainControllerSettings`) |
| Failed | Any other error; message recorded without evidence values |

## Replay mode

`-ReplayPath <dir>` makes the data-access wrappers read recorded, sanitized responses
(`graph/`, `arm/`, `exo/`, `ad/`, `gpo/`, `windows/`, `dns/`) instead of calling services.
Everything above the wrappers is identical to live mode. `tests/collector-contract.test.ts`
runs a full replay collection and validates the output with the TypeScript engine.

## Validation status

Live collection has **not** been validated against real tenants or forests in this
repository (only `windows.hosts` was run live on a development machine). See
KNOWN-LIMITATIONS.md and the collector README "Validation status and limitations".
