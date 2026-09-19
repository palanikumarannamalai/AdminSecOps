# Evidence model

Evidence integrity is a first-class feature. This document defines the evidence
package produced by collectors and how the engine verifies it. The authoritative
definitions are the Zod schemas in `packages/schemas/src/evidence.ts` and
`packages/schemas/src/datasets/`.

## Package layout

```
adminsecops-assessment-<timestamp>.zip
  evidence-manifest.json
  evidence/<module>/<datasetName>.json      one envelope per dataset
  logs/collection-log.json                  optional, ignored by the engine
```

The ZIP uses forward-slash entry names. The engine also accepts the same layout as an
extracted directory (used for the sanitized fixtures).

## Manifest (`evidence-manifest.json`)

| Field | Description |
|---|---|
| `manifestVersion` | `1.0` |
| `product` | `AdminSecOps` |
| `assessmentId` | GUID for this collection run |
| `createdAt` | ISO-8601 timestamp: the point in time assessed. Controls use this, never the wall clock. |
| `collector` | name, version, PowerShell version, platform |
| `environment` | label, tenant ID/name, primary domain, AD forest/domain (identifiers only) |
| `options` | collection options (modules, switches) |
| `modules[]` | per module: version, status (Completed/CompletedWithErrors/Failed/Skipped), start/end, prerequisite checks, errors, warnings |
| `files[]` | per evidence file: path, datasetId, module, **sha256**, sizeBytes, schemaVersion, collection status, collectedAt |

## Evidence envelope

Each file under `evidence/` is an envelope:

| Field | Description |
|---|---|
| `schemaVersion` | `1.0` |
| `datasetId` | e.g. `entra.conditionalAccessPolicies` |
| `assessmentId` | must equal the manifest |
| `collector` | name, version, module, module version |
| `collectedAt` | timestamp |
| `source` | system (MicrosoftGraph, ExchangeOnline, AzureResourceManager, ActiveDirectory, GroupPolicy, WindowsHost, DNS) and the read operations performed |
| `status` | Success, Partial, Failed, Unauthorized, NotCollected, NotApplicable |
| `errors[]`, `warnings[]` | code, message, target - never secrets or evidence values |
| `data` | the dataset payload (null unless Success/Partial) |

## Verification on ingestion (`packages/evidence`)

1. **Safe reading.** ZIPs are read entirely in memory (no temporary files). Limits:
   100 MiB archive, 5,000 entries, 64 MiB per file, 256 MiB total, compression ratio
   above 200:1 for entries over 1 MiB rejected. Absolute paths, drive letters, `..`,
   unusual characters, excessive depth, duplicate names, symbolic links and encrypted
   entries are rejected. Directories are walked without following links and every file
   must resolve inside the root.
2. **Manifest.** Must exist and match the schema, otherwise the package is rejected.
3. **Integrity.** Each listed file must exist and match its SHA-256 and size. A file that
   fails is **not used at all** (its dataset becomes unavailable -> controls NOT_ASSESSED)
   and `integrityVerified` is false. Files not listed are ignored with a warning.
4. **Safe JSON.** UTF-8 only, BOM stripped, size and depth limits, prototype-pollution
   keys rejected.
5. **Secret scan.** Files containing forbidden property names (password, secret,
   secretText, hint, tokens, private keys, cpassword, LAPS password attributes, message
   bodies, cookies...) or secret-looking values (JWTs, PEM private keys, storage account
   keys, SAS signatures, GPP cpassword) are rejected. Only JSON paths are reported, never
   the values.
6. **Envelope agreement.** datasetId, assessmentId, module, status and schemaVersion must
   match the manifest entry.
7. **Schema validation.** Payloads are validated against the dataset schema; unknown
   properties are stripped. Validation messages contain only paths and issue codes.
8. **Unknown datasets** (from a newer collector) are ignored with a warning.

## What integrity means

SHA-256 verification detects accidental corruption and modification of evidence files
after the manifest was written. The package is **not signed**: someone who can modify
the files can also rewrite the manifest. Digital signing of evidence packages is on the
roadmap (see ROADMAP.md) and is a prerequisite for the hosted service.

## References in results

Every result and finding carries `EvidenceReference`s (dataset, path, SHA-256,
collectedAt, status, source) for each dataset the control read, so every conclusion can
be traced to a specific, verified file.

## Data that is never collected

Passwords, password hashes, access/refresh tokens, private keys, authentication
cookies, e-mail message bodies, Teams messages, SharePoint/OneDrive documents, LAPS
passwords, client secret values or hints, security contact e-mail addresses and banned
password lists. See [PRIVACY.md](PRIVACY.md) and [DATA-COLLECTION.md](DATA-COLLECTION.md).
