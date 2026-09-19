# ADR-0004: Versioned evidence contract shared by collectors and engine

- Status: Accepted
- Date: 2026-09-19

## Context
Collectors (PowerShell) and the engine (TypeScript) are separate programs that may be
released independently.

## Decision
The contract is a manifest plus one envelope per dataset, defined by Zod schemas in
`packages/schemas`. Every file is hashed (SHA-256) in the manifest. Envelopes carry a
collection status so the engine can distinguish "not configured" from "not collected".
Unknown properties are stripped; unknown datasets are ignored with a warning; schema
versions are explicit. A cross-language contract test runs the collector in replay
mode and validates its output with the engine.

## Consequences
- Adding data requires a schema change first, reviewed like code.
- Stripping undeclared properties is also a privacy control: collectors cannot leak
  extra data into reports by accident.
- Integrity (hashing) is not authenticity; signing is on the roadmap.
