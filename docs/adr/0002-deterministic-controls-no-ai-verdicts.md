# ADR-0002: Deterministic controls; AI never decides PASS/FAIL

- Status: Accepted
- Date: 2026-09-19

## Context
Administrators must be able to trust, reproduce and dispute every result. Language
models are non-deterministic and can invent findings.

## Decision
Every authoritative result is produced by version-controlled TypeScript rules
(`packages/controls`) evaluated by a single engine function (`evaluateControl`). The
same evidence and library version always produce the same results (asserted by tests).
Future AI features may explain findings, summarise reports or help plan changes, but
they consume results; they never create, change or suppress them.

## Consequences
- Every control needs tests for its PASS/FAIL/REVIEW paths.
- Thresholds are explicit parameters in metadata, visible in reports.
- Judgement calls are expressed as `REVIEW` with a stated reason rather than guessed.
