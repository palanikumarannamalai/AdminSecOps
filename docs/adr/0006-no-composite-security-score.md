# ADR-0006: No composite security score

- Status: Accepted
- Date: 2026-09-19

## Context
Security products often display a single score. Scores hide what was not assessed,
weight unlike risks arbitrarily, and invite optimising the number instead of the risk.

## Decision
AdminSecOps shows counts by status and severity, a clearly labelled *coverage* ratio
(assessed / applicable controls) and a documented, tested priority order
("What should I fix first?"). No composite score is computed or displayed.

## Consequences
- Management summaries rely on counts and the fix-first list.
- If a score is ever added it must be documented, tested and shown alongside coverage.
