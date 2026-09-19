# ADR-0003: Controls as typed code in packages/controls

- Status: Accepted
- Date: 2026-09-19

## Context
The initial plan suggested a top-level `controls/` folder. Controls could be written as
declarative YAML/JSON rules or as code.

## Decision
Controls are TypeScript modules under `packages/controls/src/library/<technology>/`,
defined with `defineControl`. Metadata is validated by a Zod schema at load time; logic
is a pure function over the typed `Inventory`. Each control file has a sibling test.

## Rationale
- Real checks (Conditional Access coverage, AD CS ACL analysis, NSG rule precedence)
  need expressiveness that a declarative DSL would have to reinvent.
- Type checking against the dataset schemas catches evidence/contract drift at compile time.
- Co-locating tests with rules makes "every control has tests" enforceable
  (`library.test.ts` fails if a control ID is not referenced by a test).

## Consequences
- Custom controls (future commercial feature) will use the same API; a declarative
  layer can be added later on top of `defineControl` if needed.
- Metadata is still data: the API serves it to the UI and reports.
