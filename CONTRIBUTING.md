# Contributing

Issues and pull requests are welcome during the public beta.

Before opening an issue, reproduce the problem with the supplied fictional fixtures where
possible. Never include tenant names, domains, user or device identifiers, assessment
packages, generated reports, logs, screenshots, credentials or tokens. Use synthetic and
redacted examples only. Report security vulnerabilities as described in `SECURITY.md`.

In code, tests and documentation, use obviously fictional GUIDs such as
`aaaaaaaa-0000-4000-8000-000000000001`, or placeholders such as `<client-id>`. `npm run verify`
fails on any other GUID unless it is a Microsoft-published identifier listed, with its source,
in `scripts/known-guids.ts`.

Before submitting code, run:

```powershell
npm ci
npm run verify
npm run test:ps
npm run lint:ps
```

New controls must distinguish `PASS`, `FAIL`, `NOT_ASSESSED` and `NOT_APPLICABLE`, include
tests and document their evidence contract. New collectors must use the approved read-only
wrappers and update the generated data-collection documentation.
