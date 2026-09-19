# Contributing

Issues and pull requests are welcome during the public beta.

Before opening an issue, reproduce the problem with the supplied fictional fixtures where
possible. Never include tenant names, domains, user or device identifiers, assessment
packages, generated reports, logs, screenshots, credentials or tokens. Use synthetic and
redacted examples only. Report security vulnerabilities as described in `SECURITY.md`.

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
