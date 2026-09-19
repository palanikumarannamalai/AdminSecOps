# Adding a collector (dataset)

A new dataset touches the contract, the collector, the tests and the documentation.

## 1. Define the contract (TypeScript)

In `packages/schemas/src/datasets/<module>.ts` add a `defineDataset({...})` with:

- `id` (`<module>.<name>`), `module`, `technology`, `title`, `description`;
- `source` system and the exact read `operations` the collector performs;
- least-privilege `permissions` and licence `prerequisites`;
- `personalData` classification (`none`, `identifiers`, `identifiers-and-activity`);
- the Zod `schema` for `data`. Select only what controls need. Use `optString`/`optBool`/
  `list(...)` for values Microsoft may return as null. Keep Microsoft enums as strings
  (they evolve). Never include secrets; if the API returns secret-adjacent fields (hints,
  key values), the schema must not declare them and the collector must drop them.

Add it to the module's `*_DATASETS` array. Run `npm run docs:generate`.

## 2. Implement the collector (PowerShell)

1. Add a catalogue entry in `collectors/powershell/core/Catalog.ps1` (operations,
   permissions, collector function). `tests/Catalog.Tests.ps1` checks parity with the
   TypeScript registry.
2. Write the function in `collectors/powershell/<module>/`. Use only the wrappers in
   `core/DataAccess.ps1` (`Invoke-AsoGraphGetAll`, `Invoke-AsoArmGetAll`,
   `Invoke-AsoAllowListedCommand`, ...). Add any new cmdlet to the allow-list only if it is a
   read (`Get-*`).
3. Project explicitly to the schema's property names (camelCase). Convert timestamps with
   the context helpers (UTC ISO-8601), FILETIME `0`/max to `$null`, and keep arrays as arrays.
4. Map failures to the right status (Unauthorized, NotApplicable, Partial, Failed) with a
   clear message that contains no evidence values.

## 3. Record replay data and test

1. Add sanitized raw responses under `collectors/powershell/tests/replay/contoso/`
   (fictional names, `.example` domains, documentation IP ranges). Include an error case if
   the dataset has licence or permission requirements.
2. Add or extend Pester tests (`collectors/powershell/tests/*.Tests.ps1`).
3. Extend the TypeScript fixture environment in `scripts/fixtures/` and run `npm run fixtures`.
4. Run `npm run test:ps`, `npm run lint:ps` and `npm run verify`. The collector contract
   test must show the new dataset present and schema-valid.

## 4. Use it

Write or extend controls (ADDING-A-CONTROL.md) and add inventory summary items in
`packages/inventory/src/summary.ts` if the dataset represents countable objects.
