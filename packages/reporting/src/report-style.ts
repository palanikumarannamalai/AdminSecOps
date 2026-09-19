/** Stylesheet embedded in HTML reports (hashed into the report CSP). */
export const REPORT_CSS = `
:root { --fg:#1b2430; --muted:#5b6675; --line:#d9dee5; --bg:#ffffff; --accent:#0b4f8a;
  --crit:#8b0000; --high:#c0392b; --med:#b9770e; --low:#1f6f8b; --info:#566573;
  --pass:#1e7e34; --fail:#b02a37; --review:#8a6d00; --na:#6c757d; }
* { box-sizing: border-box; }
body { margin:0; font:14px/1.5 "Segoe UI", system-ui, -apple-system, Arial, sans-serif; color:var(--fg); background:var(--bg); }
main { max-width:1100px; margin:0 auto; padding:0 24px 48px; }
.report-header { background:#0f2742; color:#fff; padding:20px 24px; }
.report-header .brand { font-size:22px; font-weight:700; letter-spacing:.3px; }
.report-header .tagline { font-size:16px; }
.report-header .muted { color:#c9d6e3; }
h1 { font-size:24px; margin:24px 0 8px; }
h2 { font-size:19px; margin:32px 0 8px; padding-bottom:4px; border-bottom:2px solid var(--line); }
h3 { font-size:16px; margin:20px 0 8px; }
h4 { font-size:12px; letter-spacing:.6px; text-transform:uppercase; color:var(--accent); margin:18px 0 6px; }
table { border-collapse:collapse; width:100%; margin:8px 0 16px; }
caption { text-align:left; font-weight:600; padding:4px 0; }
th, td { border:1px solid var(--line); padding:6px 8px; text-align:left; vertical-align:top; }
thead th { background:#f3f5f8; }
table.facts th { width:30%; background:#f8f9fb; font-weight:600; }
.cards { display:flex; flex-wrap:wrap; gap:12px; margin:12px 0; }
.card { border:1px solid var(--line); border-radius:6px; padding:10px 16px; min-width:120px; }
.card-value { font-size:24px; font-weight:700; }
.card-label { color:var(--muted); }
.badge { display:inline-block; padding:1px 8px; border-radius:10px; border:1px solid var(--line); font-size:12px; font-weight:600; text-transform:capitalize; }
.sev-critical { background:var(--crit); color:#fff; border-color:var(--crit); }
.sev-high { background:var(--high); color:#fff; border-color:var(--high); }
.sev-medium { background:var(--med); color:#fff; border-color:var(--med); }
.sev-low { background:var(--low); color:#fff; border-color:var(--low); }
.sev-informational { background:var(--info); color:#fff; border-color:var(--info); }
.status-pass { color:var(--pass); border-color:var(--pass); }
.status-fail { color:var(--fail); border-color:var(--fail); }
.status-review { color:var(--review); border-color:var(--review); }
.status-not_applicable, .status-not_assessed { color:var(--na); }
.status-error { color:#fff; background:var(--fail); }
.finding { border:1px solid var(--line); border-left:4px solid var(--accent); border-radius:6px; padding:12px 18px; margin:18px 0; page-break-inside:avoid; }
.finding header h3 { margin-top:4px; }
.notes { background:#fff8e1; border:1px solid #f0d98c; padding:8px 12px; border-radius:4px; }
.mono { font-family:Consolas, "Cascadia Mono", monospace; word-break:break-all; }
.small { font-size:12px; }
.muted { color:var(--muted); }
.ok { color:var(--pass); }
.warn { color:var(--fail); }
.confidential { background:#f3f5f8; border-left:4px solid var(--accent); padding:8px 12px; }
.toc a { margin-right:12px; }
pre { background:#f5f7fa; border:1px solid var(--line); padding:10px; overflow-x:auto; white-space:pre-wrap; }
footer { max-width:1100px; margin:0 auto; padding:16px 24px; }
@media print { .report-header { background:#fff; color:#000; border-bottom:2px solid #000; } .toc { display:none; } a { color:inherit; } }
`;
