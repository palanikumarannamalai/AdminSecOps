ConfigReview on-premises collector and scheduled uploader (test release)

This package reads configuration only. It does not remediate findings or accept remote commands. It needs Windows and PowerShell 7.2 or newer. AD/ADCS require RSAT ActiveDirectory, and GPO requires GroupPolicy. Install prerequisites through your normal software process. Domain read permissions are needed; Windows security settings may need local administrator. Domain-controller registry reads are OPTIONAL and require additional rights. Do not automatically grant Domain Admin just to run this tool.

On-demand collection:
  pwsh -NoProfile -File .\Collect-ConfigReview.ps1 -TenantId YOUR-TENANT-GUID -OutputPath C:\ConfigReviewEvidence

Add -Module AD,ADCS,GPO to collect directory data without host checks, or -Module Windows to collect only the current host. Windows collection does not remotely scan every workstation. Add -IncludeDomainControllerSettings only when approved for registry reads on the domain controllers.

Review the generated ZIP, then sign in to the same tenant in the website and use On-premises collection > Upload. Maximum upload 20 MB compressed / 64 MB unpacked. Raw upload data is processed in memory; resulting findings may contain directory/host identifiers and follow the hosted retention policy. Local files remain until you remove them using your normal retention process. A tenant ID in a package is a declared association, not proof of ownership. Packages have integrity hashes but are not signed.

Scheduled collection:
1. Extract this package to a permanent trusted location. Restrict write access to the Windows account that will run it and administrators. Do not run scheduled scripts from a location editable by untrusted users.
2. In the website's On-premises collection panel, name an agent and create its upload credential. Copy the credential; do not paste it into chat or a command line.
3. Under the Windows account that will run collection:
  pwsh -NoProfile -File .\SetUp-ConfigReviewAgent.ps1 -TenantId YOUR-TENANT-GUID -DataPath C:\ConfigReviewAgentData -RegisterDailyTask
4. Paste the upload credential into the secure prompt. Windows DPAPI protects it for this Windows account. The created task runs daily at 09:00 while that account is signed in, with missed runs started when available. No Windows password is stored by the setup script.
5. To run while signed out, use Windows Task Scheduler to configure the task for the SAME account with 'Run whether user is logged on or not', completing Windows credential entry yourself. Do not use an S4U/no-network logon for domain collection. Test network/AD read access under that identity. This unattended mode requires customer validation; the installer does not configure it automatically.
6. To test immediately:
  pwsh -NoProfile -File .\Send-ConfigReview.ps1 -ConfigPath C:\ConfigReviewAgentData\agent.json

Only outbound HTTPS to the configured website is required for upload. The local reads still require access to AD/LDAP, SYSVOL and optionally domain-controller registry services. The uploader refuses HTTP and redirects, and never downloads or executes remote instructions. Credentials allow only uploads to their registered tenant, expire after 30 days, and can be revoked in the website. Re-enroll and set up a new private data directory to rotate a credential. Revoke the old credential and remove its scheduled task through Task Scheduler. Do not delete evidence until it is no longer needed.

Cloud and on-premises assessments are separate snapshots. This release does not merge them, automatically remediate settings, sign packages, install a Windows service, or discover every Windows host. On-premises AD/ADCS/GPO live validation must be performed in an authorised lab; synthetic replay tests are not proof of production readiness.
