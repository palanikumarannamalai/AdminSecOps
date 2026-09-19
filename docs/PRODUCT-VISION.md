# Product vision

**AdminSecOps** - *You're the admin. Are you secure?*
Security assessment and remediation guidance for Microsoft administrators.

## Who it is for

Administrators responsible for Microsoft 365, Entra ID, Azure, Intune, Active Directory,
Windows Server and hybrid Microsoft infrastructure - especially in organisations without
a dedicated security team. They know how to run PowerShell and administer Microsoft
services; they need to know what is misconfigured, how much it matters, and how to fix
it safely.

## The question it answers

> Is my Microsoft environment secure, what have I missed, and what should I fix first?

## What it is

A configuration assessment, evidence, prioritization, remediation and verification
platform:

1. **Collect** configuration facts with read-only PowerShell collectors.
2. **Verify** the evidence (hashes, schemas, secret rejection).
3. **Evaluate** it with deterministic, tested, versioned controls.
4. **Prioritize** findings with a transparent, documented order.
5. **Guide** remediation: what to check before changing, how to fix, roll back and verify.
6. **Re-assess and compare** to prove improvement and detect drift.

## What it is not

- Not a penetration testing or exploitation tool. It never attacks, probes or changes anything.
- Not a vulnerability scanner replacement (no CVE/patch scanning of hosts).
- Not a Defender replacement (no threat detection or response).
- Not an AI that guesses whether configurations are secure. AI may, in future, explain
  results; it never determines them.

## Principles

1. **Evidence before conclusions.** Every result references verified evidence files.
2. **Unknown is not compliant.** Missing evidence is `NOT_ASSESSED`, never `PASS`.
3. **Deterministic and explainable.** Same evidence, same results; every rule documented.
4. **Administrator-first guidance.** Concrete admin-center paths, impact, rollback, validation.
5. **Least privilege, least data.** Read-only permissions, configuration metadata only.
6. **Local first.** Evidence stays on the administrator's machine.
7. **Honest scope.** Placeholder or unimplemented modules are never presented as implemented.

## Free release scope

The first release is free and fully usable: collectors, the engine and 99 controls,
local dashboard, HTML/JSON reports and assessment comparison. There is no billing,
licensing or subscription enforcement.

## Future commercial differentiation (not implemented)

Continuous monitoring and scheduled assessments, assessment history and configuration
drift, multi-customer/MSP support, white-label reporting, custom controls, APIs, hosted
evidence and team RBAC, commercial reporting formats. The architecture keeps these
possible (see ARCHITECTURE.md, "Extensibility").
