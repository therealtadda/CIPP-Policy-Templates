# Standalone authentication strengths through CIPP

CIPP can provision a custom authentication strength as a dependency of a
Conditional Access (CA) template. For strength-only provisioning, this repository
also provides a runner for an **already initialized, authenticated CIPP backend
PowerShell session**. It creates no CA policy and changes none of CA-001 through
CA-006.

**No tenant deployment or installed-build integration has been performed.**
The runner is read-only unless explicitly invoked with `-Apply`. A strength has
no Report-only state: it is a definition, not an assignment. Creating this
definition does not itself enforce authentication for any user.

## Initial definition

`AuthenticationStrength\AS-001-Authenticator-WHfB-TAP.json` permits these
alternatives, not a requirement to perform all of them:

| Graph combination | Permitted method |
| --- | --- |
| `fido2` | Microsoft Authenticator passkeys, restricted to the two AAGUIDs below |
| `windowsHelloForBusiness` | Windows Hello for Business |
| `temporaryAccessPassOneTime` | One-time Temporary Access Pass |
| `temporaryAccessPassMultiUse` | Multi-use Temporary Access Pass |

| Authenticator platform | Allowed AAGUID |
| --- | --- |
| Android | `de1e552d-db1d-4423-a619-566b625cdc84` |
| iOS | `90a3ccdf-635c-4729-a248-9b709135078f` |

The FIDO2 combination configuration contains only those AAGUIDs. Other FIDO2
security keys/passkey providers, Authenticator push, TOTP, SMS, password-only,
and consumer Windows Hello are not allowed by this definition.

**This is bootstrap/recovery-capable, not phishing-resistant-only.** TAP is an
intentional alternative, including a reusable TAP until it expires. Do not
replace CA-002's built-in phishing-resistant strength with this definition
without a separate policy-design decision. Graph determines
`requirementsSatisfied`; the template does not force an MFA-claim value.

## Execution prerequisites and limits

- PowerShell 7 or later on an authorized CIPP backend with its normal runtime,
  configuration, authentication, and tenant authorization already initialized.
  Importing a module into an unrelated local shell does not establish those
  prerequisites. This repository does not bootstrap CIPP or obtain credentials.
- Available `New-GraphGETRequest` and `New-GraphPOSTRequest` commands. The read
  helper must support `-noPagination` and `-SkipValueExtraction`; the write helper
  must support `-maxRetries` and `-ScheduleRetry`. Verify the installed build
  against the source evidence below before use.
- An explicitly authorized customer **tenant GUID** and working CIPP app-only
  Graph access to that tenant. Creating the strength requires consented
  `Policy.ReadWrite.ConditionalAccess` (or Microsoft's documented higher
  permission). Existing CIPP/tenant authorization checks remain in force.
- Access to `graph.microsoft.com` in the Microsoft public cloud. Other Graph
  cloud hosts are not supported by this initial runner.
- Separate approval for tenant reads and especially `-Apply`. Local test
  success is not authorization or evidence of live integration.

This is a repository-owned backend script, not a new public CIPP REST endpoint,
native standalone catalog template type, or a supported arbitrary script-write
feature in the hosted UI. `AuthenticationStrength` is deliberately outside
`CATemplate`; do not import its JSON as a CA policy. CIPP Graph Explorer and
Custom Tests are read-only and cannot serve as deployment fallbacks. If trusted
backend access is unavailable, stop and establish a supported execution route
with the CIPP operator; do not bypass the custom-script restrictions.

## Inspect, preview, and create

From a copy of this checkout accessible to that initialized backend session:

```powershell
$TenantId = '<authorized-customer-tenant-guid>'

# Read-only: reports WouldCreate or verifies and reports Unchanged.
.\scripts\Invoke-CIPPAuthenticationStrength.ps1 -TenantId $TenantId

# Read-only preview of the explicit write path.
.\scripts\Invoke-CIPPAuthenticationStrength.ps1 -TenantId $TenantId -Apply -WhatIf

# Only after separate tenant change approval.
.\scripts\Invoke-CIPPAuthenticationStrength.ps1 -TenantId $TenantId -Apply
```

`-TemplatePath` can select a reviewed definition using the same narrow schema.
The runner supports the four listed method modes (restricted `fido2` is
mandatory), exactly one FIDO2 configuration, and a nonempty GUID allowlist.
Changing that file is a security-policy change; the supplied AS-001 definition
is the Authenticator-only starting point. Literal names/descriptions are required;
CIPP `%variable%` substitution is not supported.

The runner uses Graph v1.0 `/policies/authenticationStrengthPolicies`. It
validates collection envelopes, follows only same-collection pagination links,
and rejects malformed responses instead of treating them as an empty tenant.
It matches display names case-insensitively to detect collisions, then compares
the actual name, description, methods, and FIDO2 configuration against the
definition. Method/AAGUID order and server-generated IDs/timestamps do not
constitute drift; missing, additional, duplicate, or changed restrictions do.

| Result | Meaning |
| --- | --- |
| `WouldCreate` | No matching policy exists; no write occurred, including with `-WhatIf` or declined confirmation |
| `Unchanged` | Exactly one custom policy exists and its managed definition was verified; no write occurred |
| `Created` | One POST created the strength with embedded restrictions, and separate reads verified it |
| Terminating error | Prerequisite failure, ambiguity, drift, Graph failure, or verification failure; no success is claimed |

Results include `TenantId`, `DisplayName`, `PolicyId`, and `Status`. Existing
policies are never patched or deleted. A built-in collision, duplicate name, or
drift requires manual investigation under a separate approved change.

## Failure handling and later CA use

The create sends the FIDO2 restriction in the same request; it does not first
create an unrestricted strength. POST retries and deferred retry scheduling
are disabled. A timeout can still mean Graph created the policy. On a create or
read-back failure, inspect the target tenant before retrying. The error includes
the reported policy ID when available; absence of an ID does not prove that no
policy was created. No automatic cleanup is attempted.

Run only one deployment for a given tenant/name at a time. Display names are not
unique keys and the read-then-create sequence is not an atomic upsert. If a
concurrent run or external administrator creates a duplicate, resolve that
ambiguity before continuing.

Retain the verified tenant-local ID and full definition in the tenant-private
change record. Review any existing CA references before changing or deleting a
strength, even if its name suggests it is unused. Later assignment to CA is
outside this runner. CIPP's native CA deployment may reuse a strength by name
without comparing its methods/restrictions; verify both ID and full configuration
before referencing it, and confirm the resulting deployed CA policy.

Separately enable and scope the relevant Authentication Methods/passkey profile,
configure appropriate attestation, register Authenticator passkeys, provision
Windows Hello for Business, and enable/issue TAPs under the tenant's approved
process. An AAGUID allowlist is not itself an attestation-enablement policy.
Review supported devices, Authenticator versions, and registration flows.
Creating this strength does none of those steps.

All applicable CA policies still evaluate. Another policy can require a stronger
method or block access; TAP inclusion here does not override CA-002 or guarantee
that enrollment/recovery works. Apply appropriate Entra licensing when the
strength is later used in CA. Test actual bootstrap, recovery, sign-in, and
emergency access in a separately authorized constrained pilot.

## Offline checks

```powershell
.\tests\Test-CIPPAuthenticationStrength.Tests.ps1
.\scripts\Test-CABaseline.ps1
.\tests\Test-CABaseline.Tests.ps1
```

The new tests stub CIPP's helpers and exercise dry-run, creation payload,
read-back, reuse, drift, collisions, pagination, and failure handling. They do
not initialize CIPP, authenticate, contact a tenant, or establish production
readiness.

## Capability evidence and references

CIPP source was inspected at commit
`c73aeb87a2c71cba929f17ea6d21a7e166288e7b`, not verified on an installed instance:

- [Native CA strength creation and name lookup](https://github.com/KelvinTegelaar/CIPP-API/blob/c73aeb87a2c71cba929f17ea6d21a7e166288e7b/Modules/CIPPCore/Public/New-CIPPCAPolicy.ps1)
- [Shared CA dependency resolution](https://github.com/KelvinTegelaar/CIPP-API/blob/c73aeb87a2c71cba929f17ea6d21a7e166288e7b/Modules/CIPPCore/Public/Resolve-CIPPCADependencies.ps1)
- [GET helper: raw envelopes and pagination options](https://github.com/KelvinTegelaar/CIPP-API/blob/c73aeb87a2c71cba929f17ea6d21a7e166288e7b/Modules/CIPPCore/Public/GraphHelper/New-GraphGetRequest.ps1)
- [POST helper: tenant authorization and retry options](https://github.com/KelvinTegelaar/CIPP-API/blob/c73aeb87a2c71cba929f17ea6d21a7e166288e7b/Modules/CIPPCore/Public/GraphHelper/New-GraphPOSTRequest.ps1)
- [CIPP CA template documentation](https://docs.cipp.app/user-documentation/tenant/conditional/list-template/create-ca-template)
- [CIPP Graph Explorer](https://docs.cipp.app/user-documentation/tools/tenant-tools/graph-explorer)
- [CIPP Custom Tests are read-only](https://docs.cipp.app/user-documentation/tools/custom-tests/add)
- [Graph create strength with embedded FIDO2 configuration and permissions](https://learn.microsoft.com/en-us/graph/api/authenticationstrengthroot-post-policies?view=graph-rest-1.0)
- [Graph strength resource and MFA-claim semantics](https://learn.microsoft.com/en-us/graph/api/resources/authenticationstrengthpolicy?view=graph-rest-1.0)
- [Authenticator passkey prerequisites and AAGUIDs](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-enable-authenticator-passkey)
- [Custom strength advanced restrictions](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strength-advanced-options)
