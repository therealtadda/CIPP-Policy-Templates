# CIPP-Policy-Templates

Reusable, CIPP-first Conditional Access templates for authentication assurance,
cloud-only Entra-joined Windows access, and Intune app-protected mobile access.
**Every template defaults to Report-only. Nothing in this repository deploys to a
tenant. Enforced pilot and production readiness are blocked pending separately
authorized tenant verification.**

## Policy inventory

| Policy | Users | Resources / conditions | Requirement |
| --- | --- | --- | --- |
| CA-001 Baseline | All users | All resources, all clients/platforms | Built-in Multifactor authentication strength |
| CA-002 Privileged | 14 built-in roles plus supplemental privileged groups | All resources, all clients/platforms | Built-in Phishing resistant MFA strength |
| CA-003 Windows | All users, with external-category exclusions | All resources, Windows, all clients | Block unless the positive cloud-Entra-joined Windows device filter matches |
| CA-004 Mobile | All users, with external-category exclusions | Office 365 suite, iOS/Android, browser and mobile/desktop clients | Require app protection policy alone |
| CA-005 Platforms | All users, with external-category exclusions | All resources/clients; any platform except Windows/iOS/Android | Block |
| CA-006 External compatibility (optional) | Explicit incompatible-external groups only | All resources, all clients/platforms | Regular MFA, not an authentication strength |

Emergency users are excluded from all six policies. Each other exception applies
only to its named control. Privileged users remain in CA-001: an exception to
CA-002 alone does not remove baseline MFA. All resources means CA-protected
resource/token access, not Windows logon or all network traffic.

The Windows filter is in **exclude** mode:

```text
(device.trustType -eq "AzureAD") -and (device.operatingSystem -eq "Windows")
```

Hybrid joined (`ServerAD`), registered (`Workplace`), unregistered, or missing
device-claim Windows requests do not qualify for that exclusion. Neither a hybrid
join grant nor device compliance is an equivalent replacement.

## Files and local checks

`CATemplate\` contains six standalone, raw CIPP-compatible policy JSON objects,
not an Entra policy-plan payload or a CIPP database wrapper. The folder name is
intentional: current CIPP catalog discovery recognizes the `CATemplate` partition
key as the top-level type. `docs\native-policy-plans.md` describes optional native
preview equivalents; `docs\deployment-runbook.md` contains deployment gates,
acceptance scenarios, and rollback.

Run with PowerShell 7 or later, from this checkout:

```powershell
.\scripts\Test-CABaseline.ps1
.\tests\Test-CABaseline.Tests.ps1
```

There are no package dependencies, tenant calls, or deployment commands in these
scripts. Checks cover the deliberately supported CIPP/Graph schema subset,
closed property sets, scope, controls, built-in strength/role IDs, emergency
references, independent exceptions, and the CA-001/006 reference pairing.
Regression tests mutate these properties and require rejection. This is not a
complete Microsoft Graph schema validator, CIPP integration test, or simulation
of real token evaluation.

An optional **private, outside-this-repository** JSON file can map each variable
name below (without `%`) to a JSON array of tenant-local display names:

```powershell
.\scripts\Test-CABaseline.ps1 -VariablesPath 'C:\private\ca-variables.json'
```

This offline check rejects missing/non-List variables, empty emergency references,
unresolved tokens, ambiguous duplicate entries, reserved targeting keywords, and
group-name reuse between controls. It cannot resolve names to tenant IDs, inspect
membership, or attest to deployed policy coverage. For nonempty compatibility
groups, `-CompatibilityCoverageVerified` is an explicit operator attestation
required by this check, **not** evidence or authorization to deploy.

## Tenant-local List variables

Create these in CIPP Global Variables as type **List**, then use tenant overrides.
Names in user/group fields resolve locally at deployment; do not put real tenant
data in these reusable templates or commit the private variable file.

| Variable token | Field / purpose | Initial value |
| --- | --- | --- |
| `%caemergencyusers%` | All policies: excluded user display names | Mandatory explicit tested emergency accounts; no empty default |
| `%camfaexceptions%` | CA-001: excluded group names | `[]` |
| `%caprivilegedexceptions%` | CA-002: excluded group names | `[]` |
| `%cawindowsexceptions%` | CA-003: excluded group names | `[]` |
| `%camobileexceptions%` | CA-004: excluded group names | `[]` |
| `%caplatformexceptions%` | CA-005: excluded group names | `[]` |
| `%caprivilegedusers%` | CA-002: supplemental included group names | `[]` until coverage review requires groups |
| `%caexternalcompatibility%` | CA-001 excluded / CA-006 included group names | `[]`; activate only using the paired transition below |

An empty List removes its entry in supported CIPP versions. An unresolved
variable is not an empty List. Confirm these behaviors on the target CIPP build
before deployment. Emergency references must resolve uniquely and remain nonempty
after substitution: this is a hard release gate, not automatically guaranteed by
the template. Prefer precreated, uniquely named, reviewed security groups.

Keep the compatibility List empty unless explicitly needed. **Do not deploy
CA-006 with empty effective targeting**; importing the optional template does not
make it mandatory to deploy. Nonempty compatibility exclusions in CA-001 are
safe only when CA-006 (or an independently verified equivalent MFA requirement)
already enforces for exactly those identities. Report-only replacement coverage
is not sufficient. See the runbook for safe activation and reversal.

CA-003/004/005 exclude `internalGuest`, `b2bCollaborationGuest`,
`b2bCollaborationMember`, `b2bDirectConnectUser`, `otherExternalUser`, and
`serviceProvider`, across all external tenants. Validate actual category support
and GDAP identities in the tenant. A partner administrator represented as a
tenant-local account may need explicit control-specific exceptions. No external
category exemption is applied to CA-001/002/006.

Every exception requires an owner, justification, affected controls, review/expiry
decision, and compensating controls. Review service/device/resource users
individually; do not blanket-exclude service users. Service principals and
workload-identity policies are outside this user-policy baseline.

## CIPP import and packages

1. Review the pinned evidence below against the installed CIPP build. Use **CA
   Templates > Browse Catalog > Community Catalog** if your repository and its
   intended branch are configured/available there. This repository's presence in
   GitHub does not automatically register it in the community catalog. For the
   `Preview` output, select/configure that branch explicitly rather than assuming
   the catalog reads it instead of `main`.
2. Preview the JSON, import CA-001 through CA-005 and optionally CA-006 into CIPP's
   template store, and inspect them in the template editor. Where catalog access
   is unavailable, use **Create CA Template** to reproduce the provided fields,
   save, and compare the resulting export. Do not assume a generic JSON upload UI
   exists on every CIPP version.
3. Optionally select the five baseline templates and **Add to package**, using an
   operator-chosen package name. Keep CA-006 separate until compatibility is
   approved. Package membership is CIPP metadata, not a JSON wrapper here, and a
   package is not a native Entra policy plan.
4. Follow the runbook before any deployment. Use **Replace by display name**;
   leave automatic group creation off, prevalidate names and IDs, retain
   Report-only, and target one explicitly authorized tenant first. **Never use
   "Remove all exclusions, apply to all users".** Do not select All tenants.
5. Export the resulting effective tenant policies and compare resolved IDs,
   conditions, controls, and state. A successful import or local check does not
   prove an effective deployment is correct.

CIPP standards overwrite local tenant edits on drift remediation. Keep exceptions
in the template/List-variable source of truth; manual Entra exclusions are not
durable. Review repository sync, package membership, overwrites, and standards
ownership before redeployment or native migration.

## Prerequisites and boundaries

Covered users need Entra ID P1 or equivalent, plus appropriate Intune APP licensing
where used. P2 is not required by this baseline; optional PIM/risk features have
their own requirements. Deployment requires appropriate CA Administrator and CIPP
permissions, registered allowed authentication methods, tested emergency access,
and existing assigned iOS/Android APPs including Edge. Brokers are Authenticator
on iOS and Company Portal on Android. MAM without enrollment is allowed.

Platform identification uses unverified user-agent information. The Windows
device filter and mobile APP provide stronger signals in their scopes, but this
is **not** universally spoof-proof OS enforcement. Mobile APP covers the
**Office 365 suite only**; other SaaS remains outside that grant. Unsupported
clients, embedded views, browser redirection, bootstrap/enrollment, fresh tokens,
PIM activation, and cross-tenant MFA trust need tenant testing. Inventory existing
legacy-auth/EAS blocks; no new legacy-auth policy is included or authorized.

## Authoritative format evidence

Reviewed 2026-11-13. CIPP API source is pinned to commit
`c73aeb87a2c71cba929f17ea6d21a7e166288e7b`; this is source evidence, **not** a
claim that a target CIPP instance runs this version.

| Evidence | What it establishes |
| --- | --- |
| [CIPP raw CA example](https://github.com/KelvinTegelaar/CIPP-API/blob/c73aeb87a2c71cba929f17ea6d21a7e166288e7b/Config/49a8069e-3b46-4680-a035-9250bc675446.CATemplate.json) | Raw policy object with `displayName`, `state`, `conditions`, `grantControls`; no invented envelope |
| [Catalog discovery](https://github.com/KelvinTegelaar/CIPP-API/blob/c73aeb87a2c71cba929f17ea6d21a7e166288e7b/Modules/CIPPHTTP/Public/Entrypoints/HTTP%20Functions/Tools/GitHub/Invoke-ListCommunityRepoTemplates.ps1) | Top-level `CATemplate` folder identifies template type |
| [Community importer](https://github.com/KelvinTegelaar/CIPP-API/blob/c73aeb87a2c71cba929f17ea6d21a7e166288e7b/Modules/CIPPCore/Public/Tools/Import-CommunityTemplate.ps1) | Raw `@odata.type` containing `conditionalAccessPolicy` imports into the CA template store; table envelopes are another format, not needed here |
| [Template exporter](https://github.com/KelvinTegelaar/CIPP-API/blob/c73aeb87a2c71cba929f17ea6d21a7e166288e7b/Modules/CIPPCore/Public/New-CIPPCATemplate.ps1) | Converts tenant users/groups to display-name references and preserves policy fields |
| [Deployment implementation](https://github.com/KelvinTegelaar/CIPP-API/blob/c73aeb87a2c71cba929f17ea6d21a7e166288e7b/Modules/CIPPCore/Public/New-CIPPCAPolicy.ps1) | Variable substitution, reserved `Office365` keyword preservation, name/strength resolution; strength object becomes `{id}` for Graph |
| [CIPP template editor documentation](https://docs.cipp.app/user-documentation/tenant/conditional/list-template/create-ca-template) | List tokens in user/group arrays, empty Lists, name resolution, device filters, strengths, external targeting |
| [CIPP template/catalog documentation](https://docs.cipp.app/user-documentation/tenant/conditional/list-template) | Catalog import, cloning, package tags, and repository sync |
| [Microsoft built-in strengths](https://learn.microsoft.com/en-us/graph/api/authenticationstrengthroot-list-policies?view=graph-rest-1.0) | `...0002` = Multifactor authentication; `...0004` = Phishing resistant MFA (`...0003` is Passwordless MFA, not phishing-resistant) |
| [Microsoft role IDs](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference) and [recommended roles](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-old-require-mfa-admin) | The 14 built-in role template IDs used by CA-002 |
| [External categories](https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessguestsorexternalusers?view=graph-rest-1.0) and [all-external-tenants type](https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessallexternaltenants?view=graph-rest-1.0) | External exclusion object, category string, and `membershipKind: all` |
| [Graph conditions](https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-1.0) and [grant controls](https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-1.0) | Client enums, empty risk arrays, AND/block/MFA/APP control representation and strength relationship |

Built-in strength names and IDs travel together because CIPP resolves strengths by
display name. Verify exactly one matching **built-in** strength and the expected
ID in the target tenant before deployment; stop on ambiguity or absence, rather
than allowing fallback creation or choosing a custom policy of the same name.