# CIPP-Policy-Templates

Reusable, CIPP-first Conditional Access templates for authentication assurance,
cloud-only Entra-joined Windows access, and Intune app-protected mobile access.
**Every template defaults to Report-only. Nothing in this repository deploys to a
tenant. Enforced pilot and production readiness are blocked pending separately
authorized tenant verification.**

To connect an existing CIPP instance, start with [Using this repository with
CIPP](#using-this-repository-with-cipp). For tenant prerequisites, pilot acceptance
criteria, and rollback, read the [deployment runbook](docs/deployment-runbook.md)
before deploying anything.

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

## Using this repository with CIPP

These are operator instructions for an existing CIPP instance, not a script that
installs CIPP or deploys policies. Page labels can vary by CIPP version; use the
linked CIPP documentation and verify the installed build against the format
evidence below.

| Connection setting | Value |
| --- | --- |
| GitHub repository | `therealtadda/CIPP-Policy-Templates` |
| Repository URL | `https://github.com/therealtadda/CIPP-Policy-Templates` |
| Branch containing this preview baseline | `Preview` (case-sensitive) |
| Template folder / type | `CATemplate` / Conditional Access |
| Baseline templates | CA-001 through CA-005 |
| Conditional template | CA-006, only after external compatibility is approved |

### 1. Register the repository as a template source

1. Sign in to CIPP with access to **Tools > Catalog**. Catalog browsing/import
   requires the `CIPP.TemplateLibrary` permission; configuring a scheduled
   Template Library also requires the applicable Scheduler permission.
2. Select **Add Source**, not **Create Repository**: this GitHub repository
   already exists.
3. Enter `therealtadda/CIPP-Policy-Templates` in **GitHub repository URL or
   owner/repo**. CIPP also accepts the repository URL above.
4. CIPP detects template types from its recognized folder names. If a type must
   be selected manually, choose Conditional Access (`CATemplate`). Save the source
   and confirm its card appears.

Public repository browsing/import does not normally need your own GitHub token.
For a private fork, configure and test the [CIPP GitHub
integration](https://docs.cipp.app/user-documentation/cipp/integrations/github)
with access to that repository first. Store credentials only in CIPP's secure
integration settings, never in policy JSON or this repository. Publishing back
to GitHub is not required to consume these templates.

### 2. Select the branch and bring templates into CIPP

**Do not assume the default `main` branch contains the preview templates.**
CIPP's source-card **Set Upload Branch** action controls publishing to GitHub,
not the branch used to read/import templates.

For an explicitly selected source branch, use the documented
[Template Library](https://docs.cipp.app/user-documentation/tools/templatelib)
workflow:

1. Open **Tools > Template Library** and choose **Community Repository**, then
   select `therealtadda/CIPP-Policy-Templates`.
2. Under **Repository Branch > Select Branch**, choose **Preview**.
3. Review the sync warning before selecting **Submit**. A repository library
   imports every template on the selected branch, including optional CA-006.
   Importing it into the template store is not permission to deploy it.
4. Inspect the configured library and its task in **Scheduler**. Current CIPP
   documentation specifies a seven-day repository sync schedule; do not assume
   saving means the first import has already completed. Check task results and
   the CA Templates page to confirm the sync succeeded.
5. If a library for this repository already exists, review/edit its task through
   Scheduler rather than creating a duplicate. Confirm its configured branch
   remains `Preview`.

**Sync can overwrite stored templates with the same name.** Review existing
templates, standards assignments, and remediation before enabling it: changing a
stored template can affect tenants when an attached standard subsequently runs.
A library sync itself is not a request to deploy these policies to all tenants,
even if its Scheduler entry shows **All Tenants**.

For a one-time, selective import, use **Tools > Catalog**, open the source card,
or use **CA Templates > Browse Catalog > Community Catalog**. Preview the JSON
and import CA-001 through CA-005; leave CA-006 unselected unless needed. Confirm
that the displayed source branch actually contains the `Preview` files. If the
installed catalog only reads the default branch and offers no read-branch
selection, use the Template Library branch selector above instead; changing the
upload branch will not fix this.

After import, open **Tenant Administration > Conditional Access > CA Templates**
and confirm the expected names, variable tokens, and Report-only state. Where
catalog/library import is unavailable, **Create CA Template** can reproduce the
fields from each JSON file; save and compare the export. Do not assume every
version offers a generic JSON file-upload control.

### 3. Configure each tenant's references

1. Open CIPP [Global
   Variables](https://docs.cipp.app/user-documentation/tenant/administration/tenants/global-variables)
   and create the eight variables in the table above with type **List**. Enter
   names without the surrounding `%` characters.
2. Give optional Lists the value `[]`. Leave `caexternalcompatibility` empty
   until the paired CA-001/006 transition in the runbook is approved.
3. In the target tenant's **Edit Tenant > Custom Variables**, set tenant-specific
   overrides. `caemergencyusers` must contain explicit, tested emergency user
   display names. Other Lists contain precreated group display names, one per
   entry, not user names.
4. Verify each name resolves uniquely to the intended tenant-local object, review
   group membership, and confirm the emergency set is nonempty. An undefined
   token is not an empty List. Stop on unresolved/ambiguous names.
5. Complete licensing, authentication-method, APP/broker, existing-policy, and
   recovery checks in the [runbook](docs/deployment-runbook.md). CA does not create
   the required Intune app protection policies.

### 4. Package and deploy only when authorized

Optionally select CA-001 through CA-005 on **CA Templates**, then **Add to
package** with a name such as `CA Baseline - Preview`. Keep CA-006 outside the
baseline package until compatibility is approved. Package membership is CIPP
metadata, not a JSON wrapper, and a CIPP package is not an Entra policy plan.

For separately authorized deployment, use **Deploy Template** and review:

| Deployment option | Required choice / review |
| --- | --- |
| Tenant | One explicitly authorized test tenant, never All tenants for the initial review |
| Policy state | Report-only (`enabledForReportingButNotEnforced`) |
| User/group handling | **Replace by display name**, with independently verified names/IDs |
| Group creation | Off; use reviewed, precreated groups |
| Exclusion handling | Retain emergency and control-specific exclusions; **never "Remove all exclusions, apply to all users"** |
| Overwrite existing policy | Leave off for a first deployment; enable only for a reviewed update after exporting the existing policy and checking ownership |
| Security Defaults | Do not disable as a shortcut; preserve protection until an approved replacement set is ready |

All users targeting in these source templates is intentional. A constrained
enforced pilot needs separately reviewed tenant-local pilot copies/scopes; do
not switch the reusable All users package directly to On.

### 5. Verify, maintain, and troubleshoot

Export effective tenant policies after deployment and compare resolved user/group
IDs, built-in strength IDs, external categories, Windows filter, Office 365 APP
scope, controls, exclusions, and state against the [runbook's round-trip
checklist](docs/deployment-runbook.md#3-cipp-round-trip-and-report-only-review).
Use What If and relevant sign-in logs for initial analysis. Import success and
Report-only results do not replace an authorized enforced pilot, particularly
for APP and broker/device interactions.

| Symptom | Check before continuing |
| --- | --- |
| Source cannot be added | Repository spelling, visibility, GitHub integration access for private repositories, and CIPP permissions |
| Source shows no templates | Read branch is `Preview`, `CATemplate` folder exists on that branch, catalog warnings, and installed CIPP capability; do not change the upload branch to fix reads |
| Library saved but templates missing | Scheduler task state/results and selected source branch; a scheduled sync may not have run yet |
| Deployment reports an unresolved variable/name | All eight Lists exist, tenant overrides are correct, display names are unique, and emergency references resolve |
| CA-006 has no target users/groups | Keep it undeployed while compatibility is unused; do not broaden it to All users |
| A local change disappears | Repository sync or standards remediation restored the source; change the intended source of truth instead |

CIPP standards overwrite tenant edits on drift remediation. Keep exceptions in
the template/List-variable source of truth; manual Entra exclusions are not
durable. Clone a repository-synced template in CIPP when a separately owned,
editable working copy is needed, and document which version owns deployment.
Review updates before re-importing or enabling **Force re-import**, which can
discard local template edits. Do not attach these Report-only preview sources to
production remediation without a reviewed state/ownership strategy.

For broader enablement, rollback, and native-plan ownership handoff, follow the
[deployment runbook](docs/deployment-runbook.md) and [native policy-plan
design](docs/native-policy-plans.md). No tenant deployment or production approval
is implied by following the repository connection/import steps.

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