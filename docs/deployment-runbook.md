# Deployment runbook

**Repository validation only has been authorized. No tenant access, import,
deployment, enforced pilot, native migration, or production enablement has been
performed. Each tenant operation below requires separate authorization.**

This baseline is a reviewable starting point, not a released production package.
Use the five baseline templates independently or as a CIPP package. CA-006 is an
optional, separately gated compatibility component.

## 1. Private preflight and release blockers

Create a tenant-private change record, never in this repository. Assign an owner,
approver, pilot scope, maintenance window, observation period, acceptance owner,
and rollback operator.

| Gate | Required evidence before deployment/promotion |
| --- | --- |
| Platform and licenses | Installed CIPP build supports raw CA templates, List expansion/empty removal, device filters, external targeting, and strength resolution; covered users have Entra ID P1 or equivalent and appropriate Intune APP licenses |
| Permission | Authorized CA Administrator and appropriate CIPP permissions; no unnecessary tenant-wide automation |
| Existing protections | Export all current policies and states, Security Defaults, standards/baseline assignments, package/repository sync, existing legacy-auth and Exchange ActiveSync blocks, and relevant cross-tenant settings |
| Emergency recovery | Explicit emergency users resolve uniquely, are excluded from all relevant policies/rules, and can recover through a tested route; independent monitoring/alerts and credentials remain available |
| Methods | Intended users have enabled/registered permitted MFA; administrators have usable phishing-resistant methods before CA-002 enforcement |
| Exceptions | Every exception has owner, justification, exact controls, membership, review/expiry decision, and compensating controls; separately scoped groups resolve uniquely |
| APP | Assigned iOS/iPadOS and Android Intune APPs cover intended users and supported apps including Edge; licensing, broker registration, remediation, and application support are verified |
| Administrative coverage | Review built-in/custom/AU roles, active/eligible PIM, delegated/GDAP administrators, supplemental group coverage, and fresh-token behavior |
| Compatibility | Explicit incompatible external identities only; preserve MFA throughout the CA-001/006 transition described below |
| Rollback | Prior exports and source-of-truth values retained; operator can restore effective protection and emergency access without waiting for a broken managed device |

P2 is not required for this baseline. Separately chosen risk/PIM features may
require it. Do not disable Security Defaults until an approved replacement
protection set is ready. Preserve existing effective protections throughout.
Report-only templates do not replace Security Defaults or existing enforced CA.

Inventory legacy/unsupported protocols; a Windows platform check or
modern-client-only mobile APP policy does not prove legacy auth is blocked. If a
gap requires a new dedicated legacy-auth policy, seek a separate scoped decision.
None is supplied here. Workload identities/service principals are out of scope.

## 2. Resolve names and variables before CIPP import/deployment

Create the eight List variables in the README. Use explicit user display names
for emergency accounts and precreated security-group display names for the other
Lists. Empty optional Lists must be `[]`, not a blank string or an undefined
variable. Set the compatibility List empty by default. Import CA-006 only when
needed and do not deploy it with no effective inclusions.

Run the local validator and regression tests. Optionally validate a private
variable map with `-VariablesPath`. That map is an offline review input; this
repository does not upload it into CIPP.

Before *any* deployment, resolve every referenced name against the target tenant
and record exactly one object ID per name, correct object type, and reviewed
membership. Reject missing/ambiguous names, stale IDs, unresolved `%tokens%`, an
empty resolved emergency set, or emergency users absent from any policy. Do not
proceed based only on a successful script exit. Reject groups reused for different
control purposes and inspect overlapping membership rather than assuming distinct
names imply distinct populations.

Use **Replace by display name**, with automatic group creation disabled. Current
CIPP code has different name-resolution branches; do not assume every installed
build fails closed for every missing name merely because the docs describe
strict resolution. Prevalidate independently and stop before deployment if a
mandatory name cannot resolve. **Never select "Remove all exclusions, apply to
all users".** Do not strip emergency exclusions to fix an import error.

Authentication-strength IDs are portable built-in IDs, not customer IDs:

| Control | Expected built-in display name | Expected ID |
| --- | --- | --- |
| Baseline MFA strength | Multifactor authentication | `00000000-0000-0000-0000-000000000002` |
| Privileged strength | Phishing resistant MFA | `00000000-0000-0000-0000-000000000004` |

CIPP looks up strengths by name and converts the strength object to an ID for
Graph. Confirm uniqueness, `policyType: builtIn`, and those IDs in the target
tenant; fail on a custom policy with the same name, a missing built-in, or an
unexpected mapping. Do not allow fallback creation to substitute a custom
strength, and do not combine regular MFA and strength grants in a policy.

CA-002 includes these role template IDs, verified against Microsoft's role
reference:

| Built-in role | Template ID |
| --- | --- |
| Global Administrator | `62e90394-69f5-4237-9190-012177145e10` |
| Application Administrator | `9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3` |
| Authentication Administrator | `c4e39bd9-1100-46d3-8c65-fb160da0071f` |
| Billing Administrator | `b0f54661-2d74-4c50-afa3-1ec803f12efe` |
| Cloud Application Administrator | `158c047a-c907-4556-b7ef-446551a6b5f7` |
| Conditional Access Administrator | `b1be1c3e-b65d-4f19-8427-f6fa0d97feb9` |
| Exchange Administrator | `29232cdf-9323-42fd-ade2-1d097af3e4de` |
| Helpdesk Administrator | `729827e3-9c14-49f7-bb1b-9608f156bbb8` |
| Password Administrator | `966707d0-3269-4727-9be2-8c3a10f19b9d` |
| Privileged Authentication Administrator | `7be44c8a-adaf-4e2a-84d6-ab2649e08a13` |
| Privileged Role Administrator | `e8611ab8-c189-46e8-94e1-60213ab1f814` |
| Security Administrator | `194ae4cb-b126-40b2-bd5b-6091b380977d` |
| SharePoint Administrator | `f28a1f50-f6e7-4571-818b-6a12f2af6b6c` |
| User Administrator | `fe930be7-5e62-47db-91af-98c3a49a38b1` |

Review additional privileged roles before use. Directory-role targeting is
incomplete for custom/AU-scoped roles, eligible-but-not-active PIM, and some
delegated scenarios. Maintain supplemental privileged groups for uncovered
identities. Test PIM activation and fresh tokens; an existing token need not
immediately reflect a role or membership change.

## 3. CIPP round-trip and Report-only review

Use the README's catalog/editor and package workflow. Inspect each imported
template, then deploy only under separate authorization to an explicitly selected
test tenant, retaining **Report-only** and all required exclusions.

Export both CIPP templates and resulting effective Entra policies. Compare
semantic content, not formatting or server-added read-only fields:

| Area | Required comparison after tenant-local substitution |
| --- | --- |
| Shape/state | Standalone CA policy, expected display name, Report-only; no unexpected session/location/risk/flow conditions |
| Identities | All users only on CA-001/003/004/005; CA-002 role/group union only; CA-006 explicit compatible replacement scope only |
| Exclusions | Nonempty emergency user IDs everywhere; each control's own group IDs only; CA-001/006 compatibility group IDs exactly equal |
| External targeting | All six intended categories/all external tenants on CA-003/004/005 only; inspect real guest/GDAP and local partner identities |
| Resources/clients | `All` with no resource exclusions except mobile `Office365`; mobile browser plus mobile/desktop clients, all clients elsewhere |
| Windows | Windows platform only, block, device-filter mode `exclude`, exact positive `AzureAD` AND Windows expression |
| Mobile/platform | iOS/Android and `compliantApplication` alone; any-platform block excludes only Windows/iOS/Android |
| Authentication | Expected built-in strength IDs, no mixed regular-MFA grant; CA-006 only regular `mfa`; AND operators |

Graph `compliantApplication` means **Require app protection policy**, not device
compliance. `Office365` is the resource-suite keyword, not a client application
ID; do not replace it with Outlook/Teams client IDs or manually enumerate service
dependencies. Verify the reserved keyword survives CIPP import/deployment on the
installed build. Export comparison must demonstrate no unresolved tokens or
tenant-foreign names/IDs remain.

Use What If plus interactive and relevant noninteractive sign-in logs. Record
resource audiences, authentication details/methods, device claims, each matching
policy/rule and outcome, and exception resolution. Report-only analysis is not
proof that APP/broker enforcement will work. Do not enable all templates merely
because JSON parses or What If appears successful.

## 4. Optional external compatibility without an MFA gap

Email OTP, Google, personal Microsoft accounts, and SAML/WS-Fed external
identities can need regular MFA instead of an authentication-strength control.
Inventory exact identities and group membership. Do not exclude all external
users from CA-001. Validate resource/home-tenant cross-tenant MFA trust where
applicable; do not assume a claimed home-tenant MFA satisfies local requirements.

CA-006 does not satisfy privileged phishing-resistant MFA. External privileged
users need supported Entra authentication and the necessary cross-tenant trust,
or a separately approved CA-002 exception while baseline/compatibility MFA stays.

The paired token is a final-state contract, not an atomic two-policy transaction.
Changing it while CA-001 is standards-managed can change CA-001 immediately on
the next run, even if CA-006 is only Report-only.

1. Leave the shared compatibility List empty and freeze the relevant CA-001
   standards/remediation updates, **without disabling its current enforcement**.
   Keep the previously deployed baseline exclusions unchanged.
2. In an authorized change, make a controlled tenant-local working copy of
   CA-006 with only the exact proposed group references and emergency exclusions.
   Configure/verify it in Report-only while CA-001's effective exclusion remains
   empty. Existing access may still be restricted by strength during this stage.
3. Complete the authorized compatibility pilot, then enable and verify CA-006
   MFA enforcement for those exact identities (or prove an existing equivalent
   enforced MFA policy already covers them). Do not treat Report-only as coverage.
4. Only then populate `%caexternalcompatibility%` in the durable source of truth
   and redeploy CA-001/006. Verify identical resolved group IDs and actual
   membership, no extra CA-006 exclusions, and effective MFA enforcement.
   Reconcile the temporary copy so no duplicate unmanaged policy remains; keep
   verified enforcement until its managed replacement is enabled.
5. Resume the reviewed standards configuration only after the effective deployed
   pair and source values agree. Record the operator coverage attestation before
   using `-CompatibilityCoverageVerified` for offline variable checks.

For reversal/removal, first restore baseline strength coverage for identities
leaving compatibility (and verify they can satisfy it), then remove their
replacement MFA requirement. Do not disable CA-006 while a baseline exclusion
still exempts its users unless another verified enforced MFA requirement covers
them. Keep old enforcement active during rollback transitions.

## 5. Constrained enforced pilot and acceptance matrix

**Blocked until separate tenant authorization.** Use tenant-local pilot copies
scoped to an approved small test group (and the applicable privileged subset),
with explicit emergency/external/per-control exclusions intact. The reusable
source templates remain All users/Report-only. Avoid unintentionally enforcing a
full All users policy when trying to pilot a control. Retain existing protections;
any required pilot exceptions to existing blocks are separately reviewed.

APP prerequisites: separate iOS/iPadOS and Android Intune APP assignments, supported
native apps plus Edge, Microsoft Authenticator on iOS, Company Portal on Android,
and broker/device registration. MAM without enrollment is allowed; mobile devices
do not need Windows-style Entra join.

| Enforced scenario | Expected result, subject to all other applicable policies |
| --- | --- |
| Cloud-Entra-joined Windows, valid device signal, permitted MFA | Allowed |
| Same Windows device, password-only | Baseline MFA strength required |
| Windows hybrid/registered/unregistered or missing device claims | CA-003 blocks unless specifically excepted |
| Administrator, push/SMS only | CA-002 not satisfied |
| Administrator, eligible passkey/FIDO2, WHfB, or multifactor certificate | Privileged strength satisfied; other requirements still apply |
| Privileged-strength exception | CA-001 MFA still applies |
| Supported iOS/Android app, assigned APP, registration/broker, MFA | Protected Office 365 access succeeds |
| Protected Edge versus Safari/Chrome or unprotected native client | Protected access succeeds; unsupported access denied or redirected without an unprotected final-resource bypass |
| No APP, missing broker, unsupported embedded view | No unprotected access to scoped resources; verify actual remediation behavior |
| Mobile non-Microsoft-365 SaaS | Baseline authentication applies; APP is not guaranteed |
| macOS, Linux, unknown platform | CA-005 blocks unless its own exception or external exclusion applies |
| Entra guest/service-provider admin | Device/app/platform exclusions apply; appropriate authentication/privileged strength remains |
| Non-Entra incompatible guest | Narrow paired CA-001/006 targeting enforces MFA, no silent gap |
| Emergency account | Verified recovery route works and use is monitored |
| New role/PIM/group/exception change | Fresh-token and relevant noninteractive evaluation demonstrates intended coverage |
| Redeployment and standards remediation | Source exceptions persist; no drift or duplicate unmanaged enforcement |
| Native migration, if chosen | Correct shared/rule scope; CIPP ownership handed off; no re-enabled originals or protection gap |

Explicitly test supported Windows browsers, normal/private browsing, remote
sessions, device-code flows, device join, Autopilot/Intune enrollment, security
registration, recovery, and device signals. The All resources block can affect
bootstrap. Identify exact required resource exceptions from controlled evidence,
not speculative broad Graph/Intune bypasses. This baseline includes **no resource
exclusions**, especially none on CA-001. Necessary design changes require review.

Platform detection uses unverified user-agent data. Test altered/missing signals,
but do not claim cryptographic OS identification or universal spoof-proof
coverage. Stronger Windows/device and mobile/APP checks cover their respective
scopes; mobile non-M365 resources retain a known boundary. Unsupported app and
Safari/Chrome behavior can involve redirection: assess final resource access,
not just the initial prompt.

For every case, record actual sign-ins, policy matches, resource audiences,
authentication details and fresh-token results. App-protection Report-only
failures alone do not prove an enforced failure. Do not infer success from the
absence of a prompt or from a cached token.

## 6. Promotion, ownership, and rollback

Production promotion is a separate decision after pilot evidence is accepted,
exceptions reconciled, bootstrap/recovery works, round-trip fidelity verified, and
the rollback route is tested. Promote deliberately through approved user cohorts;
do not blindly enable an All users package.

Record which template/variables/standards own every policy and its intended
state. CIPP overwrite/standards remediation can revert local Entra edits; change
durable source values, not just live policy exclusions. Confirm the next
management run preserves intended states, resolved exceptions, and policy IDs.
Do not let repository sync accidentally reset promoted policies to Report-only;
maintain reviewed tenant-local production state/ownership separately from these
Report-only reusable templates.

If access or fidelity fails, stop promotion. Use the verified emergency route,
pause only the relevant remediation that would fight recovery, restore exported
prior policies/states and source values, and verify prior effective protection
before disabling replacements. Rolling back a new baseline must not disable
pre-existing independent protections. For the compatibility pair, preserve MFA
coverage throughout; for native cutover, follow the ownership-first procedure in
`native-policy-plans.md`. Verify recovery with fresh tokens and logs.

**Remaining release gates:** installed-build capability checks, tenant-local
resolution/effective JSON comparison, enforced pilot, production authorization,
and documented rollback evidence. None is claimed complete by the local tests.

## Supporting documentation

- [CIPP create-template fields and variable behavior](https://docs.cipp.app/user-documentation/tenant/conditional/list-template/create-ca-template)
- [Device-filter semantics and missing attributes](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-condition-filters-for-devices)
- [Grant controls](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant)
- [APP policy guidance](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-approved-app-or-app-protection)
- [Intune app-based CA prerequisites](https://learn.microsoft.com/en-us/intune/device-security/conditional-access-integration/app-based-policies)
- [Office 365 resource grouping](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps)
- [External authentication strengths](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strength-external-users)
- [Guest MFA strength and trust](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-guests-mfa-strength)
