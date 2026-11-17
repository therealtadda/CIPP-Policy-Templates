# CIPP identity initialization

`scripts\Initialize-CIPPTenant.ps1` is an **explicitly invoked, tenant-changing**
PowerShell 7 tool for an existing CIPP instance. It prepares the SAM application,
enterprise application, dedicated service user, actual application/delegated
consent, and optionally GDAP groups, invitations, and access assignments.
It does not install CIPP, assign licenses, enroll MFA, deploy policies, or change
Security Defaults/Conditional Access. The CA templates remain Report-only.

**Implementation checks are offline and mocked. No live tenant setup or
end-to-end CIPP connection has been verified by this repository.** Run this tool
only with separate authorization for the selected tenant and requested privileges.
Finish onboarding and verify access in the installed CIPP build.

## Prerequisites and privilege

- Windows, PowerShell 7, an interactive browser, and the
  `Microsoft.Graph.Authentication` module. If absent, install it explicitly:
  `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`.
- An existing CIPP HTTPS console origin and the correct tenant GUIDs.
  Public Microsoft cloud is supported; sovereign clouds are not implemented.
- An MFA-authenticated administrator authorized to create users/applications,
  assign directory roles and application permissions, and grant tenant-wide
  consent. Activate sufficient administrator privileges before execution
  (typically Global Administrator for the setup operator). The script does not
  assign Global Administrator to the service account.
- For partner mode, actual Microsoft partner enrollment and the existing
  **AdminAgents** security group. The tool will not create a replacement
  AdminAgents group. GDAP also requires the customer's independent approval.
- A trusted local **non-synchronized, non-network** export parent directory.
  The selected run directory must not already exist. Repository paths, known
  OneDrive paths, junctions, symbolic links, and cloud placeholders are rejected.
  Other synchronization products cannot all be detected: choose the parent
  carefully. Do not use shared/writable-by-others locations.

The script requests the full reviewed CIPP baseline, **not least privilege for
these six CA templates alone**. Direct-mode service users receive all 15
documented CIPP runtime roles, including Privileged Role Administrator and
Security Administrator. Partner users receive AdminAgents membership and
membership in one security group per role; those groups are mapped to customers
only after GDAP approval. Protect all exports as highly privileged credentials.
Do not grant local partner-tenant roles merely to simulate customer delegation.

Bootstrap administrator credentials and the runtime service account are separate.
The Graph SDK uses a process-scoped interactive administrator session, and the
script disconnects it on exit. Use a fresh PowerShell process rather than sharing
a process with another administrator workflow.

## Permission source and authentication strengths

`config\CIPPInitializationPermissions.json` records upstream CIPP-API revision
`c73aeb87a2c71cba929f17ea6d21a7e166288e7b`, including SAMManifest and
AdditionalPermissions. The Graph baseline contains **67 application permissions
and 91 delegated scopes**. Applicable non-Graph SAM permissions are included;
the Partner Center resource is omitted in Direct mode.

The tool resolves GUID permissions against resource service principals, creates
missing resource service principals, merges `requiredResourceAccess`, creates
missing application-role assignments and organization-wide delegated grants,
and reads grants back for verification. Unrelated grants, per-user grants, and
existing application callback settings are preserved. Missing/disabled GUID
permissions stop setup; no smaller Graph baseline is substituted. CIPP's
explicitly named, sometimes unpublished AdditionalPermissions scopes are granted
by their upstream names and verified in the resulting consent grants.
For GUID scopes absent from the v1.0 catalog, resolution uses the beta
`publishedPermissionScopes` catalog, matching CIPP's upstream lookup; this is a
read-only catalog fallback, not a bypass of disabled or missing permissions.

The inventory explicitly checks both permission types for `Policy.Read.All`,
`Policy.ReadWrite.ConditionalAccess`, `Policy.ReadWrite.AuthenticationMethod`,
and the directory capabilities used by CIPP. Strength creation uses
`Policy.ReadWrite.ConditionalAccess` (or its documented higher privilege), not an
invented strength-specific Graph scope. This script **does not create strengths**:
Direct-mode runtime verification reads policies and verifies unique built-in MFA
and phishing-resistant strengths with IDs ending in `0002` and `0004`.
Partner-mode customer CA checks remain pending customer onboarding; the script
does not grant home-tenant roles just to pass a partner-tenant CA probe.

Compare this source revision to the CIPP version you run. To regenerate from
another **reviewed full commit SHA**, then review the diff before execution:

```powershell
.\scripts\Update-CIPPInitializationPermissions.ps1 -Revision '<40-character-commit-sha>'
```

The updater downloads JSON data only. It does not authenticate to a tenant.
It preserves untranslated non-Graph GUIDs for authoritative runtime resolution,
but rejects missing Graph translations. Runtime initialization never downloads
an unreviewed permission set from a moving branch. Review the documented role
inventory separately when updating; roles come from CIPP's recommended-roles doc.

## Direct/own-tenant setup

The following IDs/domains are examples, not real connection values. First review
the operation without authentication or writes:

```powershell
$setup = @{
    Mode = 'Direct'
    TenantId = '11111111-1111-1111-1111-111111111111'
    CippUrl = 'https://cipp.example.com'
    ServiceAccountUpn = 'CIPPService@contoso.onmicrosoft.com'
    CreateServiceAccount = $true
    ExportDirectory = 'C:\CIPP-private\contoso-first'
}
.\scripts\Initialize-CIPPTenant.ps1 @setup -WhatIf
.\scripts\Initialize-CIPPTenant.ps1 @setup -SkipTokenAcquisition
```

The parent `C:\CIPP-private` must already exist and be trusted/private.
The script prompts for confirmation before changes. `-Confirm:$false` explicitly
suppresses that confirmation; it does not skip sign-in, MFA, or customer approval.

The first execution creates a random initial password requiring change on first
sign-in and exports it immediately. Recover it as described below, change it and
enroll **Microsoft MFA** as the dedicated service user. Do not bypass existing
CA/Security Defaults to make this succeed. Configure any separately approved MFA
enforcement through your tenant's normal administration process.

Resume with the exported application ID and secret, omitting
`-CreateServiceAccount`, using a **new export directory**:

```powershell
. .\scripts\Initialize-CIPPTenant.ps1
$export = 'C:\CIPP-private\contoso-first\credentials.dpapi'
$metadata = Read-CIPPInitializationExport $export
$secret = Read-CIPPInitializationExport $export -Field ApplicationSecret
.\scripts\Initialize-CIPPTenant.ps1 -Mode Direct `
    -TenantId $metadata.TenantId -CippUrl 'https://cipp.example.com' `
    -ServiceAccountUpn 'CIPPService@contoso.onmicrosoft.com' `
    -ApplicationId $metadata.ApplicationId -ApplicationSecret $secret `
    -ExportDirectory 'C:\CIPP-private\contoso-authenticated'
```

Type `MFA-READY` only after enrollment/password setup, then complete browser
authentication as the **service user**, not the bootstrap administrator.
The browser uses authorization code + PKCE, a state-checked localhost callback,
and offline access, not device code or password authentication.
The returned token is checked against the selected user ID and tenant ID.
MFA enrollment/claims still require CIPP's own Permissions check; token receipt
alone is not proof of MFA enforcement or a completed CIPP connection.

## Existing identities and additional direct tenants

An existing app requires explicit `-ApplicationId`. The script refuses implicit
reuse/takeover by the display name `CIPP-SAM`. An existing user is selected by its
exact UPN; omit `-CreateServiceAccount`. Ambiguous objects are rejected.

Existing secret values cannot be retrieved from Graph. Supply
`-ApplicationSecret` as a SecureString, enter it at the secure prompt, or
explicitly request `-NewClientSecret` in the **home tenant**. New secrets expire
after `-SecretLifetimeDays` (default 90, maximum 180). Old credentials are not
deleted. Rotate CIPP's stored credential and verify it before retiring old keys.
Current CIPP defaults to managed certificates; this tool intentionally provides
the documented **client-secret/manual-entry** path. Leave CIPP-managed
certificate provisioning and rotation to CIPP. If an app-management policy
blocks secret creation, setup stops; review an app-specific exception or use
CIPP's certificate wizard. Never disable tenant-wide secret restrictions.

For an **additional direct tenant**, reuse the primary SAM registration:

```powershell
.\scripts\Initialize-CIPPTenant.ps1 -Mode Direct `
    -HomeTenantId '11111111-1111-1111-1111-111111111111' `
    -TenantId '22222222-2222-2222-2222-222222222222' `
    -ApplicationId '<primary-SAM-client-id>' -ApplicationSecret $secret `
    -CippUrl 'https://cipp.example.com' `
    -ServiceAccountUpn 'CIPPService@customer.onmicrosoft.com' `
    -CreateServiceAccount -SkipTokenAcquisition `
    -ExportDirectory 'C:\CIPP-private\customer-first'
```

The operator authenticates to the home tenant to validate the existing app, then
to the customer tenant to grant consent/create the local service user. The home
application is not modified and its existing localhost callback must match
`-LoopbackPort` (default 8400). Rerun after MFA enrollment as in the direct example.
The customer export can contain the privileged **home application secret**;
do not distribute it to customer administrators.

Finish in CIPP **Add a tenant > Add Direct Tenant** with the customer's service
account. CIPP must record its per-tenant token and tenant metadata through that
supported flow. **Never paste an additional tenant's token/ID over primary SAM
credentials.** The export deliberately supplies no primary `ConsoleFields` for
this case. To manage the primary tenant itself, use CIPP's appropriate Own Tenant
Mode/partner-tenant setting, not Add Direct Tenant with the primary tenant ID.

## Partner/GDAP setup and resume

Use `-Mode Partner` against the SAM home/partner tenant. With the default
`-GdapAction Prepare`, the script creates/reuses role security groups, adds the
service account to those groups and AdminAgents, and creates **no relationship**.
You can finish customer invitations/onboarding entirely in CIPP.

For optional invitation creation, add:

```powershell
$partner = @{
    Mode = 'Partner'
    TenantId = '11111111-1111-1111-1111-111111111111'
    CippUrl = 'https://cipp.example.com'
    ServiceAccountUpn = 'CIPPService@partner.onmicrosoft.com'
    ApplicationId = '<existing-SAM-client-id>'
    SkipTokenAcquisition = $true
    CustomerTenantId = '33333333-3333-3333-3333-333333333333'
    GdapAction = 'Invite'
    RelationshipName = 'CIPP-Contoso'
    RelationshipDurationDays = 730
    ExportDirectory = 'C:\CIPP-private\contoso-invite'
}
.\scripts\Initialize-CIPPTenant.ps1 @partner
```

Use `-CreateServiceAccount` only when the partner service user does not exist.
Omit `-ApplicationId` only for first-time SAM creation. Omit
`-SkipTokenAcquisition` to capture a service-user token during that execution.

Give the exported `CustomerApprovalUrl` to the authorized customer administrator.
The script never approves for them. Default approval waiting is zero: the result
is `AwaitingCustomerApproval`, **not success**. `-ApprovalWaitSeconds` enables a
bounded wait (maximum 3600); otherwise resume after acceptance:

```powershell
$partner.GdapAction = 'Map'
$partner.Remove('RelationshipName')
$partner.RelationshipId = '<exported-relationship-id>'
$partner.ExportDirectory = 'C:\CIPP-private\contoso-mapped'
.\scripts\Initialize-CIPPTenant.ps1 @partner
```

Mapping verifies the customer, active relationship, and approved roles, and
creates only missing role/group assignments. It does not add roles to a locked
relationship. Non-active assignments are reported as `AccessAssignmentsPending`;
rerun Map after propagation. `-AutoExtend` explicitly requests 180-day
auto-extension; default is no auto-extension. Duration is 1-730 days.

Default group names are `M365 GDAP <role display name>`. To reuse a custom mapping,
`-GdapGroupMapPath` accepts a private JSON object mapping documented role display
names to existing static security-group GUIDs; omitted roles use default groups.
`-AdminAgentsGroupId` disambiguates the real partner AdminAgents group. IDs of
created/reused groups and assignments are included in the export.

Finally reconcile these groups in CIPP's GDAP role template and complete its
**GDAP Tenant Onboarding**/CPV refresh. Review whether the tenant should be
excluded from All Tenants standards/baselines **before** onboarding. This tool
does not write CIPP's database, register the tenant in CIPP, apply baselines,
create a reseller/billing relationship, or claim those steps are complete.

## Recovering credentials and CIPP console mapping

The new directory ACL allows only the executing Windows account and SYSTEM.
`credentials.dpapi` is encrypted using Windows current-user DPAPI; recovery
requires the **same account and machine**. Back up the needed values to an
approved secret vault before removing that Windows profile/machine.
`-ExportFormat Plaintext` explicitly chooses `credentials.json` with the same
restrictive ACL. It is not the default and is never an automatic fallback.

Do not run under a PowerShell transcript, debug HTTP logging, screen recording,
or an untrusted terminal. No script automatically prints credentials or copies
them to the clipboard. Recovery returns metadata by default, a SecureString for
a selected credential, and plaintext only with explicit `-Reveal`:

```powershell
. .\scripts\Initialize-CIPPTenant.ps1
$path = 'C:\CIPP-private\contoso-authenticated\credentials.dpapi'
$metadata = Read-CIPPInitializationExport $path
$metadata.ConsoleFields     # Identifiers only; no secrets
Read-CIPPInitializationExport $path -Field ApplicationSecret -Reveal
Read-CIPPInitializationExport $path -Field RefreshToken -Reveal
# For a newly created service account, before first sign-in:
# Read-CIPPInitializationExport $path -Field ServiceAccountInitialPassword -Reveal
```

For a **primary/home connection**, use CIPP Setup Wizard **Manually enter
credentials**:

| CIPP field | Export value |
| --- | --- |
| Tenant ID | `HomeTenantId` / `ConsoleFields.TenantID` |
| Application ID | `ApplicationId` / `ConsoleFields.ApplicationID` (client ID, not application object ID) |
| Application Secret | Credential field `ApplicationSecret` (value, not `SecretKeyId`) |
| Refresh Token | Credential field `RefreshToken` (verified runtime service-user token, not bootstrap/access token) |

Metadata also includes application and enterprise-application object IDs,
service-user ID, secret expiry/key ID, resource service-principal IDs, runtime
role IDs, and any GDAP relationship/group/access-assignment IDs. Initial user
passwords belong in your secret vault, not in CIPP's Application Secret field.
If runtime identity verification fails, `UnverifiedRefreshToken` is retained
privately for cleanup but is **not** populated into verified console fields.

## Failures, acceptance, and cleanup

The private checkpoint is updated as credentials/identifiers become available.
Later failures terminate with `Status=Failed`, stage, and export location.
No automatic destructive rollback is attempted: removing an existing identity
or consent could break another CIPP instance. Review partial exports, rerun with
explicit existing IDs/UPN and a new export directory, or manually revoke only
the newly created credentials/objects after checking their use. If a directory
or credential write itself fails, stop and inspect the last checkpoint before
retrying; never assume a failed response proves no remote change occurred.
Graph POSTs are not blindly retried, to avoid duplicate secrets/relationships.
Transient GET/PATCH retries are bounded; propagation delays may require a rerun.

Before calling a connection ready, complete CIPP's supported onboarding, refresh
CPV, and run **Permissions**, **GDAP** (where applicable), and **Tenants** checks.
Confirm the service account, MFA claim, usable refresh token, granted Graph
permissions, customer access, and correct primary/direct credential placement.
Review authentication strengths and effective roles in each intended tenant.
Only after that should policy import/pilot follow the separate
[deployment runbook](deployment-runbook.md).

Local regression commands:

```powershell
.\tests\Initialize-CIPPTenant.Tests.ps1
.\scripts\Test-CABaseline.ps1
.\tests\Test-CABaseline.Tests.ps1
```

## References

- [CIPP Setup Wizard and manual credential fields](https://docs.cipp.app/user-documentation/cipp/sam-setup-wizard)
- [Service account and Microsoft MFA](https://docs.cipp.app/setup/installation/creating-the-cipp-service-account-gdap-ready)
- [Direct/GDAP onboarding](https://docs.cipp.app/setup/installation/gdap-invite-wizard)
- [CIPP recommended roles](https://docs.cipp.app/setup/maintaining-cipp/recommended-roles)
- [CIPP Permissions and CPV checks](https://docs.cipp.app/user-documentation/cipp/settings/permissions)
- [Graph CA policy permissions](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-post-policies?view=graph-rest-1.0)
- [Graph authentication-strength permissions](https://learn.microsoft.com/en-us/graph/api/authenticationstrengthroot-post-policies?view=graph-rest-1.0)
