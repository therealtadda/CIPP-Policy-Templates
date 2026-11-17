# CIPP repository integration contract

This repository publishes raw Conditional Access templates in `CATemplate` for
CIPP's built-in Template Library and manual CA deployment workflows. It does not
authenticate to CIPP, deploy templates, or call Microsoft Graph.

## Supported CIPP path: Template Library

The supported consumer is CIPP's documented
[Template Library](https://docs.cipp.app/user-documentation/tools/templatelib):

1. In **Tools > Catalog**, register
   `therealtadda/CIPP-Policy-Templates` as an existing community source. A
   public repository does not normally require a GitHub token; a private fork
   does require the GitHub integration and repository access.
2. Open **Tools > Template Library**, choose **Community Repository**, select
   this source, and explicitly select the reviewed release branch. A branch is
   required configuration, not an immutable source revision.
3. Review the warning and submit the library. A repository library imports
   **every template file on the selected branch**. The Conditional Access set is
   all six `CATemplate` JSON files, including optional CA-006. The type switches
   shown for tenant-based libraries do not filter a community repository.
4. CIPP creates a scheduled task. Community repository libraries run every
   seven days. The page requires `CIPP.TemplateLibrary` plus the Scheduler
   permission that runs the task. Check Scheduler results rather than assuming
   Submit completed the first import.
5. Same-name stored templates can be overwritten by a later sync. CIPP skips an
   unchanged template from the same source; changed or same-name source content
   still requires operator review. Existing deployed tenant policies are not
   automatically changed by importing a template, but standards or later
   deployment/remediation can use the updated stored template.

If a library already exists for this repository, edit that Scheduler task or
library instead of creating a duplicate. CIPP limits each repository to one
library. Confirm the tenant filter behavior in Scheduler is understood:
repository libraries are listed with **All Tenants**, but that describes the
scheduled source task; it is not authorization to deploy the imported templates
to every tenant.

## What the built-in path consumes

Template Library consumes the CIPP-recognized `CATemplate` JSON files on the
selected branch. It does **not** consume:

- `cipp-policy-manifest.json`;
- `scripts/Get-CIPPCatalog.ps1`;
- repository test or documentation files;
- the manifest's revision, checksum, selection-set, or lifecycle metadata.

Accordingly, branch control and release review are the source-integrity boundary
for the built-in path. Protect the reviewed release branch, require review for
changes, and record the reviewed commit separately if immutable provenance is
needed for a change record. CIPP's Template Library sync is branch-based and
does not provide an immutable-commit-pinned deployment from this repository.

The optional PowerShell catalog reader and manifest remain available for
repository CI or an external orchestrator that needs deterministic inventory,
closed-schema validation, SHA-256 checks, and explicit revision pinning. They are
not CIPP application wiring and are not invoked by Template Library.

## Tenant deployment through CIPP

After the library has imported the templates, use the documented
[CA Policies deployment workflow](https://docs.cipp.app/user-documentation/tenant/conditional/list-policies):

1. Choose **one explicitly authorized target tenant** and the reviewed template.
2. Inspect the editable raw policy JSON and confirm display name, state,
   identities, conditions, exclusions, grants, and unresolved tokens.
3. Select **Replace by display name**. Turn **Create groups if they do not
   exist** off. Every referenced user/group must already exist and resolve
   uniquely in the target tenant.
4. Retain all emergency and control-specific exclusions. Never choose **Remove
   all exclusions, apply to all users**.
5. Set **Policy State** to **Disabled** explicitly. The source templates contain
   Report-only state, and CIPP templates normally default to Report-only, so the
   operator must override that default for the initial write.
6. Leave **Overwrite Existing Policy** off for a first deployment. Enable it
   only for a reviewed update after exporting the existing policy and confirming
   ownership; overwrite replaces the same-named policy in full.
7. Leave **Disable Security Defaults if enabled when creating policy** off
   unless a separate change specifically authorizes that action.
8. Submit the deployment and re-read the target tenant policy in CIPP. Verify it
   is `disabled` and semantically matches the source after tenant-local name
   substitution before treating the write as complete.

The raw CIPP template is still input to CIPP's deployment workflow; it is not
submitted directly to Microsoft Graph. Do not construct Graph payloads from the
manifest or from the source catalog output.

## Separate activation gate

Creation/update at `disabled` is deliberately separate from activation. After
the disabled policy passes the runbook's round-trip, ownership, emergency-access,
and reference checks, perform a separate explicit CIPP edit of that tenant
policy to **Report-only** (`enabledForReportingButNotEnforced`).

That activation requires a second operator decision and fresh authorization. Do
not enable Report-only as part of create/update, do not retry a failed write in
an activating mode, and do not jump directly from disabled to enabled.
Report-only permits observation but is not production enforcement; the later
enforced pilot is another separately authorized phase.

## Variables and failure handling

Create the eight tenant references in CIPP as type **List**, with tenant-specific
overrides where needed. An empty List is entered as `[]`, which removes that
array entry. A missing variable is not the same as an empty List; unresolved CA
references must stop the predeployment review and are not an instruction to
remove exclusions.

The optional local reader provides stable schema/inventory errors for release
review. Template Library does not consume those errors or the manifest at sync
time. For the built-in path, review CIPP Scheduler results, CA template JSON,
deployment errors, and the resulting tenant policy.

## Cross-repository DKIM/DMARC boundary

A sibling DKIM/DMARC repository may provide its own CIPP-consumable scripts and
task definitions. This CA repository does not depend on that repository and
does not define CIPP application wiring for it. Tenant credentials, resolved
object IDs, and operation state remain tenant-private outside both template
repositories.
