# Equivalent native Entra policy plans

This is an operator design, **not an import payload**. Standalone CIPP templates
remain the supported delivery baseline. Native Entra policy plans are preview;
the reviewed CIPP interfaces do not establish native plan import/export,
deployment, or drift management. A CIPP package only groups standalone templates.

## Authentication assurance plan

Shared conditions: **emergency user exclusions only**. No shared identity
inclusions, group/role inclusions, resources, or baseline/privileged exceptions.

| Rule | Rule-level identities | Rule-level resources / conditions | Grant / rule exceptions |
| --- | --- | --- | --- |
| CA-001 | All users | All resources, all platforms/clients | Built-in MFA strength; baseline MFA exception groups and only the paired compatibility groups |
| CA-002 | The same 14 built-in roles as the JSON plus supplemental privileged groups | All resources, all platforms/clients | Phishing-resistant MFA strength; privileged-strength exceptions only |
| CA-006, only when needed | Exactly the incompatible-external groups excluded by CA-001 | All resources, all platforms/clients | Regular MFA; no extra exception beyond shared emergency users |

Keep CA-002 identities on the rule. Shared inclusions accumulate with rule
inclusions; a shared All users or privileged group inclusion can broaden another
rule. Shared exclusions cannot be removed by a rule. Privileged exceptions do not
belong in shared conditions because baseline MFA must still apply. Incompatible
external privileged identities do not gain a phishing-resistant exception merely
by being in CA-006.

## Endpoint access plan

Shared conditions: emergency user exclusions and the approved external categories
from CA-003/004/005, across all external tenants. Leave all inclusions, resources,
platforms, clients, filters, and per-control exception groups on individual rules.

| Rule | Rule identities | Rule resources / conditions | Grant / rule exceptions |
| --- | --- | --- | --- |
| CA-003 | All users | All resources; Windows; all clients; exclude-mode qualifying device filter | Block; Windows exception groups only |
| CA-004 | All users | Office 365; iOS/Android; browser and mobile/desktop clients | APP alone; mobile exception groups only |
| CA-005 | All users | All resources/clients; any platform excluding Windows/iOS/Android | Block; unsupported-platform exception groups only |

Retain this exact CA-003 rule:

```text
(device.trustType -eq "AzureAD") -and (device.operatingSystem -eq "Windows")
```

Do not move All resources into shared conditions: mobile protects Office 365,
not all resources. Do not move All users to shared conditions even in the endpoint
plan; keep effective targeting explicit and consistent with the standalone rules.
If the migration tool proposes different shared conditions, correct them and
compare the effective union of inclusions and exclusions before proceeding.

## Capability and ownership gates

Before native adoption, obtain separate tenant authorization and verify preview
availability/licensing, administrative permissions, per-rule controls and state,
log visibility, and accurate effective targeting. In particular, prove support
for **exclude-mode device filters** with the exact Windows expression and for all
**external-user categories/all-external-tenants** conditions. Verify the Office
365 grouping, built-in strengths, role/group unions, and emergency exclusions.

If anything cannot be represented faithfully or observed, retain that policy as a
standalone CIPP policy. Partial migration is preferable to silently weakening a
control. No Graph plan schema is supplied: use Microsoft's documented migration
experience or verified native creation, not speculative API fields.

## Gated migration and rollback

1. Export current policies, template/variable values, standards assignments,
   package/sync ownership, and emergency recovery instructions into the tenant's
   private change record. Record which system owns every original and replacement.
2. Migrate each approved group using Entra's migration experience. Original
   policies remain unchanged and continue to evaluate independently. Generated
   rules start **Off**. Do not assume migrating disabled the originals.
3. Inspect shared conditions and every rule. Explicitly change replacement rules
   to **Report-only**, compare effective resolved identities/resources/controls to
   the originals, and review interactive and relevant noninteractive sign-ins.
   Keep original enforcement intact during this comparison.
4. Complete a separately authorized constrained enforced pilot and all acceptance
   cases in the deployment runbook. Report-only does not validate APP/broker
   enforcement, and What If alone cannot prove token behavior.
5. Before cutover, remove or suspend the specific CIPP standards/baselines,
   scheduled remediation, and other automation that could recreate, re-enable, or
   revert superseded standalone policies. Do not turn off original enforcement
   yet. Confirm the ownership handoff is persistent across the next scheduled run.
6. Enable and verify replacement rules, then disable original policies only after
   replacement coverage is confirmed. Maintain overlap rather than a protection
   gap. All applicable originals and rules must pass during overlap; a shared
   exclusion cannot override an original block. Retain the originals for rollback.
7. Check fresh-token sign-ins and management runs after cutover, retain evidence
   for the agreed observation period, and only decommission originals under
   approved change/retention policy.

Rollback restores original effective enforcement **before** disabling
replacements, then restores original CIPP source-of-truth ownership without a
conflicting remediation loop. Verify emergency access, resolved exceptions, and
fresh-token behavior. Do not discard originals or prior configuration during
preview adoption. Removing a replacement exception while the original still
enforces is not a guaranteed way to restore access.

**Status:** design documented; no tenant capability check, migration, pilot, or
cutover has been performed. Preview adoption and production readiness remain
blocked pending separate authorization and evidence.

## Microsoft references

- [Policy-plan concepts and shared conditions](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policy-plans)
- [Create a policy plan](https://learn.microsoft.com/en-us/entra/identity/conditional-access/how-to-create-conditional-access-policy-plan)
- [Migrate policies: Off defaults, independent originals, validation, cutover](https://learn.microsoft.com/en-us/entra/identity/conditional-access/how-to-migrate-conditional-access-policy-plan)
