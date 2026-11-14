#requires -Version 7.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\scripts\Test-CABaseline.ps1')
$original = Read-CABaselinePolicies (Join-Path $PSScriptRoot '..\CATemplate')
Test-CABaselinePolicies $original
$passed = 1

function Assert-Rejected {
    param([string]$Name, [scriptblock]$Action, [string]$ExpectedError)
    $failure = $null
    try { & $Action } catch { $failure = $_.Exception.Message }
    if (-not $failure -or $failure -notlike "*$ExpectedError*") {
        throw "FAIL $Name : expected rejection containing '$ExpectedError'; got '$failure'"
    }
    $script:passed++
}

$mutations = @(
    @('enforcement default', { $p['CA-001'].state = 'enabled' }, 'state'),
    @('emergency removal', { $p['CA-003'].conditions.users.excludeUsers = @() }, 'emergency'),
    @('exception coupling', { $p['CA-004'].conditions.users.excludeGroups = @('%cawindowsexceptions%') }, 'independent exceptions'),
    @('compatibility mismatch', { $p['CA-006'].conditions.users.includeGroups = @('%camfaexceptions%') }, 'included groups'),
    @('broad compatibility scope', { $p['CA-006'].conditions.users.includeUsers = @('All') }, 'included users'),
    @('privileged scope broadening', { $p['CA-002'].conditions.users.includeUsers = @('All') }, 'included users'),
    @('missing privileged role', { $p['CA-002'].conditions.users.includeRoles = @($p['CA-002'].conditions.users.includeRoles | Select-Object -Skip 1) }, 'privileged roles'),
    @('supplemental group removal', { $p['CA-002'].conditions.users.includeGroups = @() }, 'included groups'),
    @('baseline privileged exemption', { $p['CA-001'].conditions.users.excludeRoles = @('62e90394-69f5-4237-9190-012177145e10') }, 'excluded roles'),
    @('authentication external bypass', { $p['CA-001'].conditions.users.excludeGuestsOrExternalUsers = @{} }, 'users keys'),
    @('external exclusion removal', { $p['CA-003'].conditions.users.Remove('excludeGuestsOrExternalUsers') }, 'users keys'),
    @('service provider removal', { $p['CA-004'].conditions.users.excludeGuestsOrExternalUsers.guestOrExternalUserTypes = 'b2bCollaborationGuest' }, 'external categories'),
    @('external tenant narrowing', { $p['CA-005'].conditions.users.excludeGuestsOrExternalUsers.externalTenants.membershipKind = 'enumerated' }, 'external tenant membership'),
    @('hybrid join substitution', { $p['CA-003'].conditions.devices.deviceFilter.rule = '(device.trustType -eq "ServerAD")' }, 'cloud-only'),
    @('missing OS claim check', { $p['CA-003'].conditions.devices.deviceFilter.rule = '(device.trustType -eq "AzureAD")' }, 'cloud-only'),
    @('inverted filter', { $p['CA-003'].conditions.devices.deviceFilter.mode = 'include' }, 'positive qualifying'),
    @('compliance substitution', { $p['CA-003'].grantControls.builtInControls = @('compliantDevice') }, 'built-in controls'),
    @('wrong mobile resource', { $p['CA-004'].conditions.applications.includeApplications = @('All') }, 'resources'),
    @('mobile browser omission', { $p['CA-004'].conditions.clientAppTypes = @('mobileAppsAndDesktopClients') }, 'client types'),
    @('approved client bypass', { $p['CA-004'].grantControls.builtInControls = @('approvedApplication') }, 'built-in controls'),
    @('OR bypass', { $p['CA-004'].grantControls.operator = 'OR'; $p['CA-004'].grantControls.builtInControls += 'mfa' }, 'grant operator'),
    @('unknown platform omission', { $p['CA-005'].conditions.platforms.includePlatforms = @('macOS', 'linux') }, 'included platforms'),
    @('unsupported platform allowance', { $p['CA-005'].conditions.platforms.excludePlatforms += 'macOS' }, 'excluded platforms'),
    @('wrong MFA strength', { $p['CA-001'].grantControls.authenticationStrength.id = '00000000-0000-0000-0000-000000000003' }, 'strength ID'),
    @('wrong privileged strength name', { $p['CA-002'].grantControls.authenticationStrength.displayName = 'Passwordless MFA' }, 'strength name'),
    @('custom strength substitution', { $p['CA-001'].grantControls.authenticationStrength.policyType = 'custom' }, 'strength type'),
    @('mixed MFA and strength', { $p['CA-001'].grantControls.builtInControls = @('mfa') }, 'built-in controls'),
    @('session bypass addition', { $p['CA-001'].sessionControls = @{} }, 'keys'),
    @('trusted location bypass', { $p['CA-001'].conditions.locations = @{ excludeLocations = @('AllTrusted') } }, 'conditions keys'),
    @('resource exception', { $p['CA-003'].conditions.applications.excludeApplications = @('Office365') }, 'excludeApplications'),
    @('risk-based MFA narrowing', { $p['CA-001'].conditions.signInRiskLevels = @('high') }, 'signInRiskLevels'),
    @('unrequested policy', { $p['CA-007'] = $p['CA-001'] }, 'inventory'),
    @('missing template', { $p.Remove('CA-006') }, 'inventory'),
    @('invalid array shape', { $p['CA-001'].conditions.users.includeUsers = 'All' }, 'included users')
)
foreach ($test in $mutations) {
    $p = $original | ConvertTo-Json -Depth 50 | ConvertFrom-Json -AsHashtable -Depth 50
    & $test[1]
    Assert-Rejected $test[0] { Test-CABaselinePolicies $p } $test[2]
}

$values = @{
    caemergencyusers = @('Synthetic recovery user')
    camfaexceptions = @(); caprivilegedexceptions = @(); cawindowsexceptions = @()
    camobileexceptions = @(); caplatformexceptions = @(); caprivilegedusers = @()
    caexternalcompatibility = @()
}
Test-CAVariableValues $values
$passed++
$bad = $values.Clone(); $bad.caemergencyusers = @()
Assert-Rejected 'empty emergency list' { Test-CAVariableValues $bad } 'mandatory emergency'
$bad = $values.Clone(); $bad.Remove('camobileexceptions')
Assert-Rejected 'missing variable' { Test-CAVariableValues $bad } 'variables keys'
$bad = $values.Clone(); $bad.caemergencyusers = @('%unresolved%')
Assert-Rejected 'unresolved variable' { Test-CAVariableValues $bad } 'resolved display names'
$bad = $values.Clone(); $bad.camfaexceptions = 'All'
Assert-Rejected 'non-List variable' { Test-CAVariableValues $bad } 'expected a List'
$bad = $values.Clone(); $bad.camfaexceptions = @('All')
Assert-Rejected 'reserved name' { Test-CAVariableValues $bad } 'resolved display names'
$bad = $values.Clone(); $bad.caemergencyusers = @('Duplicate', 'duplicate')
Assert-Rejected 'ambiguous duplicate' { Test-CAVariableValues $bad } 'duplicate display names'
$bad = $values.Clone(); $bad.caexternalcompatibility = @('Synthetic external group')
Assert-Rejected 'replacement MFA gap' { Test-CAVariableValues $bad } 'replacement MFA coverage'
Test-CAVariableValues $bad -CompatibilityCoverageVerified
$passed++
$bad = $values.Clone(); $bad.camfaexceptions = @('Shared group'); $bad.caprivilegedexceptions = @('Shared group')
Assert-Rejected 'cross-control exception reuse' { Test-CAVariableValues $bad } 'reused'
Write-Output "PASS: $passed local checks (valid baseline/variables and security-regression mutations). No tenant behavior was tested."
