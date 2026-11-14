#requires -Version 7.0
[CmdletBinding()]
param(
    [string]$TemplatePath = (Join-Path $PSScriptRoot '..\CATemplate'),
    [string]$VariablesPath,
    [switch]$CompatibilityCoverageVerified
)

$ErrorActionPreference = 'Stop'

function Assert-CAEqual {
    param($Actual, $Expected, [string]$Path)
    $a = ConvertTo-Json -InputObject $Actual -Depth 30 -Compress
    $e = ConvertTo-Json -InputObject $Expected -Depth 30 -Compress
    if ($a -cne $e) { throw "${Path}: expected $e; got $a" }
}

function Assert-CAKeys {
    param($Value, [string[]]$Keys, [string]$Path)
    if ($Value -isnot [System.Collections.IDictionary]) { throw "${Path}: expected an object" }
    Assert-CAEqual @($Value.Keys | Sort-Object) @($Keys | Sort-Object) "$Path keys"
}

function Test-CABaselinePolicies {
    param([System.Collections.IDictionary]$Policies)

    Assert-CAKeys $Policies @('CA-001', 'CA-002', 'CA-003', 'CA-004', 'CA-005', 'CA-006') 'policy inventory'
    $names = @{
        'CA-001' = 'CA-001 - Baseline - Require MFA strength'
        'CA-002' = 'CA-002 - Privileged - Require phishing-resistant strength'
        'CA-003' = 'CA-003 - Windows - Block non-Entra-joined devices'
        'CA-004' = 'CA-004 - Mobile - Require app protection'
        'CA-005' = 'CA-005 - Platforms - Block unsupported platforms'
        'CA-006' = 'CA-006 - External - MFA compatibility'
    }
    $exclusions = @{
        'CA-001' = @('%camfaexceptions%', '%caexternalcompatibility%')
        'CA-002' = @('%caprivilegedexceptions%')
        'CA-003' = @('%cawindowsexceptions%')
        'CA-004' = @('%camobileexceptions%')
        'CA-005' = @('%caplatformexceptions%')
        'CA-006' = @()
    }
    $roles = @(
        '62e90394-69f5-4237-9190-012177145e10',
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3',
        'c4e39bd9-1100-46d3-8c65-fb160da0071f',
        'b0f54661-2d74-4c50-afa3-1ec803f12efe',
        '158c047a-c907-4556-b7ef-446551a6b5f7',
        'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9',
        '29232cdf-9323-42fd-ade2-1d097af3e4de',
        '729827e3-9c14-49f7-bb1b-9608f156bbb8',
        '966707d0-3269-4727-9be2-8c3a10f19b9d',
        '7be44c8a-adaf-4e2a-84d6-ab2649e08a13',
        'e8611ab8-c189-46e8-94e1-60213ab1f814',
        '194ae4cb-b126-40b2-bd5b-6091b380977d',
        'f28a1f50-f6e7-4571-818b-6a12f2af6b6c',
        'fe930be7-5e62-47db-91af-98c3a49a38b1'
    )

    foreach ($id in $Policies.Keys) {
        $p = $Policies[$id]
        Assert-CAKeys $p @('@odata.type', 'displayName', 'state', 'conditions', 'grantControls') $id
        Assert-CAEqual $p.'@odata.type' '#microsoft.graph.conditionalAccessPolicy' "$id type"
        Assert-CAEqual $p.displayName $names[$id] "$id displayName"
        Assert-CAEqual $p.state 'enabledForReportingButNotEnforced' "$id state"
        $endpoint = $id -in @('CA-003', 'CA-004', 'CA-005')
        $conditionKeys = @('users', 'applications', 'clientAppTypes', 'signInRiskLevels', 'userRiskLevels', 'servicePrincipalRiskLevels')
        if ($endpoint) { $conditionKeys += 'platforms' }
        if ($id -eq 'CA-003') { $conditionKeys += 'devices' }
        Assert-CAKeys $p.conditions $conditionKeys "$id conditions"
        foreach ($risk in @('signInRiskLevels', 'userRiskLevels', 'servicePrincipalRiskLevels')) {
            Assert-CAEqual $p.conditions[$risk] @() "$id $risk"
        }
        $u = $p.conditions.users
        $userKeys = @('includeUsers', 'excludeUsers', 'includeGroups', 'excludeGroups', 'includeRoles', 'excludeRoles')
        if ($endpoint) { $userKeys += 'excludeGuestsOrExternalUsers' }
        Assert-CAKeys $u $userKeys "$id users"
        $includedUsers = if ($id -in @('CA-002', 'CA-006')) { ,@() } else { ,@('All') }
        $includedGroups = switch ($id) {
            'CA-002' { ,@('%caprivilegedusers%') }
            'CA-006' { ,@('%caexternalcompatibility%') }
            default { ,@() }
        }
        Assert-CAEqual $u.includeUsers $includedUsers "$id included users"
        Assert-CAEqual $u.includeGroups $includedGroups "$id included groups"
        Assert-CAEqual $u.excludeUsers @('%caemergencyusers%') "$id emergency exclusions"
        Assert-CAEqual $u.excludeGroups $exclusions[$id] "$id independent exceptions"
        Assert-CAEqual $u.excludeRoles @() "$id excluded roles"
        $includedRoles = if ($id -eq 'CA-002') { ,$roles } else { ,@() }
        Assert-CAEqual $u.includeRoles $includedRoles "$id privileged roles"
        if ($endpoint) {
            $external = $u.excludeGuestsOrExternalUsers
            Assert-CAKeys $external @('guestOrExternalUserTypes', 'externalTenants') "$id external exclusions"
            Assert-CAEqual $external.guestOrExternalUserTypes 'internalGuest,b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser,serviceProvider' "$id external categories"
            Assert-CAKeys $external.externalTenants @('@odata.type', 'membershipKind') "$id external tenants"
            Assert-CAEqual $external.externalTenants.'@odata.type' '#microsoft.graph.conditionalAccessAllExternalTenants' "$id external tenant type"
            Assert-CAEqual $external.externalTenants.membershipKind 'all' "$id external tenant membership"
        }
        $apps = $p.conditions.applications
        Assert-CAKeys $apps @('includeApplications', 'excludeApplications', 'includeUserActions', 'includeAuthenticationContextClassReferences') "$id applications"
        $resources = if ($id -eq 'CA-004') { ,@('Office365') } else { ,@('All') }
        Assert-CAEqual $apps.includeApplications $resources "$id resources"
        foreach ($key in @('excludeApplications', 'includeUserActions', 'includeAuthenticationContextClassReferences')) {
            Assert-CAEqual $apps[$key] @() "$id applications.$key"
        }
        $clients = if ($id -eq 'CA-004') { ,@('browser', 'mobileAppsAndDesktopClients') } else { ,@('all') }
        Assert-CAEqual $p.conditions.clientAppTypes $clients "$id client types"
        if ($endpoint) {
            $platforms = $p.conditions.platforms
            Assert-CAKeys $platforms @('includePlatforms', 'excludePlatforms') "$id platforms"
            $included = switch ($id) {
                'CA-003' { ,@('windows') }
                'CA-004' { ,@('iOS', 'android') }
                'CA-005' { ,@('all') }
            }
            $excluded = if ($id -eq 'CA-005') { ,@('windows', 'iOS', 'android') } else { ,@() }
            Assert-CAEqual $platforms.includePlatforms $included "$id included platforms"
            Assert-CAEqual $platforms.excludePlatforms $excluded "$id excluded platforms"
        }
        if ($id -eq 'CA-003') {
            Assert-CAKeys $p.conditions.devices @('deviceFilter') "$id devices"
            $filter = $p.conditions.devices.deviceFilter
            Assert-CAKeys $filter @('mode', 'rule') "$id device filter"
            Assert-CAEqual $filter.mode 'exclude' "$id positive qualifying exclusion"
            Assert-CAEqual $filter.rule '(device.trustType -eq "AzureAD") -and (device.operatingSystem -eq "Windows")' "$id cloud-only Windows filter"
        }
        $grant = $p.grantControls
        $grantKeys = @('operator', 'builtInControls')
        $strengthPolicy = $id -in @('CA-001', 'CA-002')
        if ($strengthPolicy) { $grantKeys += 'authenticationStrength' }
        Assert-CAKeys $grant $grantKeys "$id grants"
        Assert-CAEqual $grant.operator 'AND' "$id grant operator"
        $controls = switch ($id) {
            'CA-003' { ,@('block') }
            'CA-004' { ,@('compliantApplication') }
            'CA-005' { ,@('block') }
            'CA-006' { ,@('mfa') }
            default { ,@() }
        }
        Assert-CAEqual $grant.builtInControls $controls "$id built-in controls"
        if ($strengthPolicy) {
            $strength = $grant.authenticationStrength
            Assert-CAKeys $strength @('id', 'displayName', 'policyType') "$id strength"
            $strengthId = if ($id -eq 'CA-001') { '00000000-0000-0000-0000-000000000002' } else { '00000000-0000-0000-0000-000000000004' }
            $strengthName = if ($id -eq 'CA-001') { 'Multifactor authentication' } else { 'Phishing resistant MFA' }
            Assert-CAEqual $strength.id $strengthId "$id built-in strength ID"
            Assert-CAEqual $strength.displayName $strengthName "$id built-in strength name"
            Assert-CAEqual $strength.policyType 'builtIn' "$id built-in strength type"
        }
    }
    Assert-CAEqual @($Policies['CA-001'].conditions.users.excludeGroups | Where-Object { $_ -eq '%caexternalcompatibility%' }) $Policies['CA-006'].conditions.users.includeGroups 'paired external compatibility targeting'
}

function Read-CABaselinePolicies {
    param([string]$Path)
    $policies = @{}
    $files = @(Get-ChildItem -LiteralPath $Path -File -Filter '*.json' -ErrorAction Stop)
    foreach ($file in $files) {
        if ($file.Name -notmatch '^(CA-00[1-6])-.+\.json$') { throw "Unexpected template: $($file.Name)" }
        $id = $Matches[1]
        if ($policies.ContainsKey($id)) { throw "Duplicate template: $id" }
        $policies[$id] = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json -AsHashtable -Depth 50
    }
    return $policies
}

function Test-CAVariableValues {
    param([System.Collections.IDictionary]$Values, [switch]$CompatibilityCoverageVerified)
    $keys = @('caemergencyusers', 'camfaexceptions', 'caprivilegedexceptions', 'cawindowsexceptions', 'camobileexceptions', 'caplatformexceptions', 'caprivilegedusers', 'caexternalcompatibility')
    Assert-CAKeys $Values $keys 'tenant List variables'
    foreach ($key in $keys) {
        $list = $Values[$key]
        if ($list -isnot [array]) { throw "${key}: expected a List (JSON array)" }
        foreach ($name in $list) {
            if ($name -isnot [string] -or [string]::IsNullOrWhiteSpace($name) -or $name -ne $name.Trim() -or $name -match '%' -or $name -in @('All', 'None', 'GuestsOrExternalUsers')) {
                throw "${key}: entries must be explicit, nonempty resolved display names"
            }
        }
        if (@($list | Sort-Object -Unique).Count -ne $list.Count) { throw "${key}: duplicate display names" }
    }
    if ($Values.caemergencyusers.Count -eq 0) { throw 'caemergencyusers: mandatory emergency references are empty' }
    if ($Values.caexternalcompatibility.Count -gt 0 -and -not $CompatibilityCoverageVerified) {
        throw 'caexternalcompatibility: replacement MFA coverage must be verified before an effective baseline exclusion'
    }
    # Distinct names reduce accidental cross-control coupling; membership still needs tenant review.
    $groupOwners = @{}
    foreach ($key in $keys | Where-Object { $_ -ne 'caemergencyusers' }) {
        foreach ($name in $Values[$key]) {
            if ($groupOwners.ContainsKey($name)) { throw "Group '$name' reused by $key and $($groupOwners[$name])" }
            $groupOwners[$name] = $key
        }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    $policies = Read-CABaselinePolicies -Path $TemplatePath
    Test-CABaselinePolicies -Policies $policies
    Write-Output 'PASS: six CIPP-native templates match the supported schema subset and baseline invariants.'
    if ($VariablesPath) {
        $values = Get-Content -LiteralPath $VariablesPath -Raw | ConvertFrom-Json -AsHashtable -Depth 20
        Test-CAVariableValues -Values $values -CompatibilityCoverageVerified:$CompatibilityCoverageVerified
        Write-Output 'PASS: offline List-variable checks. Tenant name/ID resolution and effective coverage are NOT verified.'
    }
    Write-Output 'Tenant round-trip, enforced pilot, and production readiness remain blocked pending separate authorization.'
}
