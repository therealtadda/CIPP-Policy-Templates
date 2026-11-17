#requires -Version 7.0
<#
.SYNOPSIS
    Inspects or creates a standalone authentication strength through CIPP's backend.
.DESCRIPTION
    Requires an already initialized, authenticated CIPP backend PowerShell session.
    Read-only unless -Apply is supplied. Existing strengths must match exactly;
    updates, deletion, method enablement, and CA assignment are not supported.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [string]$TemplatePath = (Join-Path $PSScriptRoot '..\AuthenticationStrength\AS-001-Authenticator-WHfB-TAP.json'),

    [switch]$Apply
)

$ErrorActionPreference = 'Stop'
$root = 'https://graph.microsoft.com/v1.0/policies/authenticationStrengthPolicies'

function Assert-StrengthGuid {
    param($Value, [string]$Label)
    $parsed = [guid]::Empty
    if ($Value -isnot [string] -or -not [guid]::TryParseExact($Value, 'D', [ref]$parsed) -or $parsed -eq [guid]::Empty) {
        throw "$Label must be a nonempty GUID in D format."
    }
}

function Assert-StrengthKeys {
    param($Value, [string[]]$Keys, [string]$Label)
    if ($Value -isnot [System.Collections.IDictionary]) { throw "$Label must be an object." }
    if (@($Value.Keys).Count -ne $Keys.Count -or @($Value.Keys | Where-Object { $_ -cnotin $Keys }).Count) {
        throw "$Label must contain only these keys: $($Keys -join ', ')."
    }
}

function Assert-StrengthStringArray {
    param($Value, [string]$Label)
    if ($Value -isnot [array] -or $Value.Count -eq 0) { throw "$Label must be a nonempty array." }
    $seen = @{}
    foreach ($item in $Value) {
        if ($item -isnot [string] -or [string]::IsNullOrWhiteSpace($item) -or $seen.ContainsKey($item)) {
            throw "$Label must contain unique nonempty strings."
        }
        $seen[$item] = $true
    }
}

function Test-StrengthSet {
    param($Actual, [array]$Expected)
    if ($Actual -isnot [array] -or $Actual.Count -ne $Expected.Count) { return $false }
    $seen = @{}
    foreach ($item in $Actual) {
        if ($item -isnot [string] -or $seen.ContainsKey($item) -or $item -cnotin $Expected) { return $false }
        $seen[$item] = $true
    }
    return $true
}

function Read-StrengthObject {
    param([string]$Uri)
    $response = @(New-GraphGETRequest -uri $Uri -tenantid $TenantId -AsApp $true -noPagination $true -SkipValueExtraction -ErrorAction Stop)
    if ($response.Count -ne 1 -or $null -eq $response[0]) { throw "Incomplete Graph response from $Uri." }
    $object = ConvertTo-Json -InputObject $response[0] -Depth 50 | ConvertFrom-Json -AsHashtable -Depth 50
    if ($object -isnot [System.Collections.IDictionary] -or $object.Contains('error')) {
        throw "Invalid Graph response from $Uri."
    }
    return $object
}

function Read-StrengthCollection {
    param([string]$Uri)
    $collectionUri = [uri]$Uri
    $visited = @{}
    do {
        if ($visited.ContainsKey($Uri)) { throw "Repeated Graph pagination link for $collectionUri." }
        $visited[$Uri] = $true
        $page = Read-StrengthObject $Uri
        if (-not $page.Contains('value') -or $page.value -isnot [array]) {
            throw "Incomplete Graph collection response from $Uri."
        }
        foreach ($item in $page.value) {
            if ($item -isnot [System.Collections.IDictionary]) { throw "Invalid Graph collection entry from $Uri." }
            $item
        }
        $next = $page['@odata.nextLink']
        if ($null -ne $next) {
            $nextUri = $null
            if ($next -isnot [string] -or -not [uri]::TryCreate($next, [UriKind]::Absolute, [ref]$nextUri) -or
                $nextUri.Scheme -cne 'https' -or $nextUri.Authority -cne $collectionUri.Authority -or
                $nextUri.AbsolutePath -cne $collectionUri.AbsolutePath -or $nextUri.UserInfo -or $nextUri.Fragment) {
                throw "Unsafe Graph pagination link for $collectionUri."
            }
        }
        $Uri = $next
    } while ($Uri)
}

function Assert-StrengthMatch {
    param($Policy, [array]$Configurations, [string]$ExpectedId)
    Assert-StrengthGuid $Policy.id 'Graph policy ID'
    if ($Policy.id -ne $ExpectedId) { throw 'Graph policy ID does not match the requested ID.' }
    if ($Policy.policyType -cne 'custom') { throw 'The matching strength is not a custom policy; refusing to reuse it.' }
    $differences = @()
    foreach ($key in @('displayName', 'description')) {
        if ($Policy[$key] -isnot [string] -or $Policy[$key] -cne $template[$key]) { $differences += $key }
    }
    if (-not (Test-StrengthSet $Policy.allowedCombinations $template.allowedCombinations)) { $differences += 'allowedCombinations' }
    if ($Configurations.Count -ne 1) {
        $differences += 'combinationConfigurations count'
    } else {
        $actual = $Configurations[0]
        $expected = $template.combinationConfigurations[0]
        $knownKeys = @('id', '@odata.context', '@odata.type', 'appliesToCombinations', 'allowedAAGUIDs')
        if (@($actual.Keys | Where-Object { $_ -cnotin $knownKeys }).Count) { $differences += 'unknown combination configuration fields' }
        if ($actual['@odata.type'] -cne $expected['@odata.type']) { $differences += 'combination configuration type' }
        if (-not (Test-StrengthSet $actual.appliesToCombinations $expected.appliesToCombinations)) {
            $differences += 'appliesToCombinations'
        }
        $aaguids = $actual.allowedAAGUIDs
        if ($aaguids -is [array] -and @($aaguids | Where-Object { $_ -isnot [string] }).Count -eq 0) {
            $aaguids = @($aaguids | ForEach-Object { $_.ToLowerInvariant() })
        }
        if (-not (Test-StrengthSet $aaguids $expected.allowedAAGUIDs)) { $differences += 'allowedAAGUIDs' }
    }
    if ($differences.Count) {
        throw "Authentication strength drift in '$($template.displayName)': $($differences -join ', '). No update was attempted."
    }
}

# Require a tenant GUID, not a display name, domain, or fleet-wide selector.
Assert-StrengthGuid $TenantId 'TenantId (one explicit tenant)'
$template = Get-Content -LiteralPath $TemplatePath -Raw | ConvertFrom-Json -AsHashtable -Depth 30
Assert-StrengthKeys $template @('displayName', 'description', 'allowedCombinations', 'combinationConfigurations') 'Template'
foreach ($key in @('displayName', 'description')) {
    if ($template[$key] -isnot [string] -or [string]::IsNullOrWhiteSpace($template[$key]) -or $template[$key].Contains('%')) {
        throw "Template $key must be a nonempty literal string without CIPP replacement tokens (%)."
    }
}
Assert-StrengthStringArray $template.allowedCombinations 'allowedCombinations'
$supportedModes = @('fido2', 'windowsHelloForBusiness', 'temporaryAccessPassOneTime', 'temporaryAccessPassMultiUse')
if (@($template.allowedCombinations | Where-Object { $_ -cnotin $supportedModes }).Count -or
    $template.allowedCombinations -cnotcontains 'fido2') {
    throw 'Only FIDO2, WHfB, and TAP combinations are supported, and restricted fido2 is required.'
}
if ($template.combinationConfigurations -isnot [array] -or $template.combinationConfigurations.Count -ne 1) {
    throw 'combinationConfigurations must contain exactly one FIDO2 restriction.'
}
$configuration = $template.combinationConfigurations[0]
Assert-StrengthKeys $configuration @('@odata.type', 'appliesToCombinations', 'allowedAAGUIDs') 'FIDO2 configuration'
if ($configuration['@odata.type'] -cne '#microsoft.graph.fido2CombinationConfiguration' -or
    -not (Test-StrengthSet $configuration.appliesToCombinations @('fido2'))) {
    throw 'FIDO2 configuration must apply only to fido2 with the documented OData type.'
}
Assert-StrengthStringArray $configuration.allowedAAGUIDs 'allowedAAGUIDs'
foreach ($aaguid in $configuration.allowedAAGUIDs) { Assert-StrengthGuid $aaguid 'AAGUID' }
$configuration.allowedAAGUIDs = @($configuration.allowedAAGUIDs | ForEach-Object { $_.ToLowerInvariant() })

foreach ($name in @('New-GraphGETRequest', 'New-GraphPOSTRequest')) {
    $command = Get-Command $name -CommandType Function, Cmdlet -ErrorAction SilentlyContinue
    if (-not $command) {
        throw "Missing $name. Run in an initialized, authenticated CIPP backend PowerShell session, not Custom Tests."
    }
}

$policies = @(Read-StrengthCollection $root)
foreach ($policy in $policies) {
    Assert-StrengthGuid $policy.id 'Graph policy ID'
    if ($policy.displayName -isnot [string] -or [string]::IsNullOrWhiteSpace($policy.displayName)) {
        throw 'Incomplete Graph policy listing: displayName is missing.'
    }
}
$matches = @($policies | Where-Object { $_.displayName -eq $template.displayName })
if ($matches.Count -gt 1) { throw "Duplicate authentication strengths named '$($template.displayName)'; resolve ambiguity before retrying." }
$id = $null
$status = 'WouldCreate'
if ($matches.Count -eq 1) {
    $id = $matches[0].id
    $policy = Read-StrengthObject "$root/$id"
    $configurations = @(Read-StrengthCollection "$root/$id/combinationConfigurations")
    Assert-StrengthMatch $policy $configurations $id
    $status = 'Unchanged'
} elseif ($Apply -and $PSCmdlet.ShouldProcess("$TenantId : $($template.displayName)", 'Create authentication strength (no CA assignment)')) {
    try {
        # A create is not idempotent. Do not retry an uncertain POST or queue a deferred write.
        $created = @(New-GraphPOSTRequest -uri $root -tenantid $TenantId -AsApp $true -type POST -body (
            ConvertTo-Json -InputObject $template -Depth 30 -Compress
        ) -maxRetries 1 -ScheduleRetry $false)
        if ($created.Count -ne 1) { throw 'Create did not return exactly one policy.' }
        $id = $created[0].id
        Assert-StrengthGuid $id 'Created policy ID'
        $policy = Read-StrengthObject "$root/$id"
        $configurations = @(Read-StrengthCollection "$root/$id/combinationConfigurations")
        Assert-StrengthMatch $policy $configurations $id
        $status = 'Created'
    } catch {
        $identity = if ($id) { " Reported policy ID: $id." } else { ' No policy ID was confirmed.' }
        throw "Creation or verification failed for tenant $TenantId.$identity Inspect the tenant before retrying; no cleanup or update was attempted. $($_.Exception.Message)"
    }
}

[pscustomobject]@{
    TenantId    = $TenantId
    DisplayName = $template.displayName
    PolicyId    = $id
    Status      = $status
}
