#requires -Version 7.0
$ErrorActionPreference = 'Stop'
$runner = Join-Path $PSScriptRoot '..\scripts\Invoke-CIPPAuthenticationStrength.ps1'
$templatePath = Join-Path $PSScriptRoot '..\AuthenticationStrength\AS-001-Authenticator-WHfB-TAP.json'
$definition = Get-Content -LiteralPath $templatePath -Raw | ConvertFrom-Json -AsHashtable
$tenant = '11111111-1111-4111-8111-111111111111'
$policyId = '22222222-2222-4222-8222-222222222222'
$root = 'https://graph.microsoft.com/v1.0/policies/authenticationStrengthPolicies'
$passed = 0

function Copy-TestData {
    param($Value)
    ConvertTo-Json -InputObject $Value -Depth 40 | ConvertFrom-Json -AsHashtable -Depth 40
}

function Reset-Scenario {
    $script:scenario = @{
        Listing = @()
        Live = (Copy-TestData $definition)
        Configurations = (Copy-TestData $definition).combinationConfigurations
        Gets = @()
        Posts = @()
    }
    $script:scenario.Live.id = $policyId
    $script:scenario.Live.policyType = 'custom'
    $global:CIPPAuthenticationStrengthTestState = $script:scenario
}

function Set-Existing {
    $script:scenario.Listing = @(@{ id = $policyId; displayName = $definition.displayName; policyType = 'custom' })
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "FAIL: $Message" }
    $script:passed++
}

function Assert-Rejected {
    param([scriptblock]$Action, [string]$Expected)
    $failure = $null
    try { $null = & $Action } catch { $failure = $_.Exception.Message }
    Assert-True ($failure -and $failure -like "*$Expected*") "Expected '$Expected', got '$failure'."
}

function New-GraphGETRequest {
    [CmdletBinding()]
    param($uri, $tenantid, $AsApp, $noPagination, [switch]$SkipValueExtraction)
    Assert-True ($tenantid -eq $tenant -and $AsApp -eq $true -and $noPagination -eq $true -and $SkipValueExtraction) 'GET must use the explicit tenant, app-only auth, and validated page envelopes.'
    $state = $global:CIPPAuthenticationStrengthTestState
    $state.Gets += $uri
    if ($state.ReadError) { throw 'Simulated read failure' }
    if ($uri -eq $root) {
        if ($state.ContainsKey('BadPage')) { return $state.BadPage }
        $page = @{ value = @($state.Listing) }
        if ($state.NextLink) { $page['@odata.nextLink'] = $state.NextLink }
        return $page
    }
    if ($uri -eq "${root}?`$skiptoken=second") {
        return @{ value = @($state.SecondPage) }
    }
    if ($uri -eq "$root/$policyId") { return $state.Live }
    if ($uri -eq "$root/$policyId/combinationConfigurations") {
        return @{ value = @($state.Configurations) }
    }
    throw "Unexpected GET: $uri"
}

function New-GraphPOSTRequest {
    param($uri, $tenantid, $AsApp, $type, $body, $maxRetries, $ScheduleRetry)
    Assert-True ($uri -eq $root -and $tenantid -eq $tenant -and $AsApp -eq $true -and $type -ceq 'POST') 'POST must only create a strength in the explicit tenant.'
    Assert-True ($maxRetries -eq 1 -and $ScheduleRetry -eq $false) 'POST must not retry or queue an uncertain creation.'
    $state = $global:CIPPAuthenticationStrengthTestState
    $state.Posts += ,($body | ConvertFrom-Json -AsHashtable)
    if ($state.PostError) { throw 'Simulated uncertain create failure' }
    if ($state.InvalidCreate) { return @{ id = 'invalid' } }
    if ($state.EmptyCreate) { return }
    if ($state.CreateMutation) { & $state.CreateMutation }
    return @{ id = $policyId }
}

function Invoke-Runner {
    param([hashtable]$Options = @{})
    & $runner -TenantId $tenant @Options
}

try {
Reset-Scenario
$result = Invoke-Runner
Assert-True ($result.Status -eq 'WouldCreate' -and -not $result.PolicyId -and $scenario.Posts.Count -eq 0) 'Default invocation must not create.'
$result = Invoke-Runner @{ Apply = $true; WhatIf = $true }
Assert-True ($result.Status -eq 'WouldCreate' -and $scenario.Posts.Count -eq 0) 'WhatIf must not create.'

Reset-Scenario
$result = Invoke-Runner @{ Apply = $true }
Assert-True ($result.Status -eq 'Created' -and $result.PolicyId -eq $policyId -and $scenario.Posts.Count -eq 1) 'Apply must create exactly once and return the verified ID.'
$sent = $scenario.Posts[0]
Assert-True ($sent.allowedCombinations.Count -eq 4 -and
    $sent.allowedCombinations -ccontains 'fido2' -and
    $sent.allowedCombinations -ccontains 'windowsHelloForBusiness' -and
    $sent.allowedCombinations -ccontains 'temporaryAccessPassOneTime' -and
    $sent.allowedCombinations -ccontains 'temporaryAccessPassMultiUse') 'Create must include exactly the requested methods.'
Assert-True ($sent.combinationConfigurations.Count -eq 1 -and
    $sent.combinationConfigurations[0].allowedAAGUIDs.Count -eq 2 -and
    $sent.combinationConfigurations[0].allowedAAGUIDs -contains 'de1e552d-db1d-4423-a619-566b625cdc84' -and
    $sent.combinationConfigurations[0].allowedAAGUIDs -contains '90a3ccdf-635c-4729-a248-9b709135078f' -and
    $sent.combinationConfigurations[0].appliesToCombinations[0] -ceq 'fido2') 'Create must restrict FIDO2 to both Authenticator AAGUIDs in the same POST.'
Assert-True (-not $sent.Contains('id') -and -not $sent.Contains('requirementsSatisfied') -and
    $scenario.Gets -contains "$root/$policyId/combinationConfigurations") 'Creation must omit server fields and read back restrictions.'

Reset-Scenario
Set-Existing
[array]::Reverse($scenario.Live.allowedCombinations)
[array]::Reverse($scenario.Configurations[0].allowedAAGUIDs)
$scenario.Configurations[0].allowedAAGUIDs = @($scenario.Configurations[0].allowedAAGUIDs | ForEach-Object { $_.ToUpperInvariant() })
$scenario.Configurations[0].id = '33333333-3333-4333-8333-333333333333'
$scenario.Live.createdDateTime = '2026-01-01T00:00:00Z'
$result = Invoke-Runner @{ Apply = $true }
Assert-True ($result.Status -eq 'Unchanged' -and $result.PolicyId -eq $policyId -and $scenario.Posts.Count -eq 0) 'Equivalent reordered methods/AAGUIDs and server metadata must reuse without writing.'

$drifts = @(
    @({ $scenario.Live.allowedCombinations = @('fido2') }, 'allowedCombinations'),
    @({ $scenario.Live.allowedCombinations += 'sms' }, 'allowedCombinations'),
    @({ $scenario.Live.allowedCombinations[1] = 'fido2' }, 'allowedCombinations'),
    @({ $scenario.Live.description = 'Different purpose' }, 'description'),
    @({ $scenario.Live.displayName = 'Renamed' }, 'displayName'),
    @({ $scenario.Configurations = @() }, 'combinationConfigurations'),
    @({ $scenario.Configurations += (Copy-TestData $scenario.Configurations[0]) }, 'combinationConfigurations'),
    @({ $scenario.Configurations[0].allowedAAGUIDs = @() }, 'allowedAAGUIDs'),
    @({ $scenario.Configurations[0].Remove('allowedAAGUIDs') }, 'allowedAAGUIDs'),
    @({ $scenario.Configurations[0].allowedAAGUIDs += '44444444-4444-4444-8444-444444444444' }, 'allowedAAGUIDs'),
    @({ $scenario.Configurations[0].allowedAAGUIDs = @($scenario.Configurations[0].allowedAAGUIDs[0]) * 2 }, 'allowedAAGUIDs'),
    @({ $scenario.Configurations[0].appliesToCombinations = @('windowsHelloForBusiness') }, 'appliesToCombinations'),
    @({ $scenario.Configurations[0]['@odata.type'] = '#microsoft.graph.x509CertificateCombinationConfiguration' }, 'configuration type'),
    @({ $scenario.Configurations[0].newRestriction = 'unknown' }, 'unknown combination'),
    @({ $scenario.Live.policyType = 'builtIn' }, 'not a custom'),
    @({ $scenario.Live.id = '55555555-5555-4555-8555-555555555555' }, 'requested ID')
)
foreach ($test in $drifts) {
    Reset-Scenario
    Set-Existing
    & $test[0]
    Assert-Rejected { Invoke-Runner @{ Apply = $true } } $test[1]
    Assert-True ($scenario.Posts.Count -eq 0) "Drift '$($test[1])' must not write."
}

Reset-Scenario
Set-Existing
$scenario.Listing += Copy-TestData $scenario.Listing[0]
Assert-Rejected { Invoke-Runner @{ Apply = $true } } 'Duplicate'
Assert-True ($scenario.Posts.Count -eq 0) 'Duplicate names must not write.'

Reset-Scenario
$scenario.NextLink = "${root}?`$skiptoken=second"
$scenario.SecondPage = @(@{ id = $policyId; displayName = $definition.displayName })
$result = Invoke-Runner @{ Apply = $true }
Assert-True ($result.Status -eq 'Unchanged' -and $scenario.Posts.Count -eq 0) 'An existing strength on a later page must not be recreated.'

foreach ($nextLink in @($root, 'https://example.invalid/policies', "$root/other", "$root#fragment")) {
    Reset-Scenario
    $scenario.NextLink = $nextLink
    Assert-Rejected { Invoke-Runner @{ Apply = $true } } $(if ($nextLink -eq $root) { 'Repeated' } else { 'Unsafe' })
    Assert-True ($scenario.Posts.Count -eq 0) 'Invalid pagination must not write.'
}
foreach ($badPage in @($null, @{}, @{ error = @{ message = 'Denied' } }, @{ unrelated = @() }, @{ value = $null }, @{ value = 'not-an-array' }, @{ value = @('not-an-object') })) {
    Reset-Scenario
    $scenario.BadPage = $badPage
    Assert-Rejected { Invoke-Runner @{ Apply = $true } } 'Graph'
    Assert-True ($scenario.Posts.Count -eq 0) 'Malformed collection responses must not be treated as missing strength.'
}
Reset-Scenario
$scenario.ReadError = $true
Assert-Rejected { Invoke-Runner @{ Apply = $true } } 'Simulated read failure'
Assert-True ($scenario.Posts.Count -eq 0) 'Read failure must not write.'

foreach ($flag in @('PostError', 'InvalidCreate', 'EmptyCreate')) {
    Reset-Scenario
    $scenario[$flag] = $true
    Assert-Rejected { Invoke-Runner @{ Apply = $true } } 'Inspect the tenant before retrying'
    Assert-True ($scenario.Posts.Count -eq 1) 'A failed or uncertain create must not be retried.'
}
Reset-Scenario
$scenario.CreateMutation = { $global:CIPPAuthenticationStrengthTestState.Configurations = @() }
Assert-Rejected { Invoke-Runner @{ Apply = $true } } "Reported policy ID: $policyId"
Assert-True ($scenario.Posts.Count -eq 1) 'Incomplete post-create restrictions must fail verification without cleanup or retry.'
Reset-Scenario
$scenario.CreateMutation = { $global:CIPPAuthenticationStrengthTestState.ReadError = $true }
Assert-Rejected { Invoke-Runner @{ Apply = $true } } 'Simulated read failure'

Reset-Scenario
foreach ($invalidTenant in @('AllTenants', 'All Tenants', 'contoso.onmicrosoft.com', [guid]::Empty.ToString())) {
    Assert-Rejected { & $runner -TenantId $invalidTenant -Apply } 'one explicit tenant'
}
Assert-True ($scenario.Gets.Count -eq 0 -and $scenario.Posts.Count -eq 0) 'Invalid tenant selectors must fail before Graph access.'

$temp = Join-Path ([System.IO.Path]::GetTempPath()) "cipp-strength-test-$([guid]::NewGuid()).json"
try {
    $invalidTemplates = @(
        @({ $bad.requirementsSatisfied = 'mfa' }, 'keys'),
        @({ $bad.displayName = '%tenantid%' }, 'literal string'),
        @({ $bad.allowedCombinations = @('fido2', 'sms') }, 'Only FIDO2'),
        @({ $bad.allowedCombinations = @('windowsHelloForBusiness') }, 'restricted fido2'),
        @({ $bad.allowedCombinations = 'fido2' }, 'nonempty array'),
        @({ $bad.allowedCombinations = @('fido2', 'fido2') }, 'unique'),
        @({ $bad.combinationConfigurations = @() }, 'exactly one'),
        @({ $bad.combinationConfigurations[0].allowedAAGUIDs = @() }, 'nonempty array'),
        @({ $bad.combinationConfigurations[0].allowedAAGUIDs = @('not-a-guid') }, 'AAGUID'),
        @({ $bad.combinationConfigurations[0].appliesToCombinations = @('windowsHelloForBusiness') }, 'apply only to fido2'),
        @({ $bad.combinationConfigurations[0]['@odata.type'] = 'incorrect' }, 'OData type')
    )
    foreach ($test in $invalidTemplates) {
        Reset-Scenario
        $bad = Copy-TestData $definition
        & $test[0]
        ConvertTo-Json -InputObject $bad -Depth 30 | Set-Content -LiteralPath $temp
        Assert-Rejected { Invoke-Runner @{ TemplatePath = $temp; Apply = $true } } $test[1]
        Assert-True ($scenario.Gets.Count -eq 0 -and $scenario.Posts.Count -eq 0) 'Invalid template must fail before Graph access.'
    }
} finally {
    Remove-Item -LiteralPath $temp -ErrorAction SilentlyContinue
}

Remove-Item Function:\New-GraphPOSTRequest
Assert-Rejected { Invoke-Runner } 'Missing New-GraphPOSTRequest'
Remove-Item Function:\New-GraphGETRequest
Assert-Rejected { Invoke-Runner } 'Missing New-GraphGETRequest'
Write-Output "PASS: $passed offline assertions for authentication-strength deployment. No tenant calls were made."
} finally {
    Remove-Variable CIPPAuthenticationStrengthTestState -Scope Global -ErrorAction SilentlyContinue
}
