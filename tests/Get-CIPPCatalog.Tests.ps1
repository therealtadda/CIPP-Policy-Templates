#requires -Version 7.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\scripts\Get-CIPPCatalog.ps1')
$repoRoot = Split-Path -Parent $PSScriptRoot
$sourceRevision = '0123456789abcdef0123456789abcdef01234567'
$manifest = Read-CIPPCatalogManifest $repoRoot
Test-CIPPCatalogManifest $manifest $repoRoot
$passed = 1

function Assert-CatalogRejected {
    param([string]$Name, [scriptblock]$Action, [string]$ExpectedError)
    $failure = $null
    try { & $Action } catch { $failure = $_.Exception.Message }
    if (-not $failure -or $failure -notlike "*$ExpectedError*") {
        throw "FAIL $Name : expected rejection containing '$ExpectedError'; got '$failure'"
    }
    $script:passed++
}

$catalog = Get-CIPPCatalog -RepoRoot $repoRoot -SourceRevision $sourceRevision
$catalogIds = @($catalog.policies | ForEach-Object id)
Assert-CAEqual $catalogIds @('CA-001', 'CA-002', 'CA-003', 'CA-004', 'CA-005', 'CA-006') 'catalog order'
Assert-CAEqual $catalog.source.revision $sourceRevision 'source revision output'
Assert-CAEqual $catalog.source.repository 'therealtadda/CIPP-Policy-Templates' 'source repository output'
if ($catalog.policies[0].Contains('sourceTemplate')) { throw 'FAIL source template leaked without explicit inclusion' }
$baseline = Get-CIPPCatalog -RepoRoot $repoRoot -SourceRevision $sourceRevision -SelectionSet 'baseline-core'
Assert-CAEqual @($baseline.policies | ForEach-Object id) @('CA-001', 'CA-002', 'CA-003', 'CA-004', 'CA-005') 'baseline selection'
$compatibility = Get-CIPPCatalog -RepoRoot $repoRoot -SourceRevision $sourceRevision -SelectionSet 'external-compatibility' -IncludeSourceTemplate
Assert-CAEqual @($compatibility.policies | ForEach-Object id) @('CA-006') 'compatibility selection'
Assert-CAEqual $compatibility.policies[0].sourceTemplate.displayName 'CA-006 - External - MFA compatibility' 'embedded source template'
$passed += 2

Assert-CatalogRejected 'unknown selection set' {
    Get-CIPPCatalog -RepoRoot $repoRoot -SourceRevision $sourceRevision -SelectionSet 'not-a-set'
} 'UNKNOWN_SELECTION_SET'

Assert-CatalogRejected 'missing revision pin' {
    Get-CIPPCatalog -RepoRoot $repoRoot
} 'SOURCE_REVISION_REQUIRED'

Assert-CatalogRejected 'branch used as revision' {
    Get-CIPPCatalog -RepoRoot $repoRoot -SourceRevision 'main'
} 'SOURCE_REVISION_REQUIRED'

$bad = $manifest | ConvertTo-Json -Depth 50 | ConvertFrom-Json -AsHashtable -Depth 50
$bad.schemaVersion = 99
Assert-CatalogRejected 'unsupported contract version' {
    Test-CIPPCatalogManifest $bad $repoRoot
} 'UNSUPPORTED_CONTRACT_VERSION'

$bad = $manifest | ConvertTo-Json -Depth 50 | ConvertFrom-Json -AsHashtable -Depth 50
$bad.policies[0].sha256 = '00' * 32
Assert-CatalogRejected 'digest drift' {
    Test-CIPPCatalogManifest $bad $repoRoot
} 'POLICY_DIGEST_MISMATCH'

$bad = $manifest | ConvertTo-Json -Depth 50 | ConvertFrom-Json -AsHashtable -Depth 50
$bad.policies[0].variables = @('%caemergencyusers%')
Assert-CatalogRejected 'metadata/policy variable drift' {
    Test-CIPPCatalogManifest $bad $repoRoot
} 'POLICY_VARIABLE_MISMATCH'

$bad = $manifest | ConvertTo-Json -Depth 50 | ConvertFrom-Json -AsHashtable -Depth 50
$bad.unrecognized = $true
Assert-CatalogRejected 'unknown manifest property' {
    Test-CIPPCatalogManifest $bad $repoRoot
} 'manifest keys'

$bad = $manifest | ConvertTo-Json -Depth 50 | ConvertFrom-Json -AsHashtable -Depth 50
$bad.policies[0].path = 'CATemplate/../CATemplate/CA-001-Baseline-MFA-strength.json'
Assert-CatalogRejected 'noncanonical policy path' {
    Test-CIPPCatalogManifest $bad $repoRoot
} 'INVALID_POLICY_PATH'

$bad = $manifest | ConvertTo-Json -Depth 50 | ConvertFrom-Json -AsHashtable -Depth 50
$bad.selectionSets[0].policyIds += 'CA-999'
Assert-CatalogRejected 'unknown selected policy' {
    Test-CIPPCatalogManifest $bad $repoRoot
} 'UNKNOWN_SELECTION_POLICY'

$bad = $manifest | ConvertTo-Json -Depth 50 | ConvertFrom-Json -AsHashtable -Depth 50
$bad.deploymentContract.repositoryPerformsTenantOperations = $true
Assert-CatalogRejected 'unsafe deployment contract' {
    Test-CIPPCatalogManifest $bad $repoRoot
} 'UNSAFE_DEPLOYMENT_CONTRACT'

$bad = $manifest | ConvertTo-Json -Depth 50 | ConvertFrom-Json -AsHashtable -Depth 50
$bad.deploymentContract.createOrUpdateState = 'enabledForReportingButNotEnforced'
Assert-CatalogRejected 'implicit report-only create' {
    Test-CIPPCatalogManifest $bad $repoRoot
} 'UNSAFE_INITIAL_STATE'

$bad = $manifest | ConvertTo-Json -Depth 50 | ConvertFrom-Json -AsHashtable -Depth 50
$bad.deploymentContract.activationRequiresSeparateExplicitStep = $false
Assert-CatalogRejected 'combined activation' {
    Test-CIPPCatalogManifest $bad $repoRoot
} 'UNSAFE_ACTIVATION_CONTRACT'

$bad = $manifest | ConvertTo-Json -Depth 50 | ConvertFrom-Json -AsHashtable -Depth 50
$bad.deploymentContract.sourceTemplateIsGraphPayload = $true
Assert-CatalogRejected 'source treated as Graph payload' {
    Test-CIPPCatalogManifest $bad $repoRoot
} 'UNSAFE_SOURCE_PAYLOAD_CONTRACT'

Write-Output "PASS: $passed catalog checks (inventory, revision pinning, deterministic selection, source isolation, and lifecycle safety rejection)."
