#requires -Version 7.0
[CmdletBinding()]
param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$SourceRevision,
    [string]$SelectionSet,
    [string]$VariablesPath,
    [switch]$CompatibilityCoverageVerified,
    [switch]$IncludeSourceTemplate,
    [switch]$AsJson
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Test-CABaseline.ps1')

function Get-CANormalizedRelativePath {
    param([string]$Path)
    return $Path.Replace('/', [IO.Path]::DirectorySeparatorChar)
}

function Get-CAPolicyTokens {
    param([System.Collections.IDictionary]$Policy)
    $json = ConvertTo-Json -InputObject $Policy -Depth 50 -Compress
    return @([regex]::Matches($json, '%[a-z0-9]+%') | ForEach-Object Value | Sort-Object -Unique)
}

function Assert-CACatalogCondition {
    param([bool]$Condition, [string]$Code, [string]$Message)
    if (-not $Condition) { throw "${Code}: $Message" }
}

function Read-CIPPCatalogManifest {
    param([string]$RepoRoot)
    $manifestPath = Join-Path $RepoRoot 'cipp-policy-manifest.json'
    Assert-CACatalogCondition (Test-Path -LiteralPath $manifestPath -PathType Leaf) 'CATALOG_MANIFEST_MISSING' "Missing $manifestPath"
    return Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -AsHashtable -Depth 50
}

function Test-CIPPCatalogManifest {
    param(
        [System.Collections.IDictionary]$Manifest,
        [string]$RepoRoot
    )

    Assert-CAKeys $Manifest @('schemaVersion', 'kind', 'catalogId', 'templateRoot', 'sourceTemplateFormat', 'sourceContract', 'discovery', 'compatibility', 'deploymentContract', 'variables', 'policies', 'selectionSets') 'manifest keys'
    Assert-CACatalogCondition ([int]$Manifest.schemaVersion -eq 2) 'UNSUPPORTED_CONTRACT_VERSION' 'Only catalog schemaVersion 2 is supported.'
    Assert-CACatalogCondition ($Manifest.kind -ceq 'cipp-conditional-access-catalog') 'INVALID_CATALOG_KIND' 'Expected kind cipp-conditional-access-catalog.'
    Assert-CACatalogCondition ($Manifest.templateRoot -ceq 'CATemplate') 'UNSUPPORTED_TEMPLATE_ROOT' 'CIPP raw policy discovery requires the CATemplate root.'
    Assert-CACatalogCondition ($Manifest.sourceTemplateFormat -ceq 'raw-cipp-conditional-access-template') 'UNSUPPORTED_SOURCE_FORMAT' 'Expected raw CIPP Conditional Access template objects.'
    Assert-CAKeys $Manifest.sourceContract @('repository', 'revisionType', 'revisionRequired', 'branchNamesAreDiscoveryHintsOnly', 'digestAlgorithm') 'source contract'
    Assert-CACatalogCondition ($Manifest.sourceContract.repository -ceq 'therealtadda/CIPP-Policy-Templates') 'INVALID_SOURCE_REPOSITORY' 'Unexpected policy source repository.'
    Assert-CACatalogCondition ($Manifest.sourceContract.revisionType -ceq 'git-commit-sha') 'INVALID_SOURCE_REVISION_TYPE' 'Source revisions must be Git commit SHAs.'
    Assert-CACatalogCondition ($Manifest.sourceContract.revisionRequired -eq $true) 'REVISION_PIN_REQUIRED' 'An immutable source revision is mandatory.'
    Assert-CACatalogCondition ($Manifest.sourceContract.branchNamesAreDiscoveryHintsOnly -eq $true) 'UNSAFE_BRANCH_CONTRACT' 'Branch names cannot be deployment provenance.'
    Assert-CACatalogCondition ($Manifest.sourceContract.digestAlgorithm -ceq 'sha256') 'UNSUPPORTED_DIGEST_ALGORITHM' 'Policy digests must use SHA-256.'
    Assert-CAKeys $Manifest.discovery @('entryPoint', 'policyPattern', 'ordering') 'discovery contract'
    Assert-CACatalogCondition ($Manifest.discovery.entryPoint -ceq 'scripts/Get-CIPPCatalog.ps1') 'INVALID_DISCOVERY_ENTRY_POINT' 'The manifest must identify this catalog reader.'
    Assert-CACatalogCondition ($Manifest.discovery.policyPattern -ceq '*.json') 'INVALID_DISCOVERY_PATTERN' 'The supported policy discovery pattern is *.json.'
    Assert-CACatalogCondition ($Manifest.discovery.ordering -ceq 'id-ascending') 'INVALID_DISCOVERY_ORDER' 'Catalog output must be ordered by ascending policy ID.'
    Assert-CAKeys $Manifest.compatibility @('unknownContractVersion', 'minimumCippCapabilities') 'compatibility contract'
    Assert-CACatalogCondition ($Manifest.compatibility.unknownContractVersion -ceq 'reject') 'INVALID_COMPATIBILITY_BEHAVIOR' 'Unknown contract versions must be rejected.'
    Assert-CACatalogCondition (@($Manifest.compatibility.minimumCippCapabilities).Count -gt 0) 'MISSING_CAPABILITY_CONTRACT' 'At least one required CIPP capability must be declared.'
    Assert-CACatalogCondition ($Manifest.deploymentContract.repositoryPerformsTenantOperations -eq $false) 'UNSAFE_DEPLOYMENT_CONTRACT' 'The repository contract must not perform tenant operations.'
    Assert-CACatalogCondition ($Manifest.deploymentContract.defaultAction -ceq 'discover-and-validate-only') 'UNSAFE_DEPLOYMENT_CONTRACT' 'The only default action is discovery and validation.'
    Assert-CACatalogCondition ($Manifest.deploymentContract.requiresExplicitTenantAuthorization -eq $true) 'UNSAFE_DEPLOYMENT_CONTRACT' 'Explicit tenant authorization must remain mandatory.'
    Assert-CAKeys $Manifest.deploymentContract @('repositoryPerformsTenantOperations', 'defaultAction', 'requiresExplicitTenantAuthorization', 'sourceTemplateIsGraphPayload', 'createOrUpdateState', 'activationState', 'activationRequiresSeparateExplicitStep', 'requiresReplaceByDisplayName', 'requiresPrecreatedObjects', 'createOrUpdateSteps', 'activationSteps', 'prohibitedActions') 'deployment contract'
    Assert-CACatalogCondition ($Manifest.deploymentContract.sourceTemplateIsGraphPayload -eq $false) 'UNSAFE_SOURCE_PAYLOAD_CONTRACT' 'Source template objects cannot be sent directly as Graph payloads.'
    Assert-CACatalogCondition ($Manifest.deploymentContract.createOrUpdateState -ceq 'disabled') 'UNSAFE_INITIAL_STATE' 'Create/update operations must force the disabled state.'
    Assert-CACatalogCondition ($Manifest.deploymentContract.activationState -ceq 'enabledForReportingButNotEnforced') 'UNSAFE_ACTIVATION_STATE' 'The initial activation target must be Report-only.'
    Assert-CACatalogCondition ($Manifest.deploymentContract.activationRequiresSeparateExplicitStep -eq $true) 'UNSAFE_ACTIVATION_CONTRACT' 'Activation must be a separate explicit operation.'
    Assert-CACatalogCondition (@($Manifest.deploymentContract.createOrUpdateSteps).Count -gt 0) 'MISSING_CREATE_UPDATE_STEPS' 'Create/update lifecycle steps must be declared.'
    Assert-CACatalogCondition (@($Manifest.deploymentContract.activationSteps).Count -gt 0) 'MISSING_ACTIVATION_STEPS' 'Activation lifecycle steps must be declared.'

    $policiesPath = Join-Path $RepoRoot $Manifest.templateRoot
    $actualFiles = @(Get-ChildItem -LiteralPath $policiesPath -File -Filter '*.json' -ErrorAction Stop)
    $entries = @($Manifest.policies | Sort-Object id)
    Assert-CACatalogCondition ($entries.Count -eq $actualFiles.Count) 'CATALOG_FILE_COUNT_MISMATCH' 'Every template file must have exactly one manifest entry.'
    $ids = @($entries | ForEach-Object id)
    Assert-CACatalogCondition (@($ids | Sort-Object -Unique).Count -eq $ids.Count) 'DUPLICATE_POLICY_ID' 'Policy IDs must be unique.'
    $paths = @($entries | ForEach-Object path)
    Assert-CACatalogCondition (@($paths | Sort-Object -Unique).Count -eq $paths.Count) 'DUPLICATE_POLICY_PATH' 'Policy paths must be unique.'

    $variables = @($Manifest.variables | Sort-Object token)
    $variableTokens = @($variables | ForEach-Object token)
    Assert-CACatalogCondition (@($variableTokens | Sort-Object -Unique).Count -eq $variableTokens.Count) 'DUPLICATE_VARIABLE' 'Variable tokens must be unique.'
    foreach ($variable in $variables) {
        Assert-CAKeys $variable @('token', 'cippType', 'objectKind', 'required') 'variable definition'
        Assert-CACatalogCondition ($variable.token -match '^%[a-z0-9]+%$') 'INVALID_VARIABLE_TOKEN' "Invalid token: $($variable.token)"
        Assert-CACatalogCondition ($variable.cippType -ceq 'List') 'UNSUPPORTED_VARIABLE_TYPE' "$($variable.token) must use CIPP List type."
        Assert-CACatalogCondition ($variable.objectKind -in @('user', 'group')) 'INVALID_VARIABLE_OBJECT_KIND' "$($variable.token) must target users or groups."
        Assert-CACatalogCondition ($variable.required -is [bool]) 'INVALID_VARIABLE_DEFINITION' "$($variable.token) required must be a boolean."
    }

    $policies = Read-CABaselinePolicies -Path $policiesPath
    Test-CABaselinePolicies -Policies $policies
    $referencedTokens = @()
    foreach ($entry in $entries) {
        Assert-CAKeys $entry @('id', 'path', 'displayName', 'sha256', 'optional', 'selectionSet', 'variables') 'policy catalog entry'
        Assert-CACatalogCondition ($entry.id -cmatch '^CA-[0-9]{3}$') 'INVALID_POLICY_ID' "$($entry.id) is not a supported policy ID."
        Assert-CACatalogCondition ($entry.optional -is [bool]) 'INVALID_POLICY_DEFINITION' "$($entry.id) optional must be a boolean."
        Assert-CACatalogCondition ($entry.path -cmatch '^CATemplate/CA-[0-9]{3}-.+\.json$') 'INVALID_POLICY_PATH' "$($entry.path) is not a canonical CATemplate-relative path."
        $relativePath = Get-CANormalizedRelativePath $entry.path
        $fullPath = Join-Path $RepoRoot $relativePath
        Assert-CACatalogCondition (Test-Path -LiteralPath $fullPath -PathType Leaf) 'CATALOG_POLICY_MISSING' "$($entry.path) does not exist."
        Assert-CACatalogCondition (
            ($entry.path -ceq ($Manifest.templateRoot + '/' + (Split-Path -Leaf $entry.path)))
        ) 'INVALID_POLICY_PATH' "$($entry.path) is outside or traverses $($Manifest.templateRoot)."
        Assert-CACatalogCondition ((Split-Path -Leaf $entry.path) -match "^$($entry.id)-.+\.json$") 'INVALID_POLICY_FILENAME' "$($entry.path) does not match its policy ID."
        Assert-CACatalogCondition ($policies.ContainsKey($entry.id)) 'UNKNOWN_POLICY_ID' "$($entry.id) is absent from the template inventory."
        $policy = $policies[$entry.id]
        Assert-CACatalogCondition ($policy.displayName -ceq $entry.displayName) 'POLICY_DISPLAY_NAME_MISMATCH' "$($entry.id) displayName differs between template and manifest."
        Assert-CACatalogCondition ($entry.sha256 -cmatch '^[0-9A-F]{64}$') 'INVALID_POLICY_DIGEST' "$($entry.id) SHA-256 must be 64 uppercase hexadecimal characters."
        $hash = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash
        Assert-CACatalogCondition ($hash -ceq $entry.sha256) 'POLICY_DIGEST_MISMATCH' "$($entry.id) SHA-256 digest changed; review policy and update manifest together."
        $entryTokens = @($entry.variables | Sort-Object -Unique)
        $templateTokens = @(Get-CAPolicyTokens $policy)
        $entryTokensJson = ConvertTo-Json -InputObject $entryTokens -Compress
        $templateTokensJson = ConvertTo-Json -InputObject $templateTokens -Compress
        Assert-CACatalogCondition ($entryTokensJson -ceq $templateTokensJson) 'POLICY_VARIABLE_MISMATCH' "$($entry.id) manifest variables do not match the policy payload."
        $referencedTokens += $entryTokens
        foreach ($token in $entryTokens) {
            Assert-CACatalogCondition ($variableTokens -contains $token) 'UNDECLARED_VARIABLE' "$($entry.id) references undeclared variable $token."
        }
    }
    Assert-CAEqual @($variableTokens | Sort-Object) @($referencedTokens | Sort-Object -Unique) 'catalog variable inventory'

    $manifestFileNames = @($entries | ForEach-Object { Split-Path -Leaf $_.path } | Sort-Object)
    $actualFileNames = @($actualFiles | ForEach-Object Name | Sort-Object)
    Assert-CACatalogCondition (
        (ConvertTo-Json -InputObject $manifestFileNames -Compress) -ceq
        (ConvertTo-Json -InputObject $actualFileNames -Compress)
    ) 'CATALOG_FILE_MISMATCH' 'Manifest paths and CATemplate files do not match.'

    $sets = @($Manifest.selectionSets)
    $setIds = @($sets | ForEach-Object id)
    Assert-CACatalogCondition (@($setIds | Sort-Object -Unique).Count -eq $setIds.Count) 'DUPLICATE_SELECTION_SET' 'Selection-set IDs must be unique.'
    foreach ($set in $sets) {
        $selectionKeys = if ($null -ne $set.pairedWith) {
            @('id', 'policyIds', 'recommendedForInitialSelection', 'pairedWith', 'activationGates')
        } else {
            @('id', 'policyIds', 'recommendedForInitialSelection', 'activationGates')
        }
        Assert-CAKeys $set $selectionKeys 'selection set'
        Assert-CACatalogCondition ($set.recommendedForInitialSelection -is [bool]) 'INVALID_SELECTION_SET' "$($set.id) recommendedForInitialSelection must be a boolean."
        foreach ($id in @($set.policyIds | Where-Object { $null -ne $_ })) {
            Assert-CACatalogCondition ($ids -contains $id) 'UNKNOWN_SELECTION_POLICY' "$($set.id) references unknown policy $id."
            $entry = @($entries | Where-Object id -ceq $id)[0]
            Assert-CACatalogCondition ($entry.selectionSet -ceq $set.id) 'POLICY_SELECTION_MISMATCH' "$id is assigned to '$($entry.selectionSet)', not '$($set.id)'."
        }
        if ($null -ne $set.pairedWith) {
            foreach ($id in @($set.pairedWith)) {
                Assert-CACatalogCondition ($ids -contains $id) 'UNKNOWN_PAIRED_POLICY' "$($set.id) pairs with unknown policy $id."
            }
        }
        Assert-CACatalogCondition (@($set.activationGates).Count -gt 0) 'MISSING_ACTIVATION_GATES' "$($set.id) requires explicit activation gates."
    }
    Assert-CACatalogCondition ($sets.Count -gt 0) 'MISSING_SELECTION_SETS' 'At least one selection set is required.'
}

function Get-CIPPCatalog {
    param(
        [string]$RepoRoot,
        [string]$SourceRevision,
        [string]$SelectionSet,
        [switch]$IncludeSourceTemplate
    )

    $manifest = Read-CIPPCatalogManifest -RepoRoot $RepoRoot
    Test-CIPPCatalogManifest -Manifest $manifest -RepoRoot $RepoRoot
    Assert-CACatalogCondition ($SourceRevision -cmatch '^[0-9a-f]{40}$|^[0-9a-f]{64}$') 'SOURCE_REVISION_REQUIRED' 'Supply the immutable full Git commit SHA used to fetch this catalog.'
    $entries = @($manifest.policies | Sort-Object id)
    if ($SelectionSet) {
        $set = @($manifest.selectionSets | Where-Object id -ceq $SelectionSet)
        Assert-CACatalogCondition ($set.Count -eq 1) 'UNKNOWN_SELECTION_SET' "Selection set '$SelectionSet' is not declared."
        $entries = @($entries | Where-Object { $set[0].policyIds -contains $_.id } | Sort-Object id)
    }

    $policyOutput = foreach ($entry in $entries) {
        $item = [ordered]@{
            id = $entry.id
            path = $entry.path
            displayName = $entry.displayName
            sha256 = $entry.sha256
            optional = [bool]$entry.optional
            selectionSet = $entry.selectionSet
            variables = @($entry.variables | Sort-Object)
        }
        if ($IncludeSourceTemplate) {
            $fullPath = Join-Path $RepoRoot (Get-CANormalizedRelativePath $entry.path)
            $item.sourceTemplate = Get-Content -LiteralPath $fullPath -Raw | ConvertFrom-Json -AsHashtable -Depth 50
        }
        $item
    }

    return [ordered]@{
        schemaVersion = $manifest.schemaVersion
        kind = $manifest.kind
        catalogId = $manifest.catalogId
        sourceTemplateFormat = $manifest.sourceTemplateFormat
        source = [ordered]@{
            repository = $manifest.sourceContract.repository
            revision = $SourceRevision
            revisionType = $manifest.sourceContract.revisionType
        }
        selectionSet = if ($SelectionSet) { $SelectionSet } else { $null }
        compatibility = $manifest.compatibility
        deploymentContract = $manifest.deploymentContract
        variables = @($manifest.variables | Sort-Object token)
        policies = @($policyOutput)
        selectionSets = @($manifest.selectionSets | Sort-Object id)
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    if ($VariablesPath) {
        $values = Get-Content -LiteralPath $VariablesPath -Raw | ConvertFrom-Json -AsHashtable -Depth 20
        Test-CAVariableValues -Values $values -CompatibilityCoverageVerified:$CompatibilityCoverageVerified
    }
    $catalog = Get-CIPPCatalog -RepoRoot $RepoRoot -SourceRevision $SourceRevision -SelectionSet $SelectionSet -IncludeSourceTemplate:$IncludeSourceTemplate
    if ($AsJson) {
        ConvertTo-Json -InputObject $catalog -Depth 60
    } else {
        $catalog
    }
}
