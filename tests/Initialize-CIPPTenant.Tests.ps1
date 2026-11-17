#requires -Version 7.0
$ErrorActionPreference = 'Stop'
$initializer = Join-Path $PSScriptRoot '..\scripts\Initialize-CIPPTenant.ps1'
. $initializer
$inventory = Read-CIPPInitializationInventory
$passed = 0

function Assert-True {
    param([bool]$Condition, [string]$Name)
    if (-not $Condition) { throw "FAIL: $Name" }
    $script:passed++
}

function Assert-Throws {
    param([scriptblock]$Action, [string]$Message)
    $caughtMessage = $null
    try { & $Action | Out-Null } catch { $caughtMessage = $_.Exception.Message }
    Assert-True ($caughtMessage -and $caughtMessage.Contains($Message)) "Expected rejection: $Message; got $caughtMessage"
}

$graph = @($inventory.resources | Where-Object resourceAppId -EQ $script:CIPPGraphAppId)[0]
Assert-True (@($graph.permissions | Where-Object type -EQ Role).Count -eq 67) 'Complete pinned Graph application baseline'
Assert-True (@($graph.permissions | Where-Object type -EQ Scope).Count -eq 91) 'Complete pinned Graph delegated baseline'
Assert-True ('Global Administrator' -notin $inventory.runtimeRoles) 'No permanent Global Administrator shortcut'
$old = @(@{ resourceAppId = 'extra-resource'; resourceAccess = @(@{ id = 'extra-role'; type = 'Role' }) })
$merged = @(Merge-CIPPRequiredResourceAccess $old @(@{ resourceAppId = 'new-resource'; permissions = @(@{ id = 'new-role'; type = 'Role' }) }))
Assert-True ($merged.Count -eq 2 -and 'extra-role' -in $merged.resourceAccess.id) 'Manifest merge preserves unrelated grants'
Assert-Throws { Get-CIPPUniqueObject @(@{ id = 'a' }, @{ id = 'b' }) 'identity' } 'Ambiguous'
Assert-True ((Read-CIPPOAuthCallback 'GET /?code=synthetic%2Bcode&state=state HTTP/1.1' 'state' 8400) -ceq 'synthetic+code') 'OAuth code decoding'
Assert-Throws { Read-CIPPOAuthCallback 'GET /?code=x&state=wrong HTTP/1.1' 'state' 8400 } 'state mismatch'
Assert-Throws { Read-CIPPOAuthCallback 'GET /?code=x&state=state&state=state HTTP/1.1' 'state' 8400 } 'Duplicate'
Assert-Throws { Read-CIPPOAuthCallback 'GET /?error=denied&state=state HTTP/1.1' 'state' 8400 } 'refused'

$transport = ${function:Invoke-CIPPGraph}
function Start-Sleep { param($Seconds, $Milliseconds) }
$script:transportCalls = 0
function Invoke-MgGraphRequest { $script:transportCalls++; throw 'synthetic transport failure' }
function Get-CIPPHttpStatus { param($Record) 429 }
Assert-Throws { & $transport '/users' } 'HTTP 429'
Assert-True ($script:transportCalls -eq 4) 'Bounded GET retries'
$script:transportCalls = 0
Assert-Throws { & $transport '/applications/app/addPassword' POST @{} } 'HTTP 429'
Assert-True ($script:transportCalls -eq 1) 'No duplicate credential POST retries'
Assert-Throws { & $transport 'https://example.invalid/steal-token' } 'unexpected origin'
Assert-Throws { Get-CIPPGraphUri 'https://graph.microsoft.com:8443/users' } 'unexpected origin'

$receiver = ${function:Receive-CIPPOAuthCode}
$script:callbackMode = 'Good'
function Start-Process {
    param([string]$FilePath)
    if ($script:callbackMode -eq 'None') { return }
    $values = @{}
    foreach ($part in ([uri]$FilePath).Query.TrimStart('?') -split '&') {
        $pair = $part -split '=', 2
        $values[$pair[0]] = [uri]::UnescapeDataString($pair[1])
    }
    $script:callbackClient = [Net.Sockets.TcpClient]::new()
    $script:callbackClient.Connect([Net.IPAddress]::Loopback, ([uri]$values.redirect_uri).Port)
    $bytes = [Text.Encoding]::ASCII.GetBytes("GET /?code=synthetic-local-code&state=$($values.state) HTTP/1.1`r`nHost: localhost`r`n`r`n")
    $script:callbackClient.GetStream().Write($bytes, 0, $bytes.Length)
}
$reservation = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$reservation.Start()
$testPort = $reservation.LocalEndpoint.Port
$reservation.Stop()
try {
    Assert-True ((& $receiver 'tenant' 'client' 'service@example.invalid' 'challenge' 'state' $testPort 2) -eq 'synthetic-local-code') 'Actual loopback callback handles simulated browser response'
} finally {
    if ($script:callbackClient) { $script:callbackClient.Dispose() }
}
$script:callbackMode = 'None'
Assert-Throws { & $receiver 'tenant' 'client' 'service@example.invalid' 'challenge' 'state' $testPort 1 } 'timed out'

function Reset-CIPPMock {
    $script:mock = @{
        Applications = @(); ServicePrincipals = @{}; Grants = @(); AppRoles = @(); Users = @()
        RoleAssignments = @(); Groups = @{}; Members = @{}; Relationships = @{}; AccessAssignments = @()
        Calls = @(); Connections = @(); FailAt = ''; WrongIdentity = $false
        SecretCreates = 0; UserCreates = 0; RuntimeCalls = @(); WrongTenant = $false; DuplicateStrengthPage = $false
    }
    foreach ($resource in $inventory.resources) {
        $roles = @(); $scopes = @()
        foreach ($permission in $resource.permissions) {
            $entry = @{
                id = $(if ($permission.id) { $permission.id } else { [guid]::NewGuid().ToString() })
                value = $(if ($permission.value) { $permission.value } else { 'ResolvedFromTenant-' + $permission.id })
                isEnabled = $true; allowedMemberTypes = @('Application')
            }
            if ($permission.type -eq 'Role') { $roles += $entry } else { $scopes += $entry }
        }
        $script:mock.ServicePrincipals[$resource.resourceAppId] = @{
            id = [guid]::NewGuid().ToString(); appId = $resource.resourceAppId
            appRoles = $roles; oauth2PermissionScopes = $scopes; publishedPermissionScopes = $scopes
        }
    }
    $script:mock.Roles = @($inventory.runtimeRoles | ForEach-Object {
        @{ id = [guid]::NewGuid().ToString(); displayName = $_; isBuiltIn = $true }
    })
    $adminGroup = @{ id = [guid]::NewGuid().ToString(); displayName = 'AdminAgents'; securityEnabled = $true; mailEnabled = $false; groupTypes = @() }
    $script:mock.Groups[$adminGroup.id] = $adminGroup
}

function Invoke-CIPPGraph {
    param([string]$Path, [string]$Method = 'GET', $Body)
    $script:mock.Calls += @{ Path = $Path; Method = $Method; Body = $Body; Tenant = $script:mock.CurrentTenant }
    if ($Path -match '^https://graph.microsoft.com/beta/servicePrincipals/([^?]+)\?') {
        return @($script:mock.ServicePrincipals.Values | Where-Object id -EQ $Matches[1])[0]
    }
    if ($Path -match '^https://graph.microsoft.com/v1.0/(.+)$') { $Path = '/' + $Matches[1] }
    if ($Path -eq '/synthetic-page1') { return @{ value = @(@{ id = 'page1' }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/synthetic-page2' } }
    if ($Path -eq '/synthetic-page2') { return @{ value = @(@{ id = 'page2' }) } }
    if ($Path -eq '/synthetic-cycle') { return @{ value = @(); '@odata.nextLink' = '/synthetic-cycle' } }
    if ($Path -eq '/synthetic-invalid-collection') { return @{} }
    if ($Path -match '^/applications\?\$filter=appId eq ''([^'']+)''$') {
        return @{ value = @($script:mock.Applications | Where-Object appId -EQ $Matches[1]) }
    }
    if ($Path -eq "/applications?`$filter=displayName eq 'CIPP-SAM'") {
        return @{ value = @($script:mock.Applications | Where-Object displayName -EQ 'CIPP-SAM') }
    }
    if ($Path -eq '/applications' -and $Method -eq 'POST') {
        $app = @{} + $Body
        $app.id = [guid]::NewGuid().ToString(); $app.appId = [guid]::NewGuid().ToString()
        $script:mock.Applications += $app
        return $app
    }
    if ($Path -match '^/applications/([^/]+)/addPassword$') {
        $script:mock.SecretCreates++
        return @{ secretText = 'synthetic-client-secret'; keyId = [guid]::NewGuid().ToString(); endDateTime = '2030-01-01T00:00:00Z' }
    }
    if ($Path -match '^/applications/([^/]+)$' -and $Method -eq 'PATCH') {
        $app = @($script:mock.Applications | Where-Object id -EQ $Matches[1])[0]
        foreach ($key in $Body.Keys) { $app[$key] = $Body[$key] }
        return
    }
    if ($Path -match '^/servicePrincipals\?\$filter=appId eq ''([^'']+)''$') {
        return @{ value = @($script:mock.ServicePrincipals.Values | Where-Object appId -EQ $Matches[1]) }
    }
    if ($Path -eq '/servicePrincipals' -and $Method -eq 'POST') {
        $sp = @{ id = [guid]::NewGuid().ToString(); appId = $Body.appId; appRoles = @(); oauth2PermissionScopes = @() }
        $script:mock.ServicePrincipals[$Body.appId] = $sp
        return $sp
    }
    if ($Path -match '^/servicePrincipals/([^/]+)/appRoleAssignments$') {
        if ($Method -eq 'POST') { $script:mock.AppRoles += (@{ id = [guid]::NewGuid().ToString() } + $Body); return }
        return @{ value = @($script:mock.AppRoles) }
    }
    if ($Path -like '/oauth2PermissionGrants*') {
        if ($Method -eq 'POST') {
            $grant = @{ id = [guid]::NewGuid().ToString() } + $Body
            $script:mock.Grants += $grant
            return $grant
        }
        if ($Method -eq 'PATCH') {
            $id = $Path.Split('/')[-1]
            $grant = @($script:mock.Grants | Where-Object id -EQ $id)[0]
            $grant.scope = $Body.scope
            return
        }
        return @{ value = @($script:mock.Grants) }
    }
    if ($Path.StartsWith('/users?')) { return @{ value = @($script:mock.Users) } }
    if ($Path -eq '/users' -and $Method -eq 'POST') {
        if ($script:mock.FailAt -eq 'UserCreate') { throw 'Synthetic user creation failure' }
        $script:mock.UserCreates++
        $user = @{ id = [guid]::NewGuid().ToString(); userPrincipalName = $Body.userPrincipalName; accountEnabled = $true; userType = 'Member' }
        $script:mock.Users += $user
        return $user
    }
    if ($Path -like '/users/*') { return $script:mock.Users[0] }
    if ($Path -eq '/roleManagement/directory/roleDefinitions') { return @{ value = $script:mock.Roles } }
    if ($Path -like '/roleManagement/directory/roleAssignments*') {
        if ($Method -eq 'POST') { $script:mock.RoleAssignments += $Body; return }
        return @{ value = $script:mock.RoleAssignments }
    }
    if ($Path -match '^/groups\?\$filter=displayName eq ''([^'']+)''$') {
        return @{ value = @($script:mock.Groups.Values | Where-Object displayName -EQ $Matches[1]) }
    }
    if ($Path -eq '/groups' -and $Method -eq 'POST') {
        $group = @{ id = [guid]::NewGuid().ToString(); groupTypes = @() } + $Body
        $script:mock.Groups[$group.id] = $group
        return $group
    }
    if ($Path -match '^/groups/([^/]+)/members') {
        $id = $Matches[1]
        if ($Method -eq 'POST') {
            $script:mock.Members[$id] = @($script:mock.Members[$id]) + @{ id = $Body.'@odata.id'.Split('/')[-1] }
            return
        }
        return @{ value = @($script:mock.Members[$id] | Where-Object { $_ }) }
    }
    if ($Path -match '^/groups/([^/]+)$') { return $script:mock.Groups[$Matches[1]] }
    if ($Path.StartsWith('/tenantRelationships/delegatedAdminRelationships?')) { return @{ value = @() } }
    if ($Path -eq '/tenantRelationships/delegatedAdminRelationships' -and $Method -eq 'POST') {
        $relationship = @{ id = 'synthetic-relationship'; status = 'created' } + $Body
        $script:mock.Relationships[$relationship.id] = $relationship
        return $relationship
    }
    if ($Path -match '^/tenantRelationships/delegatedAdminRelationships/([^/]+)/requests$') {
        $script:mock.Relationships[$Matches[1]].status = 'approvalPending'
        return @{ id = 'synthetic-request' }
    }
    if ($Path -match '^/tenantRelationships/delegatedAdminRelationships/([^/]+)/accessAssignments$') {
        if ($Method -eq 'POST') {
            $assignment = @{ id = [guid]::NewGuid().ToString(); status = 'active' } + $Body
            $script:mock.AccessAssignments += $assignment
            return $assignment
        }
        return @{ value = @($script:mock.AccessAssignments) }
    }
    if ($Path -match '^/tenantRelationships/delegatedAdminRelationships/([^/]+)$') { return $script:mock.Relationships[$Matches[1]] }
    throw "Unmocked Graph request: $Method $Path"
}

function Get-Module { param($ListAvailable) @{ Name = 'Microsoft.Graph.Authentication' } }
function Import-Module { param($Name, $ErrorAction) }
function Disconnect-MgGraph { param($ErrorAction) }
function Connect-CIPPInitializationAdmin {
    param([string]$Tenant, [switch]$Partner)
    $script:mock.CurrentTenant = $Tenant
    $script:mock.Connections += $Tenant
}
function Read-Host { param($Prompt, [switch]$AsSecureString) if ($AsSecureString) { ConvertTo-SecureString 'synthetic-existing-secret' -AsPlainText -Force } else { 'MFA-READY' } }
function Receive-CIPPOAuthCode { 'synthetic-code' }
function Request-CIPPToken { @{ access_token = 'synthetic-access-token'; refresh_token = 'synthetic-refresh-token' } }
function Get-CIPPRuntimeData {
    param([string]$AccessToken, [string]$Path)
    $script:mock.RuntimeCalls += $Path
    switch -Wildcard ($Path) {
        '/me?*' { return @{ id = $(if ($script:mock.WrongIdentity) { 'wrong-user' } else { $script:mock.Users[0].id }) } }
        '/organization?*' { return @{ value = @(@{ id = $(if ($script:mock.WrongTenant) { 'wrong-tenant' } else { $script:mock.CurrentTenant }) }) } }
        '/identity/conditionalAccess/policies?*' { return @{ value = @() } }
        '/policies/authenticationStrengthPolicies' {
            $result = @{ value = @(
                @{ id = '00000000-0000-0000-0000-000000000002'; displayName = 'Multifactor authentication'; policyType = 'builtIn' },
                @{ id = '00000000-0000-0000-0000-000000000004'; displayName = 'Phishing resistant MFA'; policyType = 'builtIn' }
            ) }
            if ($script:mock.DuplicateStrengthPage) { $result.'@odata.nextLink' = 'https://graph.microsoft.com/v1.0/synthetic-strength-page2' }
            return $result
        }
        'https://graph.microsoft.com/v1.0/synthetic-strength-page2' { return @{ value = @(@{ id = 'custom'; displayName = 'Multifactor authentication'; policyType = 'custom' }) } }
        default { throw "Unmocked runtime path: $Path" }
    }
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('CIPP-initialization-tests-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($testRoot)
function New-TestOptions {
    @{
        TenantId = [guid]'11111111-1111-1111-1111-111111111111'
        CippUrl = [uri]'https://cipp.example.invalid'
        ServiceAccountUpn = 'CIPPService@tenant.example.invalid'
        ExportDirectory = Join-Path $testRoot ([guid]::NewGuid().ToString('N'))
        CreateServiceAccount = $true; SkipTokenAcquisition = $true
    }
}

function Read-TestState {
    param([string]$Path)
    Read-CIPPInitializationExport -Path $Path -Field All -Reveal
}

try {
    $options = New-TestOptions
    Assert-CIPPInitializationOptions $options
    Assert-True ($options.ExportFormat -eq 'Dpapi') 'Encrypted default'
    $bad = New-TestOptions; $bad.ExportDirectory = Join-Path (Split-Path $PSScriptRoot) 'private-export'
    Assert-Throws { Assert-CIPPInitializationOptions $bad } 'outside the repository'
    $bad = New-TestOptions; $bad.GdapAction = 'Invite'
    Assert-Throws { Assert-CIPPInitializationOptions $bad } 'require Partner'
    $bad = New-TestOptions; $bad.HomeTenantId = [guid]'22222222-2222-2222-2222-222222222222'
    Assert-Throws { Assert-CIPPInitializationOptions $bad } 'existing home ApplicationId'
    $bad = New-TestOptions; $bad.CippUrl = [uri]'https://cipp.example.invalid/wrong'
    Assert-Throws { Assert-CIPPInitializationOptions $bad } 'HTTPS origin'
    $bad = New-TestOptions; $bad.ApplicationSecret = ConvertTo-SecureString 'synthetic-input' -AsPlainText -Force
    Assert-Throws { Assert-CIPPInitializationOptions $bad } 'requires an existing ApplicationId'
    & $initializer -TenantId $options.TenantId -CippUrl $options.CippUrl -ServiceAccountUpn $options.ServiceAccountUpn -ExportDirectory $options.ExportDirectory -WhatIf
    Assert-True (-not (Test-Path -LiteralPath $options.ExportDirectory)) 'WhatIf writes no export and needs no Graph SDK/sign-in'

    New-CIPPExportDirectory $options.ExportDirectory
    $synthetic = @{ Credentials = @{ ApplicationSecret = 'synthetic-secret-roundtrip' }; Status = 'Partial' }
    Save-CIPPInitializationState $synthetic $options.ExportDirectory Dpapi
    $encrypted = Join-Path $options.ExportDirectory 'credentials.dpapi'
    $recovered = Read-TestState $encrypted
    Assert-True ($recovered.Credentials.ApplicationSecret -eq 'synthetic-secret-roundtrip') 'DPAPI round-trip'
    Assert-True (-not (Get-Content $encrypted -Raw).Contains('synthetic-secret-roundtrip')) 'No plaintext credential on disk'
    Assert-True (Get-Acl $options.ExportDirectory).AreAccessRulesProtected 'Directory ACL is protected'
    $allowed = @((Get-Acl $options.ExportDirectory).Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value })
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    Assert-True (@($allowed | Where-Object { $_ -notin @($currentSid, 'S-1-5-18') }).Count -eq 0) 'No inherited broad access'
    Assert-Throws { Assert-CIPPExportPath $options.ExportDirectory } 'never overwritten'
    $plain = New-TestOptions; $plain.ExportFormat = 'Plaintext'
    Assert-CIPPInitializationOptions $plain
    New-CIPPExportDirectory $plain.ExportDirectory
    Save-CIPPInitializationState $synthetic $plain.ExportDirectory $plain.ExportFormat
    Assert-True ((Read-TestState (Join-Path $plain.ExportDirectory 'credentials.json')).Status -eq 'Partial') 'Explicit plaintext export'
    Assert-True (-not (Read-CIPPInitializationExport $encrypted).Contains('Credentials')) 'Default recovery omits all credentials'
    Assert-True ((Read-CIPPInitializationExport $encrypted -Field ApplicationSecret) -is [securestring]) 'Selected field is secure by default'
    Assert-Throws { Read-CIPPInitializationExport $encrypted -Field All } 'explicit -Reveal'

    Reset-CIPPMock
    $pages = @(Get-CIPPCollection '/synthetic-page1')
    Assert-True ($pages.Count -eq 2 -and $pages[1].id -eq 'page2') 'Graph pagination follows subsequent pages'
    Assert-Throws { Get-CIPPCollection '/synthetic-cycle' } 'repeated a page'
    Assert-Throws { Get-CIPPCollection '/synthetic-invalid-collection' } 'invalid collection response'
    $resources = @(Resolve-CIPPPermissionResources $inventory Direct)
    Assert-True ($resources.Count -eq 12) 'Only Partner Center resource excluded in direct mode'
    $resource = $resources | Where-Object resourceAppId -EQ $script:CIPPGraphAppId
    $script:mock.Grants += @{ id = 'preserve-grant'; clientId = 'client'; resourceId = $resource.servicePrincipalId; consentType = 'AllPrincipals'; scope = 'Synthetic.UnrelatedScope' }
    $script:mock.Grants += @{ id = 'preserve-user-grant'; clientId = 'client'; resourceId = $resource.servicePrincipalId; consentType = 'Principal'; principalId = 'another-user'; scope = 'User.Read' }
    Grant-CIPPResourcePermissions 'client' $resources
    Assert-True ('Synthetic.UnrelatedScope' -in ($script:mock.Grants[0].scope -split ' ')) 'Consent union preserves extra scope'
    Assert-True ($script:mock.Grants[1].scope -eq 'User.Read') 'Per-user grants untouched'
    $writes = @($script:mock.Calls | Where-Object Method -NE GET).Count
    Grant-CIPPResourcePermissions 'client' $resources
    Assert-True (@($script:mock.Calls | Where-Object Method -NE GET).Count -eq $writes) 'Consent rerun is idempotent'
    $script:mock.ServicePrincipals[$script:CIPPGraphAppId].appRoles = @()
    Assert-Throws { Resolve-CIPPPermissionResources $inventory Direct } 'Required permission unavailable'
    Reset-CIPPMock
    $scope = @($graph.permissions | Where-Object type -EQ Scope)[0]
    $script:mock.ServicePrincipals[$script:CIPPGraphAppId].oauth2PermissionScopes = @(
        $script:mock.ServicePrincipals[$script:CIPPGraphAppId].oauth2PermissionScopes | Where-Object id -NE $scope.id
    )
    $resolvedPublished = @(Resolve-CIPPPermissionResources $inventory Direct)
    Assert-True ($scope.id -in $resolvedPublished.permissions.id) 'Published first-party GUID scope resolved through CIPP-compatible beta catalog fallback'
    Reset-CIPPMock
    $script:mock.ServicePrincipals[$script:CIPPGraphAppId].appRoles[0].isEnabled = $false
    Assert-Throws { Resolve-CIPPPermissionResources $inventory Direct } 'Disabled or mismatched'

    Reset-CIPPMock
    $options = New-TestOptions; Assert-CIPPInitializationOptions $options
    $result = Invoke-CIPPInitialization $options $inventory
    $state = Read-TestState (Join-Path $options.ExportDirectory 'credentials.dpapi')
    Assert-True ($result.Status -eq 'PreparedAwaitingServiceAccountAuthentication') 'No connection success before service authentication'
    Assert-True ($state.GrantVerification -eq 'Verified' -and $state.Credentials.ApplicationSecret -eq 'synthetic-client-secret') 'New SAM consent and secret captured'
    Assert-True ($state.ServiceAccountId -and $state.Credentials.ServiceAccountInitialPassword -and $state.SecretKeyId) 'New identity IDs/password/key ID captured'
    Assert-True ($state.ResourceServicePrincipals.Count -eq 12 -and $script:mock.RoleAssignments.Count -eq 15) 'Resource IDs and direct runtime roles'
    Assert-True (-not ($result | ConvertTo-Json -Depth 10).Contains('synthetic-client-secret')) 'No secret in ordinary output'
    Assert-True (@($script:mock.Calls | Where-Object { $_.Method -ne 'GET' -and $_.Path -match 'conditionalAccess|authenticationStrength' }).Count -eq 0) 'No CA/strength mutations'

    $reuse = New-TestOptions; $reuse.ApplicationId = [guid]$state.ApplicationId; $reuse.CreateServiceAccount = $false
    $reuse.SkipTokenAcquisition = $false; Assert-CIPPInitializationOptions $reuse
    $result = Invoke-CIPPInitialization $reuse $inventory -WarningAction SilentlyContinue
    $verified = Read-TestState (Join-Path $reuse.ExportDirectory 'credentials.dpapi')
    Assert-True ($script:mock.SecretCreates -eq 1 -and $script:mock.UserCreates -eq 1) 'Explicit identity reuse does not rotate secrets/passwords'
    Assert-True ($verified.Credentials.RefreshToken -eq 'synthetic-refresh-token' -and $verified.RuntimeVerification -eq 'IdentityAndCAReadVerified') 'Verified runtime refresh token exported'
    Assert-True ($verified.ConsoleFields.RefreshToken -eq 'synthetic-refresh-token') 'Primary console fields identified'
    $metadata = Read-CIPPInitializationExport (Join-Path $reuse.ExportDirectory 'credentials.dpapi')
    Assert-True (-not ($metadata | ConvertTo-Json -Depth 20).Contains('synthetic-refresh-token')) 'Metadata redacts duplicated console secrets'
    $script:mock.WrongTenant = $true
    Assert-Throws { Assert-CIPPRuntimeIdentity 'synthetic' $verified.TenantId $verified.ServiceAccountId } 'wrong service account or tenant'
    $script:mock.WrongTenant = $false
    $script:mock.DuplicateStrengthPage = $true
    Assert-Throws { Assert-CIPPStrengths 'synthetic' } 'missing, ambiguous, or incorrectly mapped'
    $script:mock.DuplicateStrengthPage = $false
    $rotate = New-TestOptions; $rotate.ApplicationId = [guid]$state.ApplicationId; $rotate.CreateServiceAccount = $false; $rotate.NewClientSecret = $true
    Assert-CIPPInitializationOptions $rotate
    $null = Invoke-CIPPInitialization $rotate $inventory
    Assert-True ($script:mock.SecretCreates -eq 2) 'Explicit secret rotation supported'

    $additional = New-TestOptions
    $additional.HomeTenantId = [guid]$state.HomeTenantId
    $additional.TenantId = [guid]'22222222-2222-2222-2222-222222222222'
    $additional.ApplicationId = [guid]$state.ApplicationId
    $additional.CreateServiceAccount = $false
    Assert-CIPPInitializationOptions $additional
    $before = $script:mock.Calls.Count
    $null = Invoke-CIPPInitialization $additional $inventory
    $extraState = Read-TestState (Join-Path $additional.ExportDirectory 'credentials.dpapi')
    $newCalls = @($script:mock.Calls | Select-Object -Skip $before)
    Assert-True (@($newCalls | Where-Object { $_.Method -ne 'GET' -and $_.Path -like '/applications*' }).Count -eq 0) 'Additional direct tenant does not mutate home app'
    Assert-True (-not $extraState.ConsoleFields.ContainsKey('TenantID') -and $extraState.ConsoleFields.instruction.Contains('Never overwrite')) 'Additional direct tenant cannot replace primary credentials'

    $script:mock.WrongIdentity = $true
    $wrong = New-TestOptions; $wrong.ApplicationId = [guid]$state.ApplicationId; $wrong.CreateServiceAccount = $false; $wrong.SkipTokenAcquisition = $false
    Assert-CIPPInitializationOptions $wrong
    Assert-Throws { Invoke-CIPPInitialization $wrong $inventory -WarningAction SilentlyContinue } 'wrong service account or tenant'
    $failedToken = Read-TestState (Join-Path $wrong.ExportDirectory 'credentials.dpapi')
    Assert-True ($failedToken.Credentials.UnverifiedRefreshToken -and -not $failedToken.ConsoleFields.RefreshToken) 'Mismatched token retained for cleanup but not offered as verified console credential'

    Reset-CIPPMock
    $script:mock.FailAt = 'UserCreate'
    $failure = New-TestOptions; Assert-CIPPInitializationOptions $failure
    Assert-Throws { Invoke-CIPPInitialization $failure $inventory } 'Synthetic user creation failure'
    $partial = Read-TestState (Join-Path $failure.ExportDirectory 'credentials.dpapi')
    Assert-True ($partial.Status -eq 'Failed' -and $partial.Credentials.ApplicationSecret -and $partial.ApplicationObjectId) 'Partial failure retains created secret and app IDs'
    Assert-True ([bool]$partial.Credentials.ServiceAccountInitialPassword) 'Proposed password checkpointed before creation'

    Reset-CIPPMock
    $partner = New-TestOptions; $partner.Mode = 'Partner'
    Assert-CIPPInitializationOptions $partner
    $null = Invoke-CIPPInitialization $partner $inventory
    $partnerState = Read-TestState (Join-Path $partner.ExportDirectory 'credentials.dpapi')
    Assert-True ($partnerState.GdapGroups.Count -eq 15 -and $script:mock.RoleAssignments.Count -eq 0) 'Partner uses role groups, not local privileged runtime assignments'
    Assert-True (-not @($script:mock.Calls | Where-Object Path -Like '/tenantRelationships/*').Count) 'Preparation creates no invitation'
    $gdap = @{ Mode = 'Partner'; GdapAction = 'Invite'; CustomerTenantId = '33333333-3333-3333-3333-333333333333'; RelationshipName = 'Synthetic customer'; RelationshipDurationDays = 30; ApprovalWaitSeconds = 0 }
    Initialize-CIPPGdap $gdap $partnerState $script:mock.Roles {}
    Assert-True ($partnerState.GdapStatus -eq 'AwaitingCustomerApproval' -and $partnerState.RelationshipId -and $partnerState.CustomerApprovalUrl) 'Invitation exported without self-approval'
    Assert-True (@($script:mock.Calls | Where-Object { $_.Body.action -eq 'approve' }).Count -eq 0) 'Customer approval never automated'
    $gdap.GdapAction = 'Map'; $gdap.RelationshipId = $partnerState.RelationshipId
    $script:mock.Relationships[$gdap.RelationshipId].status = 'active'
    Initialize-CIPPGdap $gdap $partnerState $script:mock.Roles {}
    Assert-True ($partnerState.GdapStatus -eq 'MappingsActive' -and $partnerState.AccessAssignments.Count -eq 15) 'Active relationship maps approved roles'
    $before = @($script:mock.Calls | Where-Object Method -EQ POST).Count
    Initialize-CIPPGdap $gdap $partnerState $script:mock.Roles {}
    Assert-True (@($script:mock.Calls | Where-Object Method -EQ POST).Count -eq $before) 'GDAP mappings/membership rerun is idempotent'
    $gdap.CustomerTenantId = '44444444-4444-4444-4444-444444444444'
    $before = @($script:mock.Calls | Where-Object Method -EQ POST).Count
    Assert-Throws { Initialize-CIPPGdap $gdap $partnerState $script:mock.Roles {} } 'customer mismatch'
    Assert-True (@($script:mock.Calls | Where-Object Method -EQ POST).Count -eq $before) 'Wrong-customer Map rejected before group/membership writes'
    $gdap.CustomerTenantId = '33333333-3333-3333-3333-333333333333'
    $script:mock.Relationships[$gdap.RelationshipId].accessDetails.unifiedRoles = @()
    Assert-Throws { Initialize-CIPPGdap $gdap $partnerState $script:mock.Roles {} } 'does not contain all requested roles'
} finally {
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
Write-Output "PASS: $passed initialization checks. All tenant/OAuth boundaries mocked; no tenant access performed."
