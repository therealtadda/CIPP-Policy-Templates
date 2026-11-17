#requires -Version 7.0
<#
.SYNOPSIS
Prepares CIPP SAM identities, consent, and optional GDAP relationships.
.DESCRIPTION
Tenant-changing, interactive tool. See docs\tenant-initialization.md before use.
Exports credentials privately; does not install CIPP or deploy CA policies.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateSet('Direct', 'Partner')][string]$Mode = 'Direct',
    [guid]$TenantId,
    [guid]$HomeTenantId,
    [uri]$CippUrl,
    [string]$ServiceAccountUpn,
    [switch]$CreateServiceAccount,
    [guid]$ApplicationId,
    [securestring]$ApplicationSecret,
    [switch]$NewClientSecret,
    [ValidateRange(1, 180)][int]$SecretLifetimeDays = 90,
    [string]$ExportDirectory,
    [ValidateSet('Dpapi', 'Plaintext')][string]$ExportFormat = 'Dpapi',
    [switch]$SkipTokenAcquisition,
    [ValidateRange(1024, 65535)][int]$LoopbackPort = 8400,
    [ValidateRange(30, 1800)][int]$AuthenticationTimeoutSeconds = 600,
    [ValidateSet('Prepare', 'Invite', 'Map')][string]$GdapAction = 'Prepare',
    [guid]$CustomerTenantId,
    [string]$RelationshipName,
    [string]$RelationshipId,
    [ValidateRange(1, 730)][int]$RelationshipDurationDays = 730,
    [switch]$AutoExtend,
    [ValidateRange(0, 3600)][int]$ApprovalWaitSeconds = 0,
    [string]$GdapGroupMapPath,
    [guid]$AdminAgentsGroupId
)

$ErrorActionPreference = 'Stop'
$script:CIPPGraphRoot = 'https://graph.microsoft.com/v1.0'
$script:CIPPGraphAppId = '00000003-0000-0000-c000-000000000000'

function Read-CIPPInitializationInventory {
    $path = Join-Path $PSScriptRoot '..\config\CIPPInitializationPermissions.json'
    $inventory = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -AsHashtable -Depth 30
    if ($inventory.sourceRevision -notmatch '^[a-f0-9]{40}$') { throw 'Permission inventory must identify a pinned source revision.' }
    $graph = @($inventory.resources | Where-Object resourceAppId -EQ $script:CIPPGraphAppId)
    if ($graph.Count -ne 1) { throw 'Permission inventory must contain exactly one Microsoft Graph resource.' }
    foreach ($name in $inventory.requiredGraphCapabilities) {
        foreach ($type in 'Role', 'Scope') {
            if (@($graph[0].permissions | Where-Object { $_.value -eq $name -and $_.type -eq $type }).Count -ne 1) {
                throw "Permission inventory lacks $type $name."
            }
        }
    }
    return $inventory
}

function Test-CIPPChildPath {
    param([string]$Path, [string]$Parent)
    $p = [IO.Path]::GetFullPath($Parent).TrimEnd('\', '/')
    return $Path.Equals($p, [StringComparison]::OrdinalIgnoreCase) -or
        $Path.StartsWith($p + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-CIPPExportPath {
    param([string]$Directory)
    if (-not $IsWindows) { throw 'Protected export currently requires Windows. Encryption will not be silently downgraded.' }
    if (-not $Directory -or -not [IO.Path]::IsPathFullyQualified($Directory) -or $Directory.StartsWith('\\')) {
        throw 'ExportDirectory must be an absolute local path, not a network share.'
    }
    $full = [IO.Path]::GetFullPath($Directory).TrimEnd('\')
    if ($full -notmatch '^[a-zA-Z]:\\' -or $full.Substring(2).Contains(':')) { throw 'Invalid export path.' }
    if (Test-CIPPChildPath $full (Split-Path $PSScriptRoot)) { throw 'Credential exports must be outside the repository.' }
    foreach ($syncRoot in @($env:OneDrive, $env:OneDriveCommercial, $env:OneDriveConsumer) | Where-Object { $_ }) {
        if (Test-CIPPChildPath $full $syncRoot) { throw 'Credential exports must not be in OneDrive.' }
    }
    if (Test-Path -LiteralPath $full) { throw 'ExportDirectory must be a new directory; existing exports are never overwritten.' }
    $parent = Split-Path $full
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw 'The export parent directory must already exist.' }
    $ancestor = $parent
    while ($ancestor) {
        if ((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Export paths must not traverse junctions, symbolic links, or cloud placeholders.'
        }
        if (Test-Path -LiteralPath (Join-Path $ancestor '.git')) { throw 'Credential exports must not be inside any Git checkout.' }
        $ancestor = Split-Path $ancestor
    }
    return $full
}

function New-CIPPExportDirectory {
    param([string]$Directory)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($identity)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($identity, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    $info = [IO.DirectoryInfo]::new($Directory)
    [IO.FileSystemAclExtensions]::Create($info, $acl)
    $actual = Get-Acl -LiteralPath $Directory
    if (-not $actual.AreAccessRulesProtected) { throw 'Could not protect the export directory ACL.' }
}

function Save-CIPPInitializationState {
    param([System.Collections.IDictionary]$State, [string]$Directory, [string]$Format)
    $json = ConvertTo-Json -InputObject $State -Depth 40
    $file = if ($Format -eq 'Dpapi') { 'credentials.dpapi' } else { 'credentials.json' }
    $content = if ($Format -eq 'Dpapi') {
        ConvertFrom-SecureString (ConvertTo-SecureString $json -AsPlainText -Force)
    } else { $json }
    $path = Join-Path $Directory $file
    $temporary = Join-Path $Directory 'checkpoint.tmp'
    [IO.File]::WriteAllText($temporary, $content, [Text.UTF8Encoding]::new($false))
    [IO.File]::Move($temporary, $path, $true)
}

function Read-CIPPInitializationExport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('Metadata', 'ApplicationSecret', 'RefreshToken', 'ServiceAccountInitialPassword', 'UnverifiedRefreshToken', 'All')]
        [string]$Field = 'Metadata',
        [switch]$Reveal
    )
    $content = Get-Content -LiteralPath $Path -Raw
    if ([IO.Path]::GetExtension($Path) -eq '.dpapi') {
        $content = [Net.NetworkCredential]::new('', (ConvertTo-SecureString $content)).Password
    } elseif ([IO.Path]::GetExtension($Path) -ne '.json') {
        throw 'Expected a .dpapi or explicit plaintext .json export.'
    }
    $state = $content | ConvertFrom-Json -AsHashtable -Depth 40
    if ($Field -eq 'Metadata') {
        $null = $state.Remove('Credentials')
        if ($state.ConsoleFields) {
            $null = $state.ConsoleFields.Remove('ApplicationSecret')
            $null = $state.ConsoleFields.Remove('RefreshToken')
        }
        return $state
    }
    if ($Field -eq 'All') {
        if (-not $Reveal) { throw 'Reading all credential fields requires explicit -Reveal. Prefer a single secure field.' }
        return $state
    }
    $value = $state.Credentials[$Field]
    if (-not $value) { throw "No $Field is present in this export." }
    if ($Reveal) { return $value }
    ConvertTo-SecureString $value -AsPlainText -Force
}

function Get-CIPPHttpStatus {
    param($Record)
    if ($Record.Exception.Response.StatusCode) { return [int]$Record.Exception.Response.StatusCode }
    if ($Record.Exception.ResponseStatusCode) { return [int]$Record.Exception.ResponseStatusCode }
    return 0
}

function Get-CIPPGraphUri {
    param([string]$Path)
    $uri = if ($Path.StartsWith('/')) { $script:CIPPGraphRoot + $Path } else { $Path }
    $parsed = [uri]$uri
    if ($parsed.Scheme -ne 'https' -or $parsed.Host -ne 'graph.microsoft.com' -or -not $parsed.IsDefaultPort -or $parsed.UserInfo) {
        throw 'Refusing a Graph request to an unexpected origin.'
    }
    return $parsed.AbsoluteUri
}

function Invoke-CIPPGraph {
    param([string]$Path, [ValidateSet('GET', 'POST', 'PATCH')][string]$Method = 'GET', $Body)
    $uri = Get-CIPPGraphUri $Path
    $parsed = [uri]$uri
    for ($attempt = 0; $attempt -lt 4; $attempt++) {
        try {
            $arguments = @{ Uri = $uri; Method = $Method; OutputType = 'Hashtable'; ErrorAction = 'Stop'; Verbose = $false; Debug = $false }
            if ($null -ne $Body) { $arguments.Body = ConvertTo-Json -InputObject $Body -Depth 40 -Compress; $arguments.ContentType = 'application/json' }
            return Invoke-MgGraphRequest @arguments
        } catch {
            $status = Get-CIPPHttpStatus $_
            # Retrying ambiguous POST failures can create duplicate users, secrets, or relationships.
            if ($attempt -lt 3 -and $Method -in @('GET', 'PATCH') -and $status -in @(429, 503, 504)) {
                Start-Sleep -Seconds ([math]::Pow(2, $attempt + 1))
                continue
            }
            throw "Graph $Method $($parsed.AbsolutePath) failed (HTTP $status). Check administrator privileges, resource availability, and tenant policy; no request body is logged."
        }
    }
}

function Get-CIPPCollection {
    param([string]$Path)
    $seen = [Collections.Generic.HashSet[string]]::new()
    do {
        if (-not $seen.Add($Path)) { throw 'Graph pagination repeated a page.' }
        $result = Invoke-CIPPGraph $Path
        if ($result -isnot [System.Collections.IDictionary] -or -not $result.Contains('value') -or $null -eq $result.value) {
            throw 'Graph returned an invalid collection response; refusing to infer that objects are absent.'
        }
        foreach ($item in $result.value) { $item }
        $Path = $result.'@odata.nextLink'
    } while ($Path)
}

function Connect-CIPPInitializationAdmin {
    param([string]$Tenant, [switch]$Partner)
    $scopes = @('Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All',
        'DelegatedPermissionGrant.ReadWrite.All', 'User.ReadWrite.All', 'Group.ReadWrite.All',
        'RoleManagement.ReadWrite.Directory', 'Organization.Read.All')
    if ($Partner) { $scopes += 'DelegatedAdminRelationship.ReadWrite.All' }
    $null = Connect-MgGraph -TenantId $Tenant -Scopes $scopes -ContextScope Process -NoWelcome -ErrorAction Stop
    $context = Get-MgContext
    if ($context.TenantId -ne $Tenant -or $context.AuthType -ne 'Delegated') {
        throw 'Administrator connection has the wrong tenant or authentication type.'
    }
}

function Get-CIPPUniqueObject {
    param([object[]]$Objects, [string]$Description)
    if ($Objects.Count -gt 1) { throw "Ambiguous $Description; select an immutable ID." }
    if ($Objects.Count -eq 1) { return $Objects[0] }
}

function Get-CIPPServicePrincipal {
    param([string]$AppId)
    $sp = Get-CIPPUniqueObject @(Get-CIPPCollection "/servicePrincipals?`$filter=appId eq '$AppId'") "service principal $AppId"
    if (-not $sp) { $sp = Invoke-CIPPGraph '/servicePrincipals' POST @{ appId = $AppId } }
    if (-not $sp.id) { throw "Service principal $AppId has no object ID." }
    return $sp
}

function Resolve-CIPPPermissionResources {
    param($Inventory, [string]$Mode, [scriptblock]$RecordServicePrincipal)
    foreach ($resource in $Inventory.resources) {
        if ($resource.partnerOnly -and $Mode -ne 'Partner') { continue }
        $sp = Get-CIPPServicePrincipal $resource.resourceAppId
        if ($RecordServicePrincipal) { & $RecordServicePrincipal $resource.resourceAppId $sp.id }
        $published = $null
        $permissions = foreach ($permission in $resource.permissions) {
            if ($permission.type -notin @('Role', 'Scope')) { throw 'Unknown permission type in inventory.' }
            $catalog = if ($permission.type -eq 'Role') { @($sp.appRoles) } else { @($sp.oauth2PermissionScopes) }
            $entry = if ($permission.id) {
                Get-CIPPUniqueObject @($catalog | Where-Object id -EQ $permission.id) "permission $($permission.id)"
            } else {
                Get-CIPPUniqueObject @($catalog | Where-Object value -EQ $permission.value) "scope $($permission.value)"
            }
            if (-not $entry -and $permission.id -and $permission.type -eq 'Scope') {
                if (-not $published) {
                    $published = Invoke-CIPPGraph "https://graph.microsoft.com/beta/servicePrincipals/$($sp.id)?`$select=publishedPermissionScopes"
                }
                $entry = Get-CIPPUniqueObject @($published.publishedPermissionScopes | Where-Object id -EQ $permission.id) "published scope $($permission.id)"
            }
            if ($entry) {
                if (-not $entry.isEnabled -or ($permission.value -and $entry.value -cne $permission.value)) {
                    throw "Disabled or mismatched permission $($resource.resourceAppId) / $($permission.id)."
                }
                if ($permission.type -eq 'Role' -and 'Application' -notin $entry.allowedMemberTypes) {
                    throw "Permission $($entry.value) is not an application role."
                }
                @{ id = $entry.id; type = $permission.type; value = $entry.value }
            } elseif (-not $permission.id -and $permission.type -eq 'Scope' -and $permission.source -eq 'AdditionalPermissions.json') {
                # CIPP's additional named scopes include unpublished first-party scopes.
                @{ id = $null; type = 'Scope'; value = $permission.value }
            } else {
                throw "Required permission unavailable: $($resource.resourceAppId) / $($permission.id). No reduced baseline will be granted."
            }
        }
        @{ resourceAppId = $resource.resourceAppId; servicePrincipalId = $sp.id; permissions = @($permissions) }
    }
}

function Merge-CIPPRequiredResourceAccess {
    param([object[]]$Existing, [object[]]$Resources)
    $merged = @{}
    foreach ($resource in $Existing | Where-Object { $_ }) {
        $merged[$resource.resourceAppId] = @($resource.resourceAccess)
    }
    foreach ($resource in $Resources) {
        $access = @($merged[$resource.resourceAppId] | Where-Object { $_ })
        foreach ($p in $resource.permissions | Where-Object id) {
            if (-not @($access | Where-Object { $_.id -eq $p.id -and $_.type -eq $p.type }).Count) {
                $access += @{ id = $p.id; type = $p.type }
            }
        }
        if ($access.Count) { $merged[$resource.resourceAppId] = $access }
    }
    foreach ($key in $merged.Keys | Sort-Object) { @{ resourceAppId = $key; resourceAccess = @($merged[$key]) } }
}

function Grant-CIPPResourcePermissions {
    param([string]$ClientServicePrincipalId, [object[]]$Resources)
    foreach ($resource in $Resources) {
        $roles = @($resource.permissions | Where-Object type -EQ 'Role')
        $existing = @(Get-CIPPCollection "/servicePrincipals/$ClientServicePrincipalId/appRoleAssignments")
        foreach ($role in $roles) {
            if (-not @($existing | Where-Object { $_.resourceId -eq $resource.servicePrincipalId -and $_.appRoleId -eq $role.id }).Count) {
                $null = Invoke-CIPPGraph "/servicePrincipals/$ClientServicePrincipalId/appRoleAssignments" POST @{
                    principalId = $ClientServicePrincipalId; resourceId = $resource.servicePrincipalId; appRoleId = $role.id
                }
            }
        }
        $scopes = @($resource.permissions | Where-Object type -EQ 'Scope' | ForEach-Object value)
        if ($scopes.Count) {
            $grants = @(Get-CIPPCollection "/oauth2PermissionGrants?`$filter=clientId eq '$ClientServicePrincipalId'")
            $grant = Get-CIPPUniqueObject @($grants | Where-Object {
                $_.resourceId -eq $resource.servicePrincipalId -and $_.consentType -eq 'AllPrincipals'
            }) "organization-wide grant for $($resource.resourceAppId)"
            $current = @($grant.scope -split ' ' | Where-Object { $_ })
            $union = @($current + $scopes | Sort-Object -Unique)
            if ($grant) {
                if (@($scopes | Where-Object { $_ -notin $current }).Count) {
                    $null = Invoke-CIPPGraph "/oauth2PermissionGrants/$($grant.id)" PATCH @{ scope = $union -join ' ' }
                }
            } else {
                $null = Invoke-CIPPGraph '/oauth2PermissionGrants' POST @{
                    clientId = $ClientServicePrincipalId; resourceId = $resource.servicePrincipalId
                    consentType = 'AllPrincipals'; scope = $union -join ' '
                }
            }
        }
    }
    foreach ($resource in $Resources) {
        $assignments = @(Get-CIPPCollection "/servicePrincipals/$ClientServicePrincipalId/appRoleAssignments")
        $grants = @(Get-CIPPCollection "/oauth2PermissionGrants?`$filter=clientId eq '$ClientServicePrincipalId'")
        $grantedScopes = @($grants | Where-Object {
            $_.resourceId -eq $resource.servicePrincipalId -and $_.consentType -eq 'AllPrincipals'
        } | ForEach-Object { $_.scope -split ' ' })
        foreach ($p in $resource.permissions) {
            $found = if ($p.type -eq 'Role') {
                @($assignments | Where-Object { $_.resourceId -eq $resource.servicePrincipalId -and $_.appRoleId -eq $p.id }).Count -gt 0
            } else { $p.value -in $grantedScopes }
            if (-not $found) { throw "Consent verification failed for $($resource.resourceAppId) / $($p.value)." }
        }
    }
}

function Get-CIPPRuntimeRoles {
    param([string[]]$Names)
    $definitions = @(Get-CIPPCollection '/roleManagement/directory/roleDefinitions')
    foreach ($name in $Names) {
        $role = Get-CIPPUniqueObject @($definitions | Where-Object { $_.displayName -eq $name -and $_.isBuiltIn }) "built-in role $name"
        if (-not $role) { throw "Missing built-in directory role $name." }
        $role
    }
}

function Add-CIPPGroupMember {
    param([string]$GroupId, [string]$UserId)
    $members = @(Get-CIPPCollection "/groups/$GroupId/members?`$select=id")
    if ($UserId -notin $members.id) {
        $null = Invoke-CIPPGraph "/groups/$GroupId/members/`$ref" POST @{
            '@odata.id' = "$script:CIPPGraphRoot/directoryObjects/$UserId"
        }
    }
}

function Set-CIPPDirectUserRoles {
    param([string]$UserId, [object[]]$Roles)
    $existing = @(Get-CIPPCollection "/roleManagement/directory/roleAssignments?`$filter=principalId eq '$UserId'")
    foreach ($role in $Roles) {
        if (-not @($existing | Where-Object { $_.roleDefinitionId -eq $role.id -and $_.directoryScopeId -eq '/' }).Count) {
            $null = Invoke-CIPPGraph '/roleManagement/directory/roleAssignments' POST @{
                principalId = $UserId; roleDefinitionId = $role.id; directoryScopeId = '/'
            }
        }
    }
}

function New-CIPPRandomValue {
    param([int]$Bytes = 32)
    $buffer = [byte[]]::new($Bytes)
    [Security.Cryptography.RandomNumberGenerator]::Fill($buffer)
    [Convert]::ToBase64String($buffer).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertTo-CIPPQuery {
    param([System.Collections.IDictionary]$Values)
    (@($Values.Keys | Sort-Object | ForEach-Object {
        [uri]::EscapeDataString($_) + '=' + [uri]::EscapeDataString([string]$Values[$_])
    })) -join '&'
}

function Read-CIPPOAuthCallback {
    param([string]$Request, [string]$State, [int]$Port)
    if ($Request -notmatch '^GET (/\?[^ ]{1,16000}) HTTP/1\.[01]$') { throw 'Invalid OAuth callback request.' }
    $callback = [uri]("http://localhost:$Port" + $Matches[1])
    $values = @{}
    foreach ($part in $callback.Query.TrimStart('?') -split '&') {
        $pair = $part -split '=', 2
        $key = [uri]::UnescapeDataString($pair[0])
        if ($values.ContainsKey($key)) { throw 'Duplicate OAuth callback parameter.' }
        $values[$key] = if ($pair.Count -eq 2) { [uri]::UnescapeDataString($pair[1].Replace('+', ' ')) } else { '' }
    }
    if ($values.state -cne $State) { throw 'OAuth callback state mismatch.' }
    if ($values.error -or -not $values.code) { throw 'Service-account authorization was refused; check MFA and sign-in policy.' }
    return $values.code
}

function Receive-CIPPOAuthCode {
    param([string]$Tenant, [string]$ClientId, [string]$Upn, [string]$Challenge, [string]$State, [int]$Port, [int]$Timeout)
    $redirect = "http://localhost:$Port/"
    $query = ConvertTo-CIPPQuery @{
        client_id = $ClientId; response_type = 'code'; redirect_uri = $redirect; response_mode = 'query'
        scope = 'https://graph.microsoft.com/.default offline_access'; state = $State
        code_challenge = $Challenge; code_challenge_method = 'S256'; prompt = 'login'; login_hint = $Upn
    }
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
    $client = $null
    try {
        $listener.Start()
        $null = Start-Process "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/authorize?$query"
        $deadline = [datetime]::UtcNow.AddSeconds($Timeout)
        while (-not $listener.Pending()) {
            if ([datetime]::UtcNow -gt $deadline) { throw 'Service-account browser authentication timed out.' }
            Start-Sleep -Milliseconds 200
        }
        $client = $listener.AcceptTcpClient()
        $client.ReceiveTimeout = 5000
        $client.SendTimeout = 5000
        $stream = $client.GetStream()
        $line = [Text.StringBuilder]::new()
        do {
            $remaining = ($deadline - [datetime]::UtcNow).TotalMilliseconds
            if ($remaining -le 0) { throw 'Service-account browser authentication timed out.' }
            $client.ReceiveTimeout = [int][math]::Max(1, [math]::Min(5000, $remaining))
            $byte = $stream.ReadByte()
            if ($byte -lt 0 -or $line.Length -ge 16024) { throw 'Invalid or oversized OAuth callback request.' }
            $null = $line.Append([char]$byte)
        } while ($byte -ne 10)
        $request = $line.ToString().TrimEnd("`r", "`n")
        $code = Read-CIPPOAuthCallback $request $State $Port
        $message = 'Authentication received. Return to PowerShell. CIPP onboarding is not yet complete.'
        $response = "HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`nCache-Control: no-store`r`nContent-Length: $($message.Length)`r`nConnection: close`r`n`r`n$message"
        $bytes = [Text.Encoding]::ASCII.GetBytes($response)
        $stream.Write($bytes, 0, $bytes.Length)
        return $code
    } finally {
        if ($client) { $client.Dispose() }
        $listener.Stop()
    }
}

function Request-CIPPToken {
    param([string]$Tenant, [System.Collections.IDictionary]$Form)
    try {
        Invoke-RestMethod "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token" -Method POST `
            -Body $Form -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 60 -Verbose:$false -Debug:$false -ErrorAction Stop
    } catch { throw 'OAuth token exchange failed. Check client credential, callback registration, consent, and sign-in policy. Token request/response is not logged.' }
}

function Get-CIPPRuntimeData {
    param([string]$AccessToken, [string]$Path)
    $uri = Get-CIPPGraphUri $Path
    try {
        Invoke-RestMethod $uri -Headers @{ Authorization = "Bearer $AccessToken" } `
            -TimeoutSec 60 -Verbose:$false -Debug:$false -ErrorAction Stop
    } catch { throw "Runtime Graph verification failed at $($Path.Split('?')[0]); check consent, service-user roles, licensing, and propagation." }
}

function Get-CIPPRuntimeCollection {
    param([string]$AccessToken, [string]$Path)
    $seen = [Collections.Generic.HashSet[string]]::new()
    do {
        if (-not $seen.Add($Path)) { throw 'Runtime Graph pagination repeated a page.' }
        $result = Get-CIPPRuntimeData $AccessToken $Path
        $hasValue = if ($result -is [System.Collections.IDictionary]) { $result.Contains('value') } else { $null -ne $result.PSObject.Properties['value'] }
        if (-not $hasValue -or $null -eq $result.value) { throw 'Runtime Graph returned an invalid collection response.' }
        foreach ($item in $result.value) { $item }
        $Path = $result.'@odata.nextLink'
    } while ($Path)
}

function Assert-CIPPRuntimeIdentity {
    param([string]$AccessToken, [string]$Tenant, [string]$UserId)
    $me = Get-CIPPRuntimeData $AccessToken '/me?$select=id,userPrincipalName'
    $organization = Get-CIPPRuntimeData $AccessToken '/organization?$select=id'
    if ($me.id -ne $UserId -or @($organization.value).Count -ne 1 -or $organization.value[0].id -ne $Tenant) {
        throw 'Runtime token belongs to the wrong service account or tenant.'
    }
}

function Assert-CIPPStrengths {
    param([string]$AccessToken)
    $null = Get-CIPPRuntimeData $AccessToken '/identity/conditionalAccess/policies?$top=1'
    $expected = @{
        '00000000-0000-0000-0000-000000000002' = 'Multifactor authentication'
        '00000000-0000-0000-0000-000000000004' = 'Phishing resistant MFA'
    }
    $strengths = @(Get-CIPPRuntimeCollection $AccessToken '/policies/authenticationStrengthPolicies')
    foreach ($id in $expected.Keys) {
        $byName = @($strengths | Where-Object displayName -EQ $expected[$id])
        if ($byName.Count -ne 1 -or $byName[0].id -ne $id -or $byName[0].policyType -ne 'builtIn') {
            throw "Built-in strength missing, ambiguous, or incorrectly mapped: $($expected[$id]). No custom strength was created."
        }
    }
}

function Get-CIPPConsoleFields {
    param($State)
    if ($State.TenantId -ne $State.HomeTenantId) {
        return @{ instruction = 'Additional direct tenant: use CIPP Add Direct Tenant with this service account. Never overwrite the primary SAM connection.' }
    }
    return @{
        TenantID = $State.HomeTenantId
        ApplicationID = $State.ApplicationId
        ApplicationSecret = $State.Credentials.ApplicationSecret
        RefreshToken = $State.Credentials.RefreshToken
    }
}

function Assert-CIPPInitializationOptions {
    param([System.Collections.IDictionary]$Options)
    foreach ($key in 'TenantId', 'CippUrl', 'ServiceAccountUpn', 'ExportDirectory') {
        if (-not $Options[$key] -or [string]$Options[$key] -eq [string][guid]::Empty) { throw "Required parameter: $key." }
    }
    if (-not $Options.HomeTenantId -or [string]$Options.HomeTenantId -eq [string][guid]::Empty) { $Options.HomeTenantId = $Options.TenantId }
    if (-not $Options.Mode) { $Options.Mode = 'Direct' }
    if (-not $Options.ExportFormat) { $Options.ExportFormat = 'Dpapi' }
    if (-not $Options.GdapAction) { $Options.GdapAction = 'Prepare' }
    if (-not $Options.LoopbackPort) { $Options.LoopbackPort = 8400 }
    if (-not $Options.AuthenticationTimeoutSeconds) { $Options.AuthenticationTimeoutSeconds = 600 }
    if (-not $Options.SecretLifetimeDays) { $Options.SecretLifetimeDays = 90 }
    if (-not $Options.RelationshipDurationDays) { $Options.RelationshipDurationDays = 730 }
    $url = [uri]$Options.CippUrl
    if ($url.Scheme -ne 'https' -or $url.UserInfo -or $url.Query -or $url.Fragment -or $url.AbsolutePath -ne '/') {
        throw 'CippUrl must be the HTTPS origin of the installed CIPP console, without a path, query, or credentials.'
    }
    if ($Options.ServiceAccountUpn -notmatch '^[^@\s''/]+@[^@\s''/]+$') { throw 'ServiceAccountUpn must be an explicit UPN.' }
    $additional = [string]$Options.TenantId -ne [string]$Options.HomeTenantId
    if ($additional -and ($Options.Mode -ne 'Direct' -or -not $Options.ApplicationId -or $Options.NewClientSecret)) {
        throw 'Additional direct tenants require the existing home ApplicationId; secret rotation must run against the home tenant.'
    }
    if ($Options.ApplicationSecret -and (-not $Options.ApplicationId -or $Options.NewClientSecret)) {
        throw 'ApplicationSecret requires an existing ApplicationId and cannot be combined with NewClientSecret.'
    }
    if ($Options.Mode -ne 'Partner' -and ($Options.GdapAction -ne 'Prepare' -or $Options.CustomerTenantId -or $Options.RelationshipId -or $Options.GdapGroupMapPath -or $Options.AdminAgentsGroupId -or $Options.AutoExtend)) {
        throw 'GDAP parameters require Partner mode.'
    }
    if ($Options.GdapAction -in @('Invite', 'Map') -and (-not $Options.CustomerTenantId -or $Options.CustomerTenantId -eq $Options.TenantId)) {
        throw 'GDAP Invite/Map requires a distinct CustomerTenantId.'
    }
    if ($Options.GdapAction -eq 'Invite' -and ($Options.RelationshipId -or $Options.RelationshipName -notmatch '^.{1,50}$')) {
        throw 'Invite requires a unique RelationshipName (1-50 characters) and no existing RelationshipId.'
    }
    if ($Options.GdapAction -eq 'Map' -and $Options.RelationshipId -notmatch '^[a-zA-Z0-9-]{1,100}$') {
        throw 'Map requires the existing RelationshipId.'
    }
    $Options.ExportDirectory = Assert-CIPPExportPath $Options.ExportDirectory
}

function Assert-CIPPGdapRelationship {
    param($Relationship, [string]$Customer, [object[]]$Roles)
    if ($Relationship.customer.tenantId -ne $Customer) { throw 'GDAP relationship customer mismatch.' }
    $approved = @($Relationship.accessDetails.unifiedRoles.roleDefinitionId)
    if (@($Roles.id | Where-Object { $_ -notin $approved }).Count) {
        throw 'The GDAP relationship does not contain all requested roles; create a separately approved relationship.'
    }
    if ($Relationship.status -notin @('active', 'created', 'approvalPending', 'approved', 'activating')) {
        throw "GDAP relationship cannot be mapped in status $($Relationship.status)."
    }
}

function Initialize-CIPPGdap {
    param($Options, $State, [object[]]$Roles, [scriptblock]$Checkpoint)
    $custom = if ($Options.GdapGroupMapPath) {
        Get-Content -LiteralPath $Options.GdapGroupMapPath -Raw | ConvertFrom-Json -AsHashtable
    } else { @{} }
    foreach ($key in $custom.Keys) {
        if ($key -notin $Roles.displayName) { throw "Unknown GDAP role in group mapping: $key." }
    }
    if ($Options.GdapAction -eq 'Map') {
        $relationship = Invoke-CIPPGraph "/tenantRelationships/delegatedAdminRelationships/$($Options.RelationshipId)"
        Assert-CIPPGdapRelationship $relationship ([string]$Options.CustomerTenantId) $Roles
    } elseif ($Options.GdapAction -eq 'Invite') {
        $escaped = $Options.RelationshipName.Replace("'", "''")
        if (@(Get-CIPPCollection "/tenantRelationships/delegatedAdminRelationships?`$filter=displayName eq '$escaped'").Count) {
            throw 'Relationship name already exists. Resume with Map and its relationship ID instead.'
        }
    }
    $adminGroup = if ($Options.AdminAgentsGroupId) {
        Invoke-CIPPGraph "/groups/$($Options.AdminAgentsGroupId)"
    } else {
        Get-CIPPUniqueObject @(Get-CIPPCollection "/groups?`$filter=displayName eq 'AdminAgents'") 'partner AdminAgents group'
    }
    if (-not $adminGroup.id -or $adminGroup.displayName -ne 'AdminAgents' -or -not $adminGroup.securityEnabled) {
        throw 'Partner AdminAgents group is missing or invalid. Do not create a replacement; verify Partner Center enrollment.'
    }
    $State.AdminAgentsGroupId = $adminGroup.id
    & $Checkpoint
    Add-CIPPGroupMember $adminGroup.id $State.ServiceAccountId
    $State.GdapGroups = @()
    foreach ($role in $Roles) {
        $name = "M365 GDAP $($role.displayName)"
        $group = if ($custom.Contains($role.displayName)) {
            $id = [guid]$custom[$role.displayName]
            Invoke-CIPPGraph "/groups/$id"
        } else {
            Get-CIPPUniqueObject @(Get-CIPPCollection "/groups?`$filter=displayName eq '$name'") "GDAP group $name"
        }
        if (-not $group) {
            $group = Invoke-CIPPGraph '/groups' POST @{
                displayName = $name; mailEnabled = $false; securityEnabled = $true
                mailNickname = 'CIPP-GDAP-' + [guid]::NewGuid().ToString('N')
            }
        }
        if (-not $group.id -or -not $group.securityEnabled -or $group.mailEnabled -or @($group.groupTypes).Count) {
            throw "GDAP role $($role.displayName) requires a static, non-mail-enabled security group."
        }
        if ($group.id -in $State.GdapGroups.groupId) { throw 'One GDAP group cannot map multiple roles in this tool.' }
        $State.GdapGroups += @{ roleName = $role.displayName; roleDefinitionId = $role.id; groupId = $group.id }
        & $Checkpoint
        Add-CIPPGroupMember $group.id $State.ServiceAccountId
    }
    if ($Options.GdapAction -eq 'Prepare') {
        $State.GdapStatus = 'GroupsPrepared'
        return
    }
    if ($Options.GdapAction -eq 'Invite') {
        $body = @{
            displayName = $Options.RelationshipName
            duration = "P$($Options.RelationshipDurationDays)D"
            autoExtendDuration = $(if ($Options.AutoExtend) { 'P180D' } else { 'PT0S' })
            customer = @{ tenantId = [string]$Options.CustomerTenantId }
            accessDetails = @{ unifiedRoles = @($Roles | ForEach-Object { @{ roleDefinitionId = $_.id } }) }
        }
        $relationship = Invoke-CIPPGraph '/tenantRelationships/delegatedAdminRelationships' POST $body
        $State.RelationshipId = $relationship.id
        $State.CustomerTenantId = [string]$Options.CustomerTenantId
        & $Checkpoint
        $null = Invoke-CIPPGraph "/tenantRelationships/delegatedAdminRelationships/$($relationship.id)/requests" POST @{ action = 'lockForApproval' }
    } else {
        $State.RelationshipId = $Options.RelationshipId
        $State.CustomerTenantId = [string]$Options.CustomerTenantId
    }
    $State.CustomerApprovalUrl = "https://admin.microsoft.com/Adminportal/Home?invType=GDAP&partnerId=$($State.HomeTenantId)&relationshipId=$($State.RelationshipId)#/partners/invitation"
    $State.GdapStatus = 'AwaitingCustomerApproval'
    & $Checkpoint
    $deadline = [datetime]::UtcNow.AddSeconds($Options.ApprovalWaitSeconds)
    do {
        $relationship = Invoke-CIPPGraph "/tenantRelationships/delegatedAdminRelationships/$($State.RelationshipId)"
        Assert-CIPPGdapRelationship $relationship $State.CustomerTenantId $Roles
        if ($relationship.status -eq 'active') { break }
        if ([datetime]::UtcNow -ge $deadline) { return }
        Start-Sleep -Seconds ([math]::Min(5, [math]::Max(1, ($deadline - [datetime]::UtcNow).TotalSeconds)))
    } while ($true)
    $State.AccessAssignments = @()
    foreach ($mapping in $State.GdapGroups) {
        $existing = @(Get-CIPPCollection "/tenantRelationships/delegatedAdminRelationships/$($State.RelationshipId)/accessAssignments")
        $matching = @($existing | Where-Object {
            $_.accessContainer.accessContainerId -eq $mapping.groupId -and
            $mapping.roleDefinitionId -in $_.accessDetails.unifiedRoles.roleDefinitionId -and
            $_.status -notin @('deleting', 'deleted', 'error')
        })
        $assignment = if ($matching.Count) { $matching[0] } else {
            Invoke-CIPPGraph "/tenantRelationships/delegatedAdminRelationships/$($State.RelationshipId)/accessAssignments" POST @{
                accessContainer = @{ accessContainerId = $mapping.groupId; accessContainerType = 'securityGroup' }
                accessDetails = @{ unifiedRoles = @(@{ roleDefinitionId = $mapping.roleDefinitionId }) }
            }
        }
        $State.AccessAssignments += @{ id = $assignment.id; groupId = $mapping.groupId; roleDefinitionId = $mapping.roleDefinitionId; status = $assignment.status }
        & $Checkpoint
    }
    $State.GdapStatus = if (@($State.AccessAssignments | Where-Object status -NE 'active').Count) { 'AccessAssignmentsPending' } else { 'MappingsActive' }
}

function Invoke-CIPPInitialization {
    param([System.Collections.IDictionary]$Options, $Inventory)
    New-CIPPExportDirectory $Options.ExportDirectory
    $state = [ordered]@{
        Status = 'InProgress'; Stage = 'Preflight'; Mode = $Options.Mode
        TenantId = [string]$Options.TenantId; HomeTenantId = [string]$Options.HomeTenantId
        ServiceAccountUpn = $Options.ServiceAccountUpn; PermissionSourceRevision = $Inventory.sourceRevision
        Credentials = @{}; ConsoleFields = @{}; GdapGroups = @()
        GrantVerification = 'NotRun'; RuntimeVerification = 'NotRun'; GdapStatus = 'NotApplicable'
        RemainingSteps = @('Complete Microsoft MFA enrollment and verify MFA in CIPP Permissions.',
            'Complete CIPP Setup Wizard/tenant onboarding and CPV refresh; review exclusions from All Tenants standards/baselines.',
            'Run CIPP Permissions checks. No CA policies have been deployed.')
    }
    $checkpoint = { Save-CIPPInitializationState $state $Options.ExportDirectory $Options.ExportFormat }
    & $checkpoint
    $adminConnected = $false
    try {
        if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) {
            throw 'Missing Microsoft.Graph.Authentication. Install-Module Microsoft.Graph.Authentication -Scope CurrentUser, then rerun.'
        }
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        $state.Stage = 'HomeApplication'
        Connect-CIPPInitializationAdmin $state.HomeTenantId -Partner:($Options.Mode -eq 'Partner')
        $adminConnected = $true
        $additional = $state.TenantId -ne $state.HomeTenantId
        $application = if ($Options.ApplicationId) {
            Get-CIPPUniqueObject @(Get-CIPPCollection "/applications?`$filter=appId eq '$($Options.ApplicationId)'") 'selected home application'
        } else {
            $found = @(Get-CIPPCollection "/applications?`$filter=displayName eq 'CIPP-SAM'")
            if ($found.Count) { throw 'CIPP-SAM already exists. Select it explicitly with ApplicationId; no display-name takeover is allowed.' }
            $null
        }
        if ($Options.ApplicationId -and -not $application) { throw 'Selected application was not found in HomeTenantId.' }
        $redirect = "http://localhost:$($Options.LoopbackPort)/"
        $origin = ([uri]$Options.CippUrl).GetLeftPart([UriPartial]::Authority)
        $callbacks = @("$origin/authredirect", "$origin/.auth/callback", $redirect)
        if (-not $application) {
            $application = Invoke-CIPPGraph '/applications' POST @{
                displayName = 'CIPP-SAM'; signInAudience = 'AzureADMultipleOrgs'
                isFallbackPublicClient = $true; web = @{ redirectUris = $callbacks }
            }
            $state.CreatedApplication = $true
        }
        $state.ApplicationId = $application.appId
        $state.ApplicationObjectId = $application.id
        & $checkpoint
        if ($application.signInAudience -ne 'AzureADMultipleOrgs') { throw 'Selected application must support AzureADMultipleOrgs for CIPP SAM.' }
        $state.ResourceServicePrincipals = @{}
        $recordResource = {
            param($ResourceAppId, $ObjectId)
            $state.ResourceServicePrincipals[$ResourceAppId] = $ObjectId
            & $checkpoint
        }
        if (-not $additional) {
            $resources = @(Resolve-CIPPPermissionResources $Inventory $Options.Mode $recordResource)
            $resourceAccess = @(Merge-CIPPRequiredResourceAccess @($application.requiredResourceAccess) $resources)
            $web = if ($application.web) { @{} + $application.web } else { @{} }
            $web.redirectUris = @(@($application.web.redirectUris) + $callbacks | Sort-Object -Unique)
            $null = Invoke-CIPPGraph "/applications/$($application.id)" PATCH @{
                requiredResourceAccess = $resourceAccess; web = $web
            }
        } else {
            if ($redirect -notin $application.web.redirectUris) {
                throw 'Home application is missing the loopback redirect. Initialize it in its home tenant first, using the same LoopbackPort.'
            }
        }
        if ($state.CreatedApplication -or $Options.NewClientSecret) {
            $secret = Invoke-CIPPGraph "/applications/$($application.id)/addPassword" POST @{
                passwordCredential = @{ displayName = 'CIPP initialization'; endDateTime = [datetime]::UtcNow.AddDays($Options.SecretLifetimeDays).ToString('o') }
            }
            if (-not $secret.secretText) { throw 'Graph did not return the new client secret value.' }
            $state.Credentials.ApplicationSecret = $secret.secretText
            $state.SecretKeyId = $secret.keyId
            $state.SecretExpiresAt = $secret.endDateTime
            & $checkpoint
        } elseif ($Options.ApplicationSecret) {
            $state.Credentials.ApplicationSecret = [Net.NetworkCredential]::new('', $Options.ApplicationSecret).Password
            & $checkpoint
        }
        if ($additional) {
            Connect-CIPPInitializationAdmin $state.TenantId
            $resources = @(Resolve-CIPPPermissionResources $Inventory $Options.Mode $recordResource)
        }
        $state.Stage = 'TenantConsent'
        $sp = Get-CIPPServicePrincipal $state.ApplicationId
        $state.ServicePrincipalId = $sp.id
        & $checkpoint
        Grant-CIPPResourcePermissions $sp.id $resources
        $state.GrantVerification = 'Verified'
        & $checkpoint
        $state.Stage = 'ServiceAccount'
        $escaped = $Options.ServiceAccountUpn.Replace("'", "''")
        $user = Get-CIPPUniqueObject @(Get-CIPPCollection "/users?`$filter=userPrincipalName eq '$escaped'&`$select=id,userPrincipalName,accountEnabled,userType") 'service account'
        if ($user -and $Options.CreateServiceAccount) { throw 'Service account already exists; omit CreateServiceAccount to explicitly reuse its UPN.' }
        if (-not $user) {
            if (-not $Options.CreateServiceAccount) { throw 'Service user not found. Use CreateServiceAccount to create it explicitly.' }
            $state.Credentials.ServiceAccountInitialPassword = 'Aa1!' + (New-CIPPRandomValue)
            & $checkpoint
            $user = Invoke-CIPPGraph '/users' POST @{
                accountEnabled = $true; displayName = 'CIPP Service Account'; userPrincipalName = $Options.ServiceAccountUpn
                mailNickname = $Options.ServiceAccountUpn.Split('@')[0]
                passwordProfile = @{ password = $state.Credentials.ServiceAccountInitialPassword; forceChangePasswordNextSignIn = $true }
            }
            $state.CreatedServiceAccount = $true
            $state.ServiceAccountId = $user.id
            & $checkpoint
            $user = Invoke-CIPPGraph "/users/$($user.id)?`$select=id,userPrincipalName,accountEnabled,userType"
        }
        if (-not $user.id -or -not $user.accountEnabled -or $user.userType -eq 'Guest') { throw 'Service account must be an enabled tenant-local user.' }
        $state.ServiceAccountId = $user.id
        & $checkpoint
        $roles = @(Get-CIPPRuntimeRoles $Inventory.runtimeRoles)
        $state.RuntimeRoles = @($roles | ForEach-Object { @{ name = $_.displayName; id = $_.id } })
        if ($Options.Mode -eq 'Direct') {
            Set-CIPPDirectUserRoles $user.id $roles
        } else {
            $state.Stage = 'GDAP'
            Initialize-CIPPGdap $Options $state $roles $checkpoint
            & $checkpoint
        }
        $state.Stage = 'ServiceAccountAuthentication'
        if ($Options.SkipTokenAcquisition) {
            $state.Status = 'PreparedAwaitingServiceAccountAuthentication'
        } else {
            Write-Warning "Complete Microsoft MFA enrollment/password setup for $($Options.ServiceAccountUpn) first. Use the private export to recover any initial password. Do not disable existing protections."
            if ((Read-Host 'Type MFA-READY to authenticate as this service account, or stop and resume later') -cne 'MFA-READY') {
                throw 'Service-account authentication was not confirmed. Resume using the exported IDs and credentials.'
            }
            if (-not $state.Credentials.ApplicationSecret) {
                $inputSecret = Read-Host 'Existing SAM application secret VALUE (not its key ID)' -AsSecureString
                $state.Credentials.ApplicationSecret = [Net.NetworkCredential]::new('', $inputSecret).Password
                & $checkpoint
            }
            $verifier = New-CIPPRandomValue
            $hash = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($verifier))
            $challenge = [Convert]::ToBase64String($hash).TrimEnd('=').Replace('+', '-').Replace('/', '_')
            $code = Receive-CIPPOAuthCode $state.TenantId $state.ApplicationId $Options.ServiceAccountUpn $challenge `
                (New-CIPPRandomValue) $Options.LoopbackPort $Options.AuthenticationTimeoutSeconds
            $token = Request-CIPPToken $state.TenantId @{
                client_id = $state.ApplicationId; client_secret = $state.Credentials.ApplicationSecret
                grant_type = 'authorization_code'; code = $code; redirect_uri = $redirect; code_verifier = $verifier
            }
            if (-not $token.refresh_token -or -not $token.access_token) { throw 'OAuth did not return both access and refresh tokens.' }
            $state.Credentials.UnverifiedRefreshToken = $token.refresh_token
            & $checkpoint
            Assert-CIPPRuntimeIdentity $token.access_token $state.TenantId $user.id
            $state.Credentials.RefreshToken = $token.refresh_token
            $state.Credentials.Remove('UnverifiedRefreshToken')
            & $checkpoint
            if ($Options.Mode -eq 'Direct') {
                Assert-CIPPStrengths $token.access_token
                $state.RuntimeVerification = 'IdentityAndCAReadVerified'
            } else {
                $state.RuntimeVerification = 'IdentityVerifiedCustomerCAChecksPending'
            }
            $state.Status = 'PreparedAwaitingCIPPOnboarding'
        }
        if ($state.GdapStatus -in @('AwaitingCustomerApproval', 'AccessAssignmentsPending')) { $state.Status = $state.GdapStatus }
        $state.ConsoleFields = Get-CIPPConsoleFields $state
        $state.Stage = 'Handoff'
        & $checkpoint
        [pscustomobject]@{
            Status = $state.Status; ExportDirectory = $Options.ExportDirectory
            TenantId = $state.TenantId; ApplicationId = $state.ApplicationId
            GdapStatus = $state.GdapStatus; CustomerApprovalUrl = $state.CustomerApprovalUrl
            NextStep = 'Recover fields privately; complete CIPP onboarding and Permissions/CPV checks. No policies deployed.'
        }
    } catch {
        $state.Status = 'Failed'
        $state.ConsoleFields = Get-CIPPConsoleFields $state
        & $checkpoint
        throw "Initialization stopped at $($state.Stage). Protected partial state: $($Options.ExportDirectory). $($_.Exception.Message)"
    } finally {
        if ($adminConnected) { $null = Disconnect-MgGraph -ErrorAction Continue }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    $options = @{} + $PSBoundParameters
    Assert-CIPPInitializationOptions $options
    $inventory = Read-CIPPInitializationInventory
    $resources = @($inventory.resources | Where-Object { -not $_.partnerOnly -or $options.Mode -eq 'Partner' })
    Write-Information "CIPP baseline $($inventory.sourceRevision): $(@($resources.permissions).Count) permissions, $($inventory.runtimeRoles.Count) runtime roles. Mode=$($options.Mode); GDAP=$($options.GdapAction). Existing grants are preserved." -InformationAction Continue
    if ($PSCmdlet.ShouldProcess("Tenant $($options.TenantId), SAM home $($options.HomeTenantId)", 'Prepare privileged CIPP identities, grant organization-wide consent, and export credentials')) {
        Invoke-CIPPInitialization $options $inventory
    }
}
