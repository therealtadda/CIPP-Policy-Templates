#requires -Version 7.0
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-f0-9]{40}$')]
    [string]$Revision
)

$ErrorActionPreference = 'Stop'
$base = "https://raw.githubusercontent.com/KelvinTegelaar/CIPP-API/$Revision/Config"
$manifest = Invoke-RestMethod "$base/SAMManifest.json"
$additional = Invoke-RestMethod "$base/AdditionalPermissions.json"
$translator = Invoke-RestMethod "$base/PermissionsTranslator.json"
$resources = foreach ($appId in @($manifest.requiredResourceAccess.resourceAppId + $additional.resourceAppId | Sort-Object -Unique)) {
    $permissions = @(
        foreach ($permission in @($manifest.requiredResourceAccess | Where-Object resourceAppId -EQ $appId).resourceAccess) {
            $entry = @($translator | Where-Object id -EQ $permission.id)
            $names = @($entry.value | Sort-Object -Unique)
            if ($names.Count -gt 1 -or ($names.Count -eq 0 -and $appId -eq '00000003-0000-0000-c000-000000000000')) {
                throw "Cannot uniquely resolve $appId / $($permission.id)"
            }
            $name = if ($names.Count -eq 1) { $names[0] } else { $null }
            [ordered]@{ id = $permission.id; type = $permission.type; value = $name; source = 'SAMManifest.json' }
        }
        foreach ($permission in @($additional | Where-Object resourceAppId -EQ $appId).resourceAccess) {
            [ordered]@{ id = $null; type = $permission.type; value = $permission.id; source = 'AdditionalPermissions.json' }
        }
    )
    [ordered]@{
        resourceAppId = $appId
        partnerOnly = $appId -eq 'fa3d9a0c-3fb0-42cc-9193-47c7ecd2edbd'
        permissions = $permissions
    }
}
$inventory = [ordered]@{
    sourceRepository = 'https://github.com/KelvinTegelaar/CIPP-API'
    sourceRevision = $Revision
    sourceFiles = @('Config/SAMManifest.json', 'Config/AdditionalPermissions.json', 'Config/PermissionsTranslator.json')
    purpose = 'Full CIPP SAM baseline; CA policy and authentication-strength capabilities are asserted separately.'
    resources = @($resources)
    requiredGraphCapabilities = @(
        'Policy.Read.All', 'Policy.ReadWrite.ConditionalAccess', 'Policy.ReadWrite.AuthenticationMethod',
        'Application.ReadWrite.All', 'Group.ReadWrite.All', 'User.ReadWrite.All', 'RoleManagement.ReadWrite.Directory'
    )
    runtimeRoles = @(
        'Application Administrator', 'Authentication Policy Administrator', 'Billing Administrator',
        'Cloud App Security Administrator', 'Cloud Device Administrator', 'Domain Name Administrator',
        'Exchange Administrator', 'Global Reader', 'Intune Administrator',
        'Privileged Authentication Administrator', 'Privileged Role Administrator',
        'Security Administrator', 'SharePoint Administrator', 'Teams Administrator', 'User Administrator'
    )
    roleSource = 'https://docs.cipp.app/setup/maintaining-cipp/recommended-roles'
}
$path = Join-Path $PSScriptRoot '..\config\CIPPInitializationPermissions.json'
if ($PSCmdlet.ShouldProcess($path, "Generate permission inventory from reviewed revision $Revision")) {
    $null = New-Item -ItemType Directory -Path (Split-Path $path) -Force
    $inventory | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path -Encoding utf8
}
