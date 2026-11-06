$script:KindOrder = @{ PolicyDefinition = 0; PolicySetDefinition = 1; PolicyAssignment = 2; PolicyExemption = 3 }
$script:PlanFormatVersion = 1

function Get-PolicyStateFingerprint {
    <#
    .SYNOPSIS
        Hash of the comparable state of a deployed resource. Used to detect changes between plan and deploy.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Kind,
        [AllowNull()][System.Collections.IDictionary]$Body
    )
    if ($null -eq $Body) { return 'absent' }
    $props = if ($Body.properties) { $Body.properties } else { @{} }
    $state = [ordered]@{}
    foreach ($property in $script:ComparedProperties[$Kind]) {
        $state[$property] = Get-PolicyComparableProperty -Property $property -Properties $props
    }
    if ($Kind -eq 'PolicyAssignment') {
        $state['identity'] = Get-PolicyIdentityKey $Body.identity
    }
    return Get-PolicyHash (ConvertTo-CanonicalJson $state)
}

function Get-PolicyReferencedDefinitionId {
    <#
    .SYNOPSIS
        IDs of definitions or initiatives a desired/deployed body points to.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][System.Collections.IDictionary]$Body)
    $props = if ($Body.properties) { $Body.properties } else { @{} }
    switch ($Kind) {
        'PolicySetDefinition' { return [string[]]@($props.policyDefinitions | ForEach-Object { [string]$_.policyDefinitionId } | Where-Object { $_ }) }
        'PolicyAssignment' { return [string[]]@([string]$props.policyDefinitionId | Where-Object { $_ }) }
        'PolicyExemption' { return [string[]]@([string]$props.policyAssignmentId | Where-Object { $_ }) }
        default { return [string[]]@() }
    }
}

function Resolve-PolicyRoleDefinitionId {
    <#
    .SYNOPSIS
        Turns a role definition GUID or ID into the form a role assignment at Scope expects.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$RoleDefinitionId, [Parameter(Mandatory)][string]$Scope)
    $guid = ($RoleDefinitionId -split '/')[-1]
    $root = if ($Scope -match '^(/subscriptions/[^/]+)') { $Matches[1] }
    elseif ($Scope -match '^(/providers/Microsoft\.Management/managementGroups/[^/]+)') { $Matches[1] }
    else { '' }
    return "$root/providers/Microsoft.Authorization/roleDefinitions/$guid"
}

function Get-PolicyAdditionalScope {
    <#
    .SYNOPSIS
        Scopes outside the deployment scope listing that repository assignments and exemptions use.
    .DESCRIPTION
        Listing assignments at a subscription also returns its resource groups, so resource group scopes
        below a subscription deployment scope need no extra listing. Anything else does.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][psobject]$DesiredState)
    $deploymentScope = $DesiredState.Environment.DeploymentScope.ToLowerInvariant()
    $isSubscription = (Get-PolicyScopeKind $DesiredState.Environment.DeploymentScope) -eq 'Subscription'
    return [string[]]@($DesiredState.Resources | Where-Object Kind -In 'PolicyAssignment', 'PolicyExemption' | ForEach-Object Scope |
            Where-Object { -not $isSubscription -or -not $_.ToLowerInvariant().StartsWith($deploymentScope) } | Sort-Object -Unique)
}

function New-PolicyDefinitionCatalog {
    <#
    .SYNOPSIS
        Definition and initiative bodies by lowercase ID, repository first, then Azure. Used for parameter checks and role lookups.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][psobject]$DesiredState, [AllowEmptyCollection()][object[]]$Deployed = @())
    $catalog = @{}
    foreach ($r in $DesiredState.Resources | Where-Object Kind -In 'PolicyDefinition', 'PolicySetDefinition') { $catalog[$r.Id.ToLowerInvariant()] = $r.Body }
    foreach ($d in $Deployed | Where-Object Kind -In 'PolicyDefinition', 'PolicySetDefinition') {
        if (-not $catalog.ContainsKey($d.Id.ToLowerInvariant())) { $catalog[$d.Id.ToLowerInvariant()] = $d.Body }
    }
    return $catalog
}

function Get-PolicyDefinitionCatalogEntry {
    <#
    .SYNOPSIS
        Returns a definition/initiative body by ID, from the desired state, the deployed state or Azure (cached).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][hashtable]$Catalog
    )
    $key = $Id.ToLowerInvariant()
    if ($Catalog.ContainsKey($key)) { return $Catalog[$key] }
    $kind = if ($Id -match '/policySetDefinitions/') { 'PolicySetDefinition' } else { 'PolicyDefinition' }
    $body = Invoke-PolicyRestMethod -Method GET -Path $Id -ApiVersion $script:ApiVersion[$kind] -AllowNotFound
    $Catalog[$key] = $body
    return $body
}

function Get-PolicyRequiredRole {
    <#
    .SYNOPSIS
        Role assignments an identity-enabled assignment needs: explicit roleAssignments, else the
        roleDefinitionIds of every deployIfNotExists/modify policy it covers, at the assignment scope.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject]$Desired,
        [Parameter(Mandatory)][hashtable]$Catalog
    )

    $roles = [System.Collections.Generic.List[object]]::new()
    if ($Desired.RoleAssignments -and @($Desired.RoleAssignments).Count) {
        foreach ($ra in $Desired.RoleAssignments) {
            $roles.Add([pscustomobject]@{ RoleDefinitionId = Resolve-PolicyRoleDefinitionId $ra.RoleDefinitionId $ra.Scope; Scope = $ra.Scope })
        }
    }
    else {
        $target = Get-PolicyDefinitionCatalogEntry -Id $Desired.Body.properties.policyDefinitionId -Catalog $Catalog
        $definitions = @()
        if ($target) {
            if ($target.properties.policyDefinitions) {
                $definitions = @($target.properties.policyDefinitions | ForEach-Object { Get-PolicyDefinitionCatalogEntry -Id $_.policyDefinitionId -Catalog $Catalog } | Where-Object { $_ })
            }
            else { $definitions = @($target) }
        }
        foreach ($definition in $definitions) {
            foreach ($roleId in (Get-PolicyEffectInfo -Properties $definition.properties).RoleDefinitionIds) {
                $roles.Add([pscustomobject]@{ RoleDefinitionId = Resolve-PolicyRoleDefinitionId $roleId $Desired.Scope; Scope = $Desired.Scope })
            }
        }
    }

    return @($roles | Sort-Object { "$($_.Scope)|$($_.RoleDefinitionId)".ToLowerInvariant() } -Unique)
}

function Get-PolicyPrincipalRoleAssignment {
    <#
    .SYNOPSIS
        Lists role assignments held by a principal, at, above or below Scope.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string[]]$Scope)
    $found = @{}
    foreach ($s in ($Scope | Sort-Object -Unique)) {
        $filter = '?$filter=' + [uri]::EscapeDataString("principalId eq '$PrincipalId'")
        foreach ($ra in (Get-PolicyRestCollection -Path "$s/providers/Microsoft.Authorization/roleAssignments$filter" -ApiVersion $script:ApiVersion.RoleAssignment)) {
            $found[$ra.id.ToLowerInvariant()] = $ra
        }
    }
    return @($found.Values)
}

function Test-PolicyRoleAssignmentMatch {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Required, [Parameter(Mandatory)]$Existing)
    $requiredRole = ($Required.RoleDefinitionId -split '/')[-1]
    $existingRole = ([string]$Existing.properties.roleDefinitionId -split '/')[-1]
    return ($requiredRole -eq $existingRole -and ([string]$Existing.properties.scope).TrimEnd('/') -eq $Required.Scope.TrimEnd('/'))
}

function New-PolicyPlanAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Create', 'Update', 'Replace', 'Delete', 'NoChange')][string]$Operation,
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][string]$Id,
        [AllowNull()]$Body,
        [string]$File,
        [string[]]$Changes = @(),
        [string[]]$Reasons = @(),
        [string]$Fingerprint = 'absent',
        [string]$DeployedOwner
    )
    [pscustomobject]@{
        PSTypeName            = 'AzPolicyOps.PlanAction'
        Operation             = $Operation
        Kind                  = $Kind
        Name                  = $Name
        Scope                 = $Scope
        Id                    = $Id
        File                  = $File
        Changes               = [string[]]$Changes
        Reasons               = [string[]]$Reasons
        DeployedFingerprint   = $Fingerprint
        DeployedOwner         = $DeployedOwner
        DeployedPrincipalId   = $null
        RoleAssignments       = @()
        MissingRoleAssignments = @()
        Body                  = $Body
    }
}

function ConvertTo-PolicyPlanMarkdown {
    <#
    .SYNOPSIS
        Renders a plan as Markdown for the Azure DevOps run summary and pull request comments.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][psobject]$Plan)

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("## Azure Policy plan: $($Plan.Environment)")
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("Owner ``$($Plan.PacOwnerId)``, deployment scope ``$($Plan.DeploymentScope)``, created $($Plan.CreatedAt).")
    [void]$sb.AppendLine()
    $s = $Plan.Summary
    [void]$sb.AppendLine("| Create | Update | Replace | Delete | No change |")
    [void]$sb.AppendLine('|---:|---:|---:|---:|---:|')
    [void]$sb.AppendLine("| $($s.Create) | $($s.Update) | $($s.Replace) | $($s.Delete) | $($s.NoChange) |")
    [void]$sb.AppendLine()

    $changed = @($Plan.Actions | Where-Object Operation -NE 'NoChange')
    if ($changed.Count -eq 0) {
        [void]$sb.AppendLine('No changes. Azure matches the repository.')
    }
    else {
        [void]$sb.AppendLine('| Action | Type | Name | Scope | Details |')
        [void]$sb.AppendLine('|---|---|---|---|---|')
        foreach ($a in $changed) {
            $details = @()
            if ($a.Changes) { $details += 'changes: ' + ($a.Changes -join ', ') }
            if ($a.Reasons) { $details += ($a.Reasons -join '; ') }
            if ($a.MissingRoleAssignments -and @($a.MissingRoleAssignments).Count) { $details += "$(@($a.MissingRoleAssignments).Count) role assignment(s) to add" }
            $text = ($details -join '. ').Replace('|', '\|') -replace '\r?\n', ' '
            [void]$sb.AppendLine("| **$($a.Operation)** | $($a.Kind) | ``$($a.Name)`` | ``$($a.Scope)`` | $text |")
        }
    }
    if ($Plan.Warnings -and @($Plan.Warnings).Count) {
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('### Warnings')
        foreach ($w in $Plan.Warnings) { [void]$sb.AppendLine("- $w") }
    }
    return $sb.ToString()
}

function Read-PolicyPlan {
    <#
    .SYNOPSIS
        Accepts a plan object or a path to a plan JSON file and returns a normalised plan object.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Plan)

    if ($Plan -is [string] -or $Plan -is [System.IO.FileInfo]) {
        $raw = Read-PolicyJsonFile -Path ([string]$Plan)
        if ($raw.formatVersion -ne $script:PlanFormatVersion) { throw "Plan file format $($raw.formatVersion) is not supported by this module (expects $script:PlanFormatVersion)." }
        $actions = foreach ($a in $raw.actions) {
            $obj = [pscustomobject]$a
            $obj.RoleAssignments = @($a.RoleAssignments | Where-Object { $_ } | ForEach-Object { [pscustomobject]$_ })
            $obj.MissingRoleAssignments = @($a.MissingRoleAssignments | Where-Object { $_ } | ForEach-Object { [pscustomobject]$_ })
            $obj
        }
        return [pscustomobject]@{
            PSTypeName      = 'AzPolicyOps.Plan'
            FormatVersion   = $raw.formatVersion
            Environment     = $raw.environment
            PacOwnerId      = $raw.pacOwnerId
            TenantId        = $raw.tenantId
            DeploymentScope = $raw.deploymentScope
            CreatedAt       = $raw.createdAt
            HasChanges      = [bool]$raw.hasChanges
            Summary         = [pscustomobject]$raw.summary
            Warnings        = @($raw.warnings)
            Actions         = @($actions)
        }
    }
    return $Plan
}

function Save-PolicyPlan {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][psobject]$Plan, [Parameter(Mandatory)][string]$Path)
    $doc = [ordered]@{
        formatVersion   = $Plan.FormatVersion
        environment     = $Plan.Environment
        pacOwnerId      = $Plan.PacOwnerId
        tenantId        = $Plan.TenantId
        deploymentScope = $Plan.DeploymentScope
        createdAt       = $Plan.CreatedAt
        hasChanges      = $Plan.HasChanges
        summary         = $Plan.Summary
        warnings        = @($Plan.Warnings)
        actions         = @($Plan.Actions)
    }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if ($PSCmdlet.ShouldProcess($Path, 'Write plan file')) {
        ConvertTo-Json -InputObject $doc -Depth 100 | Set-Content -LiteralPath $Path -Encoding utf8NoBOM
    }
}
