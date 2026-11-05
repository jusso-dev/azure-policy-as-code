function Get-PolicyDesiredState {
    <#
    .SYNOPSIS
        Reads the policy repository for one environment and returns the resources it should deploy.
    .DESCRIPTION
        Layout under -Path:
          definitions/   policy definitions        { "name", "properties": {...} }
          initiatives/   policy set definitions    { "name", "properties": {...} }
          assignments/   policy assignments        { "name", "scope", "properties": {...}, "identity"?, "roleAssignments"? }
          exemptions/    policy exemptions         { "name", "scope", "properties": {...} }
          environments/  one file per environment

        Any file may contain "environments": ["dev","prod"] to limit where it deploys.
        {{token}} placeholders come from the environment's tokens plus environment, pacOwnerId,
        deploymentScope, definitionScope and subscriptionId.

        Definition IDs can be written as a bare name ("policyDefinitionName": "deny-public-ip") or as
        a full ID; bare names resolve to the environment's definitionScope.

        Returns an object with Resources and Issues. Callers decide whether issues are fatal.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Environment
    )

    $root = (Resolve-Path -LiteralPath $Path).Path
    $envConfig = Get-PolicyEnvironment -Path $root -Environment $Environment
    $issues = [System.Collections.Generic.List[object]]::new()
    $resources = [System.Collections.Generic.List[object]]::new()
    $seen = @{}

    $addResource = {
        param($Kind, $Name, $Scope, $Body, $File, $Extra)
        $id = Get-PolicyResourceId -Kind $Kind -Scope $Scope -Name $Name
        $key = $id.ToLowerInvariant()
        if ($seen.ContainsKey($key)) {
            $issues.Add((New-PolicyIssue Error 'Duplicate' "$Kind '$Name' at '$Scope' is also defined in $($seen[$key])." -File $File))
            return
        }
        $seen[$key] = $File
        $resource = [pscustomobject]@{
            PSTypeName = 'AzPolicyOps.DesiredResource'
            Kind       = $Kind
            Name       = $Name
            Scope      = $Scope
            Id         = $id
            File       = $File
            Body       = $Body
        }
        if ($Extra) { foreach ($k in $Extra.Keys) { $resource | Add-Member -NotePropertyName $k -NotePropertyValue $Extra[$k] } }
        $resources.Add($resource)
    }

    $loadFolder = {
        param($Folder)
        foreach ($file in (Get-PolicyRepositoryFile -Root $root -Folder $Folder)) {
            $item = Read-PolicyRepositoryDocument -File $file -Environment $Environment -Tokens $envConfig.Tokens -Root $root -Issues $issues
            if ($item) { $item }
        }
    }

    $resolveDefinitionId = {
        param([System.Collections.IDictionary]$Container, [string]$File, [string]$Context)
        # Accept policyDefinitionName / policySetDefinitionName shorthands.
        if ($Container.policyDefinitionId) { return }
        if ($Container.policyDefinitionName) {
            $Container.policyDefinitionId = Get-PolicyResourceId -Kind PolicyDefinition -Scope $envConfig.DefinitionScope -Name $Container.policyDefinitionName
        }
        elseif ($Container.policySetDefinitionName) {
            $Container.policyDefinitionId = Get-PolicyResourceId -Kind PolicySetDefinition -Scope $envConfig.DefinitionScope -Name $Container.policySetDefinitionName
        }
        else {
            $issues.Add((New-PolicyIssue Error 'Reference.Missing' "$Context needs policyDefinitionId, policyDefinitionName or policySetDefinitionName." -File $File))
        }
        $Container.Remove('policyDefinitionName')
        $Container.Remove('policySetDefinitionName')
    }

    # Definitions
    foreach ($item in (& $loadFolder 'definitions')) {
        $doc = $item.Document
        $nameError = Test-PolicyResourceName -Name $doc.name -MaxLength 128
        if ($nameError) { $issues.Add((New-PolicyIssue Error 'Name' $nameError -File $item.File)); continue }
        foreach ($i in (Test-PolicyDefinitionDocument -Properties $doc.properties -File $item.File)) { $issues.Add($i) }
        if (-not $doc.properties.mode) { $doc.properties.mode = 'Indexed' }
        $doc.properties.policyType = 'Custom'
        Set-PolicyOwnerId -Properties $doc.properties -PacOwnerId $envConfig.PacOwnerId
        & $addResource 'PolicyDefinition' $doc.name $envConfig.DefinitionScope ([ordered]@{ properties = $doc.properties }) $item.File $null
    }

    # Initiatives
    foreach ($item in (& $loadFolder 'initiatives')) {
        $doc = $item.Document
        $nameError = Test-PolicyResourceName -Name $doc.name -MaxLength 128
        if ($nameError) { $issues.Add((New-PolicyIssue Error 'Name' $nameError -File $item.File)); continue }
        $members = @($doc.properties.policyDefinitions)
        if ($members.Count -eq 0) {
            $issues.Add((New-PolicyIssue Error 'Initiative.Empty' 'policyDefinitions must list at least one policy.' -File $item.File))
            continue
        }
        $refIds = @{}
        foreach ($member in $members) {
            & $resolveDefinitionId $member $item.File 'Initiative member'
            if (-not $member.policyDefinitionReferenceId) {
                $issues.Add((New-PolicyIssue Error 'Initiative.ReferenceId' "Every member needs policyDefinitionReferenceId (missing for $($member.policyDefinitionId))." -File $item.File))
            }
            elseif ($refIds.ContainsKey($member.policyDefinitionReferenceId)) {
                $issues.Add((New-PolicyIssue Error 'Initiative.ReferenceId' "policyDefinitionReferenceId '$($member.policyDefinitionReferenceId)' is used twice." -File $item.File))
            }
            else { $refIds[$member.policyDefinitionReferenceId] = $true }
        }
        $doc.properties.policyDefinitions = $members
        $doc.properties.policyType = 'Custom'
        Set-PolicyOwnerId -Properties $doc.properties -PacOwnerId $envConfig.PacOwnerId
        & $addResource 'PolicySetDefinition' $doc.name $envConfig.DefinitionScope ([ordered]@{ properties = $doc.properties }) $item.File $null
    }

    # Assignments
    foreach ($item in (& $loadFolder 'assignments')) {
        $doc = $item.Document
        # Assignment names are limited to 64 characters at subscription/resource group scope and 24 at management group scope.
        $scope = if ($doc.scope) { ([string]$doc.scope).TrimEnd('/') } else { $envConfig.DeploymentScope }
        $scopeKind = Get-PolicyScopeKind $scope
        if ($scopeKind -eq 'Invalid') { $issues.Add((New-PolicyIssue Error 'Scope' "scope '$scope' is not a valid ARM scope." -File $item.File)); continue }
        $nameError = Test-PolicyResourceName -Name $doc.name -MaxLength $(if ($scopeKind -eq 'ManagementGroup') { 24 } else { 64 })
        if ($nameError) { $issues.Add((New-PolicyIssue Error 'Name' $nameError -File $item.File)); continue }

        $props = $doc.properties
        & $resolveDefinitionId $props $item.File 'Assignment'
        if (-not $props.enforcementMode) { $props.enforcementMode = 'Default' }
        if ($props.enforcementMode -notin 'Default', 'DoNotEnforce') {
            $issues.Add((New-PolicyIssue Error 'Assignment.EnforcementMode' "enforcementMode must be Default or DoNotEnforce, not '$($props.enforcementMode)'." -File $item.File))
        }
        if ($props.notScopes) { $props.notScopes = @($props.notScopes | ForEach-Object { ([string]$_).TrimEnd('/') }) }
        Set-PolicyOwnerId -Properties $props -PacOwnerId $envConfig.PacOwnerId

        $body = [ordered]@{ properties = $props }
        $identityType = if ($doc.identity -and $doc.identity.type) { [string]$doc.identity.type } else { 'None' }
        if ($identityType -ne 'None') {
            $body.identity = $doc.identity
            $body.location = if ($doc.location) { $doc.location } else { $envConfig.ManagedIdentityLocation }
            if (-not $body.location) {
                $issues.Add((New-PolicyIssue Error 'Assignment.Location' 'An assignment with a managed identity needs "location" or the environment managedIdentityLocation.' -File $item.File))
            }
        }

        $roleAssignments = @()
        foreach ($ra in @($doc.roleAssignments)) {
            if (-not $ra) { continue }
            $roleAssignments += [pscustomobject]@{
                RoleDefinitionId = [string]$ra.roleDefinitionId
                Scope            = if ($ra.scope) { ([string]$ra.scope).TrimEnd('/') } else { $scope }
            }
        }
        & $addResource 'PolicyAssignment' $doc.name $scope $body $item.File @{ RoleAssignments = $roleAssignments; IdentityType = $identityType }
    }

    # Exemptions
    foreach ($item in (& $loadFolder 'exemptions')) {
        $doc = $item.Document
        $nameError = Test-PolicyResourceName -Name $doc.name -MaxLength 64
        if ($nameError) { $issues.Add((New-PolicyIssue Error 'Name' $nameError -File $item.File)); continue }
        $scope = if ($doc.scope) { ([string]$doc.scope).TrimEnd('/') } else { $envConfig.DeploymentScope }
        if ((Get-PolicyScopeKind $scope) -eq 'Invalid') { $issues.Add((New-PolicyIssue Error 'Scope' "scope '$scope' is not a valid ARM scope." -File $item.File)); continue }
        $props = $doc.properties
        if (-not $props.policyAssignmentId -and $props.policyAssignmentName) {
            $assignmentScope = if ($props.policyAssignmentScope) { ([string]$props.policyAssignmentScope).TrimEnd('/') } else { $envConfig.DeploymentScope }
            $props.policyAssignmentId = Get-PolicyResourceId -Kind PolicyAssignment -Scope $assignmentScope -Name $props.policyAssignmentName
        }
        $props.Remove('policyAssignmentName'); $props.Remove('policyAssignmentScope')
        if (-not $props.policyAssignmentId) {
            $issues.Add((New-PolicyIssue Error 'Exemption.Assignment' 'Exemption needs policyAssignmentId or policyAssignmentName.' -File $item.File)); continue
        }
        if ($props.exemptionCategory -notin 'Waiver', 'Mitigated') {
            $issues.Add((New-PolicyIssue Error 'Exemption.Category' 'exemptionCategory must be Waiver or Mitigated.' -File $item.File))
        }
        if ($props.expiresOn) {
            $expires = [datetimeoffset]::MinValue
            if (-not [datetimeoffset]::TryParse([string]$props.expiresOn, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$expires)) {
                $issues.Add((New-PolicyIssue Error 'Exemption.ExpiresOn' "expiresOn '$($props.expiresOn)' is not a valid date." -File $item.File))
            }
            elseif ($expires -lt [datetimeoffset]::UtcNow) {
                $issues.Add((New-PolicyIssue Warning 'Exemption.Expired' "Exemption expired on $($expires.ToString('yyyy-MM-dd')); remove the file or extend it." -File $item.File))
            }
        }
        Set-PolicyOwnerId -Properties $props -PacOwnerId $envConfig.PacOwnerId
        & $addResource 'PolicyExemption' $doc.name $scope ([ordered]@{ properties = $props }) $item.File $null
    }

    # Cross-reference checks that only need the repository.
    $byId = @{}
    foreach ($r in $resources) { $byId[$r.Id.ToLowerInvariant()] = $r }
    foreach ($r in $resources) {
        switch ($r.Kind) {
            'PolicySetDefinition' {
                foreach ($member in $r.Body.properties.policyDefinitions) {
                    $target = $byId[([string]$member.policyDefinitionId).ToLowerInvariant()]
                    if ($target) {
                        $memberParams = if ($member.parameters -is [System.Collections.IDictionary]) { $member.parameters } else { $null }
                        foreach ($i in (Test-PolicyAssignmentParameter -Declared $target.Body.properties.parameters -Supplied $memberParams -File $r.File -Target "policy '$($target.Name)' (member '$($member.policyDefinitionReferenceId)')")) { $issues.Add($i) }
                    }
                    elseif ($member.policyDefinitionId -match '^/providers/Microsoft\.Authorization/policyDefinitions/') {
                        continue  # Built-in; checked online by the plan.
                    }
                    elseif ($member.policyDefinitionId -match '/providers/Microsoft\.Authorization/policyDefinitions/') {
                        $issues.Add((New-PolicyIssue Warning 'Reference.External' "Member '$($member.policyDefinitionReferenceId)' points to a custom definition this repo does not manage: $($member.policyDefinitionId)" -File $r.File))
                    }
                }
            }
            'PolicyAssignment' {
                $targetId = ([string]$r.Body.properties.policyDefinitionId).ToLowerInvariant()
                $target = $byId[$targetId]
                if ($target) {
                    foreach ($i in (Test-PolicyAssignmentParameter -Declared $target.Body.properties.parameters -Supplied $r.Body.properties.parameters -File $r.File -Target "'$($target.Name)'")) { $issues.Add($i) }
                    $needsIdentity = $false
                    $definitions = if ($target.Kind -eq 'PolicyDefinition') { @($target) } else {
                        @($target.Body.properties.policyDefinitions | ForEach-Object { $byId[([string]$_.policyDefinitionId).ToLowerInvariant()] } | Where-Object { $_ })
                    }
                    foreach ($d in $definitions) {
                        $effects = (Get-PolicyEffectInfo -Properties $d.Body.properties).PossibleEffects
                        if ($effects | Where-Object { $_ -in 'deployIfNotExists', 'modify' }) { $needsIdentity = $true }
                    }
                    if ($needsIdentity -and $r.IdentityType -eq 'None') {
                        $issues.Add((New-PolicyIssue Error 'Assignment.Identity' "'$($target.Name)' can use deployIfNotExists or modify, so the assignment needs a managed identity." -File $r.File))
                    }
                }
                elseif ($targetId -and $targetId -notmatch '^/providers/microsoft\.authorization/') {
                    $issues.Add((New-PolicyIssue Warning 'Reference.External' "Assignment points to a definition this repo does not manage: $($r.Body.properties.policyDefinitionId)" -File $r.File))
                }
                $assignmentScope = $r.Scope.ToLowerInvariant()
                $defScope = ($targetId -split '/providers/microsoft\.authorization/')[0]
                if ($defScope -and -not $assignmentScope.StartsWith($defScope) -and $defScope -notmatch '^/providers/microsoft\.management/managementgroups/') {
                    $issues.Add((New-PolicyIssue Error 'Assignment.ScopeOutsideDefinition' "Assignment scope '$($r.Scope)' is outside the definition's scope '$defScope'." -File $r.File))
                }
            }
            'PolicyExemption' {
                $assignmentId = ([string]$r.Body.properties.policyAssignmentId).ToLowerInvariant()
                $assignment = $byId[$assignmentId]
                if ($assignment -and $r.Body.properties.policyDefinitionReferenceIds) {
                    $set = $byId[([string]$assignment.Body.properties.policyDefinitionId).ToLowerInvariant()]
                    if ($set -and $set.Kind -eq 'PolicySetDefinition') {
                        $known = @($set.Body.properties.policyDefinitions.policyDefinitionReferenceId)
                        foreach ($ref in $r.Body.properties.policyDefinitionReferenceIds) {
                            if ($ref -notin $known) { $issues.Add((New-PolicyIssue Error 'Exemption.ReferenceId' "policyDefinitionReferenceId '$ref' is not in initiative '$($set.Name)'." -File $r.File)) }
                        }
                    }
                }
            }
        }
    }

    [pscustomobject]@{
        PSTypeName  = 'AzPolicyOps.DesiredState'
        Environment = $envConfig
        Resources   = $resources.ToArray()
        Issues      = $issues.ToArray()
    }
}
