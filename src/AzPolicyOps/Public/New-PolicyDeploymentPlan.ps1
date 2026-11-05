function New-PolicyDeploymentPlan {
    <#
    .SYNOPSIS
        Compares the repository with Azure and works out what a deployment would change.
    .DESCRIPTION
        For every definition, initiative, assignment and exemption in the repository the plan decides:

          Create    not in Azure
          Update    in Azure, but a compared property differs (also used to adopt an unmanaged resource)
          Replace   the change cannot be made in place (removed parameter, changed parameter type,
                    new parameter without a default, exemption moved to another assignment). Resources that
                    depend on it are replaced too, because Azure blocks deleting a definition in use.
          Delete    owned by this repository's pacOwnerId in Azure but no longer in the repository
          NoChange  matches

        Resources owned by another pacOwnerId are never changed; a clash is an error unless
        -AllowOwnershipTakeover. The plan records a fingerprint of each resource it read, so
        Invoke-PolicyDeploymentPlan can refuse to apply a plan that is out of date.

        In Azure DevOps the plan is written to -OutFile (published as a pipeline artifact), a Markdown
        summary is attached to the run, and the output variable hasChanges is set so the deploy stage
        can be skipped when there is nothing to do.
    .EXAMPLE
        New-PolicyDeploymentPlan -Path ./policies -Environment prod -OutFile $(Build.ArtifactStagingDirectory)/plan.json
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Environment,
        [string]$OutFile,
        [string]$SummaryFile,
        [switch]$SkipDelete,
        [switch]$SkipRoleAssignments,
        [switch]$AllowOwnershipTakeover
    )

    $desiredState = Get-PolicyDesiredState -Path $Path -Environment $Environment
    $envConfig = $desiredState.Environment
    $errors = [System.Collections.Generic.List[string]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()

    foreach ($issue in $desiredState.Issues) {
        $line = "$($issue.File): $($issue.Message)"
        if ($issue.Severity -eq 'Error') { $errors.Add($line) } elseif ($issue.Severity -eq 'Warning') { $warnings.Add($line) }
    }
    if ($errors.Count) {
        $errors | ForEach-Object { Write-PolicyLog $_ -Level Error }
        throw "The repository has $($errors.Count) validation error(s). Run Test-PolicyRepository for details."
    }

    $context = Get-AzContext
    if (-not $context) { throw 'Not signed in to Azure. In Azure DevOps run this inside AzurePowerShell@5; elsewhere use Connect-PolicyPipelineAccount.' }

    Write-PolicyLog "Planning '$Environment' (owner $($envConfig.PacOwnerId)) as $($context.Account.Id)" -Level Section

    $deployed = Get-PolicyDeployedState -Environment $envConfig -AdditionalScope (Get-PolicyAdditionalScope -DesiredState $desiredState)

    $deployedById = @{}
    foreach ($d in $deployed) { $deployedById[$d.Id.ToLowerInvariant()] = $d }
    $desiredById = @{}
    foreach ($r in $desiredState.Resources) { $desiredById[$r.Id.ToLowerInvariant()] = $r }

    $catalog = New-PolicyDefinitionCatalog -DesiredState $desiredState -Deployed $deployed

    # References to definitions this repo does not manage must exist, and parameters must match them.
    foreach ($r in $desiredState.Resources | Where-Object Kind -In 'PolicySetDefinition', 'PolicyAssignment') {
        foreach ($refId in (Get-PolicyReferencedDefinitionId -Kind $r.Kind -Body $r.Body)) {
            if ($desiredById.ContainsKey($refId.ToLowerInvariant())) { continue }
            $target = Get-PolicyDefinitionCatalogEntry -Id $refId -Catalog $catalog
            if (-not $target) { $errors.Add("$($r.File): references '$refId', which does not exist in Azure or the repository."); continue }
            if ($r.Kind -eq 'PolicyAssignment') {
                foreach ($i in (Test-PolicyAssignmentParameter -Declared $target.properties.parameters -Supplied $r.Body.properties.parameters -File $r.File -Target $refId)) {
                    if ($i.Severity -eq 'Error') { $errors.Add("$($i.File): $($i.Message)") }
                }
            }
            else {
                $member = $r.Body.properties.policyDefinitions | Where-Object { $_.policyDefinitionId -eq $refId } | Select-Object -First 1
                $memberParams = if ($member.parameters -is [System.Collections.IDictionary]) { $member.parameters } else { $null }
                foreach ($i in (Test-PolicyAssignmentParameter -Declared $target.properties.parameters -Supplied $memberParams -File $r.File -Target $refId)) {
                    if ($i.Severity -eq 'Error') { $errors.Add("$($i.File): $($i.Message)") }
                }
            }
        }
    }

    # Desired resources.
    $actions = [ordered]@{}
    foreach ($r in $desiredState.Resources) {
        $key = $r.Id.ToLowerInvariant()
        $d = $deployedById[$key]
        if (-not $d) {
            $actions[$key] = New-PolicyPlanAction -Operation Create -Kind $r.Kind -Name $r.Name -Scope $r.Scope -Id $r.Id -Body $r.Body -File $r.File
            continue
        }
        $reasons = @()
        if ($d.Owner -eq 'OtherRepo') {
            if (-not $AllowOwnershipTakeover) {
                $errors.Add("$($r.File): $($r.Kind) '$($r.Name)' is owned by '$($d.PacOwnerId)'. Rename it, remove it from one repository, or plan with -AllowOwnershipTakeover.")
                continue
            }
            $reasons += "take ownership from '$($d.PacOwnerId)'"
        }
        elseif ($d.Owner -eq 'Unmanaged') {
            $reasons += 'adopt unmanaged resource'
        }

        $changes = @(Compare-PolicyResource -Kind $r.Kind -Desired $r.Body -Deployed $d.Body)
        $breaking = @(Get-PolicyBreakingChange -Kind $r.Kind -Desired $r.Body -Deployed $d.Body)
        $operation = if ($breaking.Count) { 'Replace' } elseif ($changes.Count) { 'Update' } else { 'NoChange' }
        if ($operation -eq 'NoChange' -and $d.Owner -ne 'ThisRepo') { $operation = 'Update'; $changes = @('metadata') }
        $fingerprint = Get-PolicyStateFingerprint -Kind $r.Kind -Body $d.Body
        $action = New-PolicyPlanAction -Operation $operation -Kind $r.Kind -Name $r.Name -Scope $r.Scope -Id $d.Id -Body $r.Body -File $r.File `
            -Changes $changes -Reasons (@($reasons) + @($breaking)) -Fingerprint $fingerprint -DeployedOwner $d.Owner
        if ($r.Kind -eq 'PolicyAssignment' -and $d.Body.identity -and $d.Body.identity.principalId) { $action.DeployedPrincipalId = $d.Body.identity.principalId }
        $actions[$key] = $action
    }

    # Deleted resources.
    foreach ($d in $deployed) {
        $key = $d.Id.ToLowerInvariant()
        if ($desiredById.ContainsKey($key) -or $d.Owner -ne 'ThisRepo') { continue }
        if ($SkipDelete) { $warnings.Add("$($d.Kind) '$($d.Name)' is no longer in the repository; not deleted because -SkipDelete was used."); continue }
        $action = New-PolicyPlanAction -Operation Delete -Kind $d.Kind -Name $d.Name -Scope $d.Scope -Id $d.Id -Body $null `
            -Reasons @('removed from repository') -Fingerprint (Get-PolicyStateFingerprint -Kind $d.Kind -Body $d.Body) -DeployedOwner $d.Owner
        if ($d.Kind -eq 'PolicyAssignment' -and $d.Body.identity -and $d.Body.identity.principalId) { $action.DeployedPrincipalId = $d.Body.identity.principalId }
        $actions[$key] = $action
    }

    # Replacing or deleting a definition/initiative needs its dependants out of the way first.
    $changed = $true
    while ($changed) {
        $changed = $false
        foreach ($a in @($actions.Values | Where-Object { $_.Operation -in 'Replace', 'Delete' -and $_.Kind -in 'PolicyDefinition', 'PolicySetDefinition' })) {
            foreach ($d in $deployed) {
                if ($d.Kind -notin 'PolicySetDefinition', 'PolicyAssignment') { continue }
                $refs = @(Get-PolicyReferencedDefinitionId -Kind $d.Kind -Body $d.Body | ForEach-Object { $_.ToLowerInvariant() })
                if ($a.Id.ToLowerInvariant() -notin $refs) { continue }
                $dep = $actions[$d.Id.ToLowerInvariant()]
                if (-not $dep) {
                    $errors.Add("$($a.Kind) '$($a.Name)' must be $(if ($a.Operation -eq 'Delete') { 'deleted' } else { 'replaced' }) but $($d.Kind) '$($d.Id)' uses it and is not managed by this repository ($($d.Owner)).")
                    continue
                }
                if ($dep.Operation -in 'Update', 'NoChange') {
                    $dep.Operation = 'Replace'
                    $dep.Reasons = [string[]](@($dep.Reasons) + "depends on $($a.Kind) '$($a.Name)' which is being $(if ($a.Operation -eq 'Delete') { 'deleted' } else { 'replaced' })")
                    $changed = $true
                }
            }
        }
    }

    # A desired resource must not reference something the plan deletes.
    foreach ($a in @($actions.Values | Where-Object { $_.Operation -ne 'Delete' -and $_.Body })) {
        foreach ($refId in (Get-PolicyReferencedDefinitionId -Kind $a.Kind -Body $a.Body)) {
            $target = $actions[$refId.ToLowerInvariant()]
            if ($target -and $target.Operation -eq 'Delete') { $errors.Add("$($a.File): references '$refId', which this plan deletes.") }
        }
    }

    # Role assignments for managed identities.
    foreach ($a in @($actions.Values | Where-Object { $_.Kind -eq 'PolicyAssignment' -and $_.Operation -ne 'Delete' })) {
        $desired = $desiredById[$a.Id.ToLowerInvariant()]
        if ($desired.IdentityType -eq 'None') { continue }
        if ($SkipRoleAssignments) { continue }
        $required = @(Get-PolicyRequiredRole -Desired $desired -Catalog $catalog)
        $a.RoleAssignments = $required
        if ($a.Operation -in 'Create', 'Replace' -or -not $a.DeployedPrincipalId) {
            $a.MissingRoleAssignments = $required
            continue
        }
        $existing = @(Get-PolicyPrincipalRoleAssignment -PrincipalId $a.DeployedPrincipalId -Scope (@($a.Scope) + @($required.Scope)))
        $missing = @($required | Where-Object { $req = $_; -not ($existing | Where-Object { Test-PolicyRoleAssignmentMatch -Required $req -Existing $_ }) })
        $a.MissingRoleAssignments = $missing
        if ($missing.Count -and $a.Operation -eq 'NoChange') {
            $a.Operation = 'Update'
            $a.Changes = [string[]]@('roleAssignments')
        }
    }

    if ($errors.Count) {
        $errors | ForEach-Object { Write-PolicyLog $_ -Level Error }
        throw "Planning failed with $($errors.Count) error(s)."
    }

    $ordered = @($actions.Values | Sort-Object { $script:KindOrder[$_.Kind] }, Name)
    $summary = [ordered]@{}
    foreach ($op in 'Create', 'Update', 'Replace', 'Delete', 'NoChange') { $summary[$op] = @($ordered | Where-Object Operation -EQ $op).Count }

    $plan = [pscustomobject]@{
        PSTypeName      = 'AzPolicyOps.Plan'
        FormatVersion   = $script:PlanFormatVersion
        Environment     = $Environment
        PacOwnerId      = $envConfig.PacOwnerId
        TenantId        = $context.Tenant.Id
        DeploymentScope = $envConfig.DeploymentScope
        CreatedAt       = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        HasChanges      = ($summary.Create + $summary.Update + $summary.Replace + $summary.Delete) -gt 0
        Summary         = [pscustomobject]$summary
        Warnings        = $warnings.ToArray()
        Actions         = $ordered
    }

    foreach ($w in $warnings) { Write-PolicyLog $w -Level Warning }
    foreach ($a in $ordered | Where-Object Operation -NE 'NoChange') {
        $detail = @($a.Changes) + @($a.Reasons) | Where-Object { $_ }
        Write-PolicyLog ("  {0,-8} {1,-20} {2}{3}" -f $a.Operation, $a.Kind, $a.Name, $(if ($detail) { " ($($detail -join '; '))" } else { '' }))
    }
    Write-PolicyLog "Plan: $($summary.Create) to create, $($summary.Update) to update, $($summary.Replace) to replace, $($summary.Delete) to delete, $($summary.NoChange) unchanged."

    if ($OutFile) { Save-PolicyPlan -Plan $plan -Path $OutFile; Write-PolicyLog "Plan written to $OutFile" }
    $markdown = ConvertTo-PolicyPlanMarkdown -Plan $plan
    if ($SummaryFile) {
        Set-Content -LiteralPath $SummaryFile -Value $markdown -Encoding utf8NoBOM
        Write-AzDevOpsCommand 'task.uploadsummary' (Resolve-Path -LiteralPath $SummaryFile).Path
    }
    $flag = $plan.HasChanges.ToString().ToLowerInvariant()
    Write-AzDevOpsCommand 'task.setvariable variable=hasChanges;isOutput=true' $flag
    Write-AzDevOpsCommand 'task.setvariable variable=hasChanges' $flag

    return $plan
}
