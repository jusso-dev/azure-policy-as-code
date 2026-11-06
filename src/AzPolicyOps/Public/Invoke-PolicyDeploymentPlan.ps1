function Invoke-PolicyDeploymentPlan {
    <#
    .SYNOPSIS
        Applies a plan made by New-PolicyDeploymentPlan.
    .DESCRIPTION
        Runs in two passes so dependencies are respected:
          1. Remove, newest dependants first: exemptions, assignments (and their role assignments),
             initiatives, definitions. Covers Delete and the first half of Replace.
          2. Write, dependencies first: definitions, initiatives, assignments, exemptions, then the role
             assignments managed identities need. Covers Create, Update and the second half of Replace.

        Before changing anything it re-reads every resource in the plan. If Azure changed after the plan
        was made (someone edited a policy in the portal, or another run deployed first) it stops, unless
        -Force. This is what makes it safe to plan in one stage, approve, and deploy in a later stage.

        Supports -WhatIf. Stops at the first failure and reports what was and was not applied.
    .EXAMPLE
        Invoke-PolicyDeploymentPlan -Plan $(Pipeline.Workspace)/plan/plan.json
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        # A plan object or the path of a plan JSON file.
        [Parameter(Mandatory)]$Plan,
        [switch]$Force,
        [ValidateRange(0, 3600)][int]$RoleAssignmentWaitSeconds = 300
    )

    $Plan = Read-PolicyPlan -Plan $Plan
    $context = Get-AzContext
    if (-not $context) { throw 'Not signed in to Azure.' }
    if ($Plan.TenantId -and $context.Tenant.Id -ne $Plan.TenantId) {
        throw "The plan was made for tenant $($Plan.TenantId) but the current context is tenant $($context.Tenant.Id)."
    }

    $results = [System.Collections.Generic.List[object]]::new()
    $pending = @($Plan.Actions | Where-Object Operation -NE 'NoChange')
    Write-PolicyLog "Applying plan for '$($Plan.Environment)' ($($Plan.CreatedAt)): $($pending.Count) change(s)" -Level Section
    if ($pending.Count -eq 0) {
        Write-PolicyLog 'Nothing to do.'
        return [pscustomobject]@{ PSTypeName = 'AzPolicyOps.DeploymentResult'; Environment = $Plan.Environment; Succeeded = $true; Results = @() }
    }

    # 1. Drift check.
    $drift = [System.Collections.Generic.List[string]]::new()
    foreach ($a in $pending) {
        $info = Get-PolicyResourceKindInfo -Kind $a.Kind
        $current = Invoke-PolicyRestMethod -Method GET -Path $a.Id -ApiVersion $info.ApiVersion -AllowNotFound
        $fingerprint = Get-PolicyStateFingerprint -Kind $a.Kind -Body $current
        if ($fingerprint -ne $a.DeployedFingerprint) {
            $drift.Add("$($a.Kind) '$($a.Name)': expected $(if ($a.DeployedFingerprint -eq 'absent') { 'not to exist' } else { 'the state seen at plan time' }), found $(if ($fingerprint -eq 'absent') { 'it missing' } else { 'a different state' }).")
        }
    }
    if ($drift.Count) {
        $drift | ForEach-Object { Write-PolicyLog $_ -Level Warning }
        if (-not $Force) { throw "Azure changed after the plan was made ($($drift.Count) resource(s)). Re-run the plan, or use -Force to apply anyway." }
    }

    $record = {
        param($Action, $Step, $Status, $Message)
        $results.Add([pscustomobject]@{ Kind = $Action.Kind; Name = $Action.Name; Operation = $Action.Operation; Step = $Step; Status = $Status; Message = $Message })
    }

    $failed = $false
    try {
        # 2. Removal pass.
        $removals = @($pending | Where-Object Operation -In 'Delete', 'Replace' | Sort-Object { - $script:KindOrder[$_.Kind] }, Name)
        foreach ($a in $removals) {
            $info = Get-PolicyResourceKindInfo -Kind $a.Kind
            if (-not $PSCmdlet.ShouldProcess($a.Id, "Delete $($a.Kind)$(if ($a.Operation -eq 'Replace') { ' (replace)' })")) { & $record $a 'Delete' 'Skipped' 'WhatIf'; continue }

            if ($a.Kind -eq 'PolicyAssignment' -and $a.DeployedPrincipalId) {
                foreach ($ra in (Get-PolicyPrincipalRoleAssignment -PrincipalId $a.DeployedPrincipalId -Scope (@($a.Scope) + @($a.RoleAssignments.Scope | Where-Object { $_ })))) {
                    Invoke-PolicyRestMethod -Method DELETE -Path $ra.id -ApiVersion $script:ApiVersion.RoleAssignment -AllowNotFound | Out-Null
                    Write-PolicyLog "  removed role assignment $($ra.name) from the assignment identity" -Level Detail
                }
            }
            Invoke-PolicyRestMethod -Method DELETE -Path $a.Id -ApiVersion $info.ApiVersion -AllowNotFound | Out-Null
            Write-PolicyLog "  deleted  $($a.Kind) $($a.Name)"
            & $record $a 'Delete' 'Succeeded' $null
        }

        # 3. Write pass.
        $writes = @($pending | Where-Object Operation -In 'Create', 'Update', 'Replace' | Sort-Object { $script:KindOrder[$_.Kind] }, Name)
        foreach ($a in $writes) {
            $info = Get-PolicyResourceKindInfo -Kind $a.Kind
            $needsWrite = -not ($a.Operation -eq 'Update' -and @($a.Changes).Count -eq 1 -and $a.Changes[0] -eq 'roleAssignments')
            $principalId = $a.DeployedPrincipalId
            $identityChanged = $a.Kind -eq 'PolicyAssignment' -and $a.Operation -eq 'Update' -and 'identity' -in @($a.Changes)

            if ($needsWrite) {
                if (-not $PSCmdlet.ShouldProcess($a.Id, "$($a.Operation) $($a.Kind)")) { & $record $a 'Write' 'Skipped' 'WhatIf'; continue }
                $response = Invoke-PolicyRestMethod -Method PUT -Path $a.Id -ApiVersion $info.ApiVersion -Body $a.Body -RetryOnErrorCode $script:EventualConsistencyErrorCodes -MaxAttempts 8
                $newPrincipalId = if ($response) { Get-PolicyIdentityPrincipalId $response.identity }
                if ($newPrincipalId -or $identityChanged) { $principalId = $newPrincipalId }
                Write-PolicyLog ("  {0,-8} {1} {2}" -f $a.Operation.ToLowerInvariant(), $a.Kind, $a.Name)
                & $record $a 'Write' 'Succeeded' $null
            }

            # An Update that drops or swaps the identity leaves the old principal's role assignments behind.
            if ($identityChanged -and $a.DeployedPrincipalId -and $principalId -ne $a.DeployedPrincipalId) {
                foreach ($ra in (Get-PolicyPrincipalRoleAssignment -PrincipalId $a.DeployedPrincipalId -Scope (@($a.Scope) + @($a.RoleAssignments.Scope | Where-Object { $_ })))) {
                    Invoke-PolicyRestMethod -Method DELETE -Path $ra.id -ApiVersion $script:ApiVersion.RoleAssignment -AllowNotFound | Out-Null
                    Write-PolicyLog "  removed role assignment $($ra.name) from the previous assignment identity" -Level Detail
                }
            }

            $missing = @($a.MissingRoleAssignments | Where-Object { $_ })
            if ($a.Kind -eq 'PolicyAssignment' -and $missing.Count) {
                if (-not $principalId) { throw "Assignment '$($a.Name)' has no managed identity principal, so its role assignments cannot be created." }
                $granted = 0
                # Invoke-PolicyRestMethod backs off 2,4,8..60s per attempt; pick the attempt count that roughly fits the wait.
                $attempts = 1; $budget = 0
                while ($attempts -lt 20 -and $budget -lt $RoleAssignmentWaitSeconds) { $budget += [Math]::Min(60, [Math]::Pow(2, $attempts)); $attempts++ }
                $attempts = [Math]::Max(2, $attempts)
                foreach ($ra in $missing) {
                    $raName = New-DeterministicGuid "$($a.Id)|$($ra.RoleDefinitionId)|$($ra.Scope)"
                    $raId = "$($ra.Scope)/providers/Microsoft.Authorization/roleAssignments/$raName"
                    if (-not $PSCmdlet.ShouldProcess($raId, "Grant role $(($ra.RoleDefinitionId -split '/')[-1]) to assignment identity")) { continue }
                    $body = @{ properties = @{
                            roleDefinitionId = $ra.RoleDefinitionId
                            principalId      = $principalId
                            principalType    = 'ServicePrincipal'
                            description      = "Azure Policy assignment $($a.Name) (managed by AzPolicyOps, $($Plan.PacOwnerId))"
                        }
                    }
                    try {
                        Invoke-PolicyRestMethod -Method PUT -Path $raId -ApiVersion $script:ApiVersion.RoleAssignment -Body $body -RetryOnErrorCode @('PrincipalNotFound') -MaxAttempts $attempts | Out-Null
                    }
                    catch {
                        if ($_.Exception.Data['ErrorCode'] -eq 'RoleAssignmentExists') { $granted++; continue }
                        if ($_.Exception.Data['StatusCode'] -eq 403) {
                            throw "Cannot grant the assignment identity its role at $($ra.Scope): the pipeline identity needs User Access Administrator or Owner there (or Role Based Access Control Administrator). $($_.Exception.Message)"
                        }
                        throw
                    }
                    Write-PolicyLog "  granted  role $(($ra.RoleDefinitionId -split '/')[-1]) at $($ra.Scope) to $($a.Name)"
                    $granted++
                }
                if ($granted) { & $record $a 'RoleAssignments' 'Succeeded' "$granted role assignment(s)" }
                else { & $record $a 'RoleAssignments' 'Skipped' 'WhatIf' }
            }
        }
    }
    catch {
        $failed = $true
        Write-PolicyLog "Deployment stopped: $($_.Exception.Message)" -Level Error
        $done = @($results | Where-Object Status -EQ 'Succeeded').Count
        Write-PolicyLog "$done step(s) completed before the failure. Re-plan and deploy again once fixed; the plan is idempotent." -Level Warning
        throw
    }
    finally {
        if (-not $failed) {
            Write-PolicyLog "Applied $(@($results | Where-Object Status -EQ 'Succeeded').Count) step(s)."
        }
    }

    [pscustomobject]@{
        PSTypeName  = 'AzPolicyOps.DeploymentResult'
        Environment = $Plan.Environment
        Succeeded   = $true
        Results     = $results.ToArray()
    }
}
