function Start-PolicyRemediation {
    <#
    .SYNOPSIS
        Creates remediation tasks for non-compliant resources of deployIfNotExists and modify policies.
    .DESCRIPTION
        For each assignment owned by -PacOwnerId at -Scope (or the assignments named in -AssignmentName),
        finds deployIfNotExists/modify policies with non-compliant resources and starts one remediation
        task per policy (per initiative member). Use -Wait to poll until the tasks finish.

        Requires the assignment's managed identity to hold the roles the policy lists, which
        Invoke-PolicyDeploymentPlan grants.
    .EXAMPLE
        Start-PolicyRemediation -Scope /subscriptions/$sub -PacOwnerId policy-prod -Wait
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Scope,
        [string]$PacOwnerId,
        [string[]]$AssignmentName,
        [switch]$Wait,
        [ValidateRange(1, 240)][int]$TimeoutMinutes = 30
    )

    $Scope = $Scope.TrimEnd('/')
    if (-not $PacOwnerId -and -not $AssignmentName) { throw 'Pass -PacOwnerId or -AssignmentName so only intended assignments are remediated.' }

    $kind = Get-PolicyScopeKind $Scope
    $filter = if ($kind -eq 'Subscription') { '' } else { '?$filter=' + [uri]::EscapeDataString('atScope()') }
    $assignments = @(Get-PolicyRestCollection -Path "$Scope/providers/Microsoft.Authorization/policyAssignments$filter" -ApiVersion $script:ApiVersion.PolicyAssignment | Where-Object {
            ($PacOwnerId -and $_.properties.metadata -and $_.properties.metadata.pacOwnerId -eq $PacOwnerId) -or ($AssignmentName -and $_.name -in $AssignmentName)
        })

    $tasks = [System.Collections.Generic.List[object]]::new()
    foreach ($assignment in $assignments) {
        $stateFilter = [uri]::EscapeDataString("ComplianceState eq 'NonCompliant' and PolicyAssignmentId eq '$($assignment.id)' and (PolicyDefinitionAction eq 'deployifnotexists' or PolicyDefinitionAction eq 'modify')")
        $apply = [uri]::EscapeDataString('groupby((PolicyDefinitionReferenceId,PolicyDefinitionId))')
        $groups = Invoke-PolicyRestMethod -Method POST -Path "$Scope/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults?`$filter=$stateFilter&`$apply=$apply" -ApiVersion $script:ApiVersion.PolicyStates
        foreach ($g in @($groups.value)) {
            $refId = [string]$g.policyDefinitionReferenceId
            $suffix = if ($refId) { "-$refId" } else { '' }
            $name = ("$($assignment.name)$suffix-" + [datetime]::UtcNow.ToString('yyyyMMddHHmmss')) -replace '[^A-Za-z0-9_-]', '-'
            if ($name.Length -gt 90) { $name = $name.Substring(0, 90) }
            $path = "$Scope/providers/Microsoft.PolicyInsights/remediations/$name"
            if (-not $PSCmdlet.ShouldProcess($path, "Remediate $($assignment.name)$(if ($refId) { " / $refId" })")) { continue }
            $body = @{ properties = @{ policyAssignmentId = $assignment.id; resourceDiscoveryMode = 'ExistingNonCompliant' } }
            if ($refId) { $body.properties.policyDefinitionReferenceId = $refId }
            $result = Invoke-PolicyRestMethod -Method PUT -Path $path -ApiVersion $script:ApiVersion.Remediation -Body $body
            Write-PolicyLog "Remediation $name started for $($assignment.name)$(if ($refId) { " / $refId" })."
            $tasks.Add([pscustomobject]@{ Name = $name; Id = $path; Assignment = $assignment.name; ReferenceId = $refId; State = $result.properties.provisioningState })
        }
    }
    if ($tasks.Count -eq 0) { Write-PolicyLog 'Nothing to remediate.' }

    if ($Wait -and $tasks.Count) {
        $deadline = [datetime]::UtcNow.AddMinutes($TimeoutMinutes)
        do {
            Start-Sleep -Seconds 20
            foreach ($t in $tasks | Where-Object State -NotIn 'Succeeded', 'Failed', 'Canceled') {
                $r = Invoke-PolicyRestMethod -Method GET -Path $t.Id -ApiVersion $script:ApiVersion.Remediation
                $t.State = $r.properties.provisioningState
                $t | Add-Member -NotePropertyName Deployments -NotePropertyValue $r.properties.deploymentStatus -Force
            }
        } while (@($tasks | Where-Object State -NotIn 'Succeeded', 'Failed', 'Canceled').Count -and [datetime]::UtcNow -lt $deadline)
        foreach ($t in $tasks) { Write-PolicyLog "  $($t.Name): $($t.State)" }
        $bad = @($tasks | Where-Object State -NE 'Succeeded')
        if ($bad.Count) { throw "$($bad.Count) remediation task(s) did not succeed: $(($bad | ForEach-Object { "$($_.Name)=$($_.State)" }) -join ', ')" }
    }
    return $tasks.ToArray()
}
