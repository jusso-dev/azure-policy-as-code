function Test-PolicyDrift {
    <#
    .SYNOPSIS
        Compares Azure with source control and reports every difference. Read-only.
    .DESCRIPTION
        Reads the repository for one environment and the custom policy in Azure at that environment's
        scopes, then sorts every resource into one of these states:

          InSync           Azure matches the repository.
          Modified         In both, but Azure differs. Reports each changed field with the repository
                           value and the Azure value, who last changed it, and whether the fix is an
                           in-place update or a replace. Includes missing role assignments on managed
                           identities.
          MissingInAzure   In the repository, not in Azure (never deployed, or deleted outside the pipeline).
          NotInRepository  Carries this repository's pacOwnerId in Azure, but its file was removed or
                           renamed. The next deploy deletes it.
          Unmanaged        Custom policy with no pacOwnerId, so it was made in the portal, CLI or another
                           tool. The pipeline leaves it alone. Bring it under source control with
                           Export-PolicyFromAzure, or delete it.
          OtherOwner       Owned by another repository's pacOwnerId. Listed only with -IncludeOtherOwners.

        Built-in definitions are never reported. It changes nothing in Azure.

        Writes an optional Markdown report (attached to the Azure DevOps run summary) and a JUnit file
        (PublishTestResults@2 shows each resource as a test, and drift as a failure). In a pipeline it sets
        the variable driftDetected to true or false.
    .EXAMPLE
        Test-PolicyDrift -Path ./policies -Environment prod
    .EXAMPLE
        # Nightly pipeline: fail the run on drift, including policy made outside the pipeline.
        Test-PolicyDrift -Path ./policies -Environment prod -FailOnDrift -FailOnUnmanaged -MarkdownFile drift.md -JUnitFile drift.xml
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Environment,
        [string]$MarkdownFile,
        [string]$JUnitFile,
        [string]$JsonFile,
        [switch]$IncludeOtherOwners,
        [switch]$SkipRoleAssignments,
        [switch]$FailOnDrift,
        [switch]$FailOnUnmanaged
    )

    $desiredState = Get-PolicyDesiredState -Path $Path -Environment $Environment
    $envConfig = $desiredState.Environment
    $repoErrors = @($desiredState.Issues | Where-Object Severity -EQ 'Error')
    if ($repoErrors.Count) {
        $repoErrors | ForEach-Object { Write-PolicyLog "$($_.File): $($_.Message)" -Level Error }
        throw "The repository has $($repoErrors.Count) validation error(s), so drift cannot be checked. Run Test-PolicyRepository for details."
    }
    $context = Get-AzContext
    if (-not $context) { throw 'Not signed in to Azure. In Azure DevOps run this inside AzurePowerShell@5; elsewhere use Connect-PolicyPipelineAccount.' }

    Write-PolicyLog "Checking drift for '$Environment' (owner $($envConfig.PacOwnerId)) at $($envConfig.DeploymentScope)" -Level Section

    $deployed = @(Get-PolicyDeployedState -Environment $envConfig -AdditionalScope (Get-PolicyAdditionalScope -DesiredState $desiredState))
    $deployedById = @{}
    foreach ($d in $deployed) { $deployedById[$d.Id.ToLowerInvariant()] = $d }
    $desiredIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $desiredState.Resources) { [void]$desiredIds.Add($r.Id) }
    $catalog = New-PolicyDefinitionCatalog -DesiredState $desiredState -Deployed $deployed

    $items = [System.Collections.Generic.List[object]]::new()
    $newItem = {
        param($State, $Kind, $Name, $Scope, $Id, $File, $Owner, $Body, $Differences, $Fix, $Note)
        $modified = Get-PolicyLastModified -Body $Body
        [pscustomobject]@{
            PSTypeName     = 'AzPolicyOps.DriftItem'
            State          = $State
            Kind           = $Kind
            Name           = $Name
            Scope          = $Scope
            Id             = $Id
            File           = $File
            Owner          = $Owner
            Differences    = @($Differences)
            Fix            = $Fix
            Note           = $Note
            LastModifiedBy = $modified.By
            LastModifiedOn = $modified.On
        }
    }

    foreach ($r in $desiredState.Resources) {
        $d = $deployedById[$r.Id.ToLowerInvariant()]
        if (-not $d) {
            $items.Add((& $newItem 'MissingInAzure' $r.Kind $r.Name $r.Scope $r.Id $r.File $null $null @() 'Create' 'In the repository but not in Azure.'))
            continue
        }
        if ($d.Owner -eq 'OtherRepo') {
            $items.Add((& $newItem 'Modified' $r.Kind $r.Name $r.Scope $r.Id $r.File $d.PacOwnerId $d.Body @() 'Blocked' "Owned by '$($d.PacOwnerId)'. The deploy refuses to change it until the clash is resolved."))
            continue
        }

        $changed = [System.Collections.Generic.List[string]]::new()
        foreach ($c in (Compare-PolicyResource -Kind $r.Kind -Desired $r.Body -Deployed $d.Body)) { $changed.Add($c) }
        if ($d.Owner -eq 'Unmanaged' -and -not $changed.Contains('metadata')) { $changed.Add('metadata') }

        $roleNote = $null
        if ($r.Kind -eq 'PolicyAssignment' -and $r.IdentityType -ne 'None' -and -not $SkipRoleAssignments -and ($principalId = Get-PolicyIdentityPrincipalId $d.Body.identity)) {
            $required = @(Get-PolicyRequiredRole -Desired $r -Catalog $catalog)
            if ($required.Count) {
                $existing = @(Get-PolicyPrincipalRoleAssignment -PrincipalId $principalId -Scope (@($r.Scope) + @($required.Scope)))
                $missing = @($required | Where-Object { $req = $_; -not ($existing | Where-Object { Test-PolicyRoleAssignmentMatch -Required $req -Existing $_ }) })
                if ($missing.Count) {
                    $changed.Add('roleAssignments')
                    $roleNote = "Managed identity is missing $($missing.Count) role assignment(s): " + (($missing | ForEach-Object { "$(($_.RoleDefinitionId -split '/')[-1]) at $($_.Scope)" }) -join ', ')
                }
            }
        }

        if ($changed.Count -eq 0) {
            $items.Add((& $newItem 'InSync' $r.Kind $r.Name $r.Scope $r.Id $r.File $d.PacOwnerId $d.Body @() $null $null))
            continue
        }
        $differences = @(Get-PolicyResourceDiff -Desired $r.Body -Deployed $d.Body -Property $changed)
        if ($d.Owner -eq 'Unmanaged') {
            $differences = @($differences | Where-Object { $_.Path -ne 'metadata.pacOwnerId' })
            $differences += [pscustomobject]@{ Path = 'metadata.pacOwnerId'; Repository = Format-PolicyDiffValue $envConfig.PacOwnerId; Azure = '(not set)' }
        }
        $breaking = @(Get-PolicyBreakingChange -Kind $r.Kind -Desired $r.Body -Deployed $d.Body)
        $fix = if ($breaking.Count) { 'Replace' } else { 'Update' }
        $notes = @()
        if ($d.Owner -eq 'Unmanaged') { $notes += 'Exists in Azure without an owner; the next deploy adopts it.' }
        if ($breaking.Count) { $notes += 'Fix needs delete and recreate: ' + ($breaking -join '; ') }
        if ($roleNote) { $notes += $roleNote }
        $items.Add((& $newItem 'Modified' $r.Kind $r.Name $r.Scope $r.Id $r.File $d.PacOwnerId $d.Body $differences $fix ($notes -join ' ')))
    }

    foreach ($d in $deployed) {
        if ($desiredIds.Contains($d.Id)) { continue }
        switch ($d.Owner) {
            'ThisRepo' { $items.Add((& $newItem 'NotInRepository' $d.Kind $d.Name $d.Scope $d.Id $null $d.PacOwnerId $d.Body @() 'Delete' 'Deployed by this repository, but its file is gone. The next deploy deletes it.')) }
            'Unmanaged' { $items.Add((& $newItem 'Unmanaged' $d.Kind $d.Name $d.Scope $d.Id $null $null $d.Body @() 'None' 'Made outside the pipeline. Export it with Export-PolicyFromAzure to manage it here, or delete it.')) }
            'OtherRepo' { if ($IncludeOtherOwners) { $items.Add((& $newItem 'OtherOwner' $d.Kind $d.Name $d.Scope $d.Id $null $d.PacOwnerId $d.Body @() 'None' "Managed by '$($d.PacOwnerId)'.")) } }
        }
    }

    $ordered = @($items | Sort-Object { @{ Modified = 0; MissingInAzure = 1; NotInRepository = 2; Unmanaged = 3; OtherOwner = 4; InSync = 5 }[$_.State] }, { $script:KindOrder[$_.Kind] }, Name)
    $summary = [ordered]@{}
    foreach ($s in 'InSync', 'Modified', 'MissingInAzure', 'NotInRepository', 'Unmanaged', 'OtherOwner') { $summary[$s] = @($ordered | Where-Object State -EQ $s).Count }
    $driftCount = $summary.Modified + $summary.MissingInAzure + $summary.NotInRepository
    $result = [pscustomobject]@{
        PSTypeName      = 'AzPolicyOps.DriftReport'
        Environment     = $Environment
        PacOwnerId      = $envConfig.PacOwnerId
        DeploymentScope = $envConfig.DeploymentScope
        DefinitionScope = $envConfig.DefinitionScope
        CheckedAt       = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        HasDrift        = $driftCount -gt 0
        HasUnmanaged    = $summary.Unmanaged -gt 0
        Summary         = [pscustomobject]$summary
        Items           = $ordered
    }

    foreach ($i in $ordered | Where-Object State -NE 'InSync') {
        $level = if ($i.State -in 'Modified', 'MissingInAzure', 'NotInRepository') { 'Warning' } else { 'Info' }
        Write-PolicyLog ("{0,-16} {1,-20} {2}" -f $i.State, $i.Kind, $i.Name) -Level $level
        foreach ($d in $i.Differences) { Write-PolicyLog "      $($d.Path): repository $($d.Repository), Azure $($d.Azure)" }
        if ($i.Note) { Write-PolicyLog "      $($i.Note)" }
        if ($i.State -eq 'Modified' -and $i.LastModifiedBy) { Write-PolicyLog "      last changed in Azure by $($i.LastModifiedBy) at $($i.LastModifiedOn)" }
    }
    Write-PolicyLog ("Drift: {0} in sync, {1} modified, {2} missing in Azure, {3} not in repository, {4} unmanaged{5}." -f `
            $summary.InSync, $summary.Modified, $summary.MissingInAzure, $summary.NotInRepository, $summary.Unmanaged, $(if ($IncludeOtherOwners) { ", $($summary.OtherOwner) other owner" } else { '' }))

    if ($MarkdownFile) {
        Set-Content -LiteralPath $MarkdownFile -Value (ConvertTo-PolicyDriftMarkdown -Report $result) -Encoding utf8NoBOM
        Write-AzDevOpsCommand 'task.uploadsummary' (Resolve-Path -LiteralPath $MarkdownFile).Path
    }
    if ($JUnitFile) { Export-PolicyDriftJUnit -Report $result -Path $JUnitFile }
    if ($JsonFile) { ConvertTo-Json -InputObject $result -Depth 20 | Set-Content -LiteralPath $JsonFile -Encoding utf8NoBOM }

    $flag = $result.HasDrift.ToString().ToLowerInvariant()
    Write-AzDevOpsCommand 'task.setvariable variable=driftDetected;isOutput=true' $flag
    Write-AzDevOpsCommand 'task.setvariable variable=driftDetected' $flag

    $failures = @()
    if ($FailOnDrift -and $result.HasDrift) { $failures += "$driftCount resource(s) drifted from source control" }
    if ($FailOnUnmanaged -and $result.HasUnmanaged) { $failures += "$($summary.Unmanaged) unmanaged custom policy resource(s) in Azure" }
    if ($failures) { throw "Drift check failed: $($failures -join '; ')." }

    return $result
}

function ConvertTo-PolicyDriftMarkdown {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][psobject]$Report)

    $esc = { param($t) ([string]$t).Replace('|', '\|') -replace '\r?\n', ' ' }
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("## Azure Policy drift: $($Report.Environment)")
    [void]$sb.AppendLine()
    $status = if ($Report.HasDrift) { '**Drift found.** Azure does not match source control.' } else { 'Azure matches source control.' }
    [void]$sb.AppendLine("$status Owner ``$($Report.PacOwnerId)``, scope ``$($Report.DeploymentScope)``, checked $($Report.CheckedAt).")
    [void]$sb.AppendLine()
    $s = $Report.Summary
    [void]$sb.AppendLine('| In sync | Modified | Missing in Azure | Not in repository | Unmanaged |')
    [void]$sb.AppendLine('|---:|---:|---:|---:|---:|')
    [void]$sb.AppendLine("| $($s.InSync) | $($s.Modified) | $($s.MissingInAzure) | $($s.NotInRepository) | $($s.Unmanaged) |")

    $drifted = @($Report.Items | Where-Object State -NE 'InSync')
    if ($drifted.Count) {
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('| State | Type | Name | Fix | Details |')
        [void]$sb.AppendLine('|---|---|---|---|---|')
        foreach ($i in $drifted) {
            $details = @()
            foreach ($d in $i.Differences) { $details += "``$($d.Path)``: repo $(& $esc $d.Repository), Azure $(& $esc $d.Azure)" }
            if ($i.Note) { $details += (& $esc $i.Note) }
            if ($i.State -eq 'Modified' -and $i.LastModifiedBy) { $details += "last changed by $($i.LastModifiedBy) at $($i.LastModifiedOn)" }
            [void]$sb.AppendLine("| **$($i.State)** | $($i.Kind) | ``$($i.Name)`` | $($i.Fix) | $($details -join '<br>') |")
        }
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('Run the deploy pipeline to put Azure back in line with source control, or commit the Azure change to the repository if it should stay.')
    }
    return $sb.ToString()
}

function Export-PolicyDriftJUnit {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Report, [Parameter(Mandatory)][string]$Path)

    $xml = [System.Xml.XmlDocument]::new()
    $suites = $xml.AppendChild($xml.CreateElement('testsuites'))
    $suite = $suites.AppendChild($xml.CreateElement('testsuite'))
    $suite.SetAttribute('name', "Azure Policy drift ($($Report.Environment))")
    $failing = @($Report.Items | Where-Object State -In 'Modified', 'MissingInAzure', 'NotInRepository')
    $suite.SetAttribute('tests', [string]@($Report.Items).Count)
    $suite.SetAttribute('failures', [string]$failing.Count)
    foreach ($i in $Report.Items) {
        $case = $suite.AppendChild($xml.CreateElement('testcase'))
        $case.SetAttribute('classname', "AzurePolicyDrift.$($i.Kind)")
        $case.SetAttribute('name', $i.Name)
        if ($i.State -in 'Modified', 'MissingInAzure', 'NotInRepository') {
            $failure = $case.AppendChild($xml.CreateElement('failure'))
            $failure.SetAttribute('message', "$($i.State) (fix: $($i.Fix))")
            $lines = @($i.Differences | ForEach-Object { "$($_.Path): repository $($_.Repository), Azure $($_.Azure)" })
            if ($i.Note) { $lines += $i.Note }
            $lines += "Id: $($i.Id)"
            $failure.InnerText = $lines -join "`n"
        }
        elseif ($i.State -in 'Unmanaged', 'OtherOwner') {
            $skipped = $case.AppendChild($xml.CreateElement('skipped'))
            $skipped.SetAttribute('message', "$($i.State): $($i.Note)")
        }
    }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $xml.Save([System.IO.Path]::GetFullPath($Path))
}
