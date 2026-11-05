function Get-PolicyComplianceSummary {
    <#
    .SYNOPSIS
        Reports compliance for the assignments a repository manages, and optionally fails on non-compliance.
    .DESCRIPTION
        Summarises the latest policy states per assignment at -Scope. With -PacOwnerId only assignments
        owned by that repository are reported. Writes a Markdown report (attached to the Azure DevOps run
        summary) and a JUnit XML file that the PublishTestResults@2 task can show in the Tests tab, where
        each assignment is a test and each non-compliant resource is a failure.

        -FailOnNonCompliance throws when any reported assignment has non-compliant resources, for
        audit-only gates.
    .EXAMPLE
        Get-PolicyComplianceSummary -Scope /subscriptions/$sub -PacOwnerId policy-prod -JUnitFile ./compliance.xml
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Scope,
        [string]$PacOwnerId,
        [string]$MarkdownFile,
        [string]$JUnitFile,
        [ValidateRange(1, 1000)][int]$MaxResourcesPerAssignment = 50,
        [switch]$FailOnNonCompliance
    )

    $Scope = $Scope.TrimEnd('/')
    $summary = Invoke-PolicyRestMethod -Method POST -Path "$Scope/providers/Microsoft.PolicyInsights/policyStates/latest/summarize" -ApiVersion $script:ApiVersion.PolicyStates
    $assignmentSummaries = @()
    if ($summary.value) { $assignmentSummaries = @($summary.value[0].policyAssignments) }

    $owned = $null
    if ($PacOwnerId) {
        $owned = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $kind = Get-PolicyScopeKind $Scope
        $filter = if ($kind -eq 'Subscription') { '' } else { '?$filter=' + [uri]::EscapeDataString('atScope()') }
        foreach ($a in (Get-PolicyRestCollection -Path "$Scope/providers/Microsoft.Authorization/policyAssignments$filter" -ApiVersion $script:ApiVersion.PolicyAssignment)) {
            if ($a.properties.metadata -and $a.properties.metadata.pacOwnerId -eq $PacOwnerId) { [void]$owned.Add($a.id) }
        }
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($s in $assignmentSummaries) {
        if ($owned -and -not $owned.Contains($s.policyAssignmentId)) { continue }
        $details = $s.results.resourceDetails
        $nonCompliant = [int]($details | Where-Object complianceState -EQ 'noncompliant' | Measure-Object -Property count -Sum).Sum
        $compliant = [int]($details | Where-Object complianceState -EQ 'compliant' | Measure-Object -Property count -Sum).Sum
        $exempt = [int]($details | Where-Object complianceState -EQ 'exempt' | Measure-Object -Property count -Sum).Sum
        $resources = @()
        if ($nonCompliant -gt 0) {
            $filter = [uri]::EscapeDataString("ComplianceState eq 'NonCompliant' and PolicyAssignmentId eq '$($s.policyAssignmentId)'")
            $states = Invoke-PolicyRestMethod -Method POST -Path "$Scope/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults?`$top=$MaxResourcesPerAssignment&`$filter=$filter" -ApiVersion $script:ApiVersion.PolicyStates
            $resources = @($states.value | ForEach-Object {
                    [pscustomobject]@{ ResourceId = $_.resourceId; PolicyDefinitionReferenceId = $_.policyDefinitionReferenceId; PolicyDefinitionName = $_.policyDefinitionName }
                })
        }
        $rows.Add([pscustomobject]@{
                PSTypeName         = 'AzPolicyOps.ComplianceRow'
                AssignmentId       = $s.policyAssignmentId
                AssignmentName     = ($s.policyAssignmentId -split '/')[-1]
                NonCompliant       = $nonCompliant
                Compliant          = $compliant
                Exempt             = $exempt
                NonCompliantSample = $resources
            })
    }

    $total = ($rows | Measure-Object NonCompliant -Sum).Sum
    Write-PolicyLog "Compliance at ${Scope}: $($rows.Count) assignment(s), $([int]$total) non-compliant resource(s)." -Level Section
    foreach ($r in $rows) { Write-PolicyLog ("  {0,-40} non-compliant {1,4}  compliant {2,4}  exempt {3,4}" -f $r.AssignmentName, $r.NonCompliant, $r.Compliant, $r.Exempt) }

    if ($MarkdownFile) {
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine("## Azure Policy compliance")
        [void]$sb.AppendLine()
        $ownerText = if ($PacOwnerId) { ", owner ``$PacOwnerId``" } else { '' }
        [void]$sb.AppendLine("Scope ``$Scope``$ownerText.")
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('| Assignment | Non-compliant | Compliant | Exempt |')
        [void]$sb.AppendLine('|---|---:|---:|---:|')
        foreach ($r in $rows) { [void]$sb.AppendLine("| ``$($r.AssignmentName)`` | $($r.NonCompliant) | $($r.Compliant) | $($r.Exempt) |") }
        if ($rows.Count -eq 0) { [void]$sb.AppendLine('| (no evaluated assignments yet) | | | |') }
        Set-Content -LiteralPath $MarkdownFile -Value $sb.ToString() -Encoding utf8NoBOM
        Write-AzDevOpsCommand "task.uploadsummary" (Resolve-Path -LiteralPath $MarkdownFile).Path
    }

    if ($JUnitFile) {
        $xml = [System.Xml.XmlDocument]::new()
        $suites = $xml.AppendChild($xml.CreateElement('testsuites'))
        $suite = $suites.AppendChild($xml.CreateElement('testsuite'))
        $suite.SetAttribute('name', "Azure Policy compliance $Scope")
        $suite.SetAttribute('tests', [string]$rows.Count)
        $suite.SetAttribute('failures', [string]@($rows | Where-Object NonCompliant -GT 0).Count)
        foreach ($r in $rows) {
            $case = $suite.AppendChild($xml.CreateElement('testcase'))
            $case.SetAttribute('classname', 'AzurePolicy')
            $case.SetAttribute('name', $r.AssignmentName)
            if ($r.NonCompliant -gt 0) {
                $failure = $case.AppendChild($xml.CreateElement('failure'))
                $failure.SetAttribute('message', "$($r.NonCompliant) non-compliant resource(s)")
                $failure.InnerText = ($r.NonCompliantSample | ForEach-Object { "$($_.ResourceId) [$($_.PolicyDefinitionReferenceId)$($_.PolicyDefinitionName)]" }) -join "`n"
            }
        }
        $dir = Split-Path -Parent $JUnitFile
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $xml.Save([System.IO.Path]::GetFullPath($JUnitFile))
    }

    if ($FailOnNonCompliance -and $total -gt 0) {
        throw "$([int]$total) non-compliant resource(s) found."
    }
    return $rows.ToArray()
}
