<#
.SYNOPSIS
    Drift job: compares Azure with source control for one environment. Changes nothing.
.DESCRIPTION
    Runs inside AzurePowerShell@5. Writes drift.md (run summary), drift.xml (JUnit for
    PublishTestResults@2, where each drifted resource is a failed test) and drift.json, and sets the
    output variable 'driftDetected'.

    By default the step succeeds and the Tests tab shows the drift. Use -FailOnDrift to fail the step
    instead, and -FailOnUnmanaged to also fail on custom policy created outside the pipeline.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Environment,
    [string]$PolicyPath = (Join-Path $PSScriptRoot '..' 'policies'),
    [string]$OutputPath = $(if ($env:COMMON_TESTRESULTSDIRECTORY) { $env:COMMON_TESTRESULTSDIRECTORY } else { Join-Path $PSScriptRoot '..' 'out' 'drift' }),
    [switch]$FailOnDrift,
    [switch]$FailOnUnmanaged,
    [switch]$IncludeOtherOwners,
    # Match the plan stage: use this when the deploy runs with -SkipRoleAssignments.
    [switch]$SkipRoleAssignments
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Initialize-PolicyTooling.ps1')
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

$report = Test-PolicyDrift -Path $PolicyPath -Environment $Environment `
    -MarkdownFile (Join-Path $OutputPath 'drift.md') -JUnitFile (Join-Path $OutputPath 'drift.xml') -JsonFile (Join-Path $OutputPath 'drift.json') `
    -IncludeOtherOwners:$IncludeOtherOwners -SkipRoleAssignments:$SkipRoleAssignments -FailOnDrift:$FailOnDrift -FailOnUnmanaged:$FailOnUnmanaged

if ($report.HasDrift) {
    Write-Host "##vso[task.logissue type=warning]Azure Policy in '$Environment' has drifted from source control. See the drift report on the run summary."
}
