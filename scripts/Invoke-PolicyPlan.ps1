<#
.SYNOPSIS
    Plan stage: compares the repository with Azure and saves the plan as a pipeline artifact.
.DESCRIPTION
    Runs inside AzurePowerShell@5, which has already signed in with the service connection. Writes
    plan.json and plan.md to -OutputPath, attaches plan.md to the run summary and sets the output
    variable 'hasChanges' (reference it as dependencies.<stage>.outputs['<job>.<step>.hasChanges']).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Environment,
    [string]$PolicyPath = (Join-Path $PSScriptRoot '..' 'policies'),
    [string]$OutputPath = $(if ($env:BUILD_ARTIFACTSTAGINGDIRECTORY) { Join-Path $env:BUILD_ARTIFACTSTAGINGDIRECTORY 'plan' } else { Join-Path $PSScriptRoot '..' 'out' 'plan' }),
    [switch]$SkipDelete,
    [switch]$SkipRoleAssignments,
    [switch]$AllowOwnershipTakeover
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Initialize-PolicyTooling.ps1')
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

$plan = New-PolicyDeploymentPlan -Path $PolicyPath -Environment $Environment `
    -OutFile (Join-Path $OutputPath 'plan.json') -SummaryFile (Join-Path $OutputPath 'plan.md') `
    -SkipDelete:$SkipDelete -SkipRoleAssignments:$SkipRoleAssignments -AllowOwnershipTakeover:$AllowOwnershipTakeover

if ($plan.Summary.Delete -gt 0) {
    Write-Host "##vso[task.logissue type=warning]This plan deletes $($plan.Summary.Delete) resource(s). Review plan.md before approving."
}
if ($plan.Summary.Replace -gt 0) {
    Write-Host "##vso[task.logissue type=warning]This plan replaces $($plan.Summary.Replace) resource(s) (delete then create). Compliance history for replaced assignments restarts."
}
