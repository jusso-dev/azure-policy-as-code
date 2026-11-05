<#
.SYNOPSIS
    Deploy stage: applies the reviewed plan artifact.
.DESCRIPTION
    Runs inside AzurePowerShell@5 in a deployment job, after the environment's approval check. Applies
    exactly the plan that was reviewed; if Azure changed since then, the deploy stops and asks for a new
    plan. Optionally triggers a compliance scan of -ComplianceScope afterwards.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$PlanFile,
    [string]$ComplianceScope,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Initialize-PolicyTooling.ps1')

if (-not (Test-Path -LiteralPath $PlanFile)) { throw "Plan file '$PlanFile' not found. Was the plan artifact downloaded?" }
$result = Invoke-PolicyDeploymentPlan -Plan $PlanFile -Force:$Force -WhatIf:$WhatIfPreference
$result.Results | Format-Table Kind, Name, Operation, Step, Status -AutoSize | Out-String | Write-Host

if ($ComplianceScope -and -not $WhatIfPreference) {
    Start-PolicyComplianceScan -Scope $ComplianceScope | Out-Null
}
