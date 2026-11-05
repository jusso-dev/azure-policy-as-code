<#
.SYNOPSIS
    Compliance job: optional scan, then a report of the repository's assignments, with optional remediation.
.DESCRIPTION
    Intended for a scheduled pipeline. Writes compliance.md (run summary) and compliance.xml (JUnit, for
    PublishTestResults@2, so non-compliant assignments show as failed tests).
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Environment,
    [string]$PolicyPath = (Join-Path $PSScriptRoot '..' 'policies'),
    [string]$Scope,
    [string]$OutputPath = $(if ($env:COMMON_TESTRESULTSDIRECTORY) { $env:COMMON_TESTRESULTSDIRECTORY } else { Join-Path $PSScriptRoot '..' 'out' 'compliance' }),
    [switch]$Scan,
    [switch]$Remediate,
    [switch]$FailOnNonCompliance
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Initialize-PolicyTooling.ps1')
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

$envConfig = Get-PolicyEnvironment -Path $PolicyPath -Environment $Environment
if (-not $Scope) { $Scope = $envConfig.DeploymentScope }

if ($Scan) { Start-PolicyComplianceScan -Scope $Scope -Wait -TimeoutMinutes 60 | Out-Null }
if ($Remediate) { Start-PolicyRemediation -Scope $Scope -PacOwnerId $envConfig.PacOwnerId -Wait -WhatIf:$WhatIfPreference | Out-Null }

Get-PolicyComplianceSummary -Scope $Scope -PacOwnerId $envConfig.PacOwnerId `
    -MarkdownFile (Join-Path $OutputPath 'compliance.md') -JUnitFile (Join-Path $OutputPath 'compliance.xml') `
    -FailOnNonCompliance:$FailOnNonCompliance | Out-Null
