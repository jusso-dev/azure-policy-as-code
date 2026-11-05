<#
.SYNOPSIS
    Validate stage: static analysis, unit tests and offline policy validation. No Azure sign-in.
.DESCRIPTION
    Runs PSScriptAnalyzer over the module and scripts, the Pester unit tests (results written as NUnit XML
    for PublishTestResults@2), and Test-PolicyRepository for every environment.
#>
[CmdletBinding()]
param(
    [string]$PolicyPath = (Join-Path $PSScriptRoot '..' 'policies'),
    [string]$ResultsPath = $(if ($env:COMMON_TESTRESULTSDIRECTORY) { $env:COMMON_TESTRESULTSDIRECTORY } else { Join-Path $PSScriptRoot '..' 'out' }),
    [string[]]$Environment,
    [switch]$TreatWarningsAsErrors,
    [switch]$SkipUnitTests
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Initialize-PolicyTooling.ps1') -IncludeTestTools
New-Item -ItemType Directory -Path $ResultsPath -Force | Out-Null
$root = Resolve-Path (Join-Path $PSScriptRoot '..')
$failures = @()

Write-Host '##[section]PSScriptAnalyzer'
$findings = Invoke-ScriptAnalyzer -Path (Join-Path $root 'src') -Recurse -Settings (Join-Path $root 'PSScriptAnalyzerSettings.psd1')
$findings += Invoke-ScriptAnalyzer -Path (Join-Path $root 'scripts') -Recurse -Settings (Join-Path $root 'PSScriptAnalyzerSettings.psd1')
foreach ($f in $findings) {
    $type = if ($f.Severity -eq 'Error') { 'error' } else { 'warning' }
    Write-Host "##vso[task.logissue type=$type;sourcepath=$($f.ScriptPath);linenumber=$($f.Line)]$($f.RuleName): $($f.Message)"
}
if ($findings) { $failures += "PSScriptAnalyzer: $($findings.Count) finding(s)" } else { Write-Host 'No findings.' }

if (-not $SkipUnitTests) {
    Write-Host '##[section]Pester unit tests'
    $config = New-PesterConfiguration
    $config.Run.Path = Join-Path $root 'tests' 'unit'
    $config.Run.PassThru = $true
    $config.Output.Verbosity = 'Normal'
    $config.TestResult.Enabled = $true
    $config.TestResult.OutputFormat = 'NUnitXml'
    $config.TestResult.OutputPath = Join-Path $ResultsPath 'unit-tests.xml'
    $result = Invoke-Pester -Configuration $config
    if ($result.FailedCount -gt 0) { $failures += "Unit tests: $($result.FailedCount) failed" }
}

Write-Host '##[section]Policy repository'
$issues = Test-PolicyRepository -Path $PolicyPath -Environment $Environment -PassThru
$errors = @($issues | Where-Object Severity -EQ 'Error')
$warnings = @($issues | Where-Object Severity -EQ 'Warning')
if ($errors.Count -or ($TreatWarningsAsErrors -and $warnings.Count)) { $failures += "Policy validation: $($errors.Count) error(s), $($warnings.Count) warning(s)" }

if ($failures) {
    $failures | ForEach-Object { Write-Host "##vso[task.logissue type=error]$_" }
    throw "Validation failed: $($failures -join '; ')"
}
Write-Host 'Validation passed.'
