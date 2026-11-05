function Test-PolicyRepository {
    <#
    .SYNOPSIS
        Offline validation of the policy repository for one or more environments. No Azure sign-in needed.
    .DESCRIPTION
        Checks JSON syntax, names, required fields, parameters against definitions, effects, tokens,
        managed identity requirements and references between files. Runs in the pipeline's Validate stage
        and in pull request builds.

        Returns the issues found. With -PassThru:$false (default) it throws when any Error is found, so the
        pipeline step fails; Warnings are logged but do not fail the build unless -TreatWarningsAsErrors.
    .EXAMPLE
        Test-PolicyRepository -Path ./policies -Environment dev, prod
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$Environment,
        [switch]$TreatWarningsAsErrors,
        [switch]$PassThru
    )

    $root = (Resolve-Path -LiteralPath $Path).Path
    if (-not $Environment) {
        $Environment = @(Get-ChildItem -LiteralPath (Join-Path $root 'environments') -Filter '*.json' -File).BaseName
        if (-not $Environment) { throw "No environment files found in '$root/environments'." }
    }

    # Environment variables referenced by environment files may not exist on a validation agent.
    # Use placeholders so structure can still be validated.
    $placeholders = @{}
    foreach ($file in (Get-ChildItem -LiteralPath (Join-Path $root 'environments') -Filter '*.json' -File)) {
        foreach ($m in [regex]::Matches((Get-Content -LiteralPath $file.FullName -Raw), '\$\{env:([A-Za-z0-9_]+)\}')) {
            $name = $m.Groups[1].Value
            if (-not [Environment]::GetEnvironmentVariable($name)) {
                $placeholders[$name] = '00000000-0000-0000-0000-000000000000'
            }
        }
    }

    $all = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($name in $placeholders.Keys) { [Environment]::SetEnvironmentVariable($name, $placeholders[$name]) }

        foreach ($envName in $Environment) {
            Write-PolicyLog "Validating environment '$envName'" -Level Section
            try {
                $state = Get-PolicyDesiredState -Path $root -Environment $envName
            }
            catch {
                $all.Add([pscustomobject]@{ PSTypeName = 'AzPolicyOps.Issue'; Severity = 'Error'; Rule = 'Environment'; File = "environments/$envName.json"; Message = $_.Exception.Message; Environment = $envName })
                continue
            }
            $counts = $state.Resources | Group-Object Kind | ForEach-Object { "$($_.Count) $($_.Name)" }
            Write-PolicyLog "  $(if ($counts) { $counts -join ', ' } else { 'no resources' })"
            foreach ($issue in $state.Issues) {
                $issue | Add-Member -NotePropertyName Environment -NotePropertyValue $envName -Force
                $all.Add($issue)
            }
        }
    }
    finally {
        foreach ($name in $placeholders.Keys) { [Environment]::SetEnvironmentVariable($name, $null) }
    }

    # The same file is often reported once per environment; collapse duplicates.
    $unique = $all | Group-Object Severity, Rule, File, Message | ForEach-Object {
        $first = $_.Group[0]
        $first | Add-Member -NotePropertyName Environment -NotePropertyValue (($_.Group.Environment | Sort-Object -Unique) -join ',') -Force -PassThru
    }

    foreach ($issue in $unique) {
        $line = "[$($issue.Rule)] $($issue.File): $($issue.Message) ($($issue.Environment))"
        switch ($issue.Severity) {
            'Error' { Write-PolicyLog $line -Level Error }
            'Warning' { Write-PolicyLog $line -Level Warning }
            default { Write-PolicyLog $line -Level Detail }
        }
    }

    $errors = @($unique | Where-Object Severity -EQ 'Error')
    $warnings = @($unique | Where-Object Severity -EQ 'Warning')
    Write-PolicyLog "Validation finished: $($errors.Count) error(s), $($warnings.Count) warning(s)."

    if ($PassThru) { return $unique }
    if ($errors.Count -or ($TreatWarningsAsErrors -and $warnings.Count)) {
        throw "Policy repository validation failed with $($errors.Count) error(s) and $($warnings.Count) warning(s)."
    }
}
