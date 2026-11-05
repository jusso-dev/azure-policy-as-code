function Export-PolicyFromAzure {
    <#
    .SYNOPSIS
        Exports existing custom policy from Azure into repository files, to bring portal-made policy under source control.
    .DESCRIPTION
        Writes custom definitions and initiatives at -DefinitionScope, and assignments and exemptions at
        -Scope, in the repository format. System metadata (createdBy and so on) is stripped. Definition IDs
        at the definition scope are written as policyDefinitionName / policySetDefinitionName so the files
        work in every environment. Existing files are not overwritten unless -Force.

        After exporting, run New-PolicyDeploymentPlan: resources that match show as 'adopt unmanaged
        resource' updates, which stamp them with the repository's pacOwnerId.
    .EXAMPLE
        Export-PolicyFromAzure -Scope /subscriptions/$sub -OutputPath ./policies
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Scope,
        [string]$DefinitionScope,
        [Parameter(Mandatory)][string]$OutputPath,
        [switch]$IncludeOtherOwners,
        [switch]$Force
    )

    $Scope = $Scope.TrimEnd('/')
    if (-not $DefinitionScope) { $DefinitionScope = $Scope }
    $DefinitionScope = $DefinitionScope.TrimEnd('/')
    $environment = [pscustomobject]@{ PacOwnerId = '__export__'; DefinitionScope = $DefinitionScope; DeploymentScope = $Scope }
    $deployed = Get-PolicyDeployedState -Environment $environment
    if (-not $IncludeOtherOwners) { $deployed = @($deployed | Where-Object Owner -EQ 'Unmanaged') }

    $shorten = {
        param([System.Collections.IDictionary]$Container)
        $id = [string]$Container.policyDefinitionId
        $prefix = "$DefinitionScope/providers/Microsoft.Authorization/"
        if ($id -and $id.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            $rest = $id.Substring($prefix.Length)
            $type, $name = $rest -split '/', 2
            $Container.Remove('policyDefinitionId')
            if ($type -eq 'policySetDefinitions') { $Container.policySetDefinitionName = $name } else { $Container.policyDefinitionName = $name }
        }
    }

    $written = [System.Collections.Generic.List[string]]::new()
    foreach ($d in $deployed) {
        $props = [ordered]@{}
        foreach ($p in $script:ComparedProperties[$d.Kind]) {
            $value = $d.Body.properties[$p]
            if ($p -eq 'metadata' -and $value -is [System.Collections.IDictionary]) {
                $copy = [ordered]@{}
                foreach ($k in $value.Keys) { if ($k -notin $script:SystemMetadataKeys -and $k -ne 'pacOwnerId') { $copy[$k] = $value[$k] } }
                $value = $copy
            }
            $value = Remove-PolicyEmptyValue $value
            if ($null -ne $value) { $props[$p] = $value }
        }

        $doc = [ordered]@{ name = $d.Name }
        $folder = switch ($d.Kind) {
            'PolicyDefinition' { 'definitions' }
            'PolicySetDefinition' {
                foreach ($m in $props.policyDefinitions) { & $shorten $m }
                'initiatives'
            }
            'PolicyAssignment' {
                & $shorten $props
                if ($d.Scope -ne $Scope) { $doc.scope = $d.Scope }
                if ($d.Body.identity -and $d.Body.identity.type -and $d.Body.identity.type -ne 'None') {
                    $doc.identity = [ordered]@{ type = $d.Body.identity.type }
                    if ($d.Body.identity.userAssignedIdentities) { $doc.identity.userAssignedIdentities = [ordered]@{}; foreach ($k in $d.Body.identity.userAssignedIdentities.Keys) { $doc.identity.userAssignedIdentities[$k] = @{} } }
                    $doc.location = $d.Body.location
                }
                'assignments'
            }
            'PolicyExemption' {
                if ($d.Scope -ne $Scope) { $doc.scope = $d.Scope }
                'exemptions'
            }
        }
        $doc.properties = $props

        $dir = Join-Path $OutputPath $folder
        $file = Join-Path $dir "$($d.Name -replace '[^A-Za-z0-9._-]', '_').json"
        if ((Test-Path -LiteralPath $file) -and -not $Force) { Write-PolicyLog "Skipping $file (exists; use -Force)." -Level Warning; continue }
        if ($PSCmdlet.ShouldProcess($file, "Export $($d.Kind) $($d.Name)")) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            ConvertTo-Json -InputObject $doc -Depth 100 | Set-Content -LiteralPath $file -Encoding utf8NoBOM
            $written.Add($file)
        }
    }
    Write-PolicyLog "Exported $($written.Count) file(s) to $OutputPath."
    return $written.ToArray()
}
