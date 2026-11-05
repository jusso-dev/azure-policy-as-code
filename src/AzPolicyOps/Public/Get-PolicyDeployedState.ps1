function Get-PolicyDeployedState {
    <#
    .SYNOPSIS
        Reads custom policy resources from Azure for an environment.
    .DESCRIPTION
        Lists custom definitions and initiatives at the definition scope, and assignments and exemptions
        at the deployment scope (including resource groups below a subscription). Also lists any extra
        scopes passed in -AdditionalScope (for example resource group scopes used by repository files when
        the deployment scope is a management group).

        Each resource is tagged with Owner: 'ThisRepo' when metadata.pacOwnerId matches the environment,
        'OtherRepo' when another pacOwnerId is set, or 'Unmanaged'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject]$Environment,
        [string[]]$AdditionalScope = @()
    )

    $resources = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    $add = {
        param($Kind, $Item)
        if (-not $Item -or -not $Item.id -or -not $seen.Add($Item.id)) { return }
        $props = if ($Item.properties) { $Item.properties } else { [ordered]@{} }
        $ownerId = if ($props.metadata -is [System.Collections.IDictionary]) { [string]$props.metadata.pacOwnerId } else { '' }
        $owner = if (-not $ownerId) { 'Unmanaged' } elseif ($ownerId -eq $Environment.PacOwnerId) { 'ThisRepo' } else { 'OtherRepo' }
        $scope = ($Item.id -split '/providers/Microsoft\.Authorization/', 2)[0]
        $resources.Add([pscustomobject]@{
                PSTypeName = 'AzPolicyOps.DeployedResource'
                Kind       = $Kind
                Name       = $Item.name
                Scope      = $scope
                Id         = $Item.id
                Owner      = $owner
                PacOwnerId = $ownerId
                Body       = $Item
            })
    }

    $definitionScope = $Environment.DefinitionScope
    $customFilter = '?$filter=' + [uri]::EscapeDataString("policyType eq 'Custom'")
    foreach ($item in (Get-PolicyRestCollection -Path "$definitionScope/providers/Microsoft.Authorization/policyDefinitions$customFilter" -ApiVersion $script:ApiVersion.PolicyDefinition)) {
        if ($item.id -like "$definitionScope/*") { & $add 'PolicyDefinition' $item }
    }
    foreach ($item in (Get-PolicyRestCollection -Path "$definitionScope/providers/Microsoft.Authorization/policySetDefinitions$customFilter" -ApiVersion $script:ApiVersion.PolicySetDefinition)) {
        if ($item.id -like "$definitionScope/*") { & $add 'PolicySetDefinition' $item }
    }

    $scopes = [System.Collections.Generic.List[string]]::new()
    $scopes.Add($Environment.DeploymentScope)
    foreach ($s in $AdditionalScope) { if ($s -and -not $scopes.Contains($s.TrimEnd('/'))) { $scopes.Add($s.TrimEnd('/')) } }

    foreach ($scope in $scopes) {
        $kind = Get-PolicyScopeKind $scope
        # At subscription scope an unfiltered list includes resource group assignments. Elsewhere use atExactScope.
        $filter = if ($kind -eq 'Subscription') { '' } else { '?$filter=' + [uri]::EscapeDataString('atExactScope()') }
        foreach ($item in (Get-PolicyRestCollection -Path "$scope/providers/Microsoft.Authorization/policyAssignments$filter" -ApiVersion $script:ApiVersion.PolicyAssignment)) {
            if ($item.id -like "$scope/*") { & $add 'PolicyAssignment' $item }
        }
        foreach ($item in (Get-PolicyRestCollection -Path "$scope/providers/Microsoft.Authorization/policyExemptions$filter" -ApiVersion $script:ApiVersion.PolicyExemption)) {
            if ($item.id -like "$scope/*") { & $add 'PolicyExemption' $item }
        }
    }

    return $resources.ToArray()
}
