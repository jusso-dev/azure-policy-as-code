function Get-PolicyBreakingChange {
    <#
    .SYNOPSIS
        Lists changes Azure refuses to apply in place, so the plan must delete and recreate the resource.
    .DESCRIPTION
        Verified against ARM (2023-04-01):
          - Definition / initiative parameters cannot be removed (InvalidPolicyParameterUpdate / InvalidPolicySetParameterUpdate).
          - A parameter's type cannot change.
          - A new parameter must have a defaultValue.
          - An exemption's policyAssignmentId cannot change (InvalidPolicyAssignmentIdUpdate).
        Scope moves need no rule here: scope is part of the resource ID, so they plan as a delete plus a create.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][ValidateSet('PolicyDefinition', 'PolicySetDefinition', 'PolicyAssignment', 'PolicyExemption')][string]$Kind,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Desired,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Deployed
    )

    $reasons = [System.Collections.Generic.List[string]]::new()
    $desiredProps = if ($Desired.properties) { $Desired.properties } else { @{} }
    $deployedProps = if ($Deployed.properties) { $Deployed.properties } else { @{} }

    if ($Kind -in 'PolicyDefinition', 'PolicySetDefinition') {
        $old = if ($deployedProps.parameters -is [System.Collections.IDictionary]) { $deployedProps.parameters } else { @{} }
        $new = if ($desiredProps.parameters -is [System.Collections.IDictionary]) { $desiredProps.parameters } else { @{} }
        foreach ($name in @($old.Keys)) {
            if (-not $new.Contains($name)) {
                $reasons.Add("parameter '$name' removed")
            }
            elseif ([string]$old[$name].type -ne [string]$new[$name].type) {
                $reasons.Add("parameter '$name' type $($old[$name].type) -> $($new[$name].type)")
            }
        }
        foreach ($name in @($new.Keys)) {
            if (-not $old.Contains($name) -and -not ($new[$name] -is [System.Collections.IDictionary] -and $new[$name].Contains('defaultValue'))) {
                $reasons.Add("new parameter '$name' has no defaultValue")
            }
        }
    }

    if ($Kind -eq 'PolicyExemption') {
        $a = [string]$desiredProps.policyAssignmentId
        $b = [string]$deployedProps.policyAssignmentId
        if ($a -and $b -and $a.ToLowerInvariant() -ne $b.ToLowerInvariant()) { $reasons.Add('policyAssignmentId changed') }
    }

    return [string[]]$reasons.ToArray()
}
