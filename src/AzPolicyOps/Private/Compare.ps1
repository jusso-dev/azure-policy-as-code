# Keys Azure adds to metadata on its own. Ignored unless the repo sets them explicitly.
$script:SystemMetadataKeys = @('createdBy', 'createdOn', 'updatedBy', 'updatedOn', 'assignedBy', 'parameterScopes')

$script:ComparedProperties = @{
    PolicyDefinition    = @('displayName', 'description', 'mode', 'metadata', 'parameters', 'policyRule')
    PolicySetDefinition = @('displayName', 'description', 'metadata', 'parameters', 'policyDefinitions', 'policyDefinitionGroups')
    PolicyAssignment    = @('displayName', 'description', 'policyDefinitionId', 'parameters', 'enforcementMode', 'notScopes', 'nonComplianceMessages', 'metadata')
    PolicyExemption     = @('displayName', 'description', 'policyAssignmentId', 'policyDefinitionReferenceIds', 'exemptionCategory', 'expiresOn', 'metadata')
}

function Remove-PolicyEmptyValue {
    <#
    .SYNOPSIS
        Drops nulls, empty strings, empty arrays and empty objects so "absent" and "empty" compare equal.
    #>
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()]$InputObject)

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [string]) { if ($InputObject -eq '') { return $null } else { return $InputObject } }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $out = [ordered]@{}
        foreach ($key in @($InputObject.Keys)) {
            $value = Remove-PolicyEmptyValue $InputObject[$key]
            if ($null -ne $value) { $out[$key] = $value }
        }
        if ($out.Count -eq 0) { return $null }
        return $out
    }
    if ($InputObject -is [System.Collections.IEnumerable]) {
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $InputObject) {
            $value = Remove-PolicyEmptyValue $item
            if ($null -ne $value) { $list.Add($value) }
        }
        if ($list.Count -eq 0) { return $null }
        return , $list.ToArray()
    }
    return $InputObject
}

function Get-PolicyComparableProperty {
    <#
    .SYNOPSIS
        Extracts the normalised, comparable value of one property from a desired or deployed resource.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Property,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Properties,
        [System.Collections.IDictionary]$DesiredProperties
    )

    $value = $Properties[$Property]

    switch ($Property) {
        'metadata' {
            if ($value -is [System.Collections.IDictionary]) {
                $copy = [ordered]@{}
                foreach ($key in $value.Keys) {
                    $keepSystemKey = $DesiredProperties -and $DesiredProperties.metadata -is [System.Collections.IDictionary] -and $DesiredProperties.metadata.Contains($key)
                    if ($key -in $script:SystemMetadataKeys -and -not $keepSystemKey) { continue }
                    $copy[$key] = $value[$key]
                }
                $value = $copy
            }
        }
        'enforcementMode' { if (-not $value) { $value = 'Default' } }
        'mode' { if (-not $value) { $value = 'Indexed' } }
        'policyDefinitionId' { if ($value) { $value = $value.ToLowerInvariant() } }
        'policyAssignmentId' { if ($value) { $value = $value.ToLowerInvariant() } }
        'expiresOn' {
            if ($value) {
                $parsed = [datetimeoffset]::MinValue
                if ($value -is [datetime]) { $value = ([datetimeoffset]$value).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
                elseif ([datetimeoffset]::TryParse([string]$value, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) {
                    $value = $parsed.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                }
            }
        }
        'policyDefinitions' {
            # Member order and ID casing are not significant. Azure fills in definitionVersion ("1.*.*")
            # on members that do not set it, so it only counts when the repository sets it.
            $versioned = @{}
            if ($DesiredProperties -and $DesiredProperties.policyDefinitions) {
                foreach ($m in $DesiredProperties.policyDefinitions) { if ($m.definitionVersion) { $versioned[[string]$m.policyDefinitionReferenceId] = $true } }
            }
            if ($value) {
                $value = @($value | ForEach-Object {
                        $member = [ordered]@{}
                        foreach ($key in $_.Keys) { $member[$key] = $_[$key] }
                        if ($member.policyDefinitionId) { $member.policyDefinitionId = $member.policyDefinitionId.ToLowerInvariant() }
                        if (-not $versioned.ContainsKey([string]$member.policyDefinitionReferenceId)) { $member.Remove('definitionVersion') }
                        $member
                    } | Sort-Object { $_.policyDefinitionReferenceId })
            }
        }
        'policyDefinitionReferenceIds' { if ($value) { $value = @($value | Sort-Object) } }
        'notScopes' { if ($value) { $value = @($value | ForEach-Object { $_.ToLowerInvariant().TrimEnd('/') } | Sort-Object) } }
    }

    return Remove-PolicyEmptyValue $value
}

function Compare-PolicyResource {
    <#
    .SYNOPSIS
        Returns the names of properties that differ between the desired body and the deployed resource.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][ValidateSet('PolicyDefinition', 'PolicySetDefinition', 'PolicyAssignment', 'PolicyExemption')][string]$Kind,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Desired,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Deployed
    )

    $changes = [System.Collections.Generic.List[string]]::new()
    $desiredProps = if ($Desired.properties) { $Desired.properties } else { @{} }
    $deployedProps = if ($Deployed.properties) { $Deployed.properties } else { @{} }

    foreach ($property in $script:ComparedProperties[$Kind]) {
        $left = Get-PolicyComparableProperty -Property $property -Properties $desiredProps -DesiredProperties $desiredProps
        $right = Get-PolicyComparableProperty -Property $property -Properties $deployedProps -DesiredProperties $desiredProps
        if (-not (Test-PolicyValueEqual -Left $left -Right $right)) { $changes.Add($property) }
    }

    if ($Kind -eq 'PolicyAssignment') {
        $desiredIdentity = if ($Desired.identity -and $Desired.identity.type) { $Desired.identity.type } else { 'None' }
        $deployedIdentity = if ($Deployed.identity -and $Deployed.identity.type) { $Deployed.identity.type } else { 'None' }
        if ($desiredIdentity -ne $deployedIdentity) { $changes.Add('identity') }
        if ($desiredIdentity -ne 'None' -and $deployedIdentity -ne 'None' -and $Desired.location -and $Deployed.location -and
            ($Desired.location -replace '\s', '') -ne ($Deployed.location -replace '\s', '')) {
            $changes.Add('location')
        }
    }

    return [string[]]$changes.ToArray()
}
