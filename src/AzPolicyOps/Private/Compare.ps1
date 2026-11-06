# Keys Azure adds to metadata on its own. Ignored unless the repo sets them explicitly.
$script:SystemMetadataKeys = @('createdBy', 'createdOn', 'updatedBy', 'updatedOn', 'assignedBy', 'parameterScopes')

$script:ComparedProperties = @{
    PolicyDefinition    = @('displayName', 'description', 'mode', 'metadata', 'parameters', 'policyRule')
    PolicySetDefinition = @('displayName', 'description', 'metadata', 'parameters', 'policyDefinitions', 'policyDefinitionGroups')
    PolicyAssignment    = @('displayName', 'description', 'policyDefinitionId', 'parameters', 'enforcementMode', 'notScopes', 'nonComplianceMessages', 'overrides', 'resourceSelectors', 'metadata')
    PolicyExemption     = @('displayName', 'description', 'policyAssignmentId', 'policyDefinitionReferenceIds', 'exemptionCategory', 'expiresOn', 'metadata')
}

function Remove-PolicyEmptyValue {
    <#
    .SYNOPSIS
        Treats a top-level null, empty string, empty array or empty object as absent, so "not set" and "empty" compare equal.
    .DESCRIPTION
        Only the value itself is checked, not its contents. Inside policyRule, parameters and similar trees an
        empty value is meaningful (for example "equals": "" or "defaultValue": []), so nested values are kept.
    #>
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()]$InputObject)

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [string]) { if ($InputObject -eq '') { return $null } else { return $InputObject } }
    $value = Remove-PolicyNullMember $InputObject
    if ($value -is [System.Collections.IDictionary] -and $value.Count -eq 0) { return $null }
    if ($value -is [array] -and $value.Count -eq 0) { return $null }
    if ($value -is [array]) { return , $value }
    return $value
}

function Remove-PolicyNullMember {
    <#
    .SYNOPSIS
        Recursively drops object keys whose value is null (Azure returns some unset fields as null).
        Empty strings, arrays and objects are kept: inside a policy they can be meaningful.
    #>
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()]$InputObject)
    if ($InputObject -is [System.Collections.IDictionary]) {
        $out = [ordered]@{}
        foreach ($key in @($InputObject.Keys)) {
            if ($null -ne $InputObject[$key]) { $out[$key] = Remove-PolicyNullMember $InputObject[$key] }
        }
        return $out
    }
    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        return , @(foreach ($item in $InputObject) { , (Remove-PolicyNullMember $item) })
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
                    if ($null -eq (Remove-PolicyEmptyValue $value[$key])) { continue }
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
                        # Azure may return empty groupNames/parameters on members; those mean the same as absent.
                        foreach ($key in $_.Keys) { if ($null -ne (Remove-PolicyEmptyValue $_[$key])) { $member[$key] = $_[$key] } }
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

function Get-PolicyIdentityKey {
    <#
    .SYNOPSIS
        Comparable form of an assignment identity: its type plus any user-assigned identity IDs (lowercased, sorted).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Position = 0)][AllowNull()]$Identity)
    if (-not $Identity -or -not $Identity.type -or $Identity.type -eq 'None') { return 'None' }
    $ids = @()
    if ($Identity.userAssignedIdentities -is [System.Collections.IDictionary]) {
        $ids = @($Identity.userAssignedIdentities.Keys | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object)
    }
    return (@([string]$Identity.type) + $ids) -join '|'
}

function Get-PolicyIdentityPrincipalId {
    <#
    .SYNOPSIS
        Principal ID of an assignment's managed identity: system-assigned, or the (single) user-assigned identity.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Position = 0)][AllowNull()]$Identity)
    if (-not $Identity) { return $null }
    if ($Identity.principalId) { return [string]$Identity.principalId }
    if ($Identity.userAssignedIdentities -is [System.Collections.IDictionary]) {
        foreach ($uai in $Identity.userAssignedIdentities.Values) {
            if ($uai -is [System.Collections.IDictionary] -and $uai.principalId) { return [string]$uai.principalId }
        }
    }
    return $null
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
        if (-not (Test-PolicyValueEqual -Left $left -Right $right -CaseSensitive)) { $changes.Add($property) }
    }

    if ($Kind -eq 'PolicyAssignment') {
        if ((Get-PolicyIdentityKey $Desired.identity) -ne (Get-PolicyIdentityKey $Deployed.identity)) { $changes.Add('identity') }
        $desiredIdentity = if ($Desired.identity -and $Desired.identity.type) { $Desired.identity.type } else { 'None' }
        $deployedIdentity = if ($Deployed.identity -and $Deployed.identity.type) { $Deployed.identity.type } else { 'None' }
        if ($desiredIdentity -ne 'None' -and $deployedIdentity -ne 'None' -and $Desired.location -and $Deployed.location -and
            ($Desired.location -replace '\s', '') -ne ($Deployed.location -replace '\s', '')) {
            $changes.Add('location')
        }
    }

    return [string[]]$changes.ToArray()
}
