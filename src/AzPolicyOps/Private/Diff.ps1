function Format-PolicyDiffValue {
    <#
    .SYNOPSIS
        Short, single-line rendering of a value for drift reports.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()]$Value, [int]$MaxLength = 120)
    if ($null -eq $Value) { return '(not set)' }
    $text = if ($Value -is [string]) { "'$Value'" } else { ConvertTo-CanonicalJson $Value }
    if ($text.Length -gt $MaxLength) { $text = $text.Substring(0, $MaxLength - 3) + '...' }
    return $text
}

function Get-PolicyValueDiff {
    <#
    .SYNOPSIS
        Lists the leaf paths where two normalised values differ, with both values.
    .DESCRIPTION
        Walks dictionaries key by key. Arrays of the same length are compared item by item; arrays of
        different lengths are reported as one difference. Used to show exactly what drifted.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]$Repository,
        [AllowNull()]$Azure,
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxDifferences = 25
    )

    $out = [System.Collections.Generic.List[object]]::new()
    $limit = $MaxDifferences
    $walk = {
        param($Left, $Right, $At)
        if ($out.Count -ge $limit) { return }
        if (Test-PolicyValueEqual -Left $Left -Right $Right) { return }
        if ($Left -is [System.Collections.IDictionary] -and $Right -is [System.Collections.IDictionary]) {
            $keys = @($Left.Keys) + @($Right.Keys) | Sort-Object -Unique
            foreach ($k in $keys) { & $walk $Left[$k] $Right[$k] "$At.$k" }
            return
        }
        $leftList = $Left -is [System.Collections.IList]
        $rightList = $Right -is [System.Collections.IList]
        if ($leftList -and $rightList -and $Left.Count -eq $Right.Count) {
            for ($i = 0; $i -lt $Left.Count; $i++) { & $walk $Left[$i] $Right[$i] "$At[$i]" }
            return
        }
        $out.Add([pscustomobject]@{ Path = $At; Repository = (Format-PolicyDiffValue $Left); Azure = (Format-PolicyDiffValue $Right) })
    }
    & $walk $Repository $Azure $Path
    return $out.ToArray()
}

function Get-PolicyResourceDiff {
    <#
    .SYNOPSIS
        Field-level differences between a repository body and the deployed resource.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Desired,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Deployed,
        [string[]]$Property = @()
    )

    $desiredProps = if ($Desired.properties) { $Desired.properties } else { @{} }
    $deployedProps = if ($Deployed.properties) { $Deployed.properties } else { @{} }
    $diffs = [System.Collections.Generic.List[object]]::new()
    foreach ($p in $Property) {
        switch ($p) {
            'identity' {
                $diffs.Add([pscustomobject]@{
                        Path       = 'identity.type'
                        Repository = Format-PolicyDiffValue $(if ($Desired.identity) { $Desired.identity.type } else { 'None' })
                        Azure      = Format-PolicyDiffValue $(if ($Deployed.identity) { $Deployed.identity.type } else { 'None' })
                    })
            }
            'location' { $diffs.Add([pscustomobject]@{ Path = 'location'; Repository = Format-PolicyDiffValue $Desired.location; Azure = Format-PolicyDiffValue $Deployed.location }) }
            'roleAssignments' { }
            default {
                $left = Get-PolicyComparableProperty -Property $p -Properties $desiredProps -DesiredProperties $desiredProps
                $right = Get-PolicyComparableProperty -Property $p -Properties $deployedProps -DesiredProperties $desiredProps
                foreach ($d in (Get-PolicyValueDiff -Repository $left -Azure $right -Path $p)) { $diffs.Add($d) }
            }
        }
    }
    return $diffs.ToArray()
}

function Get-PolicyLastModified {
    <#
    .SYNOPSIS
        Who last changed a deployed resource and when, from systemData or Azure's policy metadata.
    #>
    [CmdletBinding()]
    param([AllowNull()][System.Collections.IDictionary]$Body)
    $by = $null; $on = $null
    if ($Body) {
        if ($Body.systemData) {
            $by = if ($Body.systemData.lastModifiedBy) { $Body.systemData.lastModifiedBy } else { $Body.systemData.createdBy }
            $on = if ($Body.systemData.lastModifiedAt) { $Body.systemData.lastModifiedAt } else { $Body.systemData.createdAt }
        }
        $meta = if ($Body.properties) { $Body.properties.metadata } else { $null }
        if (-not $by -and $meta -is [System.Collections.IDictionary]) {
            $by = if ($meta.updatedBy) { $meta.updatedBy } else { $meta.createdBy }
            $on = if ($meta.updatedOn) { $meta.updatedOn } else { $meta.createdOn }
        }
    }
    if ($on -is [datetime]) { $on = $on.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    [pscustomobject]@{ By = [string]$by; On = [string]$on }
}
