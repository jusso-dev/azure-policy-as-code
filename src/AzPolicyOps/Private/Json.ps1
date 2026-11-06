function ConvertFrom-PolicyJson {
    <#
    .SYNOPSIS
        Parses JSON to case-insensitive hashtables, keeping ISO dates as strings where the host supports it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, Position = 0)][AllowEmptyString()][string]$Json)

    if ([string]::IsNullOrWhiteSpace($Json)) { return $null }
    $params = @{ AsHashtable = $true; Depth = 100; NoEnumerate = $true }
    if ($script:ConvertFromJsonSupportsDateKind) { $params.DateKind = 'String' }
    $result = $Json | ConvertFrom-Json @params
    # The comma stops PowerShell unrolling a one-item array into a scalar on return.
    return , $result
}

function Read-PolicyJsonFile {
    <#
    .SYNOPSIS
        Reads and parses a JSON file, reporting the file name on parse failures.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    try {
        return ConvertFrom-PolicyJson -Json (Get-Content -LiteralPath $Path -Raw -ErrorAction Stop)
    }
    catch {
        throw "Invalid JSON in '$Path': $($_.Exception.Message)"
    }
}

function ConvertTo-SortedStructure {
    <#
    .SYNOPSIS
        Recursively sorts dictionary keys so two equivalent objects serialise identically.
    #>
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()]$InputObject)

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [datetime]) { return $InputObject.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $out = [ordered]@{}
        foreach ($key in ($InputObject.Keys | Sort-Object)) {
            $out[[string]$key] = ConvertTo-SortedStructure $InputObject[$key]
        }
        return $out
    }
    if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
        $out = [ordered]@{}
        foreach ($prop in ($InputObject.PSObject.Properties | Sort-Object Name)) {
            $out[$prop.Name] = ConvertTo-SortedStructure $prop.Value
        }
        return $out
    }
    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $InputObject) { $list.Add((ConvertTo-SortedStructure $item)) }
        return , $list.ToArray()
    }
    return $InputObject
}

function ConvertTo-CanonicalJson {
    <#
    .SYNOPSIS
        Serialises an object to compact JSON with sorted keys, for comparisons and fingerprints.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Position = 0)][AllowNull()]$InputObject)

    if ($null -eq $InputObject) { return 'null' }
    $sorted = ConvertTo-SortedStructure $InputObject
    return (ConvertTo-Json -InputObject $sorted -Depth 100 -Compress)
}

function Test-PolicyValueEqual {
    <#
    .SYNOPSIS
        Compares two values structurally, ignoring key order. String values compare case-insensitively
        unless -CaseSensitive, which plan and drift comparisons use so a case-only change is deployed.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()]$Left, [AllowNull()]$Right, [switch]$CaseSensitive)
    $l = ConvertTo-CanonicalJson $Left
    $r = ConvertTo-CanonicalJson $Right
    if ($CaseSensitive) { return $l -ceq $r }
    return $l -eq $r
}

function Copy-PolicyObject {
    <#
    .SYNOPSIS
        Deep copies a hashtable/array structure via JSON.
    #>
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()]$InputObject)
    if ($null -eq $InputObject) { return $null }
    $copy = ConvertFrom-PolicyJson -Json (ConvertTo-Json -InputObject $InputObject -Depth 100 -Compress)
    return , $copy
}

function Get-PolicyHash {
    <#
    .SYNOPSIS
        SHA-256 hex digest of a string.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory, Position = 0)][AllowEmptyString()][string]$Value)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    $hash = [System.Security.Cryptography.SHA256]::HashData($bytes)
    return ([System.Convert]::ToHexString($hash)).ToLowerInvariant()
}

function New-DeterministicGuid {
    <#
    .SYNOPSIS
        Builds a stable GUID from a seed string, used for idempotent role assignment names.
    #>
    [CmdletBinding()]
    [OutputType([guid])]
    param([Parameter(Mandatory, Position = 0)][string]$Seed)
    $bytes = [System.Security.Cryptography.MD5]::HashData([System.Text.Encoding]::UTF8.GetBytes($Seed.ToLowerInvariant()))
    return [guid]::new($bytes)
}
