$script:TokenPattern = '\{\{\s*([A-Za-z0-9_.\-]+)\s*\}\}'

function Expand-PolicyToken {
    <#
    .SYNOPSIS
        Replaces {{token}} placeholders in a parsed JSON structure.
    .DESCRIPTION
        A string that is exactly one token is replaced by the token's value, which may be an array
        or object (for example "{{token.allowedLocations}}" -> ["westus2","australiaeast"]).
        Tokens embedded in longer strings are replaced with their string form.
        Unknown tokens are an error, so typos fail validation instead of reaching Azure.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][AllowNull()]$InputObject,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Tokens,
        [string]$Source = 'input'
    )

    if ($null -eq $InputObject) { return $null }

    if ($InputObject -is [string]) {
        $exact = [regex]::Match($InputObject, "^$script:TokenPattern$")
        if ($exact.Success) {
            $name = $exact.Groups[1].Value
            if (-not $Tokens.Contains($name)) { throw "Unknown token '{{$name}}' in $Source." }
            $value = $Tokens[$name]
            if ($value -is [string] -or $value -is [ValueType]) { return $value }
            return , (Copy-PolicyObject $value)
        }
        return [regex]::Replace($InputObject, $script:TokenPattern, {
                param($m)
                $name = $m.Groups[1].Value
                if (-not $Tokens.Contains($name)) { throw "Unknown token '{{$name}}' in $Source." }
                $value = $Tokens[$name]
                if ($null -ne $value -and $value -isnot [string] -and $value -isnot [ValueType]) {
                    throw "Token '{{$name}}' in $Source is an array or object and must be the whole string value."
                }
                return [string]$value
            })
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $out = [ordered]@{}
        foreach ($key in @($InputObject.Keys)) {
            $out[$key] = Expand-PolicyToken $InputObject[$key] -Tokens $Tokens -Source $Source
        }
        return $out
    }

    if ($InputObject -is [System.Collections.IEnumerable]) {
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $InputObject) { $list.Add((Expand-PolicyToken $item -Tokens $Tokens -Source $Source)) }
        return , $list.ToArray()
    }

    return $InputObject
}

function Get-PolicyTokenReference {
    <#
    .SYNOPSIS
        Lists every {{token}} name referenced in a parsed JSON structure.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Position = 0)][AllowNull()]$InputObject)

    $found = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $stack = [System.Collections.Generic.Stack[object]]::new()
    if ($null -ne $InputObject) { $stack.Push($InputObject) }
    while ($stack.Count -gt 0) {
        $node = $stack.Pop()
        if ($node -is [string]) {
            foreach ($m in [regex]::Matches($node, $script:TokenPattern)) { [void]$found.Add($m.Groups[1].Value) }
        }
        elseif ($node -is [System.Collections.IDictionary]) {
            foreach ($v in $node.Values) { if ($null -ne $v) { $stack.Push($v) } }
        }
        elseif ($node -is [System.Collections.IEnumerable]) {
            foreach ($v in $node) { if ($null -ne $v) { $stack.Push($v) } }
        }
    }
    return [string[]]@($found)
}

function Expand-EnvironmentReference {
    <#
    .SYNOPSIS
        Expands ${env:NAME} references in environment config strings, so IDs can come from pipeline variables.
    #>
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()]$InputObject, [string]$Source = 'environment config')

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [string]) {
        return [regex]::Replace($InputObject, '\$\{env:([A-Za-z0-9_]+)\}', {
                param($m)
                $value = [Environment]::GetEnvironmentVariable($m.Groups[1].Value)
                if ([string]::IsNullOrEmpty($value)) { throw "Environment variable '$($m.Groups[1].Value)' referenced in $Source is not set." }
                return $value
            })
    }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $out = [ordered]@{}
        foreach ($key in @($InputObject.Keys)) { $out[$key] = Expand-EnvironmentReference $InputObject[$key] -Source $Source }
        return $out
    }
    if ($InputObject -is [System.Collections.IEnumerable]) {
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $InputObject) { $list.Add((Expand-EnvironmentReference $item -Source $Source)) }
        return , $list.ToArray()
    }
    return $InputObject
}
