function Get-PolicyEnvironmentName {
    <#
    .SYNOPSIS
        Names of the environments defined under <Path>/environments (schema files excluded).
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][string]$Path)
    $dir = Join-Path $Path 'environments'
    if (-not (Test-Path -LiteralPath $dir)) { return [string[]]@() }
    return [string[]]@(Get-ChildItem -LiteralPath $dir -Filter '*.json' -File | Where-Object { $_.Name -notlike '*.schema.json' -and $_.Name -notlike '._*' } | Sort-Object Name | ForEach-Object BaseName)
}
