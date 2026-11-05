#Requires -Version 7.2
# Version 1 catches undefined variables. Higher versions throw on dot-access to missing keys of
# ordered dictionaries, and policy JSON is full of optional keys.
Set-StrictMode -Version 1.0

$script:ConvertFromJsonSupportsDateKind = (Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')

foreach ($folder in 'Private', 'Public') {
    $path = Join-Path $PSScriptRoot $folder
    # Skip AppleDouble (._*) files that macOS archives and network shares leave behind.
    foreach ($file in (Get-ChildItem -LiteralPath $path -Filter '*.ps1' -File | Where-Object Name -NotLike '._*' | Sort-Object Name)) {
        . $file.FullName
    }
}

Export-ModuleMember -Function (Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -File | Where-Object Name -NotLike '._*').BaseName
