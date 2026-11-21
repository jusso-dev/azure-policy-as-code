BeforeAll {
    $script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
    $script:PolicyRoot = Join-Path $script:RepoRoot 'policies'
    $script:ManifestPath = Join-Path $script:RepoRoot 'src' 'AzPolicyOps' 'AzPolicyOps.psd1'
    Import-Module $script:ManifestPath -Force
}

Describe 'Policy JSON files' {
    $policyJsonFiles = @(Get-ChildItem -Path (Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path 'policies') -Recurse -File -Filter '*.json' | Sort-Object FullName)

    It 'parses <Name> as valid JSON' -ForEach ($policyJsonFiles | ForEach-Object { @{ Name = $_.Name; FullName = $_.FullName } }) {
        $raw = Get-Content -LiteralPath $FullName -Raw
        { $raw | ConvertFrom-Json -AsHashtable -Depth 100 } | Should -Not -Throw
    }
}

Describe 'Policy definition JSON files' {
    $definitionFiles = @(Get-ChildItem -Path (Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path 'policies' 'definitions') -Recurse -File -Filter '*.json' | Sort-Object FullName)

    It '<Name> has required fields and valid parameters' -ForEach ($definitionFiles | ForEach-Object { @{ Name = $_.Name; FullName = $_.FullName } }) {
        $doc = Get-Content -LiteralPath $FullName -Raw | ConvertFrom-Json -AsHashtable -Depth 100
        $doc.name | Should -Not -BeNullOrEmpty
        $props = $doc.properties
        $props | Should -Not -BeNullOrEmpty
        $props.displayName | Should -Not -BeNullOrEmpty
        $props.mode | Should -BeIn @('All', 'Indexed')
        $props.policyRule | Should -Not -BeNullOrEmpty
        $props.policyRule.Contains('if') | Should -BeTrue
        $props.policyRule.Contains('then') | Should -BeTrue

        if ($props.parameters) {
            $validTypes = @('String', 'Array', 'Object', 'Boolean', 'Integer', 'Float', 'DateTime')
            foreach ($paramName in $props.parameters.Keys) {
                $paramDef = $props.parameters[$paramName]
                $paramDef.type | Should -BeIn $validTypes
                if ($paramDef.Contains('defaultValue') -and $paramDef.allowedValues) {
                    $paramDef.allowedValues | Should -Contain $paramDef.defaultValue
                }
            }
        }

        $issues = InModuleScope AzPolicyOps -Parameters @{ Properties = $props; File = $Name } {
            param($Properties, $File)
            Test-PolicyDefinitionDocument -Properties $Properties -File $File
        }
        @($issues | Where-Object Severity -In 'Error', 'Warning') | Should -HaveCount 0
    }
}

Describe 'PowerShell module and scripts' {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
    $psFiles = @(
        Get-ChildItem -Path (Join-Path $repoRoot 'src'), (Join-Path $repoRoot 'scripts') -Recurse -File -Include '*.ps1', '*.psm1', '*.psd1' |
            Sort-Object FullName
    )

    It 'parses <RelativePath> without syntax errors' -ForEach ($psFiles | ForEach-Object {
            @{
                RelativePath = [System.IO.Path]::GetRelativePath($repoRoot, $_.FullName).Replace('\', '/')
                FullName     = $_.FullName
            }
        }) {
        $tokens = $null
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($FullName, [ref]$tokens, [ref]$errors)
        $errors | Should -HaveCount 0
    }

    It 'validates and imports AzPolicyOps module without error' {
        { Test-ModuleManifest -Path $script:ManifestPath -ErrorAction Stop } | Should -Not -Throw
        { Import-Module $script:ManifestPath -Force -ErrorAction Stop } | Should -Not -Throw
        Get-Module -Name AzPolicyOps | Should -Not -BeNullOrEmpty
    }
}
