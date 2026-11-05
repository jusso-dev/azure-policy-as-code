BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'AzPolicyOps' 'AzPolicyOps.psd1') -Force
    $script:Fixture = Join-Path $PSScriptRoot '..' 'fixtures' 'policies'
    $script:Sub = '11111111-2222-3333-4444-555555555555'
    $env:UNIT_TEST_SUBSCRIPTION_ID = $script:Sub

    function New-TempRepository {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) ("azpolicyops-" + [guid]::NewGuid())
        Copy-Item -Path $script:Fixture -Destination $dir -Recurse
        return $dir
    }
    Mock -ModuleName AzPolicyOps Write-Host {}
}

AfterAll { Remove-Item Env:UNIT_TEST_SUBSCRIPTION_ID -ErrorAction SilentlyContinue }

Describe 'Get-PolicyEnvironment' {
    It 'loads the environment and adds built-in tokens' {
        $e = Get-PolicyEnvironment -Path $script:Fixture -Environment test
        $e.PacOwnerId | Should -Be 'unit-test-owner'
        $e.DeploymentScope | Should -Be "/subscriptions/$script:Sub"
        $e.DefinitionScope | Should -Be "/subscriptions/$script:Sub"
        $e.Tokens.subscriptionId | Should -Be $script:Sub
        $e.Tokens.environment | Should -Be 'test'
    }
    It 'lists available environments when one is missing' {
        { Get-PolicyEnvironment -Path $script:Fixture -Environment nope } | Should -Throw '*Available: test*'
    }
    It 'rejects a resource group deployment scope' {
        $repo = New-TempRepository
        Set-Content (Join-Path $repo 'environments' 'bad.json') '{ "pacOwnerId": "abc", "deploymentScope": "/subscriptions/x/resourceGroups/y" }'
        { Get-PolicyEnvironment -Path $repo -Environment bad } | Should -Throw '*management group or subscription*'
    }
}

Describe 'Get-PolicyDesiredState' {
    BeforeAll { $script:state = Get-PolicyDesiredState -Path $script:Fixture -Environment test }

    It 'loads every resource type and skips files for other environments' {
        $script:state.Issues | Where-Object Severity -EQ 'Error' | Should -BeNullOrEmpty
        ($script:state.Resources | Where-Object Kind -EQ 'PolicyDefinition').Name | Should -Be @('inherit-tag', 'require-tag')
        ($script:state.Resources | Where-Object Kind -EQ 'PolicySetDefinition').Name | Should -Be 'baseline'
        ($script:state.Resources | Where-Object Kind -EQ 'PolicyAssignment').Name | Should -Be @('baseline', 'inherit-tag')
        ($script:state.Resources | Where-Object Kind -EQ 'PolicyExemption').Name | Should -Be 'baseline-waiver'
    }
    It 'resolves short definition names to IDs at the definition scope' {
        $set = $script:state.Resources | Where-Object Kind -EQ 'PolicySetDefinition'
        $set.Body.properties.policyDefinitions[0].policyDefinitionId | Should -Be "/subscriptions/$script:Sub/providers/Microsoft.Authorization/policyDefinitions/require-tag"
        $set.Body.properties.policyDefinitions[0].Contains('policyDefinitionName') | Should -BeFalse
    }
    It 'expands tokens, including array tokens' {
        $a = $script:state.Resources | Where-Object { $_.Kind -eq 'PolicyAssignment' -and $_.Name -eq 'baseline' }
        $a.Body.properties.displayName | Should -Be 'Baseline (test)'
        $a.Body.properties.parameters.locations.value | Should -Be @('westus2', 'australiaeast')
    }
    It 'stamps pacOwnerId on every resource' {
        foreach ($r in $script:state.Resources) { $r.Body.properties.metadata.pacOwnerId | Should -Be 'unit-test-owner' }
    }
    It 'adds the managed identity location from the environment' {
        $a = $script:state.Resources | Where-Object { $_.Name -eq 'inherit-tag' -and $_.Kind -eq 'PolicyAssignment' }
        $a.Body.location | Should -Be 'westus2'
        $a.IdentityType | Should -Be 'SystemAssigned'
    }
    It 'resolves exemption assignment names and token scopes' {
        $x = $script:state.Resources | Where-Object Kind -EQ 'PolicyExemption'
        $x.Scope | Should -Be "/subscriptions/$script:Sub/resourceGroups/rg-legacy"
        $x.Body.properties.policyAssignmentId | Should -Be "/subscriptions/$script:Sub/providers/Microsoft.Authorization/policyAssignments/baseline"
    }
}

Describe 'Test-PolicyRepository' {
    It 'passes the fixture repository' {
        { Test-PolicyRepository -Path $script:Fixture } | Should -Not -Throw
    }
    It 'validates without the environment variable set, using a placeholder' {
        $saved = $env:UNIT_TEST_SUBSCRIPTION_ID
        Remove-Item Env:UNIT_TEST_SUBSCRIPTION_ID
        try { { Test-PolicyRepository -Path $script:Fixture } | Should -Not -Throw }
        finally { $env:UNIT_TEST_SUBSCRIPTION_ID = $saved }
        $env:UNIT_TEST_SUBSCRIPTION_ID | Should -Be $saved
    }
    It 'reports <Rule> for <Case>' -TestCases @(
        @{ Case = 'invalid JSON'; Rule = 'Json.Parse'; File = 'definitions/broken.json'; Content = '{ "name": ' }
        @{ Case = 'unknown token'; Rule = 'Token.Unknown'; File = 'definitions/token.json'; Content = '{ "name": "t", "properties": { "displayName": "{{missingToken}}", "policyRule": { "if": { "field": "type", "equals": "a" }, "then": { "effect": "audit" } } } }' }
        @{ Case = 'duplicate name'; Rule = 'Duplicate'; File = 'definitions/zz-dupe.json'; Content = '{ "name": "require-tag", "properties": { "displayName": "d", "policyRule": { "if": { "field": "type", "equals": "a" }, "then": { "effect": "audit" } } } }' }
        @{ Case = 'unknown assignment parameter'; Rule = 'Assignment.UnknownParameter'; File = 'assignments/extra.json'; Content = '{ "name": "extra", "properties": { "policyDefinitionName": "require-tag", "parameters": { "tagName": { "value": "a" }, "bogus": { "value": 1 } } } }' }
        @{ Case = 'missing required parameter'; Rule = 'Assignment.MissingParameter'; File = 'assignments/missing.json'; Content = '{ "name": "missing", "properties": { "policyDefinitionName": "require-tag" } }' }
        @{ Case = 'parameter not allowed'; Rule = 'Assignment.ParameterNotAllowed'; File = 'assignments/notallowed.json'; Content = '{ "name": "notallowed", "properties": { "policyDefinitionName": "require-tag", "parameters": { "tagName": { "value": "a" }, "effect": { "value": "Block" } } } }' }
        @{ Case = 'parameter without value wrapper'; Rule = 'Assignment.ParameterFormat'; File = 'assignments/format.json'; Content = '{ "name": "format", "properties": { "policyDefinitionName": "require-tag", "parameters": { "tagName": "a" } } }' }
        @{ Case = 'modify without identity'; Rule = 'Assignment.Identity'; File = 'assignments/noid.json'; Content = '{ "name": "noid", "properties": { "policyDefinitionName": "inherit-tag", "parameters": { "tagName": { "value": "a" } } } }' }
        @{ Case = 'bad enforcement mode'; Rule = 'Assignment.EnforcementMode'; File = 'assignments/mode.json'; Content = '{ "name": "mode", "properties": { "policyDefinitionName": "require-tag", "enforcementMode": "Off", "parameters": { "tagName": { "value": "a" } } } }' }
        @{ Case = 'invalid name'; Rule = 'Name'; File = 'definitions/badname.json'; Content = '{ "name": "bad/name", "properties": { "policyRule": { "if": { "field": "type", "equals": "a" }, "then": { "effect": "audit" } } } }' }
        @{ Case = 'unknown initiative reference'; Rule = 'Exemption.ReferenceId'; File = 'exemptions/badref.json'; Content = '{ "name": "badref", "properties": { "policyAssignmentName": "baseline", "policyDefinitionReferenceIds": [ "nope" ], "exemptionCategory": "Waiver" } }' }
        @{ Case = 'bad exemption category'; Rule = 'Exemption.Category'; File = 'exemptions/cat.json'; Content = '{ "name": "cat", "properties": { "policyAssignmentName": "baseline", "exemptionCategory": "Because" } }' }
        @{ Case = 'expired exemption'; Rule = 'Exemption.Expired'; File = 'exemptions/old.json'; Content = '{ "name": "old", "properties": { "policyAssignmentName": "baseline", "exemptionCategory": "Waiver", "expiresOn": "2020-01-01T00:00:00Z" } }' }
        @{ Case = 'duplicate reference id'; Rule = 'Initiative.ReferenceId'; File = 'initiatives/dupref.json'; Content = '{ "name": "dupref", "properties": { "policyDefinitions": [ { "policyDefinitionReferenceId": "x", "policyDefinitionName": "require-tag", "parameters": { "tagName": { "value": "a" } } }, { "policyDefinitionReferenceId": "x", "policyDefinitionName": "require-tag", "parameters": { "tagName": { "value": "a" } } } ] } }' }
    ) {
        $repo = New-TempRepository
        try {
            Set-Content -Path (Join-Path $repo $File) -Value $Content
            $issues = Test-PolicyRepository -Path $repo -PassThru
            $issues.Rule | Should -Contain $Rule
            ($issues | Where-Object Rule -EQ $Rule).File | Should -Contain $File
        }
        finally { Remove-Item $repo -Recurse -Force }
    }
    It 'throws when errors are found and -PassThru is not used' {
        $repo = New-TempRepository
        try {
            Set-Content -Path (Join-Path $repo 'definitions' 'broken.json') -Value '{'
            { Test-PolicyRepository -Path $repo } | Should -Throw '*validation failed*'
        }
        finally { Remove-Item $repo -Recurse -Force }
    }
    It 'fails on warnings only with -TreatWarningsAsErrors' {
        $repo = New-TempRepository
        try {
            Set-Content -Path (Join-Path $repo 'definitions' 'nodisplay.json') -Value '{ "name": "nodisplay", "properties": { "description": "d", "policyRule": { "if": { "field": "type", "equals": "a" }, "then": { "effect": "audit" } } } }'
            { Test-PolicyRepository -Path $repo } | Should -Not -Throw
            { Test-PolicyRepository -Path $repo -TreatWarningsAsErrors } | Should -Throw
        }
        finally { Remove-Item $repo -Recurse -Force }
    }
}
