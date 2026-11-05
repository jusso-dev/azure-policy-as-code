BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'AzPolicyOps' 'AzPolicyOps.psd1') -Force
}

Describe 'Expand-PolicyToken' {
    It 'replaces a whole-string token with an array value' {
        InModuleScope AzPolicyOps {
            $result = Expand-PolicyToken @{ value = '{{locs}}' } -Tokens @{ locs = @('a', 'b') }
            $result.value | Should -Be @('a', 'b')
            , $result.value | Should -BeOfType [object[]]
        }
    }
    It 'replaces embedded tokens inside a longer string' {
        InModuleScope AzPolicyOps {
            (Expand-PolicyToken 'Baseline ({{env}})' -Tokens @{ env = 'prod' }) | Should -Be 'Baseline (prod)'
        }
    }
    It 'throws on an unknown token' {
        InModuleScope AzPolicyOps {
            { Expand-PolicyToken '{{nope}}' -Tokens @{} -Source 'x.json' } | Should -Throw "*Unknown token '{{nope}}' in x.json*"
        }
    }
    It 'refuses to embed an array token in a longer string' {
        InModuleScope AzPolicyOps {
            { Expand-PolicyToken 'x {{locs}}' -Tokens @{ locs = @('a') } } | Should -Throw '*must be the whole string*'
        }
    }
    It 'leaves ARM expressions alone' {
        InModuleScope AzPolicyOps {
            (Expand-PolicyToken "[parameters('effect')]" -Tokens @{}) | Should -Be "[parameters('effect')]"
        }
    }
}

Describe 'Expand-EnvironmentReference' {
    It 'reads environment variables' {
        $env:AZPOLICYOPS_TEST_VALUE = 'abc'
        try {
            InModuleScope AzPolicyOps { (Expand-EnvironmentReference '/subscriptions/${env:AZPOLICYOPS_TEST_VALUE}') | Should -Be '/subscriptions/abc' }
        }
        finally { Remove-Item Env:AZPOLICYOPS_TEST_VALUE }
    }
    It 'fails clearly when the variable is missing' {
        InModuleScope AzPolicyOps { { Expand-EnvironmentReference '${env:AZPOLICYOPS_DOES_NOT_EXIST}' } | Should -Throw "*AZPOLICYOPS_DOES_NOT_EXIST*not set*" }
    }
}

Describe 'Canonical JSON and comparison' {
    It 'ignores key order' {
        InModuleScope AzPolicyOps {
            Test-PolicyValueEqual -Left ([ordered]@{ a = 1; b = @{ c = 2; d = 3 } }) -Right ([ordered]@{ b = [ordered]@{ d = 3; c = 2 }; a = 1 }) | Should -BeTrue
        }
    }
    It 'detects value changes' {
        InModuleScope AzPolicyOps { Test-PolicyValueEqual -Left @{ a = 1 } -Right @{ a = 2 } | Should -BeFalse }
    }
    It 'produces a stable deterministic GUID' {
        InModuleScope AzPolicyOps {
            (New-DeterministicGuid 'Seed') | Should -Be (New-DeterministicGuid 'seed')
            (New-DeterministicGuid 'one') | Should -Not -Be (New-DeterministicGuid 'two')
        }
    }
}

Describe 'Compare-PolicyResource' {
    BeforeAll {
        $script:desired = @{ properties = [ordered]@{
                displayName = 'X'; mode = 'All'
                parameters  = @{ effect = @{ type = 'String'; defaultValue = 'Audit' } }
                policyRule  = @{ if = @{ field = 'type'; equals = 'a' }; then = @{ effect = "[parameters('effect')]" } }
                metadata    = @{ pacOwnerId = 'o' }
            }
        }
    }
    It 'ignores system metadata Azure adds' {
        InModuleScope AzPolicyOps -Parameters @{ Desired = $script:desired } {
            param($Desired)
            $deployed = ConvertFrom-PolicyJson (ConvertTo-Json $Desired -Depth 20)
            $deployed.properties.metadata.createdBy = 'someone'
            $deployed.properties.metadata.updatedOn = '2026-01-01'
            $deployed.properties.policyType = 'Custom'
            Compare-PolicyResource -Kind PolicyDefinition -Desired $Desired -Deployed $deployed | Should -BeNullOrEmpty
        }
    }
    It 'treats a missing description and an empty one as equal' {
        InModuleScope AzPolicyOps -Parameters @{ Desired = $script:desired } {
            param($Desired)
            $deployed = ConvertFrom-PolicyJson (ConvertTo-Json $Desired -Depth 20)
            $deployed.properties.description = ''
            Compare-PolicyResource -Kind PolicyDefinition -Desired $Desired -Deployed $deployed | Should -BeNullOrEmpty
        }
    }
    It 'reports the changed properties' {
        InModuleScope AzPolicyOps -Parameters @{ Desired = $script:desired } {
            param($Desired)
            $deployed = ConvertFrom-PolicyJson (ConvertTo-Json $Desired -Depth 20)
            $deployed.properties.displayName = 'Y'
            $deployed.properties.policyRule.if.equals = 'b'
            Compare-PolicyResource -Kind PolicyDefinition -Desired $Desired -Deployed $deployed | Should -Be @('displayName', 'policyRule')
        }
    }
    It 'ignores initiative member order and ID casing' {
        InModuleScope AzPolicyOps {
            $a = @{ properties = @{ policyDefinitions = @(
                        @{ policyDefinitionReferenceId = 'one'; policyDefinitionId = '/subscriptions/S/providers/Microsoft.Authorization/policyDefinitions/A' }
                        @{ policyDefinitionReferenceId = 'two'; policyDefinitionId = '/subscriptions/s/providers/Microsoft.Authorization/policyDefinitions/b' }) }
            }
            $b = @{ properties = @{ policyDefinitions = @(
                        @{ policyDefinitionReferenceId = 'two'; policyDefinitionId = '/subscriptions/s/providers/microsoft.authorization/policydefinitions/B' }
                        @{ policyDefinitionReferenceId = 'one'; policyDefinitionId = '/subscriptions/s/providers/microsoft.authorization/policydefinitions/a' }) }
            }
            Compare-PolicyResource -Kind PolicySetDefinition -Desired $a -Deployed $b | Should -BeNullOrEmpty
        }
    }
    It 'treats a missing enforcementMode as Default' {
        InModuleScope AzPolicyOps {
            $a = @{ properties = @{ policyDefinitionId = '/x'; enforcementMode = 'Default' } }
            $b = @{ properties = @{ policyDefinitionId = '/x' } }
            Compare-PolicyResource -Kind PolicyAssignment -Desired $a -Deployed $b | Should -BeNullOrEmpty
        }
    }
    It 'detects an identity change on an assignment' {
        InModuleScope AzPolicyOps {
            $a = @{ properties = @{ policyDefinitionId = '/x' }; identity = @{ type = 'SystemAssigned' }; location = 'westus2' }
            $b = @{ properties = @{ policyDefinitionId = '/x' } }
            Compare-PolicyResource -Kind PolicyAssignment -Desired $a -Deployed $b | Should -Be @('identity')
        }
    }
}

Describe 'Get-PolicyBreakingChange' {
    It 'flags a removed parameter' {
        InModuleScope AzPolicyOps {
            $old = @{ properties = @{ parameters = @{ a = @{ type = 'String' }; b = @{ type = 'String' } } } }
            $new = @{ properties = @{ parameters = @{ a = @{ type = 'String' } } } }
            Get-PolicyBreakingChange -Kind PolicyDefinition -Desired $new -Deployed $old | Should -Be @("parameter 'b' removed")
        }
    }
    It 'flags a changed parameter type' {
        InModuleScope AzPolicyOps {
            $old = @{ properties = @{ parameters = @{ n = @{ type = 'Integer' } } } }
            $new = @{ properties = @{ parameters = @{ n = @{ type = 'String' } } } }
            Get-PolicyBreakingChange -Kind PolicySetDefinition -Desired $new -Deployed $old | Should -Match "type Integer -> String"
        }
    }
    It 'flags a new parameter without a default but allows one with a default' {
        InModuleScope AzPolicyOps {
            $old = @{ properties = @{ parameters = @{} } }
            Get-PolicyBreakingChange -Kind PolicyDefinition -Desired @{ properties = @{ parameters = @{ r = @{ type = 'String' } } } } -Deployed $old | Should -Match 'no defaultValue'
            Get-PolicyBreakingChange -Kind PolicyDefinition -Desired @{ properties = @{ parameters = @{ r = @{ type = 'String'; defaultValue = 'x' } } } } -Deployed $old | Should -BeNullOrEmpty
        }
    }
    It 'flags an exemption moved to another assignment' {
        InModuleScope AzPolicyOps {
            Get-PolicyBreakingChange -Kind PolicyExemption -Desired @{ properties = @{ policyAssignmentId = '/a' } } -Deployed @{ properties = @{ policyAssignmentId = '/b' } } | Should -Be @('policyAssignmentId changed')
        }
    }
}

Describe 'Test-PolicyDefinitionDocument' {
    It 'passes a valid definition' {
        InModuleScope AzPolicyOps {
            $p = @{ displayName = 'x'; description = 'y'; mode = 'All'
                parameters = @{ effect = @{ type = 'String'; defaultValue = 'Audit'; allowedValues = @('Audit', 'Deny') } }
                policyRule = @{ if = @{ field = 'type'; equals = 'a' }; then = @{ effect = "[parameters('effect')]" } }
            }
            @(Test-PolicyDefinitionDocument -Properties $p) | Should -HaveCount 0
        }
    }
    It 'reports undeclared and unused parameters' {
        InModuleScope AzPolicyOps {
            $p = @{ displayName = 'x'; description = 'y'
                parameters = @{ unused = @{ type = 'String' } }
                policyRule = @{ if = @{ field = "[parameters('missing')]"; equals = 'a' }; then = @{ effect = 'audit' } }
            }
            $rules = (Test-PolicyDefinitionDocument -Properties $p).Rule
            $rules | Should -Contain 'Definition.UndeclaredParameter'
            $rules | Should -Contain 'Definition.UnusedParameter'
        }
    }
    It 'reports an invalid effect' {
        InModuleScope AzPolicyOps {
            $p = @{ displayName = 'x'; description = 'y'; policyRule = @{ if = @{ field = 'type'; equals = 'a' }; then = @{ effect = 'block' } } }
            (Test-PolicyDefinitionDocument -Properties $p).Rule | Should -Contain 'Definition.Effect'
        }
    }
    It 'requires roleDefinitionIds for modify' {
        InModuleScope AzPolicyOps {
            $p = @{ displayName = 'x'; description = 'y'; policyRule = @{ if = @{ field = 'type'; equals = 'a' }; then = @{ effect = 'modify'; details = @{ operations = @() } } } }
            (Test-PolicyDefinitionDocument -Properties $p).Rule | Should -Contain 'Definition.RoleDefinitionIds'
        }
    }
    It 'rejects a default that is not an allowed value' {
        InModuleScope AzPolicyOps {
            $p = @{ displayName = 'x'; description = 'y'
                parameters = @{ effect = @{ type = 'String'; defaultValue = 'Deny'; allowedValues = @('Audit') } }
                policyRule = @{ if = @{ field = 'type'; equals = 'a' }; then = @{ effect = "[parameters('effect')]" } }
            }
            (Test-PolicyDefinitionDocument -Properties $p).Rule | Should -Contain 'Definition.DefaultNotAllowed'
        }
    }
}

Describe 'Test-PolicyResourceName' {
    It 'accepts <Name>' -TestCases @(@{ Name = 'deny-public-ip' }, @{ Name = 'a_b.c' }) {
        InModuleScope AzPolicyOps -Parameters @{ Name = $Name } { param($Name) Test-PolicyResourceName -Name $Name | Should -BeNullOrEmpty }
    }
    It 'rejects <Name>' -TestCases @(@{ Name = 'bad/name' }, @{ Name = 'ends.' }, @{ Name = '' }, @{ Name = ('x' * 65) }) {
        InModuleScope AzPolicyOps -Parameters @{ Name = $Name } { param($Name) Test-PolicyResourceName -Name $Name | Should -Not -BeNullOrEmpty }
    }
}

Describe 'Write-PolicyLog in Azure DevOps' {
    It 'writes logging commands when TF_BUILD is set' {
        $env:TF_BUILD = 'True'
        try {
            InModuleScope AzPolicyOps {
                Mock Write-Host {}
                Write-PolicyLog 'bad; thing]' -Level Error
                Should -Invoke Write-Host -ParameterFilter { $Object -eq '##vso[task.logissue type=error]bad%3B thing%5D' }
            }
        }
        finally { Remove-Item Env:TF_BUILD }
    }
}
