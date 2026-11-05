BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'AzPolicyOps' 'AzPolicyOps.psd1') -Force
    . (Join-Path $PSScriptRoot 'FakeArm.ps1')
    $script:Fixture = Join-Path $PSScriptRoot '..' 'fixtures' 'policies'
    $script:Sub = '11111111-2222-3333-4444-555555555555'
    $script:Defs = "/subscriptions/$script:Sub/providers/Microsoft.Authorization"
    $env:UNIT_TEST_SUBSCRIPTION_ID = $script:Sub

    Mock -ModuleName AzPolicyOps Write-Host {}
    Mock -ModuleName AzPolicyOps Start-Sleep {}
    Mock -ModuleName AzPolicyOps Get-AzContext {
        [pscustomobject]@{ Account = [pscustomobject]@{ Id = 'pipeline-sp' }; Tenant = [pscustomobject]@{ Id = 'tenant-1' }; Subscription = [pscustomobject]@{ Id = '11111111-2222-3333-4444-555555555555' } }
    }
    Mock -ModuleName AzPolicyOps Invoke-AzRestMethod { Invoke-FakeArm -Method $Method -Path $Path -Uri $Uri -Payload $Payload }

    function Get-Stored([string]$Id) { $global:FakeArm.Store[$Id.ToLowerInvariant()] }
    function Get-Item([psobject]$Report, [string]$Kind, [string]$Name) { $Report.Items | Where-Object { $_.Kind -eq $Kind -and $_.Name -eq $Name } }
}

AfterAll { Remove-Item Env:UNIT_TEST_SUBSCRIPTION_ID -ErrorAction SilentlyContinue }

Describe 'Test-PolicyDrift' {
    BeforeEach {
        Reset-FakeArm
        $script:repo = Join-Path ([System.IO.Path]::GetTempPath()) ("azpolicyops-" + [guid]::NewGuid())
        Copy-Item -Path $script:Fixture -Destination $script:repo -Recurse
        $plan = New-PolicyDeploymentPlan -Path $script:repo -Environment test
        $null = Invoke-PolicyDeploymentPlan -Plan $plan -Confirm:$false
    }
    AfterEach { Remove-Item $script:repo -Recurse -Force }

    It 'reports everything in sync straight after a deploy' {
        $r = Test-PolicyDrift -Path $script:repo -Environment test
        $r.HasDrift | Should -BeFalse
        $r.Summary.InSync | Should -Be 6
        @($r.Items | Where-Object State -NE 'InSync') | Should -HaveCount 0
    }

    It 'reports a portal edit with the repository and Azure values' {
        $def = Get-Stored "$script:Defs/policyDefinitions/require-tag"
        $def.properties.displayName = 'Edited in portal'
        $def.properties.parameters.effect.defaultValue = 'Deny'
        $def.properties.metadata.updatedBy = 'someone@contoso.com'
        $def.properties.metadata.updatedOn = '2026-11-05T09:00:00Z'

        $r = Test-PolicyDrift -Path $script:repo -Environment test
        $r.HasDrift | Should -BeTrue
        $item = Get-Item $r PolicyDefinition require-tag
        $item.State | Should -Be 'Modified'
        $item.Fix | Should -Be 'Update'
        $item.LastModifiedBy | Should -Be 'someone@contoso.com'
        $item.LastModifiedOn | Should -Be '2026-11-05T09:00:00Z'
        ($item.Differences | Where-Object Path -EQ 'displayName').Repository | Should -Be "'Require tag'"
        ($item.Differences | Where-Object Path -EQ 'displayName').Azure | Should -Be "'Edited in portal'"
        ($item.Differences | Where-Object Path -EQ 'parameters.effect.defaultValue').Azure | Should -Be "'Deny'"
    }

    It 'reports assignment parameter and enforcement mode changes' {
        $asg = Get-Stored "$script:Defs/policyAssignments/baseline"
        $asg.properties.enforcementMode = 'DoNotEnforce'
        $asg.properties.parameters.locations.value = @('westus2', 'australiaeast', 'eastus')

        $item = Get-Item (Test-PolicyDrift -Path $script:repo -Environment test) PolicyAssignment baseline
        $item.State | Should -Be 'Modified'
        $item.Differences.Path | Should -Contain 'enforcementMode'
        ($item.Differences | Where-Object Path -EQ 'parameters.locations.value').Azure | Should -Be '["westus2","australiaeast","eastus"]'
    }

    It 'says a change Azure cannot make in place needs a replace' {
        $def = Get-Stored "$script:Defs/policyDefinitions/require-tag"
        $def.properties.parameters.extra = @{ type = 'String'; defaultValue = 'x' }   # added in the portal
        $item = Get-Item (Test-PolicyDrift -Path $script:repo -Environment test) PolicyDefinition require-tag
        $item.Fix | Should -Be 'Replace'
        $item.Note | Should -Match "parameter 'extra' removed"
    }

    It 'reports a resource deleted from Azure as MissingInAzure' {
        $global:FakeArm.Store.Remove("/subscriptions/$script:Sub/resourcegroups/rg-legacy/providers/microsoft.authorization/policyexemptions/baseline-waiver")
        $item = Get-Item (Test-PolicyDrift -Path $script:repo -Environment test) PolicyExemption baseline-waiver
        $item.State | Should -Be 'MissingInAzure'
        $item.Fix | Should -Be 'Create'
    }

    It 'reports a resource this repo deployed whose file was removed as NotInRepository' {
        Remove-Item (Join-Path $script:repo 'exemptions' 'baseline-waiver.json')
        $item = Get-Item (Test-PolicyDrift -Path $script:repo -Environment test) PolicyExemption baseline-waiver
        $item.State | Should -Be 'NotInRepository'
        $item.Fix | Should -Be 'Delete'
    }

    It 'reports portal-made policy as Unmanaged without counting it as drift' {
        Add-FakeArmResource -Id "$script:Defs/policyDefinitions/portal-made" -Body @{
            properties = @{ policyType = 'Custom'; mode = 'All'; displayName = 'Portal'; policyRule = @{ if = @{ field = 'type'; equals = 'x' }; then = @{ effect = 'audit' } } }
        }
        $r = Test-PolicyDrift -Path $script:repo -Environment test
        (Get-Item $r PolicyDefinition portal-made).State | Should -Be 'Unmanaged'
        $r.HasDrift | Should -BeFalse
        $r.HasUnmanaged | Should -BeTrue
        { Test-PolicyDrift -Path $script:repo -Environment test -FailOnDrift } | Should -Not -Throw
        { Test-PolicyDrift -Path $script:repo -Environment test -FailOnUnmanaged } | Should -Throw '*1 unmanaged*'
    }

    It 'ignores other owners unless asked' {
        Add-FakeArmResource -Id "$script:Defs/policyDefinitions/other-team" -Body @{
            properties = @{ policyType = 'Custom'; mode = 'All'; metadata = @{ pacOwnerId = 'other-team' }; policyRule = @{ if = @{ field = 'type'; equals = 'x' }; then = @{ effect = 'audit' } } }
        }
        (Test-PolicyDrift -Path $script:repo -Environment test).Items.Name | Should -Not -Contain 'other-team'
        (Get-Item (Test-PolicyDrift -Path $script:repo -Environment test -IncludeOtherOwners) PolicyDefinition other-team).State | Should -Be 'OtherOwner'
    }

    It 'reports a missing role assignment on a managed identity' {
        $roleKey = @($global:FakeArm.Store.Keys | Where-Object { $_ -match '/roleassignments/' })[0]
        $global:FakeArm.Store.Remove($roleKey)
        $item = Get-Item (Test-PolicyDrift -Path $script:repo -Environment test) PolicyAssignment inherit-tag
        $item.State | Should -Be 'Modified'
        $item.Note | Should -Match 'missing 1 role assignment'
    }

    It 'flags an unowned resource with the same name as drift that the deploy adopts' {
        $def = Get-Stored "$script:Defs/policyDefinitions/require-tag"
        $def.properties.metadata.Remove('pacOwnerId')
        $item = Get-Item (Test-PolicyDrift -Path $script:repo -Environment test) PolicyDefinition require-tag
        $item.State | Should -Be 'Modified'
        ($item.Differences | Where-Object Path -EQ 'metadata.pacOwnerId').Repository | Should -Be "'unit-test-owner'"
        $item.Note | Should -Match 'adopts it'
    }

    It 'fails with -FailOnDrift, and the deploy clears the drift' {
        (Get-Stored "$script:Defs/policyDefinitions/require-tag").properties.displayName = 'x'
        { Test-PolicyDrift -Path $script:repo -Environment test -FailOnDrift } | Should -Throw '*1 resource(s) drifted*'
        $plan = New-PolicyDeploymentPlan -Path $script:repo -Environment test
        $null = Invoke-PolicyDeploymentPlan -Plan $plan -Confirm:$false
        (Test-PolicyDrift -Path $script:repo -Environment test -FailOnDrift).HasDrift | Should -BeFalse
    }

    It 'changes nothing in Azure' {
        (Get-Stored "$script:Defs/policyDefinitions/require-tag").properties.displayName = 'x'
        $global:FakeArm.Calls.Clear()
        $null = Test-PolicyDrift -Path $script:repo -Environment test
        @($global:FakeArm.Calls | Where-Object Method -In 'PUT', 'DELETE', 'PATCH', 'POST') | Should -HaveCount 0
    }

    It 'writes Markdown, JUnit and JSON reports and sets the pipeline variable' {
        (Get-Stored "$script:Defs/policyDefinitions/require-tag").properties.displayName = 'x'
        $md = Join-Path $script:repo 'drift.md'; $xml = Join-Path $script:repo 'drift.xml'; $json = Join-Path $script:repo 'drift.json'
        $env:TF_BUILD = 'True'
        try { $null = Test-PolicyDrift -Path $script:repo -Environment test -MarkdownFile $md -JUnitFile $xml -JsonFile $json }
        finally { Remove-Item Env:TF_BUILD }
        Get-Content $md -Raw | Should -Match '\*\*Modified\*\* \| PolicyDefinition \| `require-tag`'
        $suite = ([xml](Get-Content $xml -Raw)).testsuites.testsuite
        $suite.tests | Should -Be '6'
        $suite.failures | Should -Be '1'
        (Get-Content $json -Raw | ConvertFrom-Json).HasDrift | Should -BeTrue
        Should -Invoke -ModuleName AzPolicyOps Write-Host -ParameterFilter { $Object -eq '##vso[task.setvariable variable=driftDetected;isOutput=true]true' }
    }
}

Describe 'Get-PolicyValueDiff' {
    It 'reports nested leaf paths' {
        InModuleScope AzPolicyOps {
            $d = Get-PolicyValueDiff -Repository @{ a = @{ b = 1; c = 2 } } -Azure @{ a = @{ b = 1; c = 3 } } -Path 'root'
            $d.Path | Should -Be 'root.a.c'
            $d.Repository | Should -Be '2'
            $d.Azure | Should -Be '3'
        }
    }
    It 'reports a key that only exists on one side' {
        InModuleScope AzPolicyOps {
            $d = Get-PolicyValueDiff -Repository @{ a = 1 } -Azure @{ a = 1; extra = 'x' } -Path 'p'
            $d.Path | Should -Be 'p.extra'
            $d.Repository | Should -Be '(not set)'
        }
    }
}
