BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'AzPolicyOps' 'AzPolicyOps.psd1') -Force
    . (Join-Path $PSScriptRoot 'FakeArm.ps1')
    $script:Fixture = Join-Path $PSScriptRoot '..' 'fixtures' 'policies'
    $script:Sub = '11111111-2222-3333-4444-555555555555'
    $script:Scope = "/subscriptions/$script:Sub"
    $env:UNIT_TEST_SUBSCRIPTION_ID = $script:Sub

    Mock -ModuleName AzPolicyOps Write-Host {}
    Mock -ModuleName AzPolicyOps Start-Sleep {}
    Mock -ModuleName AzPolicyOps Get-AzContext {
        [pscustomobject]@{ Account = [pscustomobject]@{ Id = 'pipeline-sp' }; Tenant = [pscustomobject]@{ Id = 'tenant-1' }; Subscription = [pscustomobject]@{ Id = '11111111-2222-3333-4444-555555555555' } }
    }
    Mock -ModuleName AzPolicyOps Invoke-AzRestMethod { Invoke-FakeArm -Method $Method -Path $Path -Uri $Uri -Payload $Payload }

    function New-TempRepository {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) ("azpolicyops-" + [guid]::NewGuid())
        Copy-Item -Path $script:Fixture -Destination $dir -Recurse
        return $dir
    }
    function Edit-Json([string]$Path, [scriptblock]$Change) {
        $doc = Get-Content $Path -Raw | ConvertFrom-Json -AsHashtable -Depth 100
        & $Change $doc
        ConvertTo-Json $doc -Depth 100 | Set-Content $Path
    }
    function Get-Ops($Plan) {
        $h = [ordered]@{}
        foreach ($a in $Plan.Actions) { $h["$($a.Kind)/$($a.Name)"] = $a.Operation }
        return $h
    }
    function Invoke-PlanAndDeploy([string]$Repo, [switch]$SkipDelete) {
        $plan = New-PolicyDeploymentPlan -Path $Repo -Environment test -SkipDelete:$SkipDelete
        $null = Invoke-PolicyDeploymentPlan -Plan $plan -RoleAssignmentWaitSeconds 0 -Confirm:$false
        return $plan
    }
}

AfterAll { Remove-Item Env:UNIT_TEST_SUBSCRIPTION_ID -ErrorAction SilentlyContinue }

Describe 'Plan and deploy lifecycle' {
    BeforeEach {
        Reset-FakeArm
        $script:repo = New-TempRepository
    }
    AfterEach { Remove-Item $script:repo -Recurse -Force }

    It 'creates everything on first deploy, then reports no changes' {
        $plan = Invoke-PlanAndDeploy $script:repo
        $plan.Summary.Create | Should -Be 6
        $plan.HasChanges | Should -BeTrue

        $global:FakeArm.Store.Keys | Should -Contain "$script:Scope/providers/microsoft.authorization/policydefinitions/require-tag".ToLowerInvariant()
        $global:FakeArm.Store.Keys | Should -Contain "$script:Scope/resourcegroups/rg-legacy/providers/microsoft.authorization/policyexemptions/baseline-waiver".ToLowerInvariant()

        $again = New-PolicyDeploymentPlan -Path $script:repo -Environment test
        $again.HasChanges | Should -BeFalse
        $again.Summary.NoChange | Should -Be 6
    }

    It 'writes definitions before initiatives before assignments before exemptions' {
        $null = Invoke-PlanAndDeploy $script:repo
        # Role assignments are written straight after their policy assignment, so they are left out here.
        $puts = @($global:FakeArm.Calls | Where-Object { $_.Method -eq 'PUT' -and $_.Path -notmatch '/roleAssignments/' } | ForEach-Object { ($_.Path -split '\?')[0] -replace '.*/providers/Microsoft.Authorization/(\w+)/.*', '$1' })
        $order = @{ policyDefinitions = 0; policySetDefinitions = 1; policyAssignments = 2; policyExemptions = 3 }
        $ranks = $puts | ForEach-Object { $order[$_] }
        $ranks | Should -Be ($ranks | Sort-Object)
    }

    It 'grants the managed identity the roles its modify policy needs, at the assignment scope' {
        $null = Invoke-PlanAndDeploy $script:repo
        $assignment = $global:FakeArm.Store["$script:Scope/providers/microsoft.authorization/policyassignments/inherit-tag".ToLowerInvariant()]
        $assignment.identity.principalId | Should -Not -BeNullOrEmpty
        $roles = @($global:FakeArm.Store.Values | Where-Object { $_.id -match '/roleAssignments/' })
        $roles | Should -HaveCount 1
        $roles[0].properties.principalId | Should -Be $assignment.identity.principalId
        $roles[0].properties.roleDefinitionId | Should -Be "$script:Scope/providers/Microsoft.Authorization/roleDefinitions/4a9ae827-6dc8-4573-8ac7-8239d42aa03f"
        $roles[0].properties.scope | Should -Be $script:Scope
    }

    It 'restores a role assignment that was removed outside the pipeline' {
        $null = Invoke-PlanAndDeploy $script:repo
        $roleKey = @($global:FakeArm.Store.Keys | Where-Object { $_ -match '/roleassignments/' })[0]
        $global:FakeArm.Store.Remove($roleKey)
        $plan = New-PolicyDeploymentPlan -Path $script:repo -Environment test
        (Get-Ops $plan)['PolicyAssignment/inherit-tag'] | Should -Be 'Update'
        ($plan.Actions | Where-Object Name -EQ 'inherit-tag' | Where-Object Kind -EQ 'PolicyAssignment').Changes | Should -Be @('roleAssignments')
        $null = Invoke-PolicyDeploymentPlan -Plan $plan -Confirm:$false
        @($global:FakeArm.Store.Keys | Where-Object { $_ -match '/roleassignments/' }) | Should -HaveCount 1
    }

    It 'updates in place when a display name and policy rule change' {
        $null = Invoke-PlanAndDeploy $script:repo
        Edit-Json (Join-Path $script:repo 'definitions' 'require-tag.json') {
            param($d) $d.properties.displayName = 'Require tag v2'; $d.properties.policyRule.if.exists = 'true'
        }
        $plan = Invoke-PlanAndDeploy $script:repo
        $action = $plan.Actions | Where-Object { $_.Kind -eq 'PolicyDefinition' -and $_.Name -eq 'require-tag' }
        $action.Operation | Should -Be 'Update'
        $action.Changes | Should -Be @('displayName', 'policyRule')
        $plan.Summary.Update | Should -Be 1
        $global:FakeArm.Store["$script:Scope/providers/microsoft.authorization/policydefinitions/require-tag".ToLowerInvariant()].properties.displayName | Should -Be 'Require tag v2'
    }

    It 'adds a parameter with a default in place' {
        $null = Invoke-PlanAndDeploy $script:repo
        Edit-Json (Join-Path $script:repo 'definitions' 'require-tag.json') {
            param($d)
            $d.properties.parameters.tagValue = @{ type = 'String'; defaultValue = '*' }
            $d.properties.policyRule.if = @{ allOf = @($d.properties.policyRule.if, @{ value = "[parameters('tagValue')]"; notEquals = '' }) }
        }
        $plan = Invoke-PlanAndDeploy $script:repo
        (Get-Ops $plan)['PolicyDefinition/require-tag'] | Should -Be 'Update'
    }

    It 'replaces a definition when a parameter is removed, replacing its users too' {
        $null = Invoke-PlanAndDeploy $script:repo
        $before = $global:FakeArm.Store["$script:Scope/providers/microsoft.authorization/policyassignments/inherit-tag".ToLowerInvariant()].identity.principalId
        Edit-Json (Join-Path $script:repo 'definitions' 'inherit-tag.json') {
            param($d)
            $d.properties.parameters.Remove('tagName')
            $json = ConvertTo-Json $d.properties.policyRule -Depth 50
            $d.properties.policyRule = ConvertFrom-Json ($json -replace "parameters\('tagName'\)", "'costCentre'") -AsHashtable -Depth 50
        }
        Edit-Json (Join-Path $script:repo 'assignments' 'inherit-tag.json') { param($d) $d.properties.Remove('parameters') }

        $plan = New-PolicyDeploymentPlan -Path $script:repo -Environment test
        $ops = Get-Ops $plan
        $ops['PolicyDefinition/inherit-tag'] | Should -Be 'Replace'
        $ops['PolicyAssignment/inherit-tag'] | Should -Be 'Replace'
        $ops['PolicyDefinition/require-tag'] | Should -Be 'NoChange'
        ($plan.Actions | Where-Object { $_.Kind -eq 'PolicyDefinition' -and $_.Name -eq 'inherit-tag' }).Reasons | Should -Contain "parameter 'tagName' removed"

        $null = Invoke-PolicyDeploymentPlan -Plan $plan -Confirm:$false
        $after = $global:FakeArm.Store["$script:Scope/providers/microsoft.authorization/policyassignments/inherit-tag".ToLowerInvariant()]
        $after | Should -Not -BeNullOrEmpty
        $after.identity.principalId | Should -Not -Be $before
        $roles = @($global:FakeArm.Store.Values | Where-Object { $_.id -match '/roleAssignments/' })
        $roles | Should -HaveCount 1
        $roles[0].properties.principalId | Should -Be $after.identity.principalId

        (New-PolicyDeploymentPlan -Path $script:repo -Environment test).HasChanges | Should -BeFalse
    }

    It 'replaces an initiative, its assignment and the exemption when an initiative parameter type changes' {
        $null = Invoke-PlanAndDeploy $script:repo
        Edit-Json (Join-Path $script:repo 'initiatives' 'baseline.json') { param($d) $d.properties.parameters.tagName.type = 'Array' }
        $plan = New-PolicyDeploymentPlan -Path $script:repo -Environment test
        $ops = Get-Ops $plan
        $ops['PolicySetDefinition/baseline'] | Should -Be 'Replace'
        $ops['PolicyAssignment/baseline'] | Should -Be 'Replace'
    }

    It 'replaces an exemption that moves to another assignment' {
        $null = Invoke-PlanAndDeploy $script:repo
        Edit-Json (Join-Path $script:repo 'exemptions' 'baseline-waiver.json') {
            param($d) $d.properties.policyAssignmentName = 'inherit-tag'; $d.properties.Remove('policyDefinitionReferenceIds')
        }
        $plan = Invoke-PlanAndDeploy $script:repo
        (Get-Ops $plan)['PolicyExemption/baseline-waiver'] | Should -Be 'Replace'
        $global:FakeArm.Store["$script:Scope/resourcegroups/rg-legacy/providers/microsoft.authorization/policyexemptions/baseline-waiver".ToLowerInvariant()].properties.policyAssignmentId | Should -Match 'inherit-tag$'
    }

    It 'deletes resources removed from the repository, dependants first, and their role assignments' {
        $null = Invoke-PlanAndDeploy $script:repo
        Remove-Item (Join-Path $script:repo 'assignments' 'inherit-tag.json')
        Remove-Item (Join-Path $script:repo 'definitions' 'inherit-tag.json')
        $plan = New-PolicyDeploymentPlan -Path $script:repo -Environment test
        $plan.Summary.Delete | Should -Be 2
        $null = Invoke-PolicyDeploymentPlan -Plan $plan -Confirm:$false
        $deletes = @($global:FakeArm.Calls | Where-Object Method -EQ 'DELETE' | ForEach-Object { ($_.Path -split '\?')[0] })
        $deletes[0] | Should -Match '/roleAssignments/'
        $deletes[1] | Should -Match '/policyAssignments/inherit-tag$'
        $deletes[2] | Should -Match '/policyDefinitions/inherit-tag$'
        @($global:FakeArm.Store.Keys | Where-Object { $_ -match 'inherit-tag|roleassignments' }) | Should -HaveCount 0
    }

    It 'keeps removed resources with -SkipDelete and warns' {
        $null = Invoke-PlanAndDeploy $script:repo
        Remove-Item (Join-Path $script:repo 'exemptions' 'baseline-waiver.json')
        $plan = New-PolicyDeploymentPlan -Path $script:repo -Environment test -SkipDelete
        $plan.Summary.Delete | Should -Be 0
        $plan.Warnings | Should -Match 'baseline-waiver'
    }

    It 'never touches resources owned by another repository' {
        Add-FakeArmResource -Id "$script:Scope/providers/Microsoft.Authorization/policyDefinitions/someone-elses" -Body @{
            properties = @{ policyType = 'Custom'; mode = 'All'; metadata = @{ pacOwnerId = 'other-team' }; policyRule = @{ if = @{ field = 'type'; equals = 'x' }; then = @{ effect = 'audit' } } }
        }
        $plan = Invoke-PlanAndDeploy $script:repo
        $plan.Actions.Name | Should -Not -Contain 'someone-elses'
        $global:FakeArm.Store.Keys | Should -Contain "$script:Scope/providers/microsoft.authorization/policydefinitions/someone-elses"
    }

    It 'refuses a name clash with another owner unless -AllowOwnershipTakeover' {
        Add-FakeArmResource -Id "$script:Scope/providers/Microsoft.Authorization/policyDefinitions/require-tag" -Body @{
            properties = @{ policyType = 'Custom'; mode = 'All'; metadata = @{ pacOwnerId = 'other-team' }; parameters = @{ tagName = @{ type = 'String' }; effect = @{ type = 'String'; defaultValue = 'Audit' } }; policyRule = @{ if = @{ field = 'type'; equals = 'x' }; then = @{ effect = "[parameters('effect')]" } } }
        }
        { New-PolicyDeploymentPlan -Path $script:repo -Environment test } | Should -Throw '*Planning failed*'
        $plan = New-PolicyDeploymentPlan -Path $script:repo -Environment test -AllowOwnershipTakeover
        ($plan.Actions | Where-Object { $_.Kind -eq 'PolicyDefinition' -and $_.Name -eq 'require-tag' }).Reasons | Should -Contain "take ownership from 'other-team'"
    }

    It 'adopts an unmanaged resource that already matches by stamping the owner' {
        $state = Get-PolicyDesiredState -Path $script:repo -Environment test
        $def = $state.Resources | Where-Object { $_.Kind -eq 'PolicyDefinition' -and $_.Name -eq 'require-tag' }
        $body = ConvertFrom-Json (ConvertTo-Json $def.Body -Depth 50) -AsHashtable -Depth 50
        $body.properties.metadata.Remove('pacOwnerId')
        Add-FakeArmResource -Id $def.Id -Body $body
        $plan = New-PolicyDeploymentPlan -Path $script:repo -Environment test
        $a = $plan.Actions | Where-Object { $_.Kind -eq 'PolicyDefinition' -and $_.Name -eq 'require-tag' }
        $a.Operation | Should -Be 'Update'
        $a.Reasons | Should -Contain 'adopt unmanaged resource'
    }

    It 'refuses to apply a stale plan when Azure changed after planning' {
        $null = Invoke-PlanAndDeploy $script:repo
        Edit-Json (Join-Path $script:repo 'definitions' 'require-tag.json') { param($d) $d.properties.displayName = 'v2' }
        $plan = New-PolicyDeploymentPlan -Path $script:repo -Environment test
        # Someone edits the definition in the portal between plan and deploy.
        $global:FakeArm.Store["$script:Scope/providers/microsoft.authorization/policydefinitions/require-tag".ToLowerInvariant()].properties.description = 'portal edit'
        { Invoke-PolicyDeploymentPlan -Plan $plan -Confirm:$false } | Should -Throw '*Azure changed after the plan was made*'
        { Invoke-PolicyDeploymentPlan -Plan $plan -Force -Confirm:$false } | Should -Not -Throw
    }

    It 'makes no changes with -WhatIf' {
        $plan = New-PolicyDeploymentPlan -Path $script:repo -Environment test
        $null = Invoke-PolicyDeploymentPlan -Plan $plan -WhatIf
        @($global:FakeArm.Calls | Where-Object Method -In 'PUT', 'DELETE') | Should -HaveCount 0
    }

    It 'round-trips the plan through a JSON file, as between pipeline stages' {
        $file = Join-Path $script:repo 'plan.json'
        $plan = New-PolicyDeploymentPlan -Path $script:repo -Environment test -OutFile $file -SummaryFile (Join-Path $script:repo 'plan.md')
        Test-Path $file | Should -BeTrue
        Get-Content (Join-Path $script:repo 'plan.md') -Raw | Should -Match '\| 6 \| 0 \| 0 \| 0 \| 0 \|'
        $result = Invoke-PolicyDeploymentPlan -Plan $file -Confirm:$false
        $result.Succeeded | Should -BeTrue
        (New-PolicyDeploymentPlan -Path $script:repo -Environment test).HasChanges | Should -BeFalse
    }

    It 'refuses a plan made for another tenant' {
        $file = Join-Path $script:repo 'plan.json'
        $null = New-PolicyDeploymentPlan -Path $script:repo -Environment test -OutFile $file
        (Get-Content $file -Raw) -replace '"tenantId": "tenant-1"', '"tenantId": "tenant-2"' | Set-Content $file
        { Invoke-PolicyDeploymentPlan -Plan $file -Confirm:$false } | Should -Throw '*tenant-2*'
    }

    It 'fails the plan when an assignment references a definition that does not exist anywhere' {
        Set-Content (Join-Path $script:repo 'assignments' 'ghost.json') '{ "name": "ghost", "properties": { "policyDefinitionId": "/subscriptions/11111111-2222-3333-4444-555555555555/providers/Microsoft.Authorization/policyDefinitions/ghost" } }'
        { New-PolicyDeploymentPlan -Path $script:repo -Environment test } | Should -Throw '*Planning failed*'
    }

    It 'sets the Azure DevOps hasChanges output variable' {
        $env:TF_BUILD = 'True'
        try {
            $null = New-PolicyDeploymentPlan -Path $script:repo -Environment test
            Should -Invoke -ModuleName AzPolicyOps Write-Host -ParameterFilter { $Object -eq '##vso[task.setvariable variable=hasChanges;isOutput=true]true' }
        }
        finally { Remove-Item Env:TF_BUILD }
    }
}

Describe 'Invoke-PolicyRestMethod' {
    It 'retries throttled requests and then succeeds' {
        $script:attempt = 0
        Mock -ModuleName AzPolicyOps Invoke-AzRestMethod {
            $script:attempt++
            if ($script:attempt -lt 3) { return [pscustomobject]@{ StatusCode = 429; Content = '{"error":{"code":"TooManyRequests","message":"slow down"}}'; Headers = [pscustomobject]@{ RetryAfter = $null } } }
            [pscustomobject]@{ StatusCode = 200; Content = '{"ok":true}'; Headers = $null }
        }
        InModuleScope AzPolicyOps { (Invoke-PolicyRestMethod -Method GET -Path '/x' -ApiVersion '1').ok | Should -BeTrue }
        $script:attempt | Should -Be 3
    }
    It 'surfaces the ARM error code and message' {
        Mock -ModuleName AzPolicyOps Invoke-AzRestMethod { [pscustomobject]@{ StatusCode = 400; Content = '{"error":{"code":"InvalidPolicyRule","message":"bad rule"}}'; Headers = $null } }
        InModuleScope AzPolicyOps {
            try { Invoke-PolicyRestMethod -Method PUT -Path '/x' -ApiVersion '1' -Body @{}; throw 'expected failure' }
            catch {
                $_.Exception.Message | Should -Match 'InvalidPolicyRule: bad rule'
                $_.Exception.Data['ErrorCode'] | Should -Be 'InvalidPolicyRule'
            }
        }
    }
    It 'follows nextLink paging' {
        Mock -ModuleName AzPolicyOps Invoke-AzRestMethod {
            if ($Uri) { return [pscustomobject]@{ StatusCode = 200; Content = '{"value":[{"id":"b"}]}'; Headers = $null } }
            [pscustomobject]@{ StatusCode = 200; Content = '{"value":[{"id":"a"}],"nextLink":"https://management.azure.com/next?page=2"}'; Headers = $null }
        }
        InModuleScope AzPolicyOps { (Get-PolicyRestCollection -Path '/list' -ApiVersion '1').id | Should -Be @('a', 'b') }
    }
}
