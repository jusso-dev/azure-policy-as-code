<#
.SYNOPSIS
    Live Azure test of the full pipeline flow: validate, plan, deploy, update, replace, delete.
.DESCRIPTION
    Runs each step the way the Azure DevOps pipeline does: the scripts in scripts/ are invoked in a
    fresh pwsh process with TF_BUILD=True, the plan is passed between steps as a JSON file, and the
    ##vso logging commands are checked.

    Needs an Az context or ARM_* variables for a service principal with Resource Policy Contributor and
    Role Based Access Control Administrator (or User Access Administrator) on the test resource group.
    Everything is created inside -TargetResourceGroup under a unique pacOwnerId and removed at the end.

      $env:INTEGRATION_RESOURCE_GROUP = 'rg-policy-lab-target'
      Invoke-Pester ./tests/integration -Output Detailed
#>

BeforeAll {
    $script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
    Import-Module (Join-Path $script:RepoRoot 'src' 'AzPolicyOps' 'AzPolicyOps.psd1') -Force

    if (-not (Get-AzContext)) { Connect-PolicyPipelineAccount | Out-Null }
    $ctx = Get-AzContext
    $script:SubscriptionId = $ctx.Subscription.Id
    $script:ResourceGroup = if ($env:INTEGRATION_RESOURCE_GROUP) { $env:INTEGRATION_RESOURCE_GROUP } else { 'rg-policy-lab-target' }
    $script:RgScope = "/subscriptions/$script:SubscriptionId/resourceGroups/$script:ResourceGroup"
    $script:RunId = 'it' + (Get-Date -Format 'MMddHHmm') + (Get-Random -Maximum 999).ToString('000')
    $script:Owner = "azpolicyops-$script:RunId"
    $script:Prefix = "$script:RunId-"
    $script:Work = Join-Path ([System.IO.Path]::GetTempPath()) "azpolicyops-$script:RunId"
    $script:Policies = Join-Path $script:Work 'policies'
    New-Item -ItemType Directory -Force -Path $script:Policies | Out-Null
    foreach ($d in 'definitions', 'initiatives', 'assignments', 'exemptions', 'environments') { New-Item -ItemType Directory -Force -Path (Join-Path $script:Policies $d) | Out-Null }

    # The pipeline passes the subscription in as a variable; environment files read it with ${env:...}.
    $env:POLICY_SUBSCRIPTION_ID = $script:SubscriptionId
    @{
        pacOwnerId              = $script:Owner
        deploymentScope         = '/subscriptions/${env:POLICY_SUBSCRIPTION_ID}'
        managedIdentityLocation = $(if ($env:INTEGRATION_LOCATION) { $env:INTEGRATION_LOCATION } else { 'westus2' })
        tokens                  = @{ rg = $script:RgScope; tagName = 'costCentre'; prefix = $script:Prefix }
    } | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $script:Policies 'environments' 'it.json')

    function script:Write-PolicyFile([string]$Relative, [hashtable]$Doc) {
        $Doc | ConvertTo-Json -Depth 50 | Set-Content (Join-Path $script:Policies $Relative)
    }
    function script:Get-Arm([string]$Id, [string]$ApiVersion = '2023-04-01') {
        $r = Invoke-AzRestMethod -Method GET -Path "$Id`?api-version=$ApiVersion"
        if ($r.StatusCode -eq 404) { return $null }
        return $r.Content | ConvertFrom-Json -AsHashtable -Depth 100
    }

    # Runs a pipeline script the way AzurePowerShell@5 does: a new pwsh process that signs in with the
    # service connection's service principal, then runs the script, with TF_BUILD set as on an agent.
    $script:StepWrapper = Join-Path $script:Work 'azurepowershell-task.ps1'
    @'
$ErrorActionPreference = 'Stop'
$target, $rest = $args
Import-Module (Join-Path $env:AZPOLICYOPS_REPO 'src' 'AzPolicyOps' 'AzPolicyOps.psd1') -Force
Connect-PolicyPipelineAccount | Out-Null
& $target @rest
'@ | Set-Content -Path $script:StepWrapper
    $env:AZPOLICYOPS_REPO = $script:RepoRoot
    if (-not $env:ARM_CLIENT_ID) { throw 'Integration tests need ARM_TENANT_ID, ARM_SUBSCRIPTION_ID, ARM_CLIENT_ID and ARM_CLIENT_SECRET, as an Azure DevOps service connection provides.' }

    function script:Invoke-PipelineStep([string]$Script, [string[]]$Arguments) {
        $env:TF_BUILD = 'True'
        try {
            $output = & pwsh -NoProfile -NonInteractive -File $script:StepWrapper (Join-Path $script:RepoRoot 'scripts' $Script) @Arguments 2>&1 | ForEach-Object { "$_" }
            $exit = $LASTEXITCODE
        }
        finally { Remove-Item Env:TF_BUILD -ErrorAction SilentlyContinue }
        [pscustomobject]@{ ExitCode = $exit; Output = $output; Text = ($output -join "`n") }
    }
    function script:Invoke-PipelineRun([switch]$SkipDelete) {
        $planDir = Join-Path $script:Work ("plan-" + [guid]::NewGuid().ToString('n').Substring(0, 6))
        $stepArgs = @('-Environment', 'it', '-PolicyPath', $script:Policies, '-OutputPath', $planDir)
        if ($SkipDelete) { $stepArgs += '-SkipDelete' }
        if (-not $script:CanAssignRoles) { $stepArgs += '-SkipRoleAssignments' }
        $plan = Invoke-PipelineStep 'Invoke-PolicyPlan.ps1' $stepArgs
        if ($plan.ExitCode -ne 0) { throw "Plan step failed:`n$($plan.Text)" }
        $planObj = Get-Content (Join-Path $planDir 'plan.json') -Raw | ConvertFrom-Json -AsHashtable -Depth 100
        $deploy = $null
        if ($plan.Text -match 'hasChanges;isOutput=true\]true') {
            $deploy = Invoke-PipelineStep 'Invoke-PolicyDeploy.ps1' @('-PlanFile', (Join-Path $planDir 'plan.json'))
            if ($deploy.ExitCode -ne 0) { throw "Deploy step failed:`n$($deploy.Text)" }
        }
        [pscustomobject]@{ Plan = $plan; PlanFile = (Join-Path $planDir 'plan.json'); PlanObject = $planObj; Deploy = $deploy }
    }
    # The drift check must use the same role assignment setting as the deploy it is checking.
    function script:Invoke-DriftStep([string]$OutDir, [string[]]$Extra = @()) {
        $stepArgs = @('-Environment', 'it', '-PolicyPath', $script:Policies, '-OutputPath', $OutDir) + $Extra
        if (-not $script:CanAssignRoles) { $stepArgs += '-SkipRoleAssignments' }
        Invoke-PipelineStep 'Invoke-PolicyDrift.ps1' $stepArgs
    }
    function script:Get-PlanOps($Run) {
        $h = @{}
        foreach ($a in $Run.PlanObject.actions) { $h["$($a.Kind)/$($a.Name)"] = $a.Operation }
        $h
    }

    # Granting the assignment identity a role needs roleAssignments/write at the target scope.
    $perms = (Invoke-AzRestMethod -Method GET -Path "$script:RgScope/providers/Microsoft.Authorization/permissions?api-version=2022-04-01").Content | ConvertFrom-Json
    $script:CanAssignRoles = [bool]($perms.value | Where-Object {
            $p = $_
            ($p.actions | Where-Object { 'Microsoft.Authorization/roleAssignments/write' -like $_ }) -and
            -not ($p.notActions | Where-Object { 'Microsoft.Authorization/roleAssignments/write' -like $_ })
        })
    if (-not $script:CanAssignRoles) {
        Write-Warning "The signed-in identity cannot create role assignments at $script:RgScope. Role assignment checks will be skipped."
    }
    function script:Skip-WithoutRoleAccess {
        if (-not $script:CanAssignRoles) { Set-ItResult -Skipped -Because 'the test identity lacks Microsoft.Authorization/roleAssignments/write on the target resource group' }
    }

    $script:DefTag = "$($script:Prefix)require-rg-tag"
    $script:DefInherit = "$($script:Prefix)inherit-tag"
    $script:SetName = "$($script:Prefix)baseline"
    $script:AsgBaseline = "$($script:Prefix)baseline"
    $script:AsgInherit = "$($script:Prefix)inherit"
    $script:Exemption = "$($script:Prefix)waiver"
    $script:DefScope = "/subscriptions/$script:SubscriptionId/providers/Microsoft.Authorization"

    Write-PolicyFile "definitions/$script:DefTag.json" @{
        name       = $script:DefTag
        properties = @{
            displayName = 'IT: require tag on resources'
            description = 'Integration test definition'
            mode        = 'Indexed'
            metadata    = @{ category = 'Tags' }
            parameters  = @{
                tagName = @{ type = 'String' }
                effect  = @{ type = 'String'; defaultValue = 'Audit'; allowedValues = @('Audit', 'Deny', 'Disabled') }
            }
            policyRule  = @{
                if   = @{ field = "[concat('tags[', parameters('tagName'), ']')]"; exists = 'false' }
                then = @{ effect = "[parameters('effect')]" }
            }
        }
    }
    Write-PolicyFile "definitions/$script:DefInherit.json" @{
        name       = $script:DefInherit
        properties = @{
            displayName = 'IT: inherit tag from resource group'
            description = 'Integration test modify definition'
            mode        = 'Indexed'
            parameters  = @{ tagName = @{ type = 'String' } }
            policyRule  = @{
                if   = @{ allOf = @(
                        @{ field = "[concat('tags[', parameters('tagName'), ']')]"; exists = 'false' }
                        @{ value = "[resourceGroup().tags[parameters('tagName')]]"; notEquals = '' }
                    )
                }
                then = @{
                    effect  = 'modify'
                    details = @{
                        roleDefinitionIds = @('/providers/Microsoft.Authorization/roleDefinitions/4a9ae827-6dc8-4573-8ac7-8239d42aa03f')
                        operations        = @(@{ operation = 'add'; field = "[concat('tags[', parameters('tagName'), ']')]"; value = "[resourceGroup().tags[parameters('tagName')]]" })
                    }
                }
            }
        }
    }
    Write-PolicyFile "initiatives/$script:SetName.json" @{
        name       = $script:SetName
        properties = @{
            displayName       = 'IT: baseline'
            description       = 'Integration test initiative'
            parameters        = @{ tagName = @{ type = 'String' }; tagEffect = @{ type = 'String'; defaultValue = 'Audit'; allowedValues = @('Audit', 'Deny', 'Disabled') } }
            policyDefinitions = @(
                @{
                    policyDefinitionReferenceId = 'requireTag'
                    policyDefinitionName        = $script:DefTag
                    parameters                  = @{ tagName = @{ value = "[parameters('tagName')]" }; effect = @{ value = "[parameters('tagEffect')]" } }
                }
                @{
                    policyDefinitionReferenceId = 'auditVmManagedDisks'
                    policyDefinitionId          = '/providers/Microsoft.Authorization/policyDefinitions/06a78e20-9358-41c9-923c-fb736d382a4d'
                }
            )
        }
    }
    Write-PolicyFile "assignments/$script:AsgBaseline.json" @{
        name       = $script:AsgBaseline
        scope      = '{{rg}}'
        properties = @{
            displayName             = 'IT baseline ({{environment}})'
            policySetDefinitionName = $script:SetName
            enforcementMode         = 'DoNotEnforce'
            parameters              = @{ tagName = @{ value = '{{tagName}}' } }
            nonComplianceMessages   = @(@{ message = 'Integration test' })
        }
    }
    Write-PolicyFile "assignments/$script:AsgInherit.json" @{
        name       = $script:AsgInherit
        scope      = '{{rg}}'
        identity   = @{ type = 'SystemAssigned' }
        properties = @{
            displayName          = 'IT inherit tag'
            policyDefinitionName = $script:DefInherit
            enforcementMode      = 'DoNotEnforce'
            parameters           = @{ tagName = @{ value = '{{tagName}}' } }
        }
    }
    Write-PolicyFile "exemptions/$script:Exemption.json" @{
        name       = $script:Exemption
        scope      = '{{rg}}'
        properties = @{
            policyAssignmentName         = $script:AsgBaseline
            policyAssignmentScope        = '{{rg}}'
            policyDefinitionReferenceIds = @('requireTag')
            exemptionCategory            = 'Waiver'
            expiresOn                    = (Get-Date).ToUniversalTime().AddDays(30).ToString('yyyy-MM-ddT00:00:00Z')
            displayName                  = 'IT waiver'
        }
    }
}

AfterAll {
    # Remove everything this run created, whatever state the tests left it in.
    if ($script:Owner) {
        Get-ChildItem (Join-Path $script:Policies 'definitions'), (Join-Path $script:Policies 'initiatives'), (Join-Path $script:Policies 'assignments'), (Join-Path $script:Policies 'exemptions') -Filter *.json -ErrorAction SilentlyContinue | Remove-Item -Force
        try {
            $plan = New-PolicyDeploymentPlan -Path $script:Policies -Environment it
            Invoke-PolicyDeploymentPlan -Plan $plan -Force -Confirm:$false | Out-Null
        }
        catch { Write-Warning "Cleanup through the module failed: $($_.Exception.Message)" }
        Remove-Item $script:Work -Recurse -Force -ErrorAction SilentlyContinue
    }
    Remove-Item Env:POLICY_SUBSCRIPTION_ID -ErrorAction SilentlyContinue
}

Describe 'Azure Policy pipeline against live Azure' {

    It 'Validate stage passes for the test repository' {
        $r = Invoke-PipelineStep 'Invoke-PolicyValidate.ps1' @('-PolicyPath', $script:Policies, '-Environment', 'it', '-SkipUnitTests', '-ResultsPath', (Join-Path $script:Work 'results'))
        $r.Text | Should -Match 'Validation passed'
        $r.ExitCode | Should -Be 0
    }

    It 'first run creates definitions, initiative, assignments, exemption and role assignment' {
        $run = Invoke-PipelineRun
        $run.Plan.Text | Should -Match '##vso\[task.setvariable variable=hasChanges;isOutput=true\]true'
        $run.Plan.Text | Should -Match '##vso\[task.uploadsummary\]'
        $run.PlanObject.summary.Create | Should -Be 6

        $def = Get-Arm "$script:DefScope/policyDefinitions/$script:DefTag"
        $def.properties.metadata.pacOwnerId | Should -Be $script:Owner
        $set = Get-Arm "$script:DefScope/policySetDefinitions/$script:SetName"
        $set.properties.policyDefinitions | Should -HaveCount 2
        $asg = Get-Arm "$script:RgScope/providers/Microsoft.Authorization/policyAssignments/$script:AsgBaseline"
        $asg.properties.displayName | Should -Be 'IT baseline (it)'
        $asg.properties.enforcementMode | Should -Be 'DoNotEnforce'
        $inherit = Get-Arm "$script:RgScope/providers/Microsoft.Authorization/policyAssignments/$script:AsgInherit"
        $inherit.identity.principalId | Should -Not -BeNullOrEmpty
        $script:FirstPrincipal = $inherit.identity.principalId
        $ex = Get-Arm "$script:RgScope/providers/Microsoft.Authorization/policyExemptions/$script:Exemption" '2022-07-01-preview'
        $ex.properties.policyDefinitionReferenceIds | Should -Be @('requireTag')
    }

    It 'first run grants the assignment identity the role its modify policy needs' {
        Skip-WithoutRoleAccess
        $inherit = Get-Arm "$script:RgScope/providers/Microsoft.Authorization/policyAssignments/$script:AsgInherit"
        $roles = (Invoke-AzRestMethod -Method GET -Path "$script:RgScope/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=principalId eq '$($inherit.identity.principalId)'").Content | ConvertFrom-Json
        @($roles.value | Where-Object { $_.properties.roleDefinitionId -like '*4a9ae827-6dc8-4573-8ac7-8239d42aa03f' }) | Should -HaveCount 1
    }

    It 'second run is idempotent: no changes and the deploy stage is skipped' {
        $run = Invoke-PipelineRun
        $run.Plan.Text | Should -Match 'hasChanges;isOutput=true\]false'
        $run.PlanObject.summary.NoChange | Should -Be 6
        $run.Deploy | Should -BeNullOrEmpty
    }

    It 'updating a definition and an assignment parameter applies in place' {
        $file = Join-Path $script:Policies 'definitions' "$script:DefTag.json"
        $doc = Get-Content $file -Raw | ConvertFrom-Json -AsHashtable -Depth 50
        $doc.properties.displayName = 'IT: require tag on resources (v2)'
        $doc.properties.metadata.version = '1.1.0'
        $doc | ConvertTo-Json -Depth 50 | Set-Content $file

        $file = Join-Path $script:Policies 'assignments' "$script:AsgBaseline.json"
        $doc = Get-Content $file -Raw | ConvertFrom-Json -AsHashtable -Depth 50
        $doc.properties.parameters.tagEffect = @{ value = 'Disabled' }
        $doc | ConvertTo-Json -Depth 50 | Set-Content $file

        $run = Invoke-PipelineRun
        $ops = Get-PlanOps $run
        $ops["PolicyDefinition/$script:DefTag"] | Should -Be 'Update'
        $ops["PolicyAssignment/$script:AsgBaseline"] | Should -Be 'Update'
        $run.PlanObject.summary.Update | Should -Be 2
        $run.PlanObject.summary.Replace | Should -Be 0

        (Get-Arm "$script:DefScope/policyDefinitions/$script:DefTag").properties.displayName | Should -Be 'IT: require tag on resources (v2)'
        (Get-Arm "$script:RgScope/providers/Microsoft.Authorization/policyAssignments/$script:AsgBaseline").properties.parameters.tagEffect.value | Should -Be 'Disabled'
        (Invoke-PipelineRun).PlanObject.hasChanges | Should -BeFalse
    }

    It 'adding a parameter with a default to an assigned definition updates in place' {
        $file = Join-Path $script:Policies 'definitions' "$script:DefTag.json"
        $doc = Get-Content $file -Raw | ConvertFrom-Json -AsHashtable -Depth 50
        $doc.properties.parameters.excludedType = @{ type = 'String'; defaultValue = 'Microsoft.Network/networkWatchers' }
        $doc.properties.policyRule.if = @{ allOf = @($doc.properties.policyRule.if, @{ field = 'type'; notEquals = "[parameters('excludedType')]" }) }
        $doc | ConvertTo-Json -Depth 50 | Set-Content $file

        $run = Invoke-PipelineRun
        (Get-PlanOps $run)["PolicyDefinition/$script:DefTag"] | Should -Be 'Update'
        (Get-Arm "$script:DefScope/policyDefinitions/$script:DefTag").properties.parameters.Keys | Should -Contain 'excludedType'
    }

    It 'a portal edit after planning blocks the deploy (stale plan)' {
        $file = Join-Path $script:Policies 'definitions' "$script:DefTag.json"
        $doc = Get-Content $file -Raw | ConvertFrom-Json -AsHashtable -Depth 50
        $doc.properties.description = 'Integration test definition (v3)'
        $doc | ConvertTo-Json -Depth 50 | Set-Content $file

        $planDir = Join-Path $script:Work 'stale'
        $plan = Invoke-PipelineStep 'Invoke-PolicyPlan.ps1' @('-Environment', 'it', '-PolicyPath', $script:Policies, '-OutputPath', $planDir)
        $plan.ExitCode | Should -Be 0

        # Someone edits the policy in the portal while the run waits for approval.
        $live = Get-Arm "$script:DefScope/policyDefinitions/$script:DefTag"
        $live.properties.displayName = 'edited in portal'
        $body = @{ properties = $live.properties } | ConvertTo-Json -Depth 50 -Compress
        (Invoke-AzRestMethod -Method PUT -Path "$script:DefScope/policyDefinitions/$script:DefTag`?api-version=2023-04-01" -Payload $body).StatusCode | Should -BeIn 200, 201

        $deploy = Invoke-PipelineStep 'Invoke-PolicyDeploy.ps1' @('-PlanFile', (Join-Path $planDir 'plan.json'))
        $deploy.ExitCode | Should -Not -Be 0
        $deploy.Text | Should -Match 'Azure changed after the plan was made'
        (Get-Arm "$script:DefScope/policyDefinitions/$script:DefTag").properties.displayName | Should -Be 'edited in portal'

        # A fresh plan corrects the drift.
        $run = Invoke-PipelineRun
        (Get-PlanOps $run)["PolicyDefinition/$script:DefTag"] | Should -Be 'Update'
        (Get-Arm "$script:DefScope/policyDefinitions/$script:DefTag").properties.displayName | Should -Be 'IT: require tag on resources (v2)'
    }

    It 'removing a parameter replaces the definition and its assignment, and re-grants the new identity' {
        $file = Join-Path $script:Policies 'definitions' "$script:DefInherit.json"
        $doc = Get-Content $file -Raw | ConvertFrom-Json -AsHashtable -Depth 50
        $doc.properties.Remove('parameters')
        $json = ConvertTo-Json $doc.properties.policyRule -Depth 50
        $doc.properties.policyRule = ConvertFrom-Json ($json -replace "parameters\('tagName'\)", "'costCentre'") -AsHashtable -Depth 50
        $doc | ConvertTo-Json -Depth 50 | Set-Content $file
        $file = Join-Path $script:Policies 'assignments' "$script:AsgInherit.json"
        $doc = Get-Content $file -Raw | ConvertFrom-Json -AsHashtable -Depth 50
        $doc.properties.Remove('parameters')
        $doc | ConvertTo-Json -Depth 50 | Set-Content $file

        $run = Invoke-PipelineRun
        $ops = Get-PlanOps $run
        $ops["PolicyDefinition/$script:DefInherit"] | Should -Be 'Replace'
        $ops["PolicyAssignment/$script:AsgInherit"] | Should -Be 'Replace'
        $run.Plan.Text | Should -Match 'type=warning\]This plan replaces 2 resource'

        $def = Get-Arm "$script:DefScope/policyDefinitions/$script:DefInherit"
        $def.properties.parameters.Count | Should -Be 0
        $asg = Get-Arm "$script:RgScope/providers/Microsoft.Authorization/policyAssignments/$script:AsgInherit"
        $asg.identity.principalId | Should -Not -Be $script:FirstPrincipal
        (Invoke-PipelineRun).PlanObject.hasChanges | Should -BeFalse
    }

    It 'after a replace the new identity holds the role and the old one holds none' {
        Skip-WithoutRoleAccess
        $asg = Get-Arm "$script:RgScope/providers/Microsoft.Authorization/policyAssignments/$script:AsgInherit"
        $roles = (Invoke-AzRestMethod -Method GET -Path "$script:RgScope/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=principalId eq '$($asg.identity.principalId)'").Content | ConvertFrom-Json
        @($roles.value) | Should -HaveCount 1
        $old = (Invoke-AzRestMethod -Method GET -Path "$script:RgScope/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=principalId eq '$script:FirstPrincipal'").Content | ConvertFrom-Json
        @($old.value) | Should -HaveCount 0
    }

    It 'drift check reports Azure in sync with source control after deploy' {
        $out = Join-Path $script:Work 'drift-clean'
        $r = Invoke-DriftStep $out @('-FailOnDrift')
        $r.ExitCode | Should -Be 0 -Because $r.Text
        $r.Text | Should -Match 'driftDetected;isOutput=true\]false'
        $report = Get-Content (Join-Path $out 'drift.json') -Raw | ConvertFrom-Json
        $report.HasDrift | Should -BeFalse
        $report.Summary.InSync | Should -Be 6
        ([xml](Get-Content (Join-Path $out 'drift.xml') -Raw)).testsuites.testsuite.failures | Should -Be '0'
    }

    It 'drift check finds real portal edits, deletions, orphans and unmanaged policy, with field values' {
        $defId = "$script:DefScope/policyDefinitions/$script:DefTag"
        $asgId = "$script:RgScope/providers/Microsoft.Authorization/policyAssignments/$script:AsgBaseline"
        $exId = "$script:RgScope/providers/Microsoft.Authorization/policyExemptions/$script:Exemption"
        $orphanName = "$($script:Prefix)orphan"
        $portalName = "$($script:Prefix)portal-made"
        $rule = @{ if = @{ field = 'type'; equals = 'Microsoft.Network/publicIPAddresses' }; then = @{ effect = 'audit' } }

        # Edits made directly in Azure, as someone would in the portal or CLI.
        $live = Get-Arm $defId
        $live.properties.displayName = 'Edited outside the pipeline'
        $live.properties.parameters.effect.defaultValue = 'Deny'
        (Invoke-AzRestMethod -Method PUT -Path "$defId`?api-version=2023-04-01" -Payload (@{ properties = $live.properties } | ConvertTo-Json -Depth 50 -Compress)).StatusCode | Should -BeIn 200, 201
        $live = Get-Arm $asgId
        $live.properties.enforcementMode = 'Default'
        (Invoke-AzRestMethod -Method PUT -Path "$asgId`?api-version=2023-04-01" -Payload (@{ properties = $live.properties } | ConvertTo-Json -Depth 50 -Compress)).StatusCode | Should -BeIn 200, 201
        (Invoke-AzRestMethod -Method DELETE -Path "$exId`?api-version=2022-07-01-preview").StatusCode | Should -BeIn 200, 204
        (Invoke-AzRestMethod -Method PUT -Path "$script:DefScope/policyDefinitions/$orphanName`?api-version=2023-04-01" -Payload (@{ properties = @{ displayName = 'orphan'; mode = 'All'; metadata = @{ pacOwnerId = $script:Owner }; policyRule = $rule } } | ConvertTo-Json -Depth 20 -Compress)).StatusCode | Should -BeIn 200, 201
        (Invoke-AzRestMethod -Method PUT -Path "$script:DefScope/policyDefinitions/$portalName`?api-version=2023-04-01" -Payload (@{ properties = @{ displayName = 'portal made'; mode = 'All'; policyRule = $rule } } | ConvertTo-Json -Depth 20 -Compress)).StatusCode | Should -BeIn 200, 201
        try {
            $out = Join-Path $script:Work 'drift-dirty'
            $r = Invoke-DriftStep $out
            $r.ExitCode | Should -Be 0 -Because 'without -FailOnDrift the step reports drift but succeeds'
            $r.Text | Should -Match 'driftDetected;isOutput=true\]true'
            $r.Text | Should -Match 'type=warning\]Azure Policy in .it. has drifted'
            $report = Get-Content (Join-Path $out 'drift.json') -Raw | ConvertFrom-Json -AsHashtable -Depth 20
            $byName = @{}; foreach ($i in $report.Items) { $byName["$($i.Kind)/$($i.Name)"] = $i }

            $def = $byName["PolicyDefinition/$script:DefTag"]
            $def.State | Should -Be 'Modified'
            $def.Fix | Should -Be 'Update'
            ($def.Differences | Where-Object Path -EQ 'displayName').Azure | Should -Be "'Edited outside the pipeline'"
            ($def.Differences | Where-Object Path -EQ 'displayName').Repository | Should -Be "'IT: require tag on resources (v2)'"
            ($def.Differences | Where-Object Path -EQ 'parameters.effect.defaultValue').Azure | Should -Be "'Deny'"
            $def.LastModifiedBy | Should -Not -BeNullOrEmpty

            $asg = $byName["PolicyAssignment/$script:AsgBaseline"]
            $asg.State | Should -Be 'Modified'
            ($asg.Differences | Where-Object Path -EQ 'enforcementMode').Repository | Should -Be "'DoNotEnforce'"
            ($asg.Differences | Where-Object Path -EQ 'enforcementMode').Azure | Should -Be "'Default'"

            $byName["PolicyExemption/$script:Exemption"].State | Should -Be 'MissingInAzure'
            $byName["PolicyDefinition/$orphanName"].State | Should -Be 'NotInRepository'
            $byName["PolicyDefinition/$portalName"].State | Should -Be 'Unmanaged'
            $byName["PolicySetDefinition/$script:SetName"].State | Should -Be 'InSync'
            $report.Summary.Modified | Should -Be 2
            $report.Summary.MissingInAzure | Should -Be 1
            $report.Summary.NotInRepository | Should -Be 1

            Get-Content (Join-Path $out 'drift.md') -Raw | Should -Match 'Drift found'
            $suite = ([xml](Get-Content (Join-Path $out 'drift.xml') -Raw)).testsuites.testsuite
            [int]$suite.failures | Should -Be 4

            $fail = Invoke-DriftStep $out @('-FailOnDrift')
            $fail.ExitCode | Should -Not -Be 0
            $fail.Text | Should -Match '4 resource\(s\) drifted from source control'

            # Drift check is read-only: Azure still has the edit.
            (Get-Arm $defId).properties.displayName | Should -Be 'Edited outside the pipeline'

            # Deploying from source control removes the drift; the unmanaged policy is left alone.
            $null = Invoke-PipelineRun
            $after = Invoke-DriftStep (Join-Path $script:Work 'drift-after') @('-FailOnDrift')
            $after.ExitCode | Should -Be 0 -Because $after.Text
            $afterReport = Get-Content (Join-Path $script:Work 'drift-after' 'drift.json') -Raw | ConvertFrom-Json
            $afterReport.HasDrift | Should -BeFalse
            $afterReport.Summary.Unmanaged | Should -Be 1
            Get-Arm "$script:DefScope/policyDefinitions/$orphanName" | Should -BeNullOrEmpty
            (Get-Arm $defId).properties.displayName | Should -Be 'IT: require tag on resources (v2)'
            Get-Arm $exId '2022-07-01-preview' | Should -Not -BeNullOrEmpty

            $unmanaged = Invoke-DriftStep (Join-Path $script:Work 'drift-unmanaged') @('-FailOnUnmanaged')
            $unmanaged.ExitCode | Should -Not -Be 0
            $unmanaged.Text | Should -Match '1 unmanaged custom policy'
        }
        finally {
            foreach ($n in $orphanName, $portalName) { Invoke-AzRestMethod -Method DELETE -Path "$script:DefScope/policyDefinitions/$n`?api-version=2023-04-01" | Out-Null }
        }
    }

    It 'compliance scan and report run for the managed assignments' {
        $out = Join-Path $script:Work 'compliance'
        $r = Invoke-PipelineStep 'Invoke-PolicyCompliance.ps1' @('-Environment', 'it', '-PolicyPath', $script:Policies, '-Scope', $script:RgScope, '-OutputPath', $out)
        $r.ExitCode | Should -Be 0
        Test-Path (Join-Path $out 'compliance.md') | Should -BeTrue
        [xml](Get-Content (Join-Path $out 'compliance.xml') -Raw) | Should -Not -BeNullOrEmpty
        $start = Start-PolicyComplianceScan -Scope $script:RgScope
        $start.Status | Should -Be 'Started'
    }

    It 'Export-PolicyFromAzure writes repository files for unmanaged policy' {
        $name = "$($script:Prefix)portal-made"
        $body = @{ properties = @{ displayName = 'made in portal'; mode = 'All'; policyRule = @{ if = @{ field = 'type'; equals = 'Microsoft.Network/publicIPAddresses' }; then = @{ effect = 'audit' } } } } | ConvertTo-Json -Depth 20 -Compress
        (Invoke-AzRestMethod -Method PUT -Path "$script:DefScope/policyDefinitions/$name`?api-version=2023-04-01" -Payload $body).StatusCode | Should -BeIn 200, 201
        try {
            $exportDir = Join-Path $script:Work 'export'
            $files = Export-PolicyFromAzure -Scope "/subscriptions/$script:SubscriptionId" -OutputPath $exportDir
            $files | Where-Object { $_ -like "*$name.json" } | Should -HaveCount 1
            $exported = Get-Content (Join-Path $exportDir 'definitions' "$name.json") -Raw | ConvertFrom-Json -AsHashtable
            $exported.properties.displayName | Should -Be 'made in portal'
            $exported.properties.Contains('metadata') | Should -BeFalse
        }
        finally { Invoke-AzRestMethod -Method DELETE -Path "$script:DefScope/policyDefinitions/$name`?api-version=2023-04-01" | Out-Null }
    }

    It 'deleting files removes the resources, dependants first, including role assignments' {
        $principal = (Get-Arm "$script:RgScope/providers/Microsoft.Authorization/policyAssignments/$script:AsgInherit").identity.principalId
        Remove-Item (Join-Path $script:Policies 'exemptions' "$script:Exemption.json")
        Remove-Item (Join-Path $script:Policies 'assignments' "$script:AsgInherit.json")
        Remove-Item (Join-Path $script:Policies 'definitions' "$script:DefInherit.json")

        $skip = Invoke-PipelineRun -SkipDelete
        $skip.PlanObject.summary.Delete | Should -Be 0
        $skip.Plan.Text | Should -Match 'not deleted because -SkipDelete'

        $run = Invoke-PipelineRun
        $run.PlanObject.summary.Delete | Should -Be 3
        $run.Plan.Text | Should -Match 'type=warning\]This plan deletes 3 resource'
        Get-Arm "$script:RgScope/providers/Microsoft.Authorization/policyExemptions/$script:Exemption" '2022-07-01-preview' | Should -BeNullOrEmpty
        Get-Arm "$script:RgScope/providers/Microsoft.Authorization/policyAssignments/$script:AsgInherit" | Should -BeNullOrEmpty
        Get-Arm "$script:DefScope/policyDefinitions/$script:DefInherit" | Should -BeNullOrEmpty
        $roles = (Invoke-AzRestMethod -Method GET -Path "$script:RgScope/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=principalId eq '$principal'").Content | ConvertFrom-Json
        @($roles.value) | Should -HaveCount 0
        Get-Arm "$script:DefScope/policyDefinitions/$script:DefTag" | Should -Not -BeNullOrEmpty
    }
}
