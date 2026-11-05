@{
    RootModule           = 'AzPolicyOps.psm1'
    ModuleVersion        = '1.0.0'
    GUID                 = '6f0b5c8e-2d7e-4b8a-9a63-4f3f5d9c1e27'
    Author               = 'jusso-dev'
    Description          = 'Azure Policy as code: validate, plan, deploy, report compliance and remediate Azure Policy from JSON in source control, built for Azure DevOps pipelines.'
    PowerShellVersion    = '7.2'
    CompatiblePSEditions = @('Core')
    RequiredModules      = @(
        @{ ModuleName = 'Az.Accounts'; ModuleVersion = '2.13.0' }
    )
    FunctionsToExport    = @(
        'Connect-PolicyPipelineAccount'
        'Export-PolicyFromAzure'
        'Get-PolicyComplianceSummary'
        'Get-PolicyDeployedState'
        'Get-PolicyDesiredState'
        'Get-PolicyEnvironment'
        'Invoke-PolicyDeploymentPlan'
        'New-PolicyDeploymentPlan'
        'Start-PolicyComplianceScan'
        'Start-PolicyRemediation'
        'Test-PolicyRepository'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags       = @('Azure', 'Policy', 'AzureDevOps', 'PolicyAsCode', 'Governance')
            ProjectUri = 'https://github.com/jusso-dev/azure-policy-as-code'
        }
    }
}
