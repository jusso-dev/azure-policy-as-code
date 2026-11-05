function Connect-PolicyPipelineAccount {
    <#
    .SYNOPSIS
        Signs in to Azure the same way the Azure DevOps AzurePowerShell@5 task does.
    .DESCRIPTION
        In Azure DevOps you normally do not call this: the AzurePowerShell@5 task signs in with the
        service connection before your script runs. Use it to run the same scripts somewhere else
        (a build VM, a laptop, another CI system) with a service principal secret or a federated token.

        Values default to the ARM_* environment variables used by Terraform and many pipelines,
        then AZURE_* variables.
    .EXAMPLE
        $env:ARM_CLIENT_SECRET = '...'   # from a secret store, never committed
        Connect-PolicyPipelineAccount -TenantId $t -SubscriptionId $s -ClientId $c
    .EXAMPLE
        Connect-PolicyPipelineAccount -TenantId $t -SubscriptionId $s -ClientId $c -FederatedToken $idToken
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'The secret arrives as an environment variable, which is how pipelines pass secrets; it is converted once and never logged.')]
    [CmdletBinding(DefaultParameterSetName = 'Secret')]
    param(
        [string]$TenantId = (Get-FirstEnvironmentValue 'ARM_TENANT_ID', 'AZURE_TENANT_ID'),
        [string]$SubscriptionId = (Get-FirstEnvironmentValue 'ARM_SUBSCRIPTION_ID', 'AZURE_SUBSCRIPTION_ID'),
        [string]$ClientId = (Get-FirstEnvironmentValue 'ARM_CLIENT_ID', 'AZURE_CLIENT_ID'),

        [Parameter(ParameterSetName = 'Secret')]
        [securestring]$ClientSecret,

        [Parameter(Mandatory, ParameterSetName = 'Federated')]
        [string]$FederatedToken,

        [ValidateSet('AzureCloud', 'AzureUSGovernment', 'AzureChinaCloud')]
        [string]$Environment = 'AzureCloud'
    )

    foreach ($required in 'TenantId', 'SubscriptionId', 'ClientId') {
        if (-not (Get-Variable -Name $required -ValueOnly)) {
            throw "$required is required. Pass -$required or set ARM_$(($required -creplace '([a-z])([A-Z])', '$1_$2').ToUpperInvariant())."
        }
    }

    $connect = @{
        ServicePrincipal = $true
        Tenant           = $TenantId
        Subscription     = $SubscriptionId
        Environment      = $Environment
        Scope            = 'Process'
        ErrorAction      = 'Stop'
        WarningAction    = 'SilentlyContinue'
    }

    if ($PSCmdlet.ParameterSetName -eq 'Federated') {
        $connect.ApplicationId = $ClientId
        $connect.FederatedToken = $FederatedToken
    }
    else {
        if (-not $ClientSecret) {
            $plain = Get-FirstEnvironmentValue 'ARM_CLIENT_SECRET', 'AZURE_CLIENT_SECRET'
            if (-not $plain) { throw 'ClientSecret is required. Pass -ClientSecret or set ARM_CLIENT_SECRET.' }
            $ClientSecret = ConvertTo-SecureString -String $plain -AsPlainText -Force
        }
        $connect.Credential = [pscredential]::new($ClientId, $ClientSecret)
    }

    $null = Connect-AzAccount @connect
    $context = Get-AzContext
    Write-PolicyLog "Signed in as $($context.Account.Id) to subscription $($context.Subscription.Id) (tenant $($context.Tenant.Id))."
    return $context
}

function Get-FirstEnvironmentValue {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory, Position = 0)][string[]]$Name)
    foreach ($n in $Name) {
        $value = [Environment]::GetEnvironmentVariable($n)
        if ($value) { return $value }
    }
    return $null
}
