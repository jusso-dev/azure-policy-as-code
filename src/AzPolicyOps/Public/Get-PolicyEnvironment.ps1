function Get-PolicyEnvironment {
    <#
    .SYNOPSIS
        Loads an environment file from policies/environments/<name>.json.
    .DESCRIPTION
        An environment says where policy is deployed and who owns it:

          {
            "pacOwnerId": "azure-policy-as-code-prod",
            "deploymentScope": "/subscriptions/${env:POLICY_SUBSCRIPTION_ID}",
            "definitionScope": "/subscriptions/${env:POLICY_SUBSCRIPTION_ID}",
            "managedIdentityLocation": "australiaeast",
            "tokens": { "allowedLocations": [ "australiaeast", "australiasoutheast" ] }
          }

        ${env:NAME} values are read from environment variables, which is how Azure DevOps pipeline
        variables reach the script. pacOwnerId marks every resource this repo deploys, so the
        pipeline only updates or deletes resources it owns.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Environment
    )

    $file = Join-Path $Path 'environments' "$Environment.json"
    if (-not (Test-Path -LiteralPath $file)) {
        $available = @(Get-ChildItem -LiteralPath (Join-Path $Path 'environments') -Filter '*.json' -ErrorAction SilentlyContinue).BaseName -join ', '
        throw "Environment file '$file' not found. Available: $available"
    }

    $raw = Read-PolicyJsonFile -Path $file
    $raw.Remove('$schema')
    $config = Expand-EnvironmentReference $raw -Source "environments/$Environment.json"

    foreach ($key in 'pacOwnerId', 'deploymentScope') {
        if (-not $config[$key]) { throw "environments/$Environment.json: '$key' is required." }
    }
    if ($config.pacOwnerId -notmatch '^[A-Za-z0-9._-]{3,64}$') {
        throw "environments/$Environment.json: pacOwnerId must be 3-64 letters, digits, '.', '_' or '-'."
    }
    if (-not $config.definitionScope) { $config.definitionScope = $config.deploymentScope }
    foreach ($key in 'deploymentScope', 'definitionScope') {
        $config[$key] = ([string]$config[$key]).TrimEnd('/')
        $kind = Get-PolicyScopeKind $config[$key]
        if ($kind -notin 'ManagementGroup', 'Subscription') {
            throw "environments/$Environment.json: $key '$($config[$key])' must be a management group or subscription ID."
        }
    }
    if (-not $config.tokens) { $config.tokens = [ordered]@{} }

    $tokens = [ordered]@{}
    foreach ($k in $config.tokens.Keys) { $tokens[$k] = $config.tokens[$k] }
    $tokens['environment'] = $Environment
    $tokens['pacOwnerId'] = $config.pacOwnerId
    $tokens['deploymentScope'] = $config.deploymentScope
    $tokens['definitionScope'] = $config.definitionScope
    if ($config.deploymentScope -match '^/subscriptions/([^/]+)') { $tokens['subscriptionId'] = $Matches[1] }

    [pscustomobject]@{
        PSTypeName              = 'AzPolicyOps.Environment'
        Name                    = $Environment
        PacOwnerId              = [string]$config.pacOwnerId
        DeploymentScope         = [string]$config.deploymentScope
        DefinitionScope         = [string]$config.definitionScope
        ManagedIdentityLocation = [string]$config.managedIdentityLocation
        Tokens                  = $tokens
    }
}
