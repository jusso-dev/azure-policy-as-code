function Get-PolicyEnvironment {
    <#
    .SYNOPSIS
        Loads an environment file from policies/environments/<name>.json.
    .DESCRIPTION
        The policy files are shared by every environment. The environment file holds what differs:

          pacOwnerId               Stamp written to metadata.pacOwnerId on everything deployed. Only
                                   resources with this value are ever updated or deleted.
          deploymentScope          Subscription or management group that assignments default to; also the
                                   area deletes and drift checks look at.
          definitionScope          Optional. Where definitions and initiatives are created (default:
                                   deploymentScope). Use a management group to share them.
          managedIdentityLocation  Region for assignment managed identities (deployIfNotExists / modify).
          tokens                   Per-environment values for {{token}} placeholders in policy files.
          description              Free text, ignored.

        ${env:NAME} values are read from environment variables, which is how Azure DevOps pipeline
        variables reach the script. See policies/environments/README.md for a worked example.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Environment
    )

    $file = Join-Path $Path 'environments' "$Environment.json"
    if (-not (Test-Path -LiteralPath $file)) {
        $available = (Get-PolicyEnvironmentName -Path $Path) -join ', '
        throw "Environment file '$file' not found. Available: $available"
    }

    $raw = Read-PolicyJsonFile -Path $file
    $raw.Remove('$schema')
    $description = [string]$raw.description
    $raw.Remove('description')
    $known = 'pacOwnerId', 'deploymentScope', 'definitionScope', 'managedIdentityLocation', 'tokens'
    $unknown = @($raw.Keys | Where-Object { $_ -notin $known })
    if ($unknown) {
        throw "environments/$Environment.json: unknown field(s) $($unknown -join ', '). Allowed: $($known -join ', '), description. Per-environment values belong under 'tokens'."
    }
    $config = Expand-EnvironmentReference $raw -Source "environments/$Environment.json"

    $help = @{
        pacOwnerId      = 'a unique ownership stamp such as "azure-policy-as-code-prod"'
        deploymentScope = 'the subscription or management group to deploy to, such as "/subscriptions/${env:POLICY_SUBSCRIPTION_ID}"'
    }
    foreach ($key in 'pacOwnerId', 'deploymentScope') {
        if (-not $config[$key]) { throw "environments/$Environment.json: '$key' is required: $($help[$key])." }
    }
    if ($config.tokens -and $config.tokens -isnot [System.Collections.IDictionary]) {
        throw "environments/$Environment.json: 'tokens' must be an object of name/value pairs."
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
    if ((Get-PolicyScopeKind $config.definitionScope) -eq 'Subscription' -and
        -not $config.deploymentScope.StartsWith($config.definitionScope, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "environments/$Environment.json: definitionScope '$($config.definitionScope)' must be at or above deploymentScope '$($config.deploymentScope)'. Azure only lets a definition be assigned at or below where it is defined; use a management group that contains the deployment scope, or leave definitionScope out."
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
        Description             = $description
        PacOwnerId              = [string]$config.pacOwnerId
        DeploymentScope         = [string]$config.deploymentScope
        DefinitionScope         = [string]$config.definitionScope
        ManagedIdentityLocation = [string]$config.managedIdentityLocation
        Tokens                  = $tokens
    }
}

