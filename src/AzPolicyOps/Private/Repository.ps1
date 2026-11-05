$script:ValidEffects = @('append', 'audit', 'auditIfNotExists', 'deny', 'denyAction', 'deployIfNotExists', 'disabled', 'manual', 'modify', 'mutate', 'addToNetworkGroup')
$script:InvalidNameCharacters = '[<>*%&:\\?+/#|]'
$script:ZeroGuid = '00000000-0000-0000-0000-000000000000'

function New-PolicyIssue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Error', 'Warning', 'Info')][string]$Severity,
        [Parameter(Mandatory)][string]$Rule,
        [Parameter(Mandatory)][string]$Message,
        [string]$File
    )
    [pscustomobject]@{ PSTypeName = 'AzPolicyOps.Issue'; Severity = $Severity; Rule = $Rule; File = $File; Message = $Message }
}

function Test-PolicyResourceName {
    <#
    .SYNOPSIS
        Validates a policy resource name against ARM naming rules. Returns an error message or $null.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()][AllowEmptyString()][string]$Name,
        [int]$MaxLength = 64
    )
    if ([string]::IsNullOrWhiteSpace($Name)) { return "'name' is required." }
    if ($Name.Length -gt $MaxLength) { return "Name '$Name' is $($Name.Length) characters; the limit here is $MaxLength." }
    if ($Name -match $script:InvalidNameCharacters) { return "Name '$Name' contains a character Azure Policy does not allow (<>*%&:\?+/#|)." }
    if ($Name -match '[\s.]$') { return "Name '$Name' cannot end with a period or space." }
    return $null
}

function Get-PolicyEffectInfo {
    <#
    .SYNOPSIS
        Works out which effects a policy rule can produce and which role definitions it needs.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Properties)

    $effects = [System.Collections.Generic.List[string]]::new()
    $effectParameter = $null
    $rule = $Properties.policyRule
    $then = if ($rule -is [System.Collections.IDictionary]) { $rule.then } else { $null }
    $effect = if ($then -is [System.Collections.IDictionary]) { [string]$then.effect } else { $null }

    if ($effect -match "^\[parameters\('([^']+)'\)\]$") {
        $effectParameter = $Matches[1]
        $param = if ($Properties.parameters) { $Properties.parameters[$effectParameter] } else { $null }
        if ($param -is [System.Collections.IDictionary]) {
            foreach ($v in @($param.allowedValues)) { if ($v) { $effects.Add([string]$v) } }
            if ($effects.Count -eq 0 -and $param.defaultValue) { $effects.Add([string]$param.defaultValue) }
        }
    }
    elseif ($effect) {
        $effects.Add($effect)
    }

    $roles = @()
    if ($then -is [System.Collections.IDictionary] -and $then.details -is [System.Collections.IDictionary]) {
        $roles = @($then.details.roleDefinitionIds | Where-Object { $_ })
    }

    [pscustomobject]@{
        RawEffect         = $effect
        EffectParameter   = $effectParameter
        PossibleEffects   = [string[]]$effects.ToArray()
        RoleDefinitionIds = [string[]]$roles
    }
}

function Test-PolicyDefinitionDocument {
    <#
    .SYNOPSIS
        Offline checks for a policy definition body. Returns issues.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Properties,
        [string]$File
    )

    $issues = [System.Collections.Generic.List[object]]::new()

    if (-not $Properties.displayName) { $issues.Add((New-PolicyIssue Warning 'Definition.DisplayName' 'displayName is not set.' -File $File)) }
    if (-not $Properties.description) { $issues.Add((New-PolicyIssue Info 'Definition.Description' 'description is not set.' -File $File)) }

    $mode = [string]$Properties.mode
    if ($mode -and $mode -notin 'All', 'Indexed' -and $mode -notlike 'Microsoft.*.Data') {
        $issues.Add((New-PolicyIssue Error 'Definition.Mode' "mode '$mode' is not valid. Use All, Indexed or a resource provider mode." -File $File))
    }

    $rule = $Properties.policyRule
    if ($rule -isnot [System.Collections.IDictionary] -or -not $rule.Contains('if') -or -not $rule.Contains('then')) {
        $issues.Add((New-PolicyIssue Error 'Definition.PolicyRule' "policyRule must contain 'if' and 'then'." -File $File))
        return $issues.ToArray()
    }

    $declared = @()
    if ($Properties.parameters -is [System.Collections.IDictionary]) { $declared = @($Properties.parameters.Keys) }
    $ruleJson = ConvertTo-Json -InputObject $rule -Depth 100 -Compress
    $referenced = @([regex]::Matches($ruleJson, "parameters\('([^']+)'\)") | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
    foreach ($ref in $referenced) {
        if ($ref -notin $declared) {
            $issues.Add((New-PolicyIssue Error 'Definition.UndeclaredParameter' "policyRule references parameter '$ref' which is not declared." -File $File))
        }
    }
    foreach ($param in $declared) {
        if ($param -notin $referenced) {
            $issues.Add((New-PolicyIssue Warning 'Definition.UnusedParameter' "Parameter '$param' is declared but not used in policyRule." -File $File))
        }
        $p = $Properties.parameters[$param]
        if ($p -isnot [System.Collections.IDictionary] -or -not $p.type) {
            $issues.Add((New-PolicyIssue Error 'Definition.ParameterType' "Parameter '$param' must have a type." -File $File))
        }
        elseif ($p.type -notin 'String', 'Array', 'Object', 'Boolean', 'Integer', 'Float', 'DateTime') {
            $issues.Add((New-PolicyIssue Error 'Definition.ParameterType' "Parameter '$param' has unsupported type '$($p.type)'." -File $File))
        }
        if ($p -is [System.Collections.IDictionary] -and $p.Contains('defaultValue') -and $p.allowedValues -and
            -not (@($p.allowedValues | Where-Object { Test-PolicyValueEqual $_ $p.defaultValue }).Count)) {
            $issues.Add((New-PolicyIssue Error 'Definition.DefaultNotAllowed' "Parameter '$param' defaultValue is not in allowedValues." -File $File))
        }
    }

    $effectInfo = Get-PolicyEffectInfo -Properties $Properties
    if (-not $effectInfo.RawEffect) {
        $issues.Add((New-PolicyIssue Error 'Definition.Effect' 'policyRule.then.effect is missing.' -File $File))
    }
    elseif ($effectInfo.EffectParameter -and $effectInfo.PossibleEffects.Count -eq 0) {
        $issues.Add((New-PolicyIssue Warning 'Definition.EffectAllowedValues' "Effect parameter '$($effectInfo.EffectParameter)' has no allowedValues, so the effect cannot be checked." -File $File))
    }
    foreach ($e in $effectInfo.PossibleEffects) {
        if ($e -notin $script:ValidEffects) {
            $issues.Add((New-PolicyIssue Error 'Definition.Effect' "Effect '$e' is not a valid Azure Policy effect." -File $File))
        }
    }
    $needsRoles = @($effectInfo.PossibleEffects | Where-Object { $_ -in 'deployIfNotExists', 'modify' })
    if ($needsRoles.Count -and $effectInfo.RoleDefinitionIds.Count -eq 0) {
        $issues.Add((New-PolicyIssue Error 'Definition.RoleDefinitionIds' "Effect $($needsRoles -join '/') needs policyRule.then.details.roleDefinitionIds." -File $File))
    }

    return $issues.ToArray()
}

function Test-PolicyAssignmentParameter {
    <#
    .SYNOPSIS
        Checks assignment parameter values against the parameters a definition or initiative declares.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][System.Collections.IDictionary]$Declared,
        [AllowNull()][System.Collections.IDictionary]$Supplied,
        [string]$File,
        [string]$Target
    )

    $issues = [System.Collections.Generic.List[object]]::new()
    $declaredKeys = if ($Declared) { @($Declared.Keys) } else { @() }
    $suppliedKeys = if ($Supplied) { @($Supplied.Keys) } else { @() }

    foreach ($key in $suppliedKeys) {
        if ($key -notin $declaredKeys) {
            $issues.Add((New-PolicyIssue Error 'Assignment.UnknownParameter' "Parameter '$key' is not declared by $Target." -File $File))
            continue
        }
        $entry = $Supplied[$key]
        if ($entry -isnot [System.Collections.IDictionary] -or -not $entry.Contains('value')) {
            $issues.Add((New-PolicyIssue Error 'Assignment.ParameterFormat' "Parameter '$key' must be written as { `"value`": ... }." -File $File))
            continue
        }
        $allowed = $Declared[$key].allowedValues
        # ARM expressions like [parameters('x')] are resolved by Azure, so they cannot be checked here.
        $isExpression = $entry.value -is [string] -and $entry.value -match '^\[[^\[].*\]$'
        if ($allowed -and -not $isExpression -and $entry.value -isnot [System.Collections.IList] -and
            -not (@($allowed | Where-Object { Test-PolicyValueEqual $_ $entry.value }).Count)) {
            $issues.Add((New-PolicyIssue Error 'Assignment.ParameterNotAllowed' "Parameter '$key' value '$($entry.value)' is not in allowedValues ($($allowed -join ', '))." -File $File))
        }
    }
    foreach ($key in $declaredKeys) {
        $decl = $Declared[$key]
        if ($decl -is [System.Collections.IDictionary] -and -not $decl.Contains('defaultValue') -and $key -notin $suppliedKeys) {
            $issues.Add((New-PolicyIssue Error 'Assignment.MissingParameter' "Required parameter '$key' of $Target has no default and is not supplied." -File $File))
        }
    }
    return $issues.ToArray()
}

function Get-PolicyRepositoryFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Folder)
    $dir = Join-Path $Root $Folder
    if (-not (Test-Path -LiteralPath $dir)) { return @() }
    return @(Get-ChildItem -LiteralPath $dir -Recurse -File -Filter '*.json' | Sort-Object FullName)
}

function Read-PolicyRepositoryDocument {
    <#
    .SYNOPSIS
        Loads one repository file: parse, environment filter, token expansion. Returns $null when skipped.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.IO.FileInfo]$File,
        [Parameter(Mandatory)][string]$Environment,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Tokens,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Issues
    )

    $relative = [System.IO.Path]::GetRelativePath($Root, $File.FullName).Replace('\', '/')
    try {
        $doc = Read-PolicyJsonFile -Path $File.FullName
    }
    catch {
        $Issues.Add((New-PolicyIssue Error 'Json.Parse' $_.Exception.Message -File $relative))
        return $null
    }
    if ($doc -isnot [System.Collections.IDictionary]) {
        $Issues.Add((New-PolicyIssue Error 'Json.Shape' 'The file must contain a JSON object.' -File $relative))
        return $null
    }

    if ($doc.Contains('environments')) {
        $envs = @($doc.environments)
        $doc.Remove('environments')
        if ($envs.Count -and -not ($envs -contains $Environment)) { return $null }
    }
    $doc.Remove('$schema')

    try {
        $expanded = Expand-PolicyToken $doc -Tokens $Tokens -Source $relative
    }
    catch {
        $Issues.Add((New-PolicyIssue Error 'Token.Unknown' $_.Exception.Message -File $relative))
        return $null
    }

    if ($expanded.properties -isnot [System.Collections.IDictionary]) {
        $Issues.Add((New-PolicyIssue Error 'Json.Shape' "The file must have a 'properties' object." -File $relative))
        return $null
    }
    return [pscustomobject]@{ File = $relative; Document = $expanded }
}

function Set-PolicyOwnerId {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Properties, [Parameter(Mandatory)][string]$PacOwnerId)
    $metadata = [ordered]@{}
    if ($Properties.metadata -is [System.Collections.IDictionary]) {
        foreach ($k in $Properties.metadata.Keys) { $metadata[$k] = $Properties.metadata[$k] }
    }
    $metadata['pacOwnerId'] = $PacOwnerId
    $Properties['metadata'] = $metadata
}
