$script:ApiVersion = @{
    PolicyDefinition    = '2023-04-01'
    PolicySetDefinition = '2023-04-01'
    PolicyAssignment    = '2023-04-01'
    PolicyExemption     = '2022-07-01-preview'
    PolicyStates        = '2019-10-01'
    Remediation         = '2021-10-01'
    RoleAssignment      = '2022-04-01'
}

# Error codes worth retrying because ARM policy writes are eventually consistent.
$script:EventualConsistencyErrorCodes = @(
    'PolicyDefinitionNotFound'
    'PolicySetDefinitionNotFound'
    'PolicyAssignmentNotFound'
    'PrincipalNotFound'
)

function Invoke-PolicyRestMethod {
    <#
    .SYNOPSIS
        Calls the ARM REST API through Invoke-AzRestMethod with retry, throttling and error handling.
    .DESCRIPTION
        Uses the current Az context, so it works with whatever login the pipeline task established
        (service principal secret, workload identity federation or managed identity).
        Returns the parsed response body as hashtables, or $null on 404 with -AllowNotFound.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'PUT', 'POST', 'DELETE', 'PATCH')]
        [string]$Method,

        # Resource path (e.g. /subscriptions/x/providers/...), or an absolute nextLink URI.
        [Parameter(Mandatory)]
        [string]$Path,

        [string]$ApiVersion,

        [AllowNull()]
        $Body,

        [switch]$AllowNotFound,

        [string[]]$RetryOnErrorCode = @(),

        [ValidateRange(1, 20)]
        [int]$MaxAttempts = 6,

        # Return the raw PSHttpResponse instead of the parsed body.
        [switch]$Raw
    )

    $request = @{ Method = $Method; ErrorAction = 'Stop' }
    if ($Path -match '^https://') {
        $request.Uri = $Path
    }
    else {
        if (-not $ApiVersion) { throw "ApiVersion is required for path '$Path'." }
        $separator = if ($Path.Contains('?')) { '&' } else { '?' }
        $request.Path = "$Path${separator}api-version=$ApiVersion"
    }
    if ($null -ne $Body) {
        $request.Payload = ConvertTo-Json -InputObject $Body -Depth 100 -Compress
    }

    for ($attempt = 1; ; $attempt++) {
        $response = Invoke-AzRestMethod @request
        $status = [int]$response.StatusCode
        $content = $null
        if ($response.Content) {
            try { $content = ConvertFrom-PolicyJson -Json $response.Content } catch { $content = $response.Content }
        }

        if ($status -ge 200 -and $status -lt 300) {
            if ($Raw) { return $response }
            return $content
        }
        if ($status -eq 404 -and $AllowNotFound) { return $null }

        $errorCode = $null
        $errorMessage = $response.Content
        if ($content -is [System.Collections.IDictionary] -and $content.error) {
            $errorCode = $content.error.code
            $errorMessage = $content.error.message
        }

        $retryable = ($status -in 408, 429, 500, 502, 503, 504) -or ($errorCode -and $errorCode -in $RetryOnErrorCode)
        if ($retryable -and $attempt -lt $MaxAttempts) {
            $delay = [int][Math]::Min(60, [Math]::Pow(2, $attempt))
            try {
                $retryAfter = $response.Headers.RetryAfter
                if ($retryAfter -and $retryAfter.Delta) { $delay = [int][Math]::Ceiling($retryAfter.Delta.TotalSeconds) }
            }
            catch { Write-Verbose 'No Retry-After header.' }
            Write-PolicyLog "$Method $Path returned $status $errorCode; retry $attempt/$($MaxAttempts - 1) in ${delay}s" -Level Detail
            Start-Sleep -Seconds $delay
            continue
        }

        $exception = [System.InvalidOperationException]::new("$Method $Path failed with HTTP $status$(if ($errorCode) { " $errorCode" }): $errorMessage")
        $exception.Data['StatusCode'] = $status
        $exception.Data['ErrorCode'] = $errorCode
        throw $exception
    }
}

function Get-PolicyRestCollection {
    <#
    .SYNOPSIS
        GETs an ARM list endpoint and follows nextLink paging.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ApiVersion
    )

    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Path
    $first = $true
    while ($next) {
        $page = if ($first) {
            Invoke-PolicyRestMethod -Method GET -Path $next -ApiVersion $ApiVersion -AllowNotFound
        }
        else {
            Invoke-PolicyRestMethod -Method GET -Path $next -AllowNotFound
        }
        $first = $false
        if ($null -eq $page) { break }
        foreach ($item in @($page.value)) { if ($null -ne $item) { $items.Add($item) } }
        $next = $page.nextLink
    }
    return , $items.ToArray()
}

function Get-PolicyResourceKindInfo {
    <#
    .SYNOPSIS
        Maps a plan item kind to its ARM resource type and API version.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('PolicyDefinition', 'PolicySetDefinition', 'PolicyAssignment', 'PolicyExemption')][string]$Kind)
    $type = switch ($Kind) {
        'PolicyDefinition' { 'policyDefinitions' }
        'PolicySetDefinition' { 'policySetDefinitions' }
        'PolicyAssignment' { 'policyAssignments' }
        'PolicyExemption' { 'policyExemptions' }
    }
    return [pscustomobject]@{ Kind = $Kind; ResourceType = $type; ApiVersion = $script:ApiVersion[$Kind] }
}

function Get-PolicyResourceId {
    <#
    .SYNOPSIS
        Builds the ARM ID of a policy resource at a scope.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][string]$Name
    )
    $info = Get-PolicyResourceKindInfo -Kind $Kind
    return "$($Scope.TrimEnd('/'))/providers/Microsoft.Authorization/$($info.ResourceType)/$Name"
}

function Get-PolicyScopeKind {
    <#
    .SYNOPSIS
        Classifies an ARM scope as ManagementGroup, Subscription, ResourceGroup or Resource.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Scope)
    switch -Regex ($Scope) {
        '^/providers/Microsoft\.Management/managementGroups/[^/]+/?$' { return 'ManagementGroup' }
        '^/subscriptions/[^/]+/?$' { return 'Subscription' }
        '^/subscriptions/[^/]+/resourceGroups/[^/]+/?$' { return 'ResourceGroup' }
        '^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/.+' { return 'Resource' }
        default { return 'Invalid' }
    }
}
