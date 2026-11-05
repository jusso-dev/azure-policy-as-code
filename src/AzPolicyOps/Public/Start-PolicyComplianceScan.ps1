function Start-PolicyComplianceScan {
    <#
    .SYNOPSIS
        Triggers an on-demand Azure Policy compliance evaluation for a subscription or resource group.
    .DESCRIPTION
        Azure evaluates new assignments within about 30 minutes, and existing ones every 24 hours.
        Run this after a deployment to get compliance results immediately. A scan of a subscription can
        take several minutes; with -Wait the function polls until it finishes or -TimeoutMinutes passes.
    .EXAMPLE
        Start-PolicyComplianceScan -Scope /subscriptions/$sub/resourceGroups/rg-app -Wait
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Scope,
        [switch]$Wait,
        [ValidateRange(1, 240)][int]$TimeoutMinutes = 30,
        [ValidateRange(5, 300)][int]$PollSeconds = 15
    )

    $Scope = $Scope.TrimEnd('/')
    if ((Get-PolicyScopeKind $Scope) -notin 'Subscription', 'ResourceGroup') {
        throw 'On-demand compliance scans support subscription and resource group scopes only.'
    }
    if (-not $PSCmdlet.ShouldProcess($Scope, 'Trigger policy compliance evaluation')) { return }

    $response = Invoke-PolicyRestMethod -Method POST -Path "$Scope/providers/Microsoft.PolicyInsights/policyStates/latest/triggerEvaluation" -ApiVersion $script:ApiVersion.PolicyStates -Raw
    $location = $null
    try { $location = [string]$response.Headers.Location } catch { Write-Verbose 'No Location header.' }
    Write-PolicyLog "Compliance scan started for $Scope."

    if (-not $Wait) { return [pscustomobject]@{ Scope = $Scope; Status = 'Started'; StatusUri = $location } }
    if (-not $location) { throw 'The scan was started but Azure returned no status URL to poll.' }

    $deadline = [datetime]::UtcNow.AddMinutes($TimeoutMinutes)
    while ([datetime]::UtcNow -lt $deadline) {
        Start-Sleep -Seconds $PollSeconds
        $poll = Invoke-AzRestMethod -Method GET -Uri $location -ErrorAction Stop
        switch ([int]$poll.StatusCode) {
            202 { Write-PolicyLog '  scan still running' -Level Detail }
            200 {
                Write-PolicyLog "Compliance scan finished for $Scope."
                return [pscustomobject]@{ Scope = $Scope; Status = 'Succeeded'; StatusUri = $location }
            }
            default { throw "Compliance scan status check returned HTTP $($poll.StatusCode): $($poll.Content)" }
        }
    }
    throw "Compliance scan for $Scope did not finish within $TimeoutMinutes minutes."
}
