function Test-AzDevOpsHost {
    <#
    .SYNOPSIS
        True when running inside an Azure DevOps (or Azure Pipelines-compatible) agent.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    return ($env:TF_BUILD -eq 'True')
}

function Write-PolicyLog {
    <#
    .SYNOPSIS
        Writes a log line, using Azure DevOps logging commands when running on a pipeline agent.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Azure DevOps logging commands must be written to the host stream.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [AllowEmptyString()]
        [string]$Message,

        [ValidateSet('Info', 'Section', 'Warning', 'Error', 'Detail')]
        [string]$Level = 'Info'
    )

    $ado = Test-AzDevOpsHost
    switch ($Level) {
        'Section' {
            if ($ado) { Write-Host "##[section]$Message" } else { Write-Host "== $Message" -ForegroundColor Cyan }
        }
        'Warning' {
            if ($ado) { Write-Host "##vso[task.logissue type=warning]$(ConvertTo-AzDevOpsLogValue $Message)" } else { Write-Warning $Message }
        }
        'Error' {
            if ($ado) { Write-Host "##vso[task.logissue type=error]$(ConvertTo-AzDevOpsLogValue $Message)" } else { Write-Host "ERROR: $Message" -ForegroundColor Red }
        }
        'Detail' { Write-Verbose $Message }
        default { Write-Host $Message }
    }
}

function ConvertTo-AzDevOpsLogValue {
    <#
    .SYNOPSIS
        Escapes a value for use inside an Azure DevOps ##vso logging command.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Position = 0)][AllowEmptyString()][AllowNull()][string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return '' }
    return $Value.Replace('%', '%AZP25').Replace("`r", '%0D').Replace("`n", '%0A').Replace(']', '%5D').Replace(';', '%3B')
}

function Write-AzDevOpsCommand {
    <#
    .SYNOPSIS
        Emits an Azure DevOps ##vso logging command. Does nothing outside a pipeline.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Azure DevOps reads logging commands from the host stream.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Command,
        [Parameter(Position = 1)][AllowEmptyString()][string]$Value
    )
    if (Test-AzDevOpsHost) { Write-Host "##vso[$Command]$Value" }
}
