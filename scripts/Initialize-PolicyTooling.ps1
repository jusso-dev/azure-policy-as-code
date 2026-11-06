<#
.SYNOPSIS
    Installs the modules the pipeline needs and imports AzPolicyOps. First step of every pipeline job.
.DESCRIPTION
    Microsoft-hosted agents already have Az modules; self-hosted agents may not. Missing modules are
    installed for the current user from the PowerShell Gallery. Minimum versions are set in
    scripts/requirements.psd1; a newer installed or published version satisfies them.
#>
[CmdletBinding()]
param(
    [switch]$IncludeTestTools
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$requirements = Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot 'requirements.psd1')
$wanted = @($requirements.Runtime)
if ($IncludeTestTools) { $wanted += $requirements.Test }

foreach ($module in $wanted) {
    $installed = Get-Module -ListAvailable -Name $module.Name | Where-Object { $_.Version -ge [version]$module.MinimumVersion }
    if ($installed) {
        Write-Host "$($module.Name) $(($installed | Sort-Object Version -Descending | Select-Object -First 1).Version) found"
        continue
    }
    Write-Host "Installing $($module.Name) >= $($module.MinimumVersion)"
    if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) { Register-PSRepository -Default }
    Install-Module -Name $module.Name -MinimumVersion $module.MinimumVersion -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -SkipPublisherCheck
}

Import-Module (Join-Path $PSScriptRoot '..' 'src' 'AzPolicyOps' 'AzPolicyOps.psd1') -Force
Write-Host "AzPolicyOps $((Get-Module AzPolicyOps).Version) loaded on PowerShell $($PSVersionTable.PSVersion) ($([System.Runtime.InteropServices.RuntimeInformation]::OSDescription))"
