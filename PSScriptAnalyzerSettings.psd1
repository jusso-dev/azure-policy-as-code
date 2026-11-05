@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # New-*/Set-* helpers here build in-memory objects; they change nothing in Azure.
        # Functions that do change Azure implement SupportsShouldProcess.
        'PSUseShouldProcessForStateChangingFunctions'
        # Azure DevOps reads ##vso logging commands and ##[section] markers from the host stream.
        'PSAvoidUsingWriteHost'
    )
}
