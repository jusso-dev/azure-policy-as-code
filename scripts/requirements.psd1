@{
    Runtime = @(
        @{ Name = 'Az.Accounts'; MinimumVersion = '2.13.0' }
    )
    Test    = @(
        @{ Name = 'Pester'; MinimumVersion = '5.5.0' }
        @{ Name = 'PSScriptAnalyzer'; MinimumVersion = '1.21.0' }
    )
}
