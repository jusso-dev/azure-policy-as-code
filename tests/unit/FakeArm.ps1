# In-memory stand-in for the ARM policy APIs, used to mock Invoke-AzRestMethod in unit tests.
# It enforces the update rules verified against real Azure (see Private/Breaking.ps1) so plan and
# deploy logic can be tested end to end without a subscription.

function global:Reset-FakeArm {
    $global:FakeArm = @{
        Store = [ordered]@{}
        Calls = [System.Collections.Generic.List[object]]::new()
    }
    # Built-in "Allowed locations", referenced by the fixture initiative.
    Add-FakeArmResource -Id '/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c' -Body @{
        properties = @{
            policyType = 'BuiltIn'; mode = 'Indexed'; displayName = 'Allowed locations'
            parameters = @{ listOfAllowedLocations = @{ type = 'Array' } }
            policyRule = @{ if = @{ field = 'location'; notIn = "[parameters('listOfAllowedLocations')]" }; then = @{ effect = 'deny' } }
        }
    }
}

function global:New-FakeArmResponse {
    param([int]$StatusCode, $Body)
    $content = if ($null -ne $Body) { ConvertTo-Json -InputObject $Body -Depth 100 -Compress } else { '' }
    [pscustomobject]@{ StatusCode = $StatusCode; Content = $content; Headers = [pscustomobject]@{ RetryAfter = $null; Location = $null } }
}

function global:New-FakeArmError {
    param([int]$StatusCode, [string]$Code, [string]$Message)
    New-FakeArmResponse -StatusCode $StatusCode -Body @{ error = @{ code = $Code; message = $Message } }
}

function global:Add-FakeArmResource {
    <# Seeds a resource directly, bypassing PUT validation (to simulate portal-made or other-owner resources). #>
    param([string]$Id, [hashtable]$Body)
    $item = ConvertFrom-Json (ConvertTo-Json $Body -Depth 100) -AsHashtable -Depth 100
    $item.id = $Id
    $item.name = ($Id -split '/')[-1]
    $global:FakeArm.Store[$Id.ToLowerInvariant()] = $item
}

function global:Invoke-FakeArm {
    param([string]$Method, [string]$Path, [string]$Uri, [string]$Payload)

    $raw = if ($Path) { $Path } else { ([uri]$Uri).PathAndQuery }
    $global:FakeArm.Calls.Add([pscustomobject]@{ Method = $Method; Path = $raw; Payload = $Payload })
    $pathOnly, $query = $raw -split '\?', 2
    $key = $pathOnly.TrimEnd('/').ToLowerInvariant()
    $filter = ''
    if ($query) {
        foreach ($pair in $query -split '&') {
            $k, $v = $pair -split '=', 2
            if ($k -eq '$filter') { $filter = [uri]::UnescapeDataString($v) }
        }
    }
    $store = $global:FakeArm.Store
    $collectionTypes = 'policydefinitions', 'policysetdefinitions', 'policyassignments', 'policyexemptions', 'roleassignments'
    $leaf = ($key -split '/')[-1]

    if ($Method -eq 'GET' -and $leaf -in $collectionTypes) {
        $scope = $key.Substring(0, $key.LastIndexOf('/providers/microsoft.authorization/'))
        $exact = $filter -match 'atExactScope'
        $items = @($store.Values | Where-Object {
                $id = $_.id.ToLowerInvariant()
                $itemScope = $id.Substring(0, $id.LastIndexOf('/providers/microsoft.authorization/'))
                $id -match "/providers/microsoft\.authorization/$leaf/[^/]+$" -and
                $(if ($exact) { $itemScope -eq $scope } else { $itemScope.StartsWith($scope) })
            })
        if ($filter -match "principalId eq '([^']+)'") {
            $principal = $Matches[1]
            $items = @($items | Where-Object { $_.properties.principalId -eq $principal })
        }
        return New-FakeArmResponse 200 @{ value = $items }
    }

    $existing = $store[$key]
    switch ($Method) {
        'GET' {
            if ($existing) { return New-FakeArmResponse 200 $existing }
            return New-FakeArmError 404 'NotFound' "$pathOnly not found"
        }
        'DELETE' {
            if (-not $existing) { return New-FakeArmResponse 204 $null }
            if ($leaf -and $key -match '/policy(set)?definitions/') {
                $users = @($store.Values | Where-Object {
                        ($_.properties.policyDefinitionId -and ([string]$_.properties.policyDefinitionId).ToLowerInvariant() -eq $key) -or
                        ($_.properties.policyDefinitions | Where-Object { ([string]$_.policyDefinitionId).ToLowerInvariant() -eq $key })
                    })
                if ($users) { return New-FakeArmError 400 'InvalidDeletePolicyDefinitionRequest' "In use by $($users[0].id)" }
            }
            $store.Remove($key)
            return New-FakeArmResponse 200 $null
        }
        'PUT' {
            $body = ConvertFrom-Json $Payload -AsHashtable -Depth 100
            $props = $body.properties

            if ($key -match '/policy(set)?definitions/[^/]+$' -and $existing) {
                $old = if ($existing.properties.parameters) { $existing.properties.parameters } else { @{} }
                $new = if ($props.parameters) { $props.parameters } else { @{} }
                foreach ($p in $old.Keys) {
                    if (-not $new.ContainsKey($p)) { return New-FakeArmError 400 'InvalidPolicyParameterUpdate' 'Policy parameters cannot be removed during policy update.' }
                    if ($old[$p].type -ne $new[$p].type) { return New-FakeArmError 400 'InvalidPolicyParameterUpdate' "The existing policy parameter(s) '$p' type is being updated which is not allowed." }
                }
                foreach ($p in $new.Keys) {
                    if (-not $old.ContainsKey($p) -and -not $new[$p].ContainsKey('defaultValue')) { return New-FakeArmError 400 'InvalidPolicyParameterUpdate' "New parameter '$p' has no default value." }
                }
            }
            if ($key -match '/policysetdefinitions/') {
                foreach ($m in $props.policyDefinitions) {
                    $ref = $m.policyDefinitionId.ToLowerInvariant()
                    if (-not $ref.StartsWith('/providers/') -and -not $store[$ref]) { return New-FakeArmError 400 'PolicyDefinitionNotFound' "$ref not found" }
                }
            }
            if ($key -match '/policyassignments/') {
                $ref = $props.policyDefinitionId.ToLowerInvariant()
                if (-not $ref.StartsWith('/providers/') -and -not $store[$ref]) { return New-FakeArmError 400 'PolicyDefinitionNotFound' "$ref not found" }
                if ($body.identity -and $body.identity.type -eq 'SystemAssigned') {
                    if (-not $body.location) { return New-FakeArmError 400 'IdentityServiceUnavailable' "identity is unavailable for location ''" }
                    $principal = if ($existing -and $existing.identity -and $existing.identity.principalId) { $existing.identity.principalId } else { [guid]::NewGuid().ToString() }
                    $body.identity.principalId = $principal
                    $body.identity.tenantId = 'tenant-1'
                }
            }
            if ($key -match '/policyexemptions/' -and $existing -and
                $existing.properties.policyAssignmentId.ToLowerInvariant() -ne $props.policyAssignmentId.ToLowerInvariant()) {
                return New-FakeArmError 400 'InvalidPolicyAssignmentIdUpdate' 'Cannot update the existing policy exemption policy assignment.'
            }
            if ($key -match '/roleassignments/' -and $existing) {
                return New-FakeArmError 409 'RoleAssignmentExists' 'The role assignment already exists.'
            }

            # Azure adds system metadata and echoes defaults; mimic that so comparisons must ignore them.
            if ($key -match '/policysetdefinitions/') {
                foreach ($m in $props.policyDefinitions) { if (-not $m.definitionVersion) { $m.definitionVersion = '1.*.*' } }
            }
            if ($key -notmatch '/roleassignments/') {
                if (-not $props.metadata) { $props.metadata = @{} }
                $props.metadata.createdBy = 'fake-principal'
                $props.metadata.createdOn = '2026-11-05T00:00:00Z'
                if ($existing) { $props.metadata.updatedOn = '2026-11-05T01:00:00Z' }
            }
            else {
                $props.scope = $pathOnly.Substring(0, $pathOnly.IndexOf('/providers/Microsoft.Authorization/roleAssignments', [System.StringComparison]::OrdinalIgnoreCase))
            }
            $body.id = $pathOnly
            $body.name = ($pathOnly -split '/')[-1]
            $store[$key] = $body
            return New-FakeArmResponse $(if ($existing) { 200 } else { 201 }) $body
        }
        default { return New-FakeArmError 404 'NotFound' "No fake for $Method $pathOnly" }
    }
}
