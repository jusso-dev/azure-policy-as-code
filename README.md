# azure-policy-as-code

Deploy and manage Azure Policy from JSON files in Git, through an Azure DevOps pipeline.

`AzPolicyOps` is a PowerShell 7 module that reads policy definitions, initiatives, assignments and exemptions from this repository, compares them with Azure, and applies the difference. It plans first, waits for approval, then deploys. It only touches resources this repository created.

```
pull request ─► Validate ─► Plan dev ─► (approve) ─► Deploy dev ─► Plan prod ─► (approve) ─► Deploy prod
                 lint          plan.json + summary     applies the reviewed plan, then starts a compliance scan
                 unit tests
                 policy checks
```

## What it does

| Area | Behaviour |
|---|---|
| **Validate** (offline) | JSON syntax, names, required fields, effects, `{{token}}` use, parameters checked against the definition they feed, `deployIfNotExists`/`modify` needing an identity and `roleDefinitionIds`, references between files, expired exemptions. No Azure sign-in needed, so it runs on every pull request. |
| **Plan** | Reads Azure and works out `Create`, `Update`, `Replace`, `Delete` or `NoChange` for each resource, listing exactly which properties changed. Writes `plan.json` (a pipeline artifact) and `plan.md` (the run summary), and sets the `hasChanges` output variable. |
| **Replace detection** | Azure refuses some changes in place. The plan turns these into delete-and-recreate, and does the same for anything that depends on the resource: removing a parameter, changing a parameter's type, adding a parameter with no default, or moving an exemption to another assignment. All of these were confirmed against the ARM API. |
| **Deploy** | Deletes and replaces dependants first (exemptions → assignments → initiatives → definitions), then writes in the reverse order. Retries throttling and eventual-consistency errors. Supports `-WhatIf`. |
| **Stale plan guard** | Each plan records a fingerprint of the Azure state it saw. If someone edits a policy in the portal while the run waits for approval, the deploy stops and asks for a new plan. |
| **Ownership** | Every resource is stamped with `metadata.pacOwnerId`. Deletes only remove resources carrying this repository's owner ID. Resources from other teams are never changed, and a name clash fails the plan unless you pass `-AllowOwnershipTakeover`. Unmanaged resources with the same name are adopted. |
| **Managed identities** | For assignments with an identity, the roles their `deployIfNotExists`/`modify` policies list are granted at the assignment scope. Missing roles are put back, and roles are removed when the assignment is deleted or replaced. |
| **Compliance** | `Start-PolicyComplianceScan`, `Get-PolicyComplianceSummary` (Markdown, plus JUnit so non-compliant assignments appear as failed tests in Azure DevOps) and `Start-PolicyRemediation`. |
| **Adopt existing policy** | `Export-PolicyFromAzure` writes portal-made policy out as repository files. |

## Repository layout

```
policies/
  definitions/    one policy definition per file
  initiatives/    policy set definitions
  assignments/    assignments (scope defaults to the environment's deploymentScope)
  exemptions/     exemptions
  environments/   dev.json, prod.json: scope, owner ID, tokens
src/AzPolicyOps/  the module
scripts/          pipeline entry points (Validate, Plan, Deploy, Compliance)
pipelines/        Azure DevOps YAML
tests/unit/       Pester tests against an in-memory ARM fake (no Azure)
tests/integration Pester tests against a live subscription
```

### Environment file

```json
{
  "pacOwnerId": "azure-policy-as-code-prod",
  "deploymentScope": "/subscriptions/${env:POLICY_SUBSCRIPTION_ID}",
  "definitionScope": "/providers/Microsoft.Management/managementGroups/contoso",
  "managedIdentityLocation": "australiaeast",
  "tokens": { "allowedLocations": [ "australiaeast", "australiasoutheast" ], "enforcementMode": "Default" }
}
```

- `${env:NAME}` is read from an environment variable, which is how pipeline variables get in.
- `definitionScope` is optional and defaults to `deploymentScope`. Use a management group to share definitions across subscriptions.
- `{{token}}` in any policy file is replaced from `tokens`. These are built in: `environment`, `pacOwnerId`, `deploymentScope`, `definitionScope` and `subscriptionId`. A token that is the whole string value can be an array or an object.

### Policy files

Definitions and initiatives use the normal ARM shape `{ "name": ..., "properties": { ... } }`. Some extras:

- Use `"policyDefinitionName": "require-tag"` or `"policySetDefinitionName": "baseline"` instead of a full ID. The name resolves to the environment's `definitionScope`, so one file works in every environment. Built-in policies use their full `/providers/Microsoft.Authorization/...` ID.
- `"environments": ["prod"]` limits a file to those environments.
- On assignments: `scope` (any management group, subscription or resource group), `identity` plus an optional `location`, and an optional `roleAssignments` list to override the roles worked out from the policy.
- On exemptions: `policyAssignmentName` plus `policyAssignmentScope` instead of `policyAssignmentId`.

See [`policies/`](policies) for a working baseline: a tagging, allowed-locations, network and storage initiative, plus a `modify` assignment with a managed identity.

## Azure DevOps setup

1. **Service connections.** Create one Azure Resource Manager connection per environment, using workload identity federation, named `sc-azure-policy-dev` and `sc-azure-policy-prod`. Give each identity these roles at the deployment scope:
   - **Resource Policy Contributor** to write definitions, initiatives, assignments and exemptions.
   - **Role Based Access Control Administrator** (limited to the roles your policies need) or **User Access Administrator**. Only needed if an assignment uses a managed identity.
   - **Reader**, if the identity doesn't already have it, so it can read the subscription.
2. **Environments.** Create `azure-policy-dev` and `azure-policy-prod` and add approval checks to them. The deploy job waits on these.
3. **Variable group.** Create `azure-policy` with `DEV_SUBSCRIPTION_ID` and `PROD_SUBSCRIPTION_ID`.
4. **Pipelines.** Create one from `pipelines/azure-pipelines.yml` (and optionally `pipelines/compliance-pipeline.yml` for nightly reports). Then add the first one as a build validation branch policy on `main`.

Pull requests run Validate and Plan, and the plan shows on the run summary. Merging to `main` runs the deploy stages after approval. The deploy stage is skipped when the plan finds no changes.

## Running locally or on any agent

```powershell
Import-Module ./src/AzPolicyOps/AzPolicyOps.psd1

Test-PolicyRepository -Path ./policies                     # offline

Connect-PolicyPipelineAccount                               # ARM_TENANT_ID / ARM_SUBSCRIPTION_ID / ARM_CLIENT_ID / ARM_CLIENT_SECRET
$env:POLICY_SUBSCRIPTION_ID = (Get-AzContext).Subscription.Id
$plan = New-PolicyDeploymentPlan -Path ./policies -Environment dev -OutFile ./out/plan.json
Invoke-PolicyDeploymentPlan -Plan ./out/plan.json -WhatIf
Invoke-PolicyDeploymentPlan -Plan ./out/plan.json

Get-PolicyComplianceSummary -Scope "/subscriptions/$env:POLICY_SUBSCRIPTION_ID" -PacOwnerId azure-policy-as-code-dev
```

`Connect-PolicyPipelineAccount` also accepts `-FederatedToken` for OIDC sign-in from other CI systems. Inside Azure DevOps the `AzurePowerShell@5` task signs in for you.

## Tests

```powershell
Invoke-Pester ./tests/unit                     # 82 tests, no Azure needed

$env:ARM_TENANT_ID = '...'; $env:ARM_SUBSCRIPTION_ID = '...'; $env:ARM_CLIENT_ID = '...'; $env:ARM_CLIENT_SECRET = '...'
$env:INTEGRATION_RESOURCE_GROUP = 'rg-policy-test'   # an existing, empty resource group
Invoke-Pester ./tests/integration -Output Detailed
```

The unit tests mock `Invoke-AzRestMethod` with an in-memory ARM fake, which enforces the same update rules real Azure does. The integration tests run each `scripts/` entry point in a new `pwsh` process with `TF_BUILD=True`, signing in as a service principal, just as `AzurePowerShell@5` does with a service connection. They cover:

1. The Validate stage.
2. A first deploy that creates every type of resource, plus a role assignment.
3. A second run that finds no changes and skips the deploy stage.
4. Updates made in place, including adding a parameter to a definition that is already assigned.
5. A portal edit made between plan and deploy, which blocks the stale deploy before a fresh plan fixes the drift.
6. A parameter removal that replaces the definition and its assignment and moves the role to the new identity.
7. A compliance report.
8. Exporting portal-made policy.
9. Deletes, including `-SkipDelete`.

Everything an integration run creates uses a unique owner ID and is cleaned up afterwards.

## Functions

| Function | Purpose |
|---|---|
| `Test-PolicyRepository` | Offline validation |
| `Get-PolicyEnvironment`, `Get-PolicyDesiredState` | Load an environment, or the resources the repository describes |
| `Get-PolicyDeployedState` | Read custom policy resources from Azure, with their owner |
| `New-PolicyDeploymentPlan` | Work out the changes; save them to `plan.json` and `plan.md` |
| `Invoke-PolicyDeploymentPlan` | Apply a plan (`-WhatIf`, `-Force`) |
| `Start-PolicyComplianceScan` | On-demand evaluation (`-Wait`) |
| `Get-PolicyComplianceSummary` | Compliance per assignment (Markdown, JUnit, `-FailOnNonCompliance`) |
| `Start-PolicyRemediation` | Remediation tasks for `deployIfNotExists` and `modify` |
| `Export-PolicyFromAzure` | Turn existing policy into repository files |
| `Connect-PolicyPipelineAccount` | Service principal or federated sign-in outside `AzurePowerShell@5` |

`Get-Help <function> -Full` gives details for each.
