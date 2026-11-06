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
| **Drift check** | `Test-PolicyDrift` compares Azure with source control and changes nothing. It reports every resource as `InSync`, `Modified` (each changed field with the repository value and the Azure value, who last changed it, and whether the fix is an update or a replace), `MissingInAzure`, `NotInRepository` (deployed by this repository but its file is gone) or `Unmanaged` (custom policy made in the portal or by a script). It runs on a schedule in `pipelines/drift-pipeline.yml`. |
| **Compliance** | `Start-PolicyComplianceScan`, `Get-PolicyComplianceSummary` (Markdown, plus JUnit so non-compliant assignments appear as failed tests in Azure DevOps) and `Start-PolicyRemediation`. |
| **Adopt existing policy** | `Export-PolicyFromAzure` writes portal-made policy out as repository files. |

## Repository layout

```
policies/
  definitions/    one policy definition per file
  initiatives/    policy set definitions
  assignments/    assignments (scope defaults to the environment's deploymentScope)
  exemptions/     exemptions
  environments/   dev.json, prod.json: where to deploy, owner ID, per-environment values (see its README)
src/AzPolicyOps/  the module
scripts/          pipeline entry points (Validate, Plan, Deploy, Drift, Compliance)
pipelines/        Azure DevOps YAML
tests/unit/       Pester tests against an in-memory ARM fake (no Azure)
tests/integration Pester tests against a live subscription
```

### Environment files

The policy files are **shared by every environment**. Each file in `policies/environments/` (`dev.json`, `prod.json`) holds only what differs: where to deploy, the ownership stamp, and per-environment values. The file name is what you pass to `-Environment`.

```json
{
  "$schema": "./environment.schema.json",
  "description": "Production subscription. enforcementMode Default, so each policy applies its effect (the baseline initiative audits unless you set its effect parameters to Deny).",
  "pacOwnerId": "azure-policy-as-code-prod",
  "deploymentScope": "/subscriptions/${env:POLICY_SUBSCRIPTION_ID}",
  "managedIdentityLocation": "australiaeast",
  "tokens": { "allowedLocations": [ "australiaeast", "australiasoutheast" ], "enforcementMode": "Default" }
}
```

| Field | What it does |
|---|---|
| `pacOwnerId` | Stamped on everything this environment deploys. Only resources with this value are ever updated or deleted, and the drift check uses it to tell "ours" from "made in the portal". Never change it after the first deploy. |
| `deploymentScope` | Subscription or management group where assignments go, unless an assignment sets its own `scope`. It is also the area that deletes and the drift check look at. |
| `definitionScope` | Optional. Where definitions and initiatives are created. Defaults to `deploymentScope`. |
| `managedIdentityLocation` | Region for the managed identity of assignments that use `deployIfNotExists` or `modify`. |
| `tokens` | Values for `{{token}}` placeholders in policy files, for example audit in dev and enforce in prod. |

`${env:NAME}` is read from a pipeline variable, so subscription IDs stay out of Git. See [`policies/environments/README.md`](policies/environments/README.md) for every field and a worked dev vs prod example. The JSON schema gives you field help in VS Code.

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
4. **Pipelines.** Create one from `pipelines/azure-pipelines.yml`, one from `pipelines/drift-pipeline.yml` for the scheduled drift check, and optionally one from `pipelines/compliance-pipeline.yml` for nightly compliance reports. Then add the first one as a build validation branch policy on `main`.

Pull requests run Validate and Plan, and the plan shows on the run summary. Merging to `main` runs the deploy stages after approval. The deploy stage is skipped when the plan finds no changes. Prod is still planned (and deployed, after approval) when dev had nothing to deploy.

> [!IMPORTANT]
> Environment approvals only gate the deploy job. The Plan stage runs on pull requests with the same service connection, and a pull request can change the pipeline YAML and `scripts/`. To stop an unreviewed pull request writing to Azure, also add **Approvals** and a **Branch control** check (allow only `refs/heads/main`) to the service connections themselves. For more separation, plan with a second, Reader-only service connection per environment.

## Drift: is Azure still what Git says?

Changes made in the portal, with the CLI or by another tool make Azure differ from the repository. To see the differences:

```powershell
Test-PolicyDrift -Path ./policies -Environment prod
```

```
Modified         PolicyDefinition     require-tag
      displayName: repository 'Require tag', Azure 'Changed in portal'
      parameters.effect.defaultValue: repository 'Audit', Azure 'Deny'
      last changed in Azure by someone@contoso.com at 2026-11-05T12:07:48Z
Modified         PolicyAssignment     baseline
      parameters.locations.value: repository ["westus2"], Azure ["westus2","eastus"]
      enforcementMode: repository 'Default', Azure 'DoNotEnforce'
MissingInAzure   PolicyDefinition     inherit-tag
NotInRepository  PolicyDefinition     old-policy
Unmanaged        PolicyDefinition     portal-made
Drift: 1 in sync, 2 modified, 1 missing in Azure, 1 not in repository, 1 unmanaged.
```

| State | Meaning | What the next deploy does |
|---|---|---|
| `InSync` | Azure matches Git | nothing |
| `Modified` | Changed in Azure, or changed in Git and not deployed yet | puts Azure back to Git (update, or replace if Azure cannot change it in place) |
| `MissingInAzure` | In Git, not in Azure | creates it |
| `NotInRepository` | Has this repo's `pacOwnerId` but no file | deletes it |
| `Unmanaged` | Custom policy with no owner, made outside the pipeline | leaves it alone. Use `Export-PolicyFromAzure` to bring it into Git |

The check is read-only. `pipelines/drift-pipeline.yml` runs it every 6 hours for each environment and adds:
- a Markdown report on the run summary;
- one test per resource in the Tests tab, where drifted resources are failed tests;
- the `driftDetected` output variable.

`-FailOnDrift` fails the run when anything drifts, and `-FailOnUnmanaged` also fails it on portal-made policy. There are two ways to resolve drift: run the deploy pipeline, so Azure goes back to Git, or commit the change, so Git catches up with Azure.

## Running locally or on any agent

```powershell
Import-Module ./src/AzPolicyOps/AzPolicyOps.psd1

Test-PolicyRepository -Path ./policies                     # offline

Connect-PolicyPipelineAccount                               # ARM_TENANT_ID / ARM_SUBSCRIPTION_ID / ARM_CLIENT_ID / ARM_CLIENT_SECRET
$env:POLICY_SUBSCRIPTION_ID = (Get-AzContext).Subscription.Id
$plan = New-PolicyDeploymentPlan -Path ./policies -Environment dev -OutFile ./out/plan.json
Invoke-PolicyDeploymentPlan -Plan ./out/plan.json -WhatIf
Invoke-PolicyDeploymentPlan -Plan ./out/plan.json
Test-PolicyDrift -Path ./policies -Environment dev

Get-PolicyComplianceSummary -Scope "/subscriptions/$env:POLICY_SUBSCRIPTION_ID" -PacOwnerId azure-policy-as-code-dev
```

`Connect-PolicyPipelineAccount` also accepts `-FederatedToken` for OIDC sign-in from other CI systems. Inside Azure DevOps the `AzurePowerShell@5` task signs in for you.

## Tests

```powershell
Invoke-Pester ./tests/unit                     # 105 tests, no Azure needed

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
7. A drift check run straight after deploy, which reports everything in sync.
8. Real out-of-band changes: a definition and an assignment edited in Azure, an exemption deleted, an orphaned definition and a portal-made one. The drift check reports each with field values, `-FailOnDrift` fails the run, and a deploy clears the drift but leaves the unmanaged policy alone.
9. A compliance report.
10. Exporting portal-made policy.
11. Deletes, including `-SkipDelete`.

Everything an integration run creates uses a unique owner ID and is cleaned up afterwards.

## Functions

| Function | Purpose |
|---|---|
| `Test-PolicyRepository` | Offline validation |
| `Get-PolicyEnvironment`, `Get-PolicyDesiredState` | Load an environment, or the resources the repository describes |
| `Get-PolicyDeployedState` | Read custom policy resources from Azure, with their owner |
| `New-PolicyDeploymentPlan` | Work out the changes; save them to `plan.json` and `plan.md` |
| `Invoke-PolicyDeploymentPlan` | Apply a plan (`-WhatIf`, `-Force`) |
| `Test-PolicyDrift` | Read-only comparison of Azure with source control (Markdown, JUnit, JSON, `-FailOnDrift`, `-FailOnUnmanaged`) |
| `Start-PolicyComplianceScan` | On-demand evaluation (`-Wait`) |
| `Get-PolicyComplianceSummary` | Compliance per assignment (Markdown, JUnit, `-FailOnNonCompliance`) |
| `Start-PolicyRemediation` | Remediation tasks for `deployIfNotExists` and `modify` |
| `Export-PolicyFromAzure` | Turn existing policy into repository files |
| `Connect-PolicyPipelineAccount` | Service principal or federated sign-in outside `AzurePowerShell@5` |

`Get-Help <function> -Full` gives details for each.

## Licence

MIT. See [LICENSE](LICENSE).
