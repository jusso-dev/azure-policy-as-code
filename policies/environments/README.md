# Environment files

The policy files in `definitions/`, `initiatives/`, `assignments/` and `exemptions/` are **shared by every environment**. An environment file holds only what differs between environments: where to deploy, who owns what is deployed, and a few values.

One file per environment. The file name is the environment name the pipeline passes with `-Environment` (`dev.json` → `-Environment dev`).

```jsonc
{
  "$schema": "./environment.schema.json",          // editor hints and validation for this file
  "description": "Production subscription.",        // for people; ignored by the tooling
  "pacOwnerId": "azure-policy-as-code-prod",        // ownership stamp, see below
  "deploymentScope": "/subscriptions/${env:POLICY_SUBSCRIPTION_ID}",   // where assignments go
  "definitionScope": "/providers/Microsoft.Management/managementGroups/contoso", // optional: where definitions go
  "managedIdentityLocation": "australiaeast",       // region for assignment managed identities
  "tokens": {                                       // per-environment values for {{token}} in policy files
    "allowedLocations": [ "australiaeast", "australiasoutheast" ],
    "enforcementMode": "Default"
  }
}
```

| Field | Required | What it does |
|---|---|---|
| `pacOwnerId` | yes | Written to `metadata.pacOwnerId` on everything this environment deploys. The pipeline only updates or deletes resources with this value, and the drift check uses it to separate "ours" from "made in the portal" or "another team's". Make it unique per environment and **never change it** after the first deploy. |
| `deploymentScope` | yes | Subscription or management group that assignments and exemptions default to. It's also the area that deletes and the drift check look at. Individual assignments can set `"scope"` to a resource group or another scope inside it. |
| `definitionScope` | no | Where custom definitions and initiatives are created. Defaults to `deploymentScope`. Use a management group to share one copy across subscriptions. It must be at or above every assignment that uses them. |
| `managedIdentityLocation` | only with identities | Region Azure uses for the managed identity of assignments with `"identity"` (`deployIfNotExists`/`modify`). It doesn't limit which resources the policy covers. |
| `tokens` | no | Values substituted into policy files. `"{{allowedLocations}}"` in a file becomes this environment's array. Always available: `{{environment}}`, `{{pacOwnerId}}`, `{{deploymentScope}}`, `{{definitionScope}}`, `{{subscriptionId}}`. |

**`${env:NAME}`** is read from an environment variable when the pipeline runs, so subscription IDs live in the Azure DevOps variable group instead of in Git. The pipeline sets `POLICY_SUBSCRIPTION_ID` from `DEV_SUBSCRIPTION_ID` or `PROD_SUBSCRIPTION_ID`.

## Worked example

`assignments/baseline-governance.json` contains:

```json
"enforcementMode": "{{enforcementMode}}",
"parameters": { "allowedLocations": { "value": "{{allowedLocations}}" } }
```

| | dev | prod |
|---|---|---|
| Deployed to | dev subscription | prod subscription |
| `enforcementMode` | `DoNotEnforce` (audit only) | `Default` (enforced) |
| `allowedLocations` | australiaeast, australiasoutheast, westus2 | australiaeast, australiasoutheast |
| Stamped with | `azure-policy-as-code-dev` | `azure-policy-as-code-prod` |

Same file, two different deployments.

## Limit a policy file to some environments

Add `"environments": ["prod"]` to any policy file. Other environments skip it.

## See what an environment resolves to

```powershell
Import-Module ./src/AzPolicyOps/AzPolicyOps.psd1
$env:POLICY_SUBSCRIPTION_ID = '<subscription id>'
Get-PolicyEnvironment -Path ./policies -Environment prod | Format-List
(Get-PolicyDesiredState -Path ./policies -Environment prod).Resources | Format-Table Kind, Name, Scope
```
