Exemptions go here, one JSON file each. Example:

```json
{
  "name": "legacy-app-public-ip",
  "scope": "/subscriptions/<sub>/resourceGroups/rg-legacy-app",
  "properties": {
    "policyAssignmentName": "baseline-governance",
    "policyDefinitionReferenceIds": [ "noPublicIpOnNic" ],
    "exemptionCategory": "Waiver",
    "expiresOn": "2027-06-30T00:00:00Z",
    "displayName": "Legacy app needs a public IP until migration",
    "description": "Change ticket CHG-1234"
  }
}
```
