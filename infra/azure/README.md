# AdminSecOps Azure foundation

Region: **UAE North (`uaenorth`)**. Use local Azure PowerShell. These templates are deployment preparation, not a running hosted product.

## Stages and cost

1. `foundation.json` creates only `rg-adminsecops-dev-uaenorth`. An empty resource group has no resource usage charge.
2. `container-environment.json` prepares a Consumption-only Container Apps environment, without application containers, dedicated profiles, a registry or a database. Deploy only after registration, quota and template validation succeed. No workload cost estimate is implied by an empty environment.
3. Add the hosted authenticated API, tenant isolation, durable storage, managed identity and diagnostic destinations before application deployment. The existing loopback API must remain local. Configure scale-to-zero and explicit maximum replicas on the future apps.
4. Provision PostgreSQL only when the hosted service can use it. B1ms plus 32 GB was estimated at USD 19.02/month at 730 hours using public retail prices on 2026-09-21. This excludes all other services, taxes and subscription discounts/credits.

Azure Monitor is selected for environment log routing. A diagnostic destination and retention must be configured before workloads run; this template does not persist application logs. No secrets, role assignments, DNS changes or application ingress are created by these files.

## Local PowerShell validation

Select the intended MSDN subscription explicitly; do not deploy against an arbitrary default context:

```powershell
$subscriptionId = '1f93383f-91f1-4b62-b288-2ddee3ccbd0c'
$ctx = Get-AzContext -ListAvailable | Where-Object { $_.Subscription.Id -eq $subscriptionId -and $_.Account.Id -eq 'cloudadmin@palanilab.com' } | Select-Object -First 1
if (-not $ctx) { throw 'Sign in to the AdminSecOps Azure subscription first.' }
Test-AzSubscriptionDeployment -Location uaenorth -TemplateFile C:\AdminSecOps\infra\azure\foundation.json -DefaultProfile $ctx
```

After successful validation and review, provision the resource group explicitly:

```powershell
New-AzSubscriptionDeployment -Name adminsecops-foundation -Location uaenorth -TemplateFile C:\AdminSecOps\infra\azure\foundation.json -DefaultProfile $ctx
```

The environment is a separate deployment. After provider registration and quota confirmation, validate it against the created resource group before considering creation:

```powershell
Test-AzResourceGroupDeployment -ResourceGroupName rg-adminsecops-dev-uaenorth -TemplateFile C:\AdminSecOps\infra\azure\container-environment.json -DefaultProfile $ctx
```

A provider listing is not proof of subscription quota or available capacity. Keep the environment undeployed until those checks pass. Run deployments in Incremental mode; removing a resource from a template is not a cleanup operation.

## References

- [Subscription deployments](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/deploy-to-subscription)
- [Container Apps environment resource schema](https://learn.microsoft.com/en-us/azure/templates/microsoft.app/2025-01-01/managedenvironments)
- [Region selection and price comparison](../../docs/architecture/AZURE-DEPLOYMENT.md)

## Verification on 21 September 2026

- Local Azure PowerShell sign-in succeeded for the intended MSDN subscription.
- Microsoft.App and Microsoft.DBforPostgreSQL registration completed successfully.
- Both providers list UAE North; PostgreSQL capabilities include Standard_B1ms.
- Container Apps ManagedEnvironmentCount: 0 used, limit 20 after registration.
- Both templates passed local JSON parsing. Azure validation of foundation.json returned an empty error list.
- Updated Az.Accounts to 5.5.3 and completed the Microsoft authentication claims challenge. Combined foundation/environment Azure validation passed. Validation does not reserve capacity or guarantee future deployment success.
- Deployment adminsecops-foundation succeeded. Resource group rg-adminsecops-dev-uaenorth exists in uaenorth; verified resource count: 0. No Container Apps environment, database or application has been deployed.



Current online test deployment: see [ONLINE-TEST.md](ONLINE-TEST.md). The UAE templates above remain historical preparation.
