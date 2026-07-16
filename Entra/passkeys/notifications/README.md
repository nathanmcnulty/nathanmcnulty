# MFA Method Registration Notifications

This solution sends a user an email when Microsoft Entra ID records a successful MFA method registration, including passkeys. It uses a Microsoft Sentinel near-real-time (NRT) analytics rule, an alert-triggered Logic App playbook, a Sentinel automation rule, and Microsoft Graph `sendMail` with the Logic App's managed identity.

## Recommendation

Use the Sentinel design when Entra audit logs are already ingested into a Sentinel workspace. It is event-driven, normally evaluates new data once per minute, provides a searchable alert trail, and avoids a polling Logic App. If Sentinel is not already licensed and ingesting `AuditLogs`, a scheduled Logic App that queries Microsoft Graph is simpler and less expensive than introducing Sentinel only for this notification.

The analytics query covers all registrations for which Entra supplies a specific authentication method. It deliberately treats these as separate event sources:

- `Add Passkey (device-bound)` is the canonical passkey event.
- `User registered security info` is used for all other MFA methods when `AdditionalDetails` contains a nonempty `AuthenticationMethod` other than `Passkey`.

Microsoft Entra emits both events for a passkey registration. In a sample tenant, every successful `Add Passkey` event had a nearby `User registered security info` event, so alerting on both would send duplicate emails.

Guest UPNs containing `#EXT#` are excluded because a guest UPN is usually not a deliverable email address. See [Limitations](#limitations) for options.

## Architecture

```text
Entra audit log
    -> Log Analytics AuditLogs
    -> Sentinel NRT analytics rule (one alert per registration)
    -> Sentinel alert-created automation rule
    -> Consumption Logic App playbook
    -> Microsoft Graph /users/{sender}/sendMail
    -> registering user
```

The deployment template creates the API connection and Logic App in the deployment resource group, and it deploys the NRT analytics rule and automation rule to the resource group containing the Sentinel workspace. Two post-deployment permission steps are still required because they grant tenant-level authorization that an Azure Resource Manager deployment cannot safely infer.

## Prerequisites

- Microsoft Entra audit logs are sent to the target Log Analytics workspace.
- Microsoft Sentinel is enabled on that workspace.
- A dedicated Exchange Online mailbox exists for the sender, for example `security-notifications@contoso.com`.
- The deploying administrator can create Sentinel analytics and automation rules, deploy Logic Apps, grant Sentinel access to the playbook resource group, and configure Exchange Online application RBAC.

The sender parameter must identify an existing Exchange Online user or shared mailbox. It is not an arbitrary From address. A shared mailbox is a good fit for this workflow and typically does not require a license while it remains within Microsoft's shared-mailbox limits.

## Deploy

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fnathanmcnulty%2Fnathanmcnulty%2Frefs%2Fheads%2Fmain%2FEntra%2Fpasskeys%2Fnotifications%2Fmfa-registration-notification.json)

Deploy [mfa-registration-notification.json](mfa-registration-notification.json) to the resource group where the Logic App should reside. Supply the existing workspace name, workspace resource group, and sender mailbox.

After deployment, complete both permission steps below before testing.

### 1. Allow Sentinel to run the playbook

In the Microsoft Defender portal, open **Microsoft Sentinel > Configuration > Automation > Active playbooks**, select the deployed playbook, and use **Manage permissions** to grant Microsoft Sentinel access to the playbook's resource group. Sentinel's service account requires the **Microsoft Sentinel Automation Contributor** role on that resource group.

The template creates the alert-triggered automation rule, but it cannot run the playbook until this permission exists.

### 2. Allow the Logic App to send from one mailbox

The preferred approach is Exchange Online RBAC for Applications. It grants `Application Mail.Send` only for the dedicated sender mailbox and avoids the tenant-wide Microsoft Graph `Mail.Send` application role.

Get the Logic App managed identity values after deployment:

```powershell
Connect-MgGraph -Scopes "Application.Read.All"

$ManagedIdentityObjectId = "<principalId from the template deployment output>"
$ManagedIdentity = Get-MgServicePrincipal -ServicePrincipalId $ManagedIdentityObjectId
$ManagedIdentity | Select-Object Id, AppId, DisplayName
```

Then configure Exchange Online. Use a unique mailbox alias in the management scope filter.

```powershell
Connect-ExchangeOnline

$ManagedIdentityObjectId = "<managed identity service principal object ID>"
$ManagedIdentityAppId = "<managed identity application ID>"
$SenderMailboxAlias = "security-notifications"

New-ServicePrincipal `
    -AppId $ManagedIdentityAppId `
    -ObjectId $ManagedIdentityObjectId `
    -DisplayName "mfa-registration-notification"

New-ManagementScope `
    -Name "MFA notification sender mailbox" `
    -RecipientRestrictionFilter "Alias -eq '$SenderMailboxAlias'"

New-ManagementRoleAssignment `
    -Name "MFA notification Mail.Send" `
    -Role "Application Mail.Send" `
    -App $ManagedIdentityObjectId `
    -CustomResourceScope "MFA notification sender mailbox"

Test-ServicePrincipalAuthorization `
    -Identity $ManagedIdentityObjectId `
    -Resource "security-notifications@contoso.com"
```

Do not also grant the managed identity the tenant-wide Microsoft Graph `Mail.Send` application permission. Microsoft Entra application permissions and Exchange application RBAC grants are additive; an unscoped Entra grant would defeat the mailbox scope.

If Exchange application RBAC is not available in the tenant, the fallback is assigning the Microsoft Graph `Mail.Send` application role to the managed identity. That permission allows sending as any user unless constrained by a legacy Exchange Application Access Policy, so it is not the recommended default.

## PowerShell webhook alternative

[mfa-registration-notification.ps1](mfa-registration-notification.ps1) provides the email portion as a standalone managed-identity webhook handler. Use it when an Azure Automation runbook or HTTP-triggered PowerShell Function is a better operational fit than the Logic App. Do not connect both handlers to the same alert unless duplicate messages are intentional.

The script accepts either Azure Automation's `WebhookData.RequestBody`, an Azure Functions `Request.Body`, the full Sentinel alert body, or the `Custom Details` object by itself. It validates all required fields and restricts delivery to explicitly allowed recipient domains before calling Microsoft Graph.

This script replaces the email execution layer, not the detection rule. Configure an Azure Monitor scheduled-query alert, action group, or another trusted caller to POST the projected KQL fields. Sentinel automation rules natively run playbooks, so the supplied Logic App remains the direct option when Sentinel is the orchestrator.

Required configuration:

- `SenderMailbox`: existing Exchange Online mailbox used as the sender.
- `AllowedRecipientDomains`: comma- or semicolon-separated domains, such as `contoso.com,contoso.onmicrosoft.com`.
- `HelpdeskContact`: optional; defaults to `the helpdesk`.
- `EmailSubjectPrefix`: optional.

For Azure Automation, import `Microsoft.Graph.Authentication`, enable the Automation account's managed identity, create a PowerShell runbook from the script, and store the configuration as fixed webhook runbook parameters. The `WebhookData` parameter is supplied automatically. Microsoft currently documents a PowerShell 7 webhook input serialization issue, so test the current runtime carefully or use the documented PowerShell 5.1 path.

For Azure Functions, save the script as the HTTP-triggered function's `run.ps1`, bind the HTTP input as `Request` and output as `Response`, add `Microsoft.Graph.Authentication` to `requirements.psd1`, enable managed identity, and use application settings named `SENDER_MAILBOX`, `ALLOWED_RECIPIENT_DOMAINS`, `HELPDESK_CONTACT`, and optionally `EMAIL_SUBJECT_PREFIX`.

The managed identity needs only the same mailbox-scoped Exchange `Application Mail.Send` assignment described above. It does not need `AuditLog.Read.All` because the alerting system supplies the event details.

Example direct webhook body:

```json
{
  "RecipientEmail": ["user@contoso.com"],
  "AuthenticationMethod": ["Passkey (device-bound)"],
  "RegistrationTime": ["2026-01-01 12:00:00 UTC"],
  "SourceIPAddress": ["192.0.2.1"],
  "OperationName": ["Add Passkey (device-bound)"],
  "CorrelationId": ["00000000-0000-0000-0000-000000000000"]
}
```

Treat an Automation webhook URL or Function key as a secret. Azure Automation webhook requests are authorized by possession of the URL, and runbook input is retained in job logs. Avoid placing credentials or tokens in the payload.

## KQL

The template deploys this query as an NRT analytics rule:

```kql
AuditLogs
| where Result =~ "success"
| where OperationName has "Add Passkey" or OperationName == "User registered security info"
| extend TargetResources = todynamic(TargetResources), AdditionalDetails = todynamic(AdditionalDetails), InitiatedBy = todynamic(InitiatedBy)
| extend RecipientEmail = tostring(TargetResources[0].userPrincipalName), SourceIPAddress = tostring(InitiatedBy.user.ipAddress)
| mv-apply Detail = AdditionalDetails on (
    summarize AuthenticationMethod = take_anyif(tostring(Detail.value), tostring(Detail.key) == "AuthenticationMethod")
)
| extend AuthenticationMethod = case(
    OperationName has "Add Passkey", replace_string(OperationName, "Add ", ""),
    AuthenticationMethod
)
| where OperationName has "Add Passkey" or (isnotempty(AuthenticationMethod) and AuthenticationMethod !~ "Passkey")
| where isnotempty(RecipientEmail) and RecipientEmail !contains "#EXT#"
| extend AccountName = tostring(split(RecipientEmail, "@")[0]), AccountUPNSuffix = tostring(split(RecipientEmail, "@")[1])
| extend RegistrationTime = strcat(format_datetime(TimeGenerated, "yyyy-MM-dd HH:mm:ss"), " UTC")
| project TimeGenerated, RecipientEmail, AccountName, AccountUPNSuffix, AuthenticationMethod, RegistrationTime, SourceIPAddress, OperationName, CorrelationId
```

## Test and verify

1. Run the KQL directly in Advanced Hunting or the workspace Logs page and confirm it returns the expected user and method.
2. Register a test passkey. In the observed tenant, the audit operation was `Add Passkey (device-bound)`.
3. Confirm the NRT rule creates one informational alert.
4. Confirm the Sentinel automation rule records a successful playbook action.
5. Confirm the Logic App run sends a Graph request that returns HTTP `202`.
6. Confirm the user receives exactly one message with the expected method, time, and source IP address.
7. Verify that the managed identity cannot send as a mailbox outside the Exchange management scope.

## Limitations

- NRT rules use a one-minute lookback and depend on prompt ingestion of Entra audit logs. Monitor Sentinel analytics rule health for delayed or failed runs.
- Some generic `User registered security info` records have no `AuthenticationMethod` detail. They are excluded to avoid ambiguous and duplicate notifications.
- Guest users are excluded. To notify guests, resolve the target user ID to a deliverable `mail` address in Microsoft Graph before sending, which requires an additional directory-read permission and workflow action.
- The notification says that a method was registered; it does not prove the user personally performed the action. The supplied message directs users to contact the helpdesk if the activity was unexpected.
- Exchange application RBAC changes can take time to propagate. Test authorization before treating the workflow as production-ready.

## Why not the older pattern?

Older Sentinel examples attach a playbook directly to an analytics rule. Microsoft deprecated that invocation path in March 2026. This template uses an alert-created automation rule, which is the supported centralized mechanism for running alert-triggered playbooks.

The Logic App also avoids the Office 365 Outlook connector. Calling Microsoft Graph with managed identity removes a user-owned OAuth connection and supports mailbox-scoped Exchange application RBAC.

## References

- [Work with near-real-time analytics rules in Microsoft Sentinel](https://learn.microsoft.com/azure/sentinel/create-nrt-rules)
- [Create and use Microsoft Sentinel automation rules](https://learn.microsoft.com/azure/sentinel/create-manage-use-automation-rules)
- [Migrate alert-trigger playbooks to automation rules](https://learn.microsoft.com/azure/sentinel/automation/migrate-playbooks-to-automation-rules)
- [Supported Microsoft Sentinel playbook triggers and actions](https://learn.microsoft.com/azure/sentinel/automation/playbook-triggers-actions)
- [Authenticate Logic Apps with managed identities](https://learn.microsoft.com/azure/logic-apps/authenticate-with-managed-identity)
- [Role Based Access Control for Applications in Exchange Online](https://learn.microsoft.com/exchange/permissions-exo/application-rbac)
- [Start an Azure Automation runbook from a webhook](https://learn.microsoft.com/azure/automation/automation-webhooks)
- [PowerShell developer reference for Azure Functions](https://learn.microsoft.com/azure/azure-functions/functions-reference-powershell)
- [Microsoft Entra passkey FAQ](https://learn.microsoft.com/entra/identity/authentication/passkey-faq)
