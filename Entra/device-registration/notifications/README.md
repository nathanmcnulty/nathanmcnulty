# Device Registration Notifications

This solution emails a user when Microsoft Entra ID records a successful user-driven device registration. It uses a Microsoft Sentinel near-real-time (NRT) analytics rule, an alert-created automation rule, a Consumption Logic App, and Microsoft Graph `sendMail` with the Logic App's managed identity.

## Recommendation

Use `Register device` as the canonical audit operation. Microsoft lists that operation under the Device Registration Service audit activities. The broader `Add device` operation can also appear when a service or application creates a device object. The supplied query accepts both operations but requires `InitiatedBy.user.userPrincipalName`, so application-only device creation is excluded because there is no user to notify.

This Sentinel design is a good fit when Entra audit logs are already ingested into a Sentinel workspace. It is event-driven, normally evaluates new data once per minute, and provides a searchable alert trail. If Sentinel is not already licensed and ingesting `AuditLogs`, a scheduled workflow that queries Microsoft Graph is simpler than introducing Sentinel only for this notification.

## Architecture

```text
Entra device registration audit event
    -> Log Analytics AuditLogs
    -> Sentinel NRT analytics rule (one alert per registration)
    -> Sentinel alert-created automation rule
    -> Consumption Logic App playbook
    -> Microsoft Graph /users/{sender}/sendMail
    -> registering user
```

The deployment template creates the API connection and Logic App in the deployment resource group. It deploys the analytics and automation rules to the resource group containing the Sentinel workspace. Two post-deployment permission steps are required because they grant authorization outside the resources created by the template.

## Prerequisites

- Microsoft Entra audit logs are sent to the target Log Analytics workspace.
- Microsoft Sentinel is enabled on that workspace.
- A dedicated Exchange Online mailbox exists for the sender, for example `security-notifications@contoso.com`.
- The deploying administrator can create Sentinel rules and Logic Apps, grant Sentinel access to the playbook resource group, and configure Exchange Online application RBAC.

The sender parameter must identify an existing Exchange Online user or shared mailbox. It is not an arbitrary From address. A shared mailbox is a good fit and typically does not require a license while it remains within Microsoft's shared-mailbox limits.

## Deploy

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fnathanmcnulty%2Fnathanmcnulty%2Frefs%2Fheads%2Fmain%2FEntra%2Fdevice-registration%2Fnotifications%2Fdevice-registration-notification.json)

Deploy [device-registration-notification.json](device-registration-notification.json) to the resource group where the Logic App should reside. Supply the existing workspace name, workspace resource group, and sender mailbox. The template contains no tenant-specific identifiers; Azure derives the tenant and subscription at deployment time.

After deployment, complete both permission steps before testing.

### 1. Allow Sentinel to run the playbook

In the Microsoft Defender portal, open **Microsoft Sentinel > Configuration > Automation > Active playbooks**, select the deployed playbook, and use **Manage permissions** to grant Microsoft Sentinel access to the playbook's resource group. Sentinel's service account requires the **Microsoft Sentinel Automation Contributor** role on that resource group.

### 2. Allow the Logic App to send from one mailbox

The preferred approach is Exchange Online RBAC for Applications. It grants `Application Mail.Send` only for the dedicated sender mailbox and avoids the tenant-wide Microsoft Graph `Mail.Send` application role.

Get the Logic App managed identity values after deployment:

```powershell
Connect-MgGraph -Scopes "Application.Read.All"

$ManagedIdentityObjectId = "<principalId from the template deployment output>"
$ManagedIdentity = Get-MgServicePrincipal -ServicePrincipalId $ManagedIdentityObjectId
$ManagedIdentity | Select-Object Id, AppId, DisplayName
```

Then configure Exchange Online. Use the sender mailbox's unique alias in the management scope filter.

```powershell
Connect-ExchangeOnline

$ManagedIdentityObjectId = "<managed identity service principal object ID>"
$ManagedIdentityAppId = "<managed identity application ID>"
$SenderMailboxAlias = "security-notifications"

New-ServicePrincipal `
    -AppId $ManagedIdentityAppId `
    -ObjectId $ManagedIdentityObjectId `
    -DisplayName "device-registration-notification"

New-ManagementScope `
    -Name "Device notification sender mailbox" `
    -RecipientRestrictionFilter "Alias -eq '$SenderMailboxAlias'"

New-ManagementRoleAssignment `
    -Name "Device registration notification Mail.Send" `
    -Role "Application Mail.Send" `
    -App $ManagedIdentityObjectId `
    -CustomResourceScope "Device notification sender mailbox"

Test-ServicePrincipalAuthorization `
    -Identity $ManagedIdentityObjectId `
    -Resource "security-notifications@contoso.com"
```

If a mailbox-scoped management scope already exists for the sender, reuse it rather than creating another scope. Do not also grant the managed identity the tenant-wide Microsoft Graph `Mail.Send` application permission: Entra application permissions and Exchange application RBAC grants are additive.

## PowerShell webhook alternative

[device-registration-notification.ps1](device-registration-notification.ps1) provides the email portion as a standalone managed-identity webhook handler. Use it when an Azure Automation runbook or HTTP-triggered PowerShell Function is a better operational fit than the Logic App. Do not connect both handlers to the same alert unless duplicate messages are intentional.

The script accepts either Azure Automation's `WebhookData.RequestBody`, an Azure Functions `Request.Body`, the full Sentinel alert body, or the `Custom Details` object by itself. It validates required fields and restricts delivery to explicitly allowed recipient domains before calling Microsoft Graph.

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
  "DeviceName": ["DESKTOP-001"],
  "DeviceId": ["00000000-0000-0000-0000-000000000000"],
  "JoinType": ["Microsoft Entra registered"],
  "OperatingSystem": ["Windows"],
  "OSVersion": ["11"],
  "RegistrationTime": ["2026-01-01 12:00:00 UTC"],
  "SourceIPAddress": ["192.0.2.1"],
  "OperationName": ["Register device"],
  "CorrelationId": ["00000000-0000-0000-0000-000000000000"]
}
```

Treat an Automation webhook URL or Function key as a secret. Azure Automation webhook requests are authorized by possession of the URL, and runbook input is retained in job logs. Avoid placing credentials or tokens in the payload.

## KQL

The template deploys this query as an NRT analytics rule:

```kql
AuditLogs
| where Result =~ "success"
| where OperationName in ("Register device", "Add device")
| extend Actor = todynamic(InitiatedBy), Targets = todynamic(TargetResources)
| extend RecipientEmail = tostring(Actor.user.userPrincipalName), SourceIPAddress = tostring(Actor.user.ipAddress)
| where isnotempty(RecipientEmail) and RecipientEmail !contains "#EXT#"
| extend DeviceObjectId = tostring(Targets[0].id), TargetDeviceName = tostring(Targets[0].displayName), ModifiedProperties = todynamic(Targets[0].modifiedProperties)
| mv-apply Property = ModifiedProperties on (
    summarize
        DeviceIdRaw = take_anyif(tostring(Property.newValue), tostring(Property.displayName) == "DeviceId"),
        DeviceDisplayNameRaw = take_anyif(tostring(Property.newValue), tostring(Property.displayName) == "DeviceDisplayName"),
        DisplayNameRaw = take_anyif(tostring(Property.newValue), tostring(Property.displayName) == "DisplayName"),
        CloudDisplayNameRaw = take_anyif(tostring(Property.newValue), tostring(Property.displayName) == "CloudDisplayName"),
        DeviceOSRaw = take_anyif(tostring(Property.newValue), tostring(Property.displayName) == "DeviceOS"),
        DeviceOSTypeRaw = take_anyif(tostring(Property.newValue), tostring(Property.displayName) == "DeviceOSType"),
        CloudDeviceOSTypeRaw = take_anyif(tostring(Property.newValue), tostring(Property.displayName) == "CloudDeviceOSType"),
        DeviceOSVersionRaw = take_anyif(tostring(Property.newValue), tostring(Property.displayName) == "DeviceOSVersion"),
        CloudDeviceOSVersionRaw = take_anyif(tostring(Property.newValue), tostring(Property.displayName) == "CloudDeviceOSVersion"),
        DeviceTrustTypeRaw = take_anyif(tostring(Property.newValue), tostring(Property.displayName) == "DeviceTrustType")
)
| extend
    DeviceId = tostring(todynamic(DeviceIdRaw)[0]),
    RegisteredDeviceName = tostring(todynamic(DeviceDisplayNameRaw)[0]),
    ModifiedDeviceName = tostring(todynamic(DisplayNameRaw)[0]),
    CloudDeviceName = tostring(todynamic(CloudDisplayNameRaw)[0]),
    RegisteredDeviceOS = tostring(todynamic(DeviceOSRaw)[0]),
    DeviceOS = tostring(todynamic(DeviceOSTypeRaw)[0]),
    CloudDeviceOS = tostring(todynamic(CloudDeviceOSTypeRaw)[0]),
    DeviceOSVersion = tostring(todynamic(DeviceOSVersionRaw)[0]),
    CloudDeviceOSVersion = tostring(todynamic(CloudDeviceOSVersionRaw)[0]),
    DeviceTrustType = tostring(todynamic(DeviceTrustTypeRaw)[0])
| extend DeviceName = coalesce(TargetDeviceName, RegisteredDeviceName, ModifiedDeviceName, CloudDeviceName, "Not recorded"), OperatingSystem = coalesce(RegisteredDeviceOS, DeviceOS, CloudDeviceOS, "Not recorded"), OSVersion = coalesce(DeviceOSVersion, CloudDeviceOSVersion, "Not recorded")
| extend JoinType = case(DeviceTrustType =~ "Workplace", "Microsoft Entra registered", DeviceTrustType =~ "AzureAd", "Microsoft Entra joined", DeviceTrustType =~ "ServerAd", "Microsoft Entra hybrid joined", isnotempty(DeviceTrustType), DeviceTrustType, "Not recorded")
| extend AccountName = tostring(split(RecipientEmail, "@")[0]), AccountUPNSuffix = tostring(split(RecipientEmail, "@")[1])
| extend RegistrationTime = strcat(format_datetime(TimeGenerated, "yyyy-MM-dd HH:mm:ss"), " UTC")
| project TimeGenerated, RecipientEmail, AccountName, AccountUPNSuffix, DeviceName, DeviceId, DeviceObjectId, OperatingSystem, OSVersion, JoinType, RegistrationTime, SourceIPAddress, OperationName, CorrelationId
```

## Email contents

The message identifies the device name, device ID, join type, operating system and version, registration time, source IP address, audit operation, and correlation ID when Entra records those values. It tells the recipient that no action is required if they registered the device and to contact the configured helpdesk immediately if they did not.

## Test and verify

1. Run the KQL in Advanced Hunting or the workspace Logs page and confirm a known user-driven registration returns the expected user and device.
2. Register a test device and confirm Entra records `Register device` with a user initiator.
3. Confirm the NRT rule creates one informational alert.
4. Confirm the Sentinel automation rule records a successful playbook action.
5. Confirm the Logic App Graph request returns HTTP `202` and the user receives one message.
6. Verify that the managed identity cannot send as a mailbox outside the Exchange management scope.

## Limitations

- NRT rules use a one-minute lookback and depend on prompt ingestion of Entra audit logs. Monitor analytics-rule health for delayed or failed runs.
- Application-only `Add device` events are deliberately excluded because they do not identify a user to notify. This also avoids notifying users about service-created or managed device objects.
- Device details vary by registration path and client. Missing fields appear as `Not recorded` in the email.
- Guest UPNs containing `#EXT#` are excluded because the UPN is usually not a deliverable address. Resolving a guest's `mail` property would require an additional directory-read permission and workflow action.
- Exchange application RBAC changes can take time to propagate. Test authorization before treating the workflow as production-ready.

## References

- [Microsoft Entra audit activity reference](https://learn.microsoft.com/entra/identity/monitoring-health/reference-audit-activities)
- [Manage device identities using the Microsoft Entra admin center](https://learn.microsoft.com/entra/identity/devices/manage-device-identities)
- [Work with near-real-time analytics rules in Microsoft Sentinel](https://learn.microsoft.com/azure/sentinel/create-nrt-rules)
- [Create and use Microsoft Sentinel automation rules](https://learn.microsoft.com/azure/sentinel/create-manage-use-automation-rules)
- [Supported Microsoft Sentinel playbook triggers and actions](https://learn.microsoft.com/azure/sentinel/automation/playbook-triggers-actions)
- [Authenticate Logic Apps with managed identities](https://learn.microsoft.com/azure/logic-apps/authenticate-with-managed-identity)
- [Role Based Access Control for Applications in Exchange Online](https://learn.microsoft.com/exchange/permissions-exo/application-rbac)
- [Start an Azure Automation runbook from a webhook](https://learn.microsoft.com/azure/automation/automation-webhooks)
- [PowerShell developer reference for Azure Functions](https://learn.microsoft.com/azure/azure-functions/functions-reference-powershell)
