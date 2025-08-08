# Risk Policies

## Read first
- Risk-based policies should always use Sign-in frequency of Every time and never select more than one type of risk in a single policy.
- Policies targeting admins should use both roles and group targeting because roles within Administrative Units are not covered by roles targeting and PIM/Access Packages may affect efficacy of the roles selection. 
- Your emergency access accounts / group should be excluded from all CA policies and rely on monitoring/alerting for use.
- You will need to add groups and emergency access accounts to these templates after importing.

## Preparation

Prior to deploying, you should always review the reports for user and sign-in risk in Identity Protection. Set the filters to include the maximum amount of time, select all conditions, and review the historical impact these policies would have had if configured for the various risk levels (low, medium, high). This provides an idea of what you might expect once implementing these if you wanted to enable sooner than waiting for report-only data.

<img width="3291" height="1308" alt="image" src="https://github.com/user-attachments/assets/e3b10651-b120-4a2e-af03-e232baf4d2fb" />

<img width="3631" height="1311" alt="image" src="https://github.com/user-attachments/assets/24feb925-9231-46e4-a34b-6d15d0218828" />

## Deployment

We typically recommend the following 5 policies as a starting point:

- [Medium or high Sign-in risk for regular user - Require MFA](https://github.com/nathanmcnulty/nathanmcnulty/blob/1428ffc2daafca6e4e8a9984e953117776985eb4/Entra/conditional-access/risk-policies/User-SignInRisk-MediumHigh-RequireMFA.json)
- [High User risk regular users - Require password change](https://github.com/nathanmcnulty/nathanmcnulty/blob/1428ffc2daafca6e4e8a9984e953117776985eb4/Entra/conditional-access/risk-policies/User-UserRisk-High-PasswordReset.json)
  - Change to Block if not using Self-Service Password Reset
- [Low or medium Sign-in risk for admins - Require MFA](https://github.com/nathanmcnulty/nathanmcnulty/blob/1428ffc2daafca6e4e8a9984e953117776985eb4/Entra/conditional-access/risk-policies/Admin-SignInRisk-LowMedium-RequireMFA.json)
- [High Sign-in risk for admins - Block](https://github.com/nathanmcnulty/nathanmcnulty/blob/1428ffc2daafca6e4e8a9984e953117776985eb4/Entra/conditional-access/risk-policies/Admin-SignInRisk-High-Block.json)
- [Medium or high user risk for admins - Block](https://github.com/nathanmcnulty/nathanmcnulty/blob/1428ffc2daafca6e4e8a9984e953117776985eb4/Entra/conditional-access/risk-policies/Admin-UserRisk-MediumHigh-Block.json)

These are available as JSON files for download in this folder and can be directly imported to Conditional Access in Entra portal:

<img width="2627" height="1286" alt="image" src="https://github.com/user-attachments/assets/17422641-e012-4031-846d-1365dfbe7c14" />

<img width="580" height="943" alt="image" src="https://github.com/user-attachments/assets/5880d385-a80c-499e-8a80-2d11e44d7194" />
