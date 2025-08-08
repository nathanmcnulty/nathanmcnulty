# Risk Policies

## Read first
- Risk-based policies should always use Sign-in frequency of Every time and never select more than one type of risk in a single policy.
- Policies targeting admins should use both roles and group targeting because roles within Administrative Units are not covered by roles targeting and PIM/Access Packages may affect efficacy of the roles selection. 
- Your emergency access accounts / group should be excluded from all CA policies and rely on monitoring/alerting for use.
- You will need to add groups and emergency access accounts to these templates after importing.

## Preparation

Prior to deploying, you should always review the reports for user and sign-in risk in Identity Protection. Set the filters to include the maximum amount of time, select all conditions, and review the historical impact these policies would have had if configured for the various risk levels (low, medium, high). This provides an idea of what you might expect once implementing these if you wanted to enable sooner than waiting for report-only data.


## Deployment

We typically recommend the following 5 policies as a starting point:

- [Medium or high Sign-in risk for regular user - Require MFA]()
- [High User risk regular users - Require password change]()
- [Low or medium Sign-in risk for admins - Require MFA]()
- [High Sign-in risk for admins - Block]()
- [Medium or high user risk for admins - Block]()

These are available as JSON files for download in this folder and can be directly imported to Conditional Access in Entra portal:
