# Azure Policies
Most of these policies were built as a special request. I do test and validate these in my lab, but I am not an expert in building policy ;)

## [Enable Defender For Servers Plan 1](https://github.com/nathanmcnulty/nathanmcnulty/blob/master/Azure/Policy/EnableDefenderForServersPlan1.json)
If Defender for Servers has not been enabled yet, this policy will enable Defender for Servers Plan 1 on targeted subscriptions

## [Enforce Defender For Servers Plan 1](https://github.com/nathanmcnulty/nathanmcnulty/blob/master/Azure/Policy/EnforceDefenderForServersPlan1.json)
Regardless of whether Defender for Servers has been enabled or not, this policy will ensure Defender for Servers is enabled and conifgured to use Plan 1 on targeted subscriptions