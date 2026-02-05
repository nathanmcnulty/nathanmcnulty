# Teams API

This might be one of the most cursed and broken APIs at Microsoft. These scripts used to work, but they have not for a while. I'm leaving them here as an archive for others in case it is helpful :)

To list all virtual events, you must use a service principal with VirtualEvent.Read.All permissions, but to create/update/publish/cancel webinars, you must have a user because application permissions are not supported. 

For event registrations, you can only list with application permissions, and the ability to create/update/cancel registrations requires a complicated application access policy.

Some of the docs state you can grant higher privileges, such as VirtualEventRegistration-Anon.ReadWrite.All, to avoid user application access policies, but this has never worked since they moved to application access policies.