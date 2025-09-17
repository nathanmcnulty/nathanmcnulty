# Global Secure Access

These policy files should help speed up deployment of Global Secure Access. As settings become avialable in Settings Catalog or handled as part of the installer, I will try to update the policy files here.

## Windows

At the time of this writing, Global Secure Access cannot acquire QUIC, DNS over HTTPS, or DNS over TLS, so we need to disable these in our browsers. The following configuration profile disables these for Edge and Chrome. If using Firefox, you will need to add the ADMX templates to Intune and add the settings or use PowerShell scripts: 
[Browser Restrictions Configuration Profile](./windows/Global%20Secure%20Access%20-%20Browser%20Restrictions.json)

There are also several client settings that are not available in Settings Catalog yet, so I have created Remediation scripts to help you set the desired settings. This script also ensures that IPv4 is preferred over IPv6 as Global Secure Access does not support IPv6 yet.

I have added helper text in the scripts, but for reference (and future settings), the registry values come from here:
https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-install-windows-client#client-registry-keys

Below are the discovery and remediation scripts:

[Discovery script](./windows/gsa-settings-discovery.ps1)  
[Detection script](./windows/gsa-settings-detection.ps1)

## macOS

Global Secure Access for macOS requires macOS 13.0 or higher, the device must be registered to Entra with the Company Portal, and the Enterprise SSO plug-in must be deployed.

With those in place, deploy the following policies:
- [Approve system extensions](./macos/Global%20Secure%20Access%20-%20Extensions.json)
- [Configure Transparent Proxy](./macos/Global%20Secure%20Access%20-%20Transparent%20Proxy.xml)
- [Configure Browser Restrictions](./macos/Global%20Secure%20Access%20-%20Browser%20Restrictions.json)
- [Configure Tray Buttons](./macos/Global%20Secure%20Access%20-%20Tray%20Buttons.xml)
  - May consider adjusting these based on the docs: https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-install-macos-client#hide-or-unhide-system-tray-menu-buttons
- Package and deploy the client using the PKG downloaded from Entra

## iOS

Global Secure Access uses the Defender for Endpoint app as a host, so we need to deploy that first, and then enable Global Secure Access.

### For Supervised devices
- Create an app configuration policy for managed devices targeting Defender for Endpoint
  - Key: `issupervised`
  - Type: String
  - Value: `{{issupervised}}`
- Create Zero-touch (Silent) Control Filter policy
  - [Mobileconfig from Microsoft](https://download.microsoft.com/download/f/8/e/f8ed3484-b665-4c3c-9ae9-272c8a04159b/Microsoft_Defender_for_Endpoint_Control_Filter_Zerotouch.mobileconfig)

### For all devices
- Create the VPN configuration profile for Global Secure Access
  - [Follow Microsoft Learn](https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-install-ios-client#create-a-vpn-profile-and-configure-global-secure-access-for-microsoft-defender-for-endpoint)
    - Be sure to pay attention to the GSA specific key/value pairs
- Deploy the Defender for Endpoint app


## Android

