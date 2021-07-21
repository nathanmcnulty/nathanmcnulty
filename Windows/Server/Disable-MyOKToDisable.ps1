# These are my recommendations for a server template, enable services as needed
# Comments are based on experience working in a couple large environments

# Microsoft says OK to disable | May need to enable on VOIP servers such as Mitel
"AudioEndpointBuilder","Audiosrv","QWAVE" | ForEach-Object { Stop-Service -Name $_; Set-Service -Name $_ -StartupType Disabled -Verbose }

# Microsoft says OK to disable
"AxInstSV","bthserv","CDPUserSvc","dmwappushservice","FrameServer","icssvc","lfsvc","lltdsvc","MapsBroker","NcbService","OneSyncSvc","PcaSvc","PhoneSvc","RmSvc","ScDeviceEnum","SensorDataService","SensorService","SensrSvc","SharedAccess","ShellHWDetection","SSDPSRV","stisvc","TabletInputService","upnphost","WalletService","WiaRpc","wisvc","wlidsvc","WpnService","XblAuthManager","XblGameSave" | ForEach-Object { Stop-Service -Name $_ -Force; Set-Service -Name $_ -StartupType Disabled -Verbose }
Disable-ScheduledTask -TaskPath "\Microsoft\XblGameSave" -TaskName "XblGameSaveTask" -Verbose
Disable-ScheduledTask -TaskPath "\Microsoft\XblGameSave" -TaskName "XblGameSaveTaskLogon" -Verbose

# Microsoft says OK to disable | Must be set via registry
"NgcCtnrSvc","NgcSvc","PimIndexMaintenanceSvc","UnistoreSvc","UserDataSvc","WpnUserService" | ForEach-Object { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$_" -Name Start -Value 4 -Force -Verbose }

# Microsoft says No guidance but has been safe to disable in my experience
"AJRouter","CDPSvc","DeviceAssociationService","fdPHost","FDResPub","lmhosts","SensorDataService","WbioSrvc" | ForEach-Object { Stop-Service -Name $_; Set-Service -Name $_ -StartupType Disabled -Verbose }

# Disable everywhere except servers that print | May need to enable on app servers that generate PDF reports
"spooler","PrintNotify" | ForEach-Object { Stop-Service -Name $_; Set-Service -Name $_ -StartupType Disabled -Verbose }

# Disable additional store related services | Requires permissions modification to apply if not in audit mode
"AppXSvc","ClipSVC" | ForEach-Object { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$_" -Name Start -Value 4 -Force -Verbose }
"LicenseManager" | ForEach-Object { Stop-Service -Name $_; Set-Service -Name $_ -StartupType Disabled -Verbose }

# Disable LLMNR
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT" -Name DNSClient -Force -Verbose
New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMultiCast -Value 0 -PropertyType DWORD -Force -Verbose

# TESTING
#"RpcLocator","RemoteRegistry","SstpSvc","TapiSrv" | ForEach-Object { Stop-Service -Name $_ -Verbose; Set-Service -Name $_ -StartupType Disabled -Verbose }