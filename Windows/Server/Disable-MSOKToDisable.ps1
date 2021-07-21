# Microsoft's list of services that are OK to disable from https://docs.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server

# Microsoft says OK to disable
"AudioEndpointBuilder","Audiosrv","AxInstSV","bthserv","CDPUserSvc","dmwappushservice","FrameServer","icssvc","lfsvc","lltdsvc","MapsBroker","NcbService","OneSyncSvc","PcaSvc","PhoneSvc","QWAVE","RmSvc","ScDeviceEnum","SensorDataService","SensorService","SensrSvc","SharedAccess","ShellHWDetection","SSDPSRV","stisvc","TabletInputService","upnphost","WalletService","WiaRpc","wisvc","wlidsvc","WpnService","XblAuthManager","XblGameSave" | ForEach-Object { Stop-Service -Name $_; Set-Service -Name $_ -StartupType Disabled }
Disable-ScheduledTask -TaskPath "\Microsoft\XblGameSave" -TaskName "XblGameSaveTask" -Verbose
Disable-ScheduledTask -TaskPath "\Microsoft\XblGameSave" -TaskName "XblGameSaveTaskLogon" -Verbose

# Microsoft says OK to disable | Must be set via registry
"NgcCtnrSvc","NgcSvc","PimIndexMaintenanceSvc","UnistoreSvc","UserDataSvc","WpnUserService" | ForEach-Object { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$_" -Name Start -Value 4 -Force -Verbose }