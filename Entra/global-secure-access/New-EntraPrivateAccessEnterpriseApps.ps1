<#
.SYNOPSIS
    Creates Microsoft Entra Private Access enterprise apps from a CSV or direct parameters.

.DESCRIPTION
    Uses only Connect-MgGraph, Get-MgContext, and Invoke-MgGraphRequest from the
    Microsoft.Graph.Authentication module to provision Microsoft Entra Private Access
    enterprise applications.

    Input can come from either a CSV containing userPrincipalName, IP, and FQDN
    columns, or from direct parameters. Rows are grouped by FQDN when present,
    otherwise by IP, so repeated rows for the same destination create one app and
    add all referenced users.

    This script assumes the connector group already exists. If ConnectorGroupId is
    omitted, the script queries connector groups and uses Out-GridView when more
    than one group exists.

.PARAMETER CsvPath
    Path to a CSV file containing userPrincipalName, IP, and FQDN columns.

.PARAMETER UserPrincipalName
    One or more user principal names to assign when not using CsvPath.

.PARAMETER IP
    Optional IP address, range, or CIDR segment when not using CsvPath.

.PARAMETER FQDN
    Optional FQDN segment when not using CsvPath.

.PARAMETER Ports
    One or more port ranges to apply to every created application segment.
    Example: 3389-3389, 445-445, 443-443.

.PARAMETER Protocol
    Protocol to apply to every created application segment.

.PARAMETER AppNamePrefix
    Prefix used when generating enterprise app display names.

.PARAMETER ConnectorGroupId
    Optional existing connector group object ID to assign to all created apps.
    If omitted, the script queries existing connector groups and uses
    Out-GridView to select one when more than one group exists.

.EXAMPLE
    Connect-MgGraph -Scopes "Directory.ReadWrite.All","NetworkAccess.ReadWrite.All","AppRoleAssignment.ReadWrite.All" -NoWelcome
    .\New-EntraPrivateAccessEnterpriseApps.ps1 -CsvPath .\private-access.csv -Ports "3389-3389","445-445"

.EXAMPLE
    .\New-EntraPrivateAccessEnterpriseApps.ps1 -CsvPath .\private-access.csv -Ports "443-443" -Protocol tcp -ConnectorGroupId "daf709c2-6072-414f-b08c-bb2a80c631c"

.EXAMPLE
    .\New-EntraPrivateAccessEnterpriseApps.ps1 -UserPrincipalName "user1@contoso.com","user2@contoso.com" -FQDN "app.contoso.internal" -IP "10.0.0.10" -Ports "443-443"

.NOTES
    Requires PowerShell 7.0+ and Microsoft.Graph.Authentication.
    Private Access segment APIs currently use Microsoft Graph beta endpoints.

    Required delegated scopes:
    - Directory.ReadWrite.All
    - NetworkAccess.ReadWrite.All
    - AppRoleAssignment.ReadWrite.All
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(DefaultParameterSetName = 'Csv')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Csv')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$CsvPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Direct')]
    [ValidateNotNullOrEmpty()]
    [string[]]$UserPrincipalName,

    [Parameter(Mandatory = $false, ParameterSetName = 'Direct')]
    [string]$IP,

    [Parameter(Mandatory = $false, ParameterSetName = 'Direct')]
    [string]$FQDN,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$Ports,

    [Parameter(Mandatory = $false)]
    [ValidateSet('tcp', 'udp', 'tcp,udp')]
    [string]$Protocol = 'tcp',

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$AppNamePrefix = 'Private Access - ',

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$ConnectorGroupId
)

$ErrorActionPreference = 'Stop'

$script:InputMode = $PSCmdlet.ParameterSetName
$script:CustomApplicationTemplateId = '8adf8e6e-67b2-4cf2-a259-e3dc5476c621'
$script:RequiredScopes = @(
    'Directory.ReadWrite.All',
    'NetworkAccess.ReadWrite.All',
    'AppRoleAssignment.ReadWrite.All'
)
$script:UserCache = @{}

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[OK]   $Message" -ForegroundColor Green
}

function Connect-GraphSession {
    $context = Get-MgContext -ErrorAction SilentlyContinue
    $missingScopes = @()

    if ($context) {
        $missingScopes = @($script:RequiredScopes | Where-Object { $_ -notin $context.Scopes })
    }

    if (-not $context -or $missingScopes.Count -gt 0) {
        if ($missingScopes.Count -gt 0) {
            Write-Info "Current Graph session is missing scopes: $($missingScopes -join ', ')"
        }

        Write-Info "Connecting to Microsoft Graph with scopes: $($script:RequiredScopes -join ', ')"
        Connect-MgGraph -Scopes $script:RequiredScopes -NoWelcome | Out-Null
        $context = Get-MgContext
    }

    if (-not $context) {
        throw 'Unable to establish a Microsoft Graph session.'
    }

    Write-Success "Connected to Microsoft Graph as $($context.Account)"
}

function Get-GraphCollection {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )

    $items = @()
    $nextUri = $Uri

    while ($nextUri) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $nextUri -OutputType PSObject

        if ($response.PSObject.Properties['value']) {
            $items += @($response.value)
            $nextUri = $response.'@odata.nextLink'
        } else {
            $items += $response
            $nextUri = $null
        }
    }

    return @($items)
}

function ConvertTo-NormalizedText {
    param($Value)

    if ($null -eq $Value) {
        return $null
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    return $text.Trim()
}

function Convert-IpSegment {
    param(
        [Parameter(Mandatory = $true)]
        [string]$IpValue
    )

    if ($IpValue.Contains('/')) {
        return [pscustomobject]@{
            DestinationType = 'ipRangeCidr'
            DestinationHost = $IpValue
        }
    }

    if ($IpValue.Contains('-')) {
        return [pscustomobject]@{
            DestinationType = 'ipRange'
            DestinationHost = $IpValue
        }
    }

    $parsedAddress = $null
    if ([System.Net.IPAddress]::TryParse($IpValue, [ref]$parsedAddress)) {
        $cidrSuffix = if ($parsedAddress.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { 128 } else { 32 }

        return [pscustomobject]@{
            DestinationType = 'ipRangeCidr'
            DestinationHost = "$IpValue/$cidrSuffix"
        }
    }

    throw "IP value '$IpValue' is not a valid IP address, range, or CIDR block."
}

function Get-InputRows {
    if ($script:InputMode -eq 'Csv') {
        $rows = @(Import-Csv -Path $CsvPath)
        if ($rows.Count -eq 0) {
            throw "CSV file '$CsvPath' does not contain any data rows."
        }

        $requiredHeaders = @('userPrincipalName', 'IP', 'FQDN')
        $availableHeaders = @($rows[0].PSObject.Properties.Name)
        $missingHeaders = @($requiredHeaders | Where-Object { $_ -notin $availableHeaders })

        if ($missingHeaders.Count -gt 0) {
            throw "CSV file '$CsvPath' is missing required columns: $($missingHeaders -join ', ')"
        }

        return $rows
    }

    $users = @(
        $UserPrincipalName |
        ForEach-Object { ConvertTo-NormalizedText -Value $_ } |
        Where-Object { $_ } |
        Select-Object -Unique
    )
    $normalizedIp = ConvertTo-NormalizedText -Value $IP
    $normalizedFqdn = ConvertTo-NormalizedText -Value $FQDN

    if ($users.Count -eq 0) {
        throw 'Direct parameter mode requires at least one -UserPrincipalName value.'
    }

    if (-not $normalizedIp -and -not $normalizedFqdn) {
        throw 'Direct parameter mode requires -IP, -FQDN, or both.'
    }

    return @(
        $users | ForEach-Object {
            [pscustomobject]@{
                userPrincipalName = $_
                IP                = $normalizedIp
                FQDN              = $normalizedFqdn
            }
        }
    )
}

function Get-Targets {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Rows
    )

    $targets = @{}

    foreach ($row in $Rows) {
        $upn = ConvertTo-NormalizedText -Value $row.userPrincipalName
        $ip = ConvertTo-NormalizedText -Value $row.IP
        $fqdn = ConvertTo-NormalizedText -Value $row.FQDN

        if (-not $upn) {
            throw 'Each input row must contain a userPrincipalName value.'
        }

        if (-not $ip -and -not $fqdn) {
            throw "Row for '$upn' must include either IP, FQDN, or both."
        }

        $normalizedIpSegment = $null
        if ($ip) {
            $normalizedIpSegment = Convert-IpSegment -IpValue $ip
        }

        $key = if ($fqdn) {
            "fqdn:$($fqdn.ToLowerInvariant())"
        } else {
            "ip:$($normalizedIpSegment.DestinationHost.ToLowerInvariant())"
        }

        if (-not $targets.ContainsKey($key)) {
            $targets[$key] = [pscustomobject]@{
                NameKey            = if ($fqdn) { $fqdn } else { $ip }
                UserPrincipalNames = @()
                Segments           = [ordered]@{}
            }
        }

        $target = $targets[$key]

        if ($upn -notin $target.UserPrincipalNames) {
            $target.UserPrincipalNames += $upn
        }

        if ($fqdn) {
            $target.Segments["fqdn:$($fqdn.ToLowerInvariant())"] = [pscustomobject]@{
                DestinationType = 'fqdn'
                DestinationHost = $fqdn
            }
        }

        if ($normalizedIpSegment) {
            $target.Segments["$($normalizedIpSegment.DestinationType):$($normalizedIpSegment.DestinationHost.ToLowerInvariant())"] = $normalizedIpSegment
        }
    }

    return @($targets.Values | Sort-Object -Property NameKey)
}

function Get-UserByUserPrincipalName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )

    if ($script:UserCache.ContainsKey($UserPrincipalName)) {
        return $script:UserCache[$UserPrincipalName]
    }

    $encodedUpn = [System.Uri]::EscapeDataString($UserPrincipalName)

    try {
        $user = Invoke-MgGraphRequest -Method GET -Uri "/v1.0/users/${encodedUpn}?`$select=id,userPrincipalName,displayName" -OutputType PSObject
    } catch {
        throw "User '$UserPrincipalName' was not found in Microsoft Entra ID."
    }

    $script:UserCache[$UserPrincipalName] = $user
    return $user
}

function Resolve-ConnectorGroup {
    if ($ConnectorGroupId) {
        return Invoke-MgGraphRequest -Method GET -Uri "/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$ConnectorGroupId" -OutputType PSObject
    }

    $connectorGroups = Get-GraphCollection -Uri '/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups?`$select=id,name,region,isDefault'

    if ($connectorGroups.Count -eq 0) {
        throw 'No connector groups were found. Provide -ConnectorGroupId or create a connector group first.'
    }

    if ($connectorGroups.Count -eq 1) {
        return $connectorGroups[0]
    }

    if (-not (Get-Command -Name Out-GridView -ErrorAction SilentlyContinue)) {
        throw 'Multiple connector groups were found and Out-GridView is not available. Install Microsoft.PowerShell.GraphicalTools or specify -ConnectorGroupId.'
    }

    $selection = $connectorGroups |
        Select-Object id, name, region, isDefault |
        Sort-Object -Property @{ Expression = { if ($_.isDefault) { 0 } else { 1 } } }, name |
        Out-GridView -Title 'Select a connector group for Entra Private Access' -PassThru

    if (-not $selection) {
        throw 'No connector group was selected.'
    }

    if (@($selection).Count -gt 1) {
        throw 'Select only one connector group.'
    }

    return @($selection)[0]
}

function Get-ServicePrincipalByAppId {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AppId
    )

    $servicePrincipals = Get-GraphCollection -Uri "/beta/servicePrincipals?`$filter=appId eq '$AppId'&`$select=id,appId,displayName,appRoles"

    if ($servicePrincipals.Count -eq 0) {
        throw "Service principal for appId '$AppId' was not found."
    }

    if ($servicePrincipals.Count -gt 1) {
        throw "Multiple service principals were found for appId '$AppId'."
    }

    return $servicePrincipals[0]
}

function Get-OrCreatePrivateAccessApplication {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DisplayName
    )

    $escapedDisplayName = $DisplayName -replace "'", "''"
    $applications = Get-GraphCollection -Uri "/beta/applications?`$filter=displayName eq '$escapedDisplayName'&`$select=id,appId,displayName"

    if ($applications.Count -gt 1) {
        throw "Multiple applications named '$DisplayName' were found. Use a different -AppNamePrefix."
    }

    $created = $false
    $application = $null
    $servicePrincipal = $null

    if ($applications.Count -eq 1) {
        $application = $applications[0]
        $servicePrincipal = Get-ServicePrincipalByAppId -AppId $application.appId
        Write-Info "Reusing existing application '$DisplayName'"
    } else {
        $body = @{ displayName = $DisplayName } | ConvertTo-Json
        $instantiateResult = Invoke-MgGraphRequest -Method POST -Uri "/v1.0/applicationTemplates/$($script:CustomApplicationTemplateId)/instantiate" -Body $body -ContentType 'application/json' -OutputType PSObject
        $application = $instantiateResult.application
        $servicePrincipal = $instantiateResult.servicePrincipal
        $created = $true
        Write-Success "Created application '$DisplayName'"
    }

    if (-not $servicePrincipal -or -not $servicePrincipal.appRoles) {
        $servicePrincipal = Get-ServicePrincipalByAppId -AppId $application.appId
    }

    $publishBody = @{
        onPremisesPublishing = @{
            applicationType = 'nonwebapp'
            isAccessibleViaZTNAClient = $true
        }
    } | ConvertTo-Json -Depth 10

    Invoke-MgGraphRequest -Method PATCH -Uri "/beta/applications/$($application.id)" -Body $publishBody -ContentType 'application/json' -OutputType PSObject | Out-Null

    $userRole = @($servicePrincipal.appRoles) |
        Where-Object {
            $_.displayName -eq 'User' -and
            $_.isEnabled -eq $true -and
            'User' -in $_.allowedMemberTypes
        } |
        Select-Object -First 1

    if (-not $userRole) {
        throw "Service principal '$($servicePrincipal.displayName)' does not contain an enabled User app role."
    }

    return [pscustomobject]@{
        Application      = $application
        ServicePrincipal = $servicePrincipal
        UserAppRoleId    = $userRole.id
        Created          = $created
    }
}

function Get-SegmentKey {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DestinationType,

        [Parameter(Mandatory = $true)]
        [string]$DestinationHost,

        [Parameter(Mandatory = $true)]
        [string[]]$SegmentPorts,

        [Parameter(Mandatory = $true)]
        [string]$SegmentProtocol
    )

    $normalizedPorts = @($SegmentPorts | Sort-Object) -join ','
    return "$($DestinationType.ToLowerInvariant())|$($DestinationHost.ToLowerInvariant())|$($SegmentProtocol.ToLowerInvariant())|$normalizedPorts"
}

function Add-ApplicationSegments {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApplicationId,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Segments,

        [Parameter(Mandatory = $true)]
        [string[]]$SegmentPorts,

        [Parameter(Mandatory = $true)]
        [string]$SegmentProtocol
    )

    $existingSegments = Get-GraphCollection -Uri "/beta/applications/$ApplicationId/onPremisesPublishing/segmentsConfiguration/microsoft.graph.ipSegmentConfiguration/applicationSegments"
    $existingKeys = @()

    foreach ($existingSegment in $existingSegments) {
        $destinationType = ConvertTo-NormalizedText -Value $existingSegment.destinationType
        $destinationHost = ConvertTo-NormalizedText -Value $existingSegment.destinationHost
        $protocol = ConvertTo-NormalizedText -Value $existingSegment.protocol

        if ($destinationType -and $destinationHost -and $protocol) {
            $existingKeys += Get-SegmentKey -DestinationType $destinationType -DestinationHost $destinationHost -SegmentPorts @($existingSegment.ports) -SegmentProtocol $protocol
        }
    }

    $addedSegments = @()

    foreach ($segment in @($Segments.Values | Sort-Object -Property DestinationType, DestinationHost)) {
        $segmentKey = Get-SegmentKey -DestinationType $segment.DestinationType -DestinationHost $segment.DestinationHost -SegmentPorts $SegmentPorts -SegmentProtocol $SegmentProtocol

        if ($segmentKey -in $existingKeys) {
            Write-Info "Segment already exists: $($segment.DestinationType) $($segment.DestinationHost)"
            continue
        }

        $body = @{
            destinationHost = $segment.DestinationHost
            destinationType = $segment.DestinationType
            port            = 0
            ports           = $SegmentPorts
            protocol        = $SegmentProtocol
        } | ConvertTo-Json -Depth 10

        Invoke-MgGraphRequest -Method POST -Uri "/beta/applications/$ApplicationId/onPremisesPublishing/segmentsConfiguration/microsoft.graph.ipSegmentConfiguration/applicationSegments" -Body $body -ContentType 'application/json' -OutputType PSObject | Out-Null
        $addedSegments += "$($segment.DestinationType):$($segment.DestinationHost)"
        Write-Success "Added segment $($segment.DestinationType):$($segment.DestinationHost)"
    }

    return @($addedSegments)
}

function Add-UserAssignments {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipalId,

        [Parameter(Mandatory = $true)]
        [string]$UserAppRoleId,

        [Parameter(Mandatory = $true)]
        [string[]]$UserPrincipalNames
    )

    $existingAssignments = Get-GraphCollection -Uri "/beta/servicePrincipals/$ServicePrincipalId/appRoleAssignedTo?`$select=principalId,principalType,appRoleId"
    $assignedPrincipalIds = @(
        $existingAssignments |
        Where-Object { $_.principalType -eq 'User' -and $_.appRoleId -eq $UserAppRoleId } |
        Select-Object -ExpandProperty principalId
    )

    $newAssignments = @()

    foreach ($upn in @($UserPrincipalNames | Sort-Object -Unique)) {
        $user = Get-UserByUserPrincipalName -UserPrincipalName $upn

        if ($user.id -in $assignedPrincipalIds) {
            Write-Info "User '$upn' already has the User app role"
            continue
        }

        $body = @{
            principalId = $user.id
            resourceId  = $ServicePrincipalId
            appRoleId   = $UserAppRoleId
        } | ConvertTo-Json

        Invoke-MgGraphRequest -Method POST -Uri "/beta/servicePrincipals/$ServicePrincipalId/appRoleAssignedTo" -Body $body -ContentType 'application/json' -OutputType PSObject | Out-Null
        $newAssignments += $upn
        Write-Success "Assigned '$upn'"
    }

    return @($newAssignments)
}

Connect-GraphSession

$inputRows = Get-InputRows
$targets = Get-Targets -Rows $inputRows
$inputDescription = if ($script:InputMode -eq 'Csv') { 'CSV row(s)' } else { 'direct input row(s)' }

Write-Info "Loaded $($inputRows.Count) $inputDescription and identified $($targets.Count) app target(s)"

$connectorGroup = Resolve-ConnectorGroup
Write-Info "Using connector group '$($connectorGroup.name)'"

$results = @()

for ($index = 0; $index -lt $targets.Count; $index++) {
    $target = $targets[$index]
    $displayName = "$AppNamePrefix$($target.NameKey)"
    $applicationId = $null
    $appId = $null
    $servicePrincipalId = $null
    $created = $false

    Write-Host ''
    Write-Host ('[{0}/{1}] {2}' -f ($index + 1), $targets.Count, $displayName) -ForegroundColor Yellow

    try {
        $app = Get-OrCreatePrivateAccessApplication -DisplayName $displayName
        $applicationId = $app.Application.id
        $appId = $app.Application.appId
        $servicePrincipalId = $app.ServicePrincipal.id
        $created = $app.Created

        $connectorGroupBody = @{
            '@odata.id' = "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$($connectorGroup.id)"
        } | ConvertTo-Json

        Invoke-MgGraphRequest -Method PUT -Uri "/beta/applications/$applicationId/connectorGroup/`$ref" -Body $connectorGroupBody -ContentType 'application/json' -OutputType PSObject | Out-Null
        Write-Success "Assigned connector group '$($connectorGroup.name)'"

        $addedSegments = Add-ApplicationSegments -ApplicationId $applicationId -Segments $target.Segments -SegmentPorts $Ports -SegmentProtocol $Protocol
        $assignedUsers = Add-UserAssignments -ServicePrincipalId $servicePrincipalId -UserAppRoleId $app.UserAppRoleId -UserPrincipalNames $target.UserPrincipalNames

        $results += [pscustomobject]@{
            AppDisplayName      = $displayName
            ApplicationObjectId = $applicationId
            AppId               = $appId
            ServicePrincipalId  = $servicePrincipalId
            ConnectorGroupId    = $connectorGroup.id
            ConnectorGroupName  = $connectorGroup.name
            Created             = $created
            AddedSegments       = @($addedSegments)
            AssignedUsers       = @($assignedUsers)
            Status              = 'Success'
            Error               = $null
        }
    } catch {
        $message = $_.Exception.Message
        Write-Warning $message

        $results += [pscustomobject]@{
            AppDisplayName      = $displayName
            ApplicationObjectId = $applicationId
            AppId               = $appId
            ServicePrincipalId  = $servicePrincipalId
            ConnectorGroupId    = $connectorGroup.id
            ConnectorGroupName  = $connectorGroup.name
            Created             = $created
            AddedSegments       = @()
            AssignedUsers       = @()
            Status              = 'Failed'
            Error               = $message
        }
    }
}

Write-Host ''
Write-Host "Completed. Successes: $(@($results | Where-Object { $_.Status -eq 'Success' }).Count)  Failures: $(@($results | Where-Object { $_.Status -eq 'Failed' }).Count)" -ForegroundColor Cyan

$results
