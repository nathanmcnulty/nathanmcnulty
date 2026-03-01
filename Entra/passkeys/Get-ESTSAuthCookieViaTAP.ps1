# Quick helper: authenticate with TAP and return the ESTSAUTH cookie value
param(
    [string]$TAP = '5$RYJR$F',
    [string]$UserPrincipalName = 'secadmin@sharemylabs.com',
    [string]$TenantId = '847b5907-ca15-40f4-b171-eb18619dbfab'
)
$ErrorActionPreference = 'Stop'
$ClientId = '19db86c3-b2b9-44cc-b339-36da233a3be2'
$RedirectUri = 'https://mysignins.microsoft.com'
$tokenScope = "$ClientId/.default openid profile offline_access"

$webSession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
$verifierBytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($verifierBytes)
$codeVerifier = [Convert]::ToBase64String($verifierBytes) -replace '\+','-' -replace '/','_' -replace '=',''
$challengeBytes = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::ASCII.GetBytes($codeVerifier))
$codeChallenge = [Convert]::ToBase64String($challengeBytes) -replace '\+','-' -replace '/','_' -replace '=',''

$authUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?" +
    "client_id=$ClientId" +
    "&redirect_uri=$([System.Web.HttpUtility]::UrlEncode($RedirectUri))" +
    "&scope=$([System.Web.HttpUtility]::UrlEncode($tokenScope))" +
    "&response_type=code&response_mode=fragment&prompt=login" +
    "&login_hint=$([System.Web.HttpUtility]::UrlEncode($UserPrincipalName))" +
    "&code_challenge=$codeChallenge&code_challenge_method=S256&state=test"

$loginPage = Invoke-WebRequest -Uri $authUrl -UseBasicParsing -MaximumRedirection 10 -WebSession $webSession
$loginPage.Content -match '\$Config=(\{.+\});' | Out-Null
$cfg = $matches[1] | ConvertFrom-Json

$loginBody = @{
    login=''; loginfmt=$UserPrincipalName; accesspass=$TAP; ps='56'
    psRNGCDefaultType='1'; psRNGCEntropy=''; psRNGCSLK=$cfg.sFT
    canary=$cfg.canary; ctx=$cfg.sCtx; hpgrequestid=$cfg.sessionId
    flowToken=$cfg.sFT; PPSX=''; NewUser='1'; FoundMSAs=''; fspost='0'
    i21='0'; CookieDisclosure='0'; IsFidoSupported='1'; isSignupPost='0'
    DfpArtifact=''; i19='10000'
}
# Override login field
$loginBody.login = $UserPrincipalName
$formBody = ($loginBody.GetEnumerator() | ForEach-Object {
    "$([System.Web.HttpUtility]::UrlEncode($_.Key))=$([System.Web.HttpUtility]::UrlEncode($_.Value))"
}) -join '&'
$loginUrl = if ($cfg.urlPost) { "https://login.microsoftonline.com$($cfg.urlPost)" } else { 'https://login.microsoftonline.com/common/login' }

$currentUrl = $loginUrl; $currentMethod = 'POST'; $currentBody = $formBody

for ($i = 0; $i -lt 15; $i++) {
    try {
        $p = @{ Uri=$currentUrl; Method=$currentMethod; WebSession=$webSession; MaximumRedirection=0; UseBasicParsing=$true }
        if ($currentMethod -eq 'POST' -and $currentBody) { $p['Body']=$currentBody; $p['ContentType']='application/x-www-form-urlencoded' }
        $r = Invoke-WebRequest @p -ErrorAction Stop
        if ($r.StatusCode -eq 200 -and $r.Content -match 'action="([^"]+)"') {
            $fa = $matches[1]
            $hf = [regex]::Matches($r.Content, '<input[^>]+name="([^"]+)"[^>]+value="([^"]*)"')
            $fd = ($hf | ForEach-Object { "$([System.Web.HttpUtility]::UrlEncode($_.Groups[1].Value))=$([System.Web.HttpUtility]::UrlEncode($_.Groups[2].Value))" }) -join '&'
            if ($fa -and $fd) {
                if ($fa.StartsWith('/')) { $u=[uri]$currentUrl; $fa="$($u.Scheme)://$($u.Host)$fa" }
                $currentUrl=$fa; $currentMethod='POST'; $currentBody=$fd; continue
            }
        }
        break
    } catch [Microsoft.PowerShell.Commands.HttpResponseException] {
        $sc = [int]$_.Exception.Response.StatusCode
        if ($sc -ge 300 -and $sc -lt 400) {
            $loc = $_.Exception.Response.Headers.Location.ToString()
            if ($loc.StartsWith('/')) { $u=[uri]$currentUrl; $loc="$($u.Scheme)://$($u.Host)$loc" }
            try {
                foreach ($h in $_.Exception.Response.Headers.GetValues('Set-Cookie')) {
                    if ($h -match '(ESTSAUTH[^=]*)=([^;]+)') {
                        $webSession.Cookies.Add([System.Net.Cookie]::new($matches[1], $matches[2], '/', '.login.microsoftonline.com'))
                    }
                }
            } catch {}
            if ($loc -match '[#?&]code=') { break }
            if ($loc -match 'error=') { throw "Login failed: $loc" }
            $currentUrl=$loc; $currentMethod='GET'; $currentBody=$null; continue
        }
        throw
    }
}

$cookies = $webSession.Cookies.GetCookies('https://login.microsoftonline.com')
$ests = $cookies | Where-Object { $_.Name -like 'ESTSAUTH*' } | Sort-Object { $_.Value.Length } -Descending | Select-Object -First 1
if ($ests) {
    Write-Host "Got $($ests.Name) cookie ($($ests.Value.Length) chars)" -ForegroundColor Green
    Write-Output $ests.Value
} else {
    throw 'No ESTSAUTH cookie found after TAP login'
}
