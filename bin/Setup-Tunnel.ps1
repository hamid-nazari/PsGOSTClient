[CmdletBinding()]
param (
    [System.Net.IPAddress] $ServerAddress = $null,
    [System.Net.IPAddress] $DefaultGateway = $null,
    [string] $DefaultGatewayProbe = "google.com",
    [switch] $BypassLAN,
    [System.Net.IPNetwork[]] $TunnelBypassRoutes = $null,
    [int] $ViabilityTries = 15,
    [string] $GOST = "gost.exe",
    [string] $ServiceSubnet = $null,
    [System.Net.IPAddress] $ServiceGateway,
    [System.Net.IPAddress[]] $ServiceDNS = ("1.0.0.1", "8.8.8.8"),
    [switch] $TAPService,
    [string] $ServiceNICAlias = $null,
    [int] $ServicePort = 0,
    [int] $ServiceMTU = 1350,
    [int] $SSHePort = 443,
    [int] $RelayPort = 800,
    [string] $SSHCredsFile = "creds.xml",
    [pscredential] $SSHCredentials = $null,
    [string] $SSHPrivateKeyFile = $null,
    [switch] $WithSSHDDialer, 
    [switch] $ShowConfig,
    [string] $configName = "config"
)

. $PSScriptRoot\helpers.ps1

$scriptVersion = "1.2.0";
ShowBanner "`nGOST Tunnel for PowerShell (v$scriptVersion)`n`tby Hamid Nazari (https://github.com/hamid-nazari/PsGOSTClient)`n" " -=" "=-" "="

if ([System.IO.Path]::Exists($GOST)) {
    $GOST = [System.IO.Path]::GetFullPath($GOST);
}
elseif ([System.IO.Path]::Exists([System.IO.Path]::Combine($PSScriptRoot, $GOST))) {
    $GOST = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, $GOST));
}
else {
    throw "Can't find GOST executable: $GOST";
}
$workingFolder = [System.IO.Path]::GetDirectoryName($GOST);

$configFilePath = "$workingFolder/${configName}.ps1";
if (!(Test-Path $configFilePath)) {
    $configFilePath = "../config/${configName}.ps1";
    if (!(Test-Path $configFilePath)) {
        $configFilePath = "~/.gosttunnel/${configName}.ps1";
    }
}
if (Test-Path $configFilePath) {
    $configFilePath = Resolve-Path $configFilePath;
    . $configFilePath
    Write-Host "- Config file loaded from '$configFilePath'"
}

if ( $null -eq $ServerAddress) {
    throw "ServiceAddress is required"
}
if ( $null -eq $ServiceSubnet) {
    throw "ServiceSubnet is required"
}
if ( $null -eq $ServiceGateway) {
    throw "ServiceGateway is required"
}
if (0 -eq $ServicePort) {
    throw "ServicePort is required"
}

if ($null -eq $DefaultGateway) {
    $resolvedAddress = Resolve-DnsName $DefaultGatewayProbe -Type A -ErrorAction Ignore;
    if ($null -eq $resolvedAddress) {
        throw "Can't resolve address for '$DefaultGatewayProbe'";
    }
    $resolvedAddress = Find-NetRoute -RemoteIPAddress $resolvedAddress[$resolvedAddress.Count - 1].IPAddress -ErrorAction Ignore;
    if ($null -ne $resolvedAddress) {
        $DefaultGateway = $resolvedAddress[1].NextHop;
    }
    if ($null -eq $DefaultGateway) {
        throw "Can't detect Internet default gateway to access '$DefaultGatewayProbe'";
    }
    Write-Host "- Detected Internet default gateway '$DefaultGateway'"
}
else {
    Write-Host  "- Using supplied Internet default gateway '$DefaultGateway'"
}

if ($BypassLAN) {
    $tunnelPrefixLength = 32;
    $parts = $ServiceSubnet -split "/";
    $tunnelIP = [System.Net.IPAddress] $parts[0];
    if ($parts.Length -eq 2) {
        $tunnelPrefixLength = [int] $parts[1];
    }
    $lanSubnet = $null;
    foreach ($privateRange in ([System.Net.IPNetwork]::Parse("10.0.0.0/8"), [System.Net.IPNetwork]::Parse("192.168.0.0/16"), [System.Net.IPNetwork]::Parse("172.16.0.0/12"))) {
        if (!$privateRange.Contains($DefaultGateway)) {
            continue;
        }
        if ($privateRange.Contains($tunnelIP)) {
            $lanSubnet = [System.Net.IPNetwork]::new($privateRange.BaseAddress, [System.Math]::Max($tunnelPrefixLength, $privateRange.PrefixLength));
        }
        else {
            $lanSubnet = $privateRange;
        }
        break;
    }

    if ($null -ne $lanSubnet -and $lanSubnet.PrefixLength -ne 32) {
        foreach ($route in $TunnelBypassRoutes) {
            if ($route.Contains($lanSubnet.BaseAddress) -and $route.PrefixLength -le $lanSubnet.PrefixLength) {
                $lanSubnet = $null;
                break;
            }
        }
        if ($null -ne $lanSubnet) {
            $TunnelBypassRoutes += $lanSubnet;
            Write-Host "- Current LAN subnet $lanSubnet will be bypassed"
        }
    }
}

$tapPrevAlias = $null;
if ($TAPService) {
    Write-Host "- Finding a suitable TAP interface ..."
    $tapNICs = (Get-NetAdapter).Where({ $_.ComponentID -icontains "tap0901" -and $_.Status -eq "Disconnected" });
    if ($tapNICs.Count -eq 0) {
        Write-Host " + No suitable TAP interface was detected, we try to install one ..."
        & "$PSScriptRoot\tap-setup.exe" install "$([System.IO.Path]::GetFullPath("$PSScriptRoot\..\driver\OemVista.inf"))" "tap0901";
        $tapNICs = (Get-NetAdapter).Where({ $_.ComponentID -icontains "tap0901" -and $_.Status -eq "Disconnected" });
        if ($tapNICs.Count -eq 0) {
            throw "Failed installing a new TAP NIC (FreeLAN style)";
        }
        Write-Host "  o DONE"
    }
    if ($null -eq $ServiceNICAlias -or $ServiceNICAlias.Length -eq 0 -or $ServiceNICAlias.IndexOf(" ") -ne -1) {
        $ServiceNICAlias = "GOST-TAP";
    }
    $tapPrevAlias = $tapNICs[0].Name;
    Rename-NetAdapter -Name $tapPrevAlias -NewName $ServiceNICAlias;
    Write-Host " + Service will be setup on '$ServiceNICAlias' (old: $tapPrevAlias)"
}
elseif ($null -eq $ServiceNICAlias -or $ServiceNICAlias.Length -eq 0 -or $ServiceNICAlias.IndexOf(" ") -ne -1) {
    $ServiceNICAlias = "GOST-TUN";
}

$sshPKFile = $null;
if ($null -ne $SSHPrivateKeyFile -and $SSHPrivateKeyFile.Length -ne 0) {
    $sshPKFile = [System.IO.Path]::GetFullPath($SSHPrivateKeyFile);
    if (![System.IO.Path]::Exists($sshPKFile)) {
        throw "Can't find SSH private key file '$SSHPrivateKeyFile'"
    }
    Write-Host "- Using private key '$sshPKFile'"
}

$sshCredsFile = $null;
$credsLoaded = $false;
if ($null -eq $SSHCredentials) {
    if ([System.IO.Path]::Exists($SSHCredsFile)) {
        $sshCredsFile = [System.IO.Path]::GetFullPath($SSHCredsFile);
    }
    else {
        $sshCredsFile = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, $SSHCredsFile));
    }
    if ([System.IO.Path]::Exists($sshCredsFile)) {
        try {
            $SSHCredentials = Import-Clixml -Path $sshCredsFile;
            if ($null -ne $SSHCredentials) {
                $credsLoaded = $true;
                Write-Host "- Credentials loaded from '$sshCredsFile'"
            }
        }
        catch {
        }
    }
    if ($null -eq $SSHCredentials) {
        $SSHCredentials = Get-Credential -Title "Access Credentials" -Message "Please provide credentials to access the server at $ServerAddress";
    }
}

$defaultGatewayIfAlias = (Find-NetRoute -RemoteIPAddress $DefaultGateway)[0].InterfaceAlias;

Write-Host "- Exempting route to current default gateway '$DefaultGateway' form '$defaultGatewayIfAlias'"
Remove-NetRoute -DestinationPrefix "0.0.0.0/0" -NextHop $DefaultGateway -Confirm:$false -ErrorAction Ignore > $null;
try {

    Write-Host "- Modifying routing table"
    foreach ($route in $TunnelBypassRoutes) {
        New-NetRoute -DestinationPrefix $route -NextHop $DefaultGateway -InterfaceAlias $defaultGatewayIfAlias -ErrorAction Ignore -PolicyStore ActiveStore > $null;
    }
    New-NetRoute -DestinationPrefix "$ServerAddress/32" -NextHop $DefaultGateway -InterfaceAlias $defaultGatewayIfAlias -ErrorAction Ignore -PolicyStore ActiveStore > $null;

    Write-Host "- Starting GOST"
    Write-Host "  + Executable: $GOST"
    Write-Host "  + Building configuration ..."
    Write-Host "  + Tunnel subnet: $ServiceSubnet"

    $sshCreds = "";
    $passphrase = "";
    if ($null -ne $SSHCredentials) {
        $sshCreds = $SSHCredentials.UserName;
        $passphrase = $SSHCredentials.GetNetworkCredential().Password;
        if ($passphrase.Length -ne 0 -and $null -eq $sshPKFile) {
            $sshCreds += ":$passphrase";
        }
        $sshCreds += "@";
    }

    $gostConfig = "-L", "$($TAPService ? "tap" : "tun")://:${ServicePort}/:${ServicePort}?name=${ServiceNICAlias}&net=${ServiceSubnet}&mtu=${ServiceMTU}";
    $sshConfig = "${sshCreds}${ServerAddress}:${SSHPort}";
    if ($null -ne $sshPKFile) {
        $sshConfig += "?privateKeyFile=${sshPKFile}"
        if ($passphrase.Length -ne 0) {
            $sshConfig += "&passphrase=${passphrase}"
        }
    }
    $gostConfig += , "-F";
    if ($WithSSHDDialer) {
        $gostConfig += "sshd://${sshConfig}"
        $gostConfig += "-F", "relay://${ServerAddress}:${RelayPort}"
    }
    else {
        $gostConfig += "relay+ssh://${sshConfig}"
    }
    
    if ($ShowConfig) {
        Write-Host "  + Configuration: $gostConfig"
    }

    $gostJob = Start-Job -WorkingDirectory $workingFolder -Name "GOST Job" -ScriptBlock {
        param ($GOST, $gostConfig)
        & $GOST $gostConfig;
    } -ArgumentList $GOST, $gostConfig;
    Write-Host "  + Job ID: $($gostJob.Id)"
    Write-Host "- Server: $ServerAddress"
    Write-Host "- Waiting for tunnel to be established (gateway $ServiceGateway) ..."
    $tsStart = [System.DateTime]::Now;
    $tsEnd = $null;
    $latencyJob = $null;
    for ($i = 0; $i -lt $ViabilityTries; $i++) {
        if ($gostJob.JobStateInfo.State -ne [System.Management.Automation.JobState]::Running) {
            Receive-Job $gostJob;
            ShowBalloonTipInfo -Title "GOST Tunnel" -Message "Failed starting GOST" -Level "Error" -Duration 2000;
            throw "Failed starting GOST"
        }
        try {
            if (Test-Connection -TargetName $ServiceGateway -Count 1 -Quiet -ErrorAction Stop) {
                $tsEnd = [System.DateTime]::Now;
                $latencyJob = Start-ThreadJob -ScriptBlock {
                    param ($ServiceGateway)
                    Write-Host "[Tunnel latency is around $((Test-Connection -TargetName $ServiceGateway -Count 5 -ErrorAction Ignore | Measure-Object -Property Latency -Average).Average) ms]";
                } -ArgumentList $ServiceGateway -StreamingHost $Host;
                break;
            }
        }
        catch {}
        Start-Sleep -Milliseconds 500;
    }
    if ($null -eq $tsEnd) {
        Receive-Job $gostJob;
        ShowBalloonTipInfo -Title "GOST Tunnel" -Message "Failed connecting to server $ServerAddress" -Level "Warning" -Duration 2000;
        throw "Can't access tunnel gateway $ServiceGateway after $ViabilityTries tries"
    }
    Set-NetIPInterface -InterfaceAlias ${ServiceNICAlias} -AddressFamily IPv4 -NlMtuBytes $ServiceMTU;
    New-NetRoute -DestinationPrefix "0.0.0.0/0" -RouteMetric 3 -NextHop $ServiceGateway -InterfaceAlias $ServiceNICAlias -PolicyStore ActiveStore > $null;
    Set-DnsClientServerAddress -InterfaceAlias $ServiceNICAlias -ServerAddresses $ServiceDNS;
    ShowBalloonTipInfo -Title "GOST Tunnel" -Message "Connected to server $ServerAddress" -Duration 2000; 
    Write-Host "- Tunnel is up and running on '$ServiceNICAlias' [$(($tsEnd - $tsStart).TotalSeconds) s]"
    if (!$credsLoaded -and $null -ne $sshCredsFile -and $null -ne $SSHCredentials) {
        try {
            Export-Clixml -Path $sshCredsFile -InputObject $SSHCredentials;
            Write-Host "- Credentials saved to '$sshCredsFile'"
        }
        catch {}
    }

    Write-Host "`nPress any key to disconnect . . .";
    [void][System.Console]::ReadKey($true);
    ShowBalloonTipInfo -Title "GOST Tunnel" -Message "Disconnected from server $ServerAddress"; 
}
finally {

    if ($null -ne $latencyJob -and $latencyJob.JobStateInfo.State -eq [System.Management.Automation.JobState]::Running) {
        remove-job $latencyJob -Force;
    }

    if ($null -ne $gostJob -and $gostJob.JobStateInfo.State -eq [System.Management.Automation.JobState]::Running) {
        Write-Host "- Killing GOST"
        remove-job $gostJob -Force;
    }

    Write-Host "- Reverting routing table"
    Remove-NetRoute -DestinationPrefix "0.0.0.0/0" -NextHop $ServiceGateway -ErrorAction Ignore -PolicyStore ActiveStore -Confirm:$false > $null;
    Remove-NetRoute -DestinationPrefix "$ServerAddress/32" -NextHop $DefaultGateway -ErrorAction Ignore -PolicyStore ActiveStore -Confirm:$false > $null;
    foreach ($route in $TunnelBypassRoutes) {
        Remove-NetRoute -DestinationPrefix $route -NextHop $DefaultGateway -ErrorAction Ignore -PolicyStore ActiveStore -Confirm:$false > $null;
    }
    New-NetRoute -DestinationPrefix "0.0.0.0/0" -NextHop $DefaultGateway -InterfaceAlias $defaultGatewayIfAlias -ErrorAction Ignore -PolicyStore ActiveStore > $null;

    if ($TAPService) {
        Write-Host "- Reverting TAP interface"
        Rename-NetAdapter -NewName $tapPrevAlias -Name $ServiceNICAlias;
        Set-DnsClientServerAddress -InterfaceAlias $tapPrevAlias -ResetServerAddresses;
        Remove-NetIPAddress -InterfaceAlias $tapPrevAlias -Confirm:$false;
        Set-NetIPInterface -InterfaceAlias $tapPrevAlias -Dhcp Enabled;
    }

}
