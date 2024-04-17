########################################################
# Only edit this section
$serverIP = "<server>"
$serverPort = 22
$userName = "<username>"
$privateKey = "<keyfile>"
$localIP = "<local-ip>"
########################################################

$ServerAddress = [System.Net.IPAddress] $serverIP
$SSHCredentials = [pscredential]::new($userName, [securestring]::new())
$SSHPort = $serverPort
$BypassLAN = $true 
$ServiceSubnet = "$localIP/24"
$ServiceGateway = [System.Net.IPAddress]  "<gateway-ip>" 
$ServicePort = 465 
if ($null -ne $privateKey -and $privateKey.Length -ne 0) {
    if (!(Test-Path $privateKey)) {
        $SSHPrivateKeyFile = "~/.gosttunnel/$privateKey";
        if (!(Test-Path $SSHPrivateKeyFile)) {
            $SSHPrivateKeyFile = "$PSScriptRoot/$privateKey";
        }
    }
    if (Test-Path $SSHPrivateKeyFile) {
        $SSHPrivateKeyFile = Resolve-Path $SSHPrivateKeyFile;
    }
    else {
        $SSHPrivateKeyFile = $null;
    }
}
$WithSSHDDialer = $true
$TunnelBypassRoutes = [System.Net.IPNetwork[]] ("192.168.0.0/20")