function ShowBalloonTipInfo {
    [CmdletBinding()]
    param
    (
        [string]
        $Message,
        [string]
        $Title,
        [string]
        #It must be 'None','Info','Warning','Error'
        $Level = "Info",
        [int] $Duration = 1000
    )
    Add-Type -AssemblyName System.Windows.Forms
    #So your function would have to check whether there is already an icon that you can reuse.This is done by using a "shared variable", which really is a variable that has "script:" scope.
    if ($null -eq $script:balloonToolTip) {
        #we will need to add the System.Windows.Forms assembly into our PowerShell session before we can make use of the NotifyIcon class.
        $script:balloonToolTip = New-Object System.Windows.Forms.NotifyIcon
    }
    $path = Get-Process -id $pid | Select-Object -ExpandProperty Path
    $balloonToolTip.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
    $balloonToolTip.BalloonTipIcon = $Level
    $balloonToolTip.BalloonTipText = $Message
    $balloonToolTip.BalloonTipTitle = $Title
    $balloonToolTip.Visible = $true
    #I thought to display the tool tip for one seconds,so i used 1000 milliseconds when I call ShowBalloonTip.
    $balloonToolTip.ShowBalloonTip($Duration)
}

function ShowBanner {
    [CmdletBinding()]
    param
    (
        [string]
        $Message,
        [string]
        $LineStart,
        [string]
        $LineEnd,
        [string]
        $Separater
    )

    $maxLineLength = 0
    $lines = $Message -split "`n"
    [string[]]$msg = $null;
    foreach ($line in $lines) {
        $line = $line -replace "`t", "    "
        if ($line.Length -gt $maxLineLength) {
            $maxLineLength = $line.Length;
        }
        $msg += $line;
    }

    $sepLine = "".PadLeft($LineStart.Length) + $Separater.PadRight($maxLineLength + $LineStart.Length, $Separater);
    
    Write-Host "";
    Write-Host $sepLine;
    foreach ($line in $msg) {
        Write-Host "${LineStart} $($line.PadRight($maxLineLength)) ${LineEnd}"
    }
    Write-Host $sepLine;
    Write-Host "";
}