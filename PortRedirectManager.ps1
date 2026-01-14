#Requires -RunAsAdministrator
<#
.SYNOPSIS
    NAT Port Redirect Manager - TUI for Windows Port Proxy Rules
.DESCRIPTION
    A ncurses-like interface for managing Windows netsh portproxy rules
.NOTES
    Requires Administrator privileges
#>

# Hide cursor and set up console
$Host.UI.RawUI.CursorSize = 0
$OriginalBackground = $Host.UI.RawUI.BackgroundColor
$OriginalForeground = $Host.UI.RawUI.ForegroundColor

# State variables
$script:SelectedIndex = 0
$script:PortRules = @()
$script:Running = $true
$script:Message = ""
$script:MessageType = "Info" # Info, Success, Error

# Colors
$script:Colors = @{
    Header = "Cyan"
    Selected = "Black"
    SelectedBg = "White"
    Normal = "Gray"
    Border = "DarkCyan"
    Key = "Yellow"
    Success = "Green"
    Error = "Red"
    Info = "Cyan"
}

# Port proxy types
$script:ProxyTypes = @("v4tov4", "v4tov6", "v6tov4", "v6tov6")

function Clear-Screen {
    [Console]::Clear()
    [Console]::SetCursorPosition(0, 0)
}

function Write-At {
    param(
        [int]$X,
        [int]$Y,
        [string]$Text,
        [string]$ForegroundColor = "Gray",
        [string]$BackgroundColor = $OriginalBackground
    )
    [Console]::SetCursorPosition($X, $Y)
    Write-Host $Text -ForegroundColor $ForegroundColor -BackgroundColor $BackgroundColor -NoNewline
}

function Draw-Box {
    param(
        [int]$X,
        [int]$Y,
        [int]$Width,
        [int]$Height,
        [string]$Title = "",
        [string]$Color = "DarkCyan"
    )

    $topLeft = [char]0x250C
    $topRight = [char]0x2510
    $bottomLeft = [char]0x2514
    $bottomRight = [char]0x2518
    $horizontal = [char]0x2500
    $vertical = [char]0x2502

    # Top border
    $topLine = "$topLeft" + ("$horizontal" * ($Width - 2)) + "$topRight"
    Write-At -X $X -Y $Y -Text $topLine -ForegroundColor $Color

    # Title
    if ($Title) {
        $titlePos = $X + [math]::Floor(($Width - $Title.Length - 2) / 2)
        Write-At -X $titlePos -Y $Y -Text " $Title " -ForegroundColor $script:Colors.Header
    }

    # Sides
    for ($i = 1; $i -lt $Height - 1; $i++) {
        Write-At -X $X -Y ($Y + $i) -Text "$vertical" -ForegroundColor $Color
        Write-At -X ($X + $Width - 1) -Y ($Y + $i) -Text "$vertical" -ForegroundColor $Color
    }

    # Bottom border
    $bottomLine = "$bottomLeft" + ("$horizontal" * ($Width - 2)) + "$bottomRight"
    Write-At -X $X -Y ($Y + $Height - 1) -Text $bottomLine -ForegroundColor $Color
}

function Get-WSL2IPAddress {
    <#
    .SYNOPSIS
        Gets the IP address of WSL2 instance
    #>
    try {
        $wslIP = (wsl hostname -I 2>$null) -split '\s+' | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1
        if ($wslIP) {
            return $wslIP.Trim()
        }
    }
    catch {}

    # Fallback: try to get from network adapter
    try {
        $adapter = Get-NetIPAddress -InterfaceAlias "vEthernet (WSL*)" -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($adapter) {
            # Get the WSL subnet and guess the WSL IP (usually .1 is Windows, WSL is dynamic)
            return $null
        }
    }
    catch {}

    return $null
}

function Get-FirewallRuleName {
    <#
    .SYNOPSIS
        Generate consistent naming for firewall rules
    #>
    param(
        [string]$ListenAddress,
        [int]$ListenPort,
        [string]$Protocol = "TCP"
    )
    return "PortRedirect_$($ListenAddress)_$($ListenPort)_$Protocol"
}

function Get-FirewallStatus {
    <#
    .SYNOPSIS
        Get display-friendly firewall status for a rule
    .DESCRIPTION
        Returns: T=TCP, U=UDP, TU=Both, -=None
    #>
    param(
        [string]$ListenAddress,
        [int]$ListenPort
    )

    $tcpName = Get-FirewallRuleName -ListenAddress $ListenAddress -ListenPort $ListenPort -Protocol "TCP"
    $udpName = Get-FirewallRuleName -ListenAddress $ListenAddress -ListenPort $ListenPort -Protocol "UDP"

    $tcpRule = $null
    $udpRule = $null

    try {
        $tcpRule = Get-NetFirewallRule -Name $tcpName -ErrorAction SilentlyContinue
    } catch {}

    try {
        $udpRule = Get-NetFirewallRule -Name $udpName -ErrorAction SilentlyContinue
    } catch {}

    $status = ""
    if ($tcpRule -and $tcpRule.Enabled -eq "True") { $status += "T" }
    if ($udpRule -and $udpRule.Enabled -eq "True") { $status += "U" }

    if ($status -eq "") { return "-" }
    return $status
}

function Add-PortRedirectFirewallRule {
    <#
    .SYNOPSIS
        Create an inbound firewall rule for a port proxy
    #>
    param(
        [string]$ListenAddress,
        [int]$ListenPort,
        [string]$Protocol = "TCP"  # TCP, UDP, or Both
    )

    $protocols = if ($Protocol -eq "Both") { @("TCP", "UDP") } else { @($Protocol) }
    $success = $true
    $messages = @()

    foreach ($proto in $protocols) {
        $ruleName = Get-FirewallRuleName -ListenAddress $ListenAddress -ListenPort $ListenPort -Protocol $proto
        $displayName = "Port Redirect: $ListenAddress`:$ListenPort ($proto)"

        try {
            # Check if rule already exists
            $existing = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
            if ($existing) {
                $messages += "$proto rule already exists"
                continue
            }

            New-NetFirewallRule -Name $ruleName `
                -DisplayName $displayName `
                -Description "Created by PortRedirectManager for NAT port proxy" `
                -Direction Inbound `
                -Action Allow `
                -Protocol $proto `
                -LocalPort $ListenPort `
                -Profile Any `
                -Enabled True | Out-Null

            $messages += "$proto rule created"
        }
        catch {
            $success = $false
            $messages += "$proto failed: $($_.Exception.Message)"
        }
    }

    return @{
        Success = $success
        Message = $messages -join "; "
    }
}

function Remove-PortRedirectFirewallRule {
    <#
    .SYNOPSIS
        Remove firewall rules associated with a port proxy
    #>
    param(
        [string]$ListenAddress,
        [int]$ListenPort,
        [string]$Protocol = "Both"  # TCP, UDP, or Both
    )

    $protocols = if ($Protocol -eq "Both") { @("TCP", "UDP") } else { @($Protocol) }
    $success = $true
    $messages = @()

    foreach ($proto in $protocols) {
        $ruleName = Get-FirewallRuleName -ListenAddress $ListenAddress -ListenPort $ListenPort -Protocol $proto

        try {
            $existing = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
            if ($existing) {
                Remove-NetFirewallRule -Name $ruleName
                $messages += "$proto rule removed"
            }
            else {
                $messages += "$proto rule not found"
            }
        }
        catch {
            $success = $false
            $messages += "$proto failed: $($_.Exception.Message)"
        }
    }

    return @{
        Success = $success
        Message = $messages -join "; "
    }
}

function Show-SelectionMenu {
    <#
    .SYNOPSIS
        Shows a selection menu and returns the selected option
    .PARAMETER Title
        Title of the menu
    .PARAMETER Options
        Array of options to choose from
    .PARAMETER X
        X position of the menu
    .PARAMETER Y
        Y position of the menu
    .PARAMETER DefaultIndex
        Default selected index
    #>
    param(
        [string]$Title,
        [array]$Options,
        [int]$X,
        [int]$Y,
        [int]$DefaultIndex = 0
    )

    $selectedIdx = $DefaultIndex
    $width = ($Options | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum + 8
    if ($Title.Length + 4 -gt $width) { $width = $Title.Length + 4 }
    $height = $Options.Count + 2

    # Draw the menu box
    Draw-Box -X $X -Y $Y -Width $width -Height $height -Title $Title

    while ($true) {
        # Draw options
        for ($i = 0; $i -lt $Options.Count; $i++) {
            $optY = $Y + 1 + $i
            $prefix = "  "
            $fg = $script:Colors.Normal
            $bg = $OriginalBackground

            if ($i -eq $selectedIdx) {
                $prefix = "> "
                $fg = $script:Colors.Selected
                $bg = $script:Colors.SelectedBg
            }

            $text = "$prefix$($Options[$i])".PadRight($width - 2)
            Write-At -X ($X + 1) -Y $optY -Text $text -ForegroundColor $fg -BackgroundColor $bg
        }

        $key = [Console]::ReadKey($true)

        switch ($key.Key) {
            "UpArrow" {
                if ($selectedIdx -gt 0) { $selectedIdx-- }
            }
            "DownArrow" {
                if ($selectedIdx -lt $Options.Count - 1) { $selectedIdx++ }
            }
            "Enter" {
                return $Options[$selectedIdx]
            }
            "Escape" {
                return $null
            }
        }
    }
}

function Show-AddressSelectionMenu {
    <#
    .SYNOPSIS
        Shows address selection with WSL2 IP option
    #>
    param(
        [string]$Title,
        [int]$X,
        [int]$Y
    )

    $wslIP = Get-WSL2IPAddress
    $options = @()

    if ($wslIP) {
        $options += "WSL2 ($wslIP)"
    }
    $options += "Custom (enter manually)"
    $options += "localhost (127.0.0.1)"

    $width = 40
    $height = $options.Count + 4

    Draw-Box -X $X -Y $Y -Width $width -Height $height -Title $Title

    $selectedIdx = 0

    while ($true) {
        # Draw options
        for ($i = 0; $i -lt $options.Count; $i++) {
            $optY = $Y + 1 + $i
            $prefix = "  "
            $fg = $script:Colors.Normal
            $bg = $OriginalBackground

            if ($i -eq $selectedIdx) {
                $prefix = "> "
                $fg = $script:Colors.Selected
                $bg = $script:Colors.SelectedBg
            }

            $text = "$prefix$($options[$i])".PadRight($width - 2)
            Write-At -X ($X + 1) -Y $optY -Text $text -ForegroundColor $fg -BackgroundColor $bg
        }

        $key = [Console]::ReadKey($true)

        switch ($key.Key) {
            "UpArrow" {
                if ($selectedIdx -gt 0) { $selectedIdx-- }
            }
            "DownArrow" {
                if ($selectedIdx -lt $options.Count - 1) { $selectedIdx++ }
            }
            "Enter" {
                $selected = $options[$selectedIdx]

                if ($selected -match "WSL2 \((.+)\)") {
                    return $Matches[1]
                }
                elseif ($selected -match "localhost") {
                    return "127.0.0.1"
                }
                else {
                    # Custom - ask for input
                    $inputY = $Y + $options.Count + 2
                    Write-At -X ($X + 2) -Y $inputY -Text "Enter address: " -ForegroundColor $script:Colors.Normal
                    [Console]::SetCursorPosition($X + 17, $inputY)
                    [Console]::CursorVisible = $true
                    $customAddr = Read-Host
                    [Console]::CursorVisible = $false
                    if ([string]::IsNullOrWhiteSpace($customAddr)) {
                        return $null
                    }
                    return $customAddr
                }
            }
            "Escape" {
                return $null
            }
        }
    }
}

function Get-PortProxyRules {
    $rules = @()

    try {
        $output = netsh interface portproxy show all 2>$null

        $currentType = "v4tov4"

        foreach ($line in $output) {
            # Clean up the line (remove carriage returns, trim)
            $line = $line -replace "`r", ""
            $line = $line.Trim()

            # Skip empty lines
            if ([string]::IsNullOrWhiteSpace($line)) { continue }

            # Skip header lines
            if ($line -match "^Address\s+Port") { continue }
            if ($line -match "^-+") { continue }

            # Detect section type from headers like "Listen on ipv4:             Connect to ipv4:"
            if ($line -match "Listen on (\w+).*Connect to (\w+)") {
                $from = $Matches[1].ToLower() -replace "ipv", "v"
                $to = $Matches[2].ToLower() -replace "ipv", "v"
                $currentType = "${from}to${to}"
                continue
            }

            # Parse data lines - match IP/address followed by port, repeated twice
            # Format: "0.0.0.0         3210        172.25.245.23   3210"
            if ($line -match "^(\S+)\s+(\d+)\s+(\S+)\s+(\d+)") {
                $rules += [PSCustomObject]@{
                    Type = $currentType
                    ListenAddress = $Matches[1]
                    ListenPort = [int]$Matches[2]
                    ConnectAddress = $Matches[3]
                    ConnectPort = [int]$Matches[4]
                    FirewallStatus = "-"
                }
            }
        }

        # Populate firewall status for each rule
        foreach ($rule in $rules) {
            $rule.FirewallStatus = Get-FirewallStatus -ListenAddress $rule.ListenAddress -ListenPort $rule.ListenPort
        }
    }
    catch {
        $script:Message = "Error reading rules: $_"
        $script:MessageType = "Error"
    }

    return ,$rules
}

function Add-PortProxyRule {
    param(
        [string]$Type = "v4tov4",
        [string]$ListenAddress,
        [int]$ListenPort,
        [string]$ConnectAddress,
        [int]$ConnectPort
    )

    try {
        $cmd = "netsh interface portproxy add $Type listenaddress=$ListenAddress listenport=$ListenPort connectaddress=$ConnectAddress connectport=$ConnectPort"
        $result = Invoke-Expression $cmd 2>&1

        if ($LASTEXITCODE -eq 0) {
            $script:Message = "Rule added successfully"
            $script:MessageType = "Success"
            return $true
        }
        else {
            $script:Message = "Failed to add rule: $result"
            $script:MessageType = "Error"
            return $false
        }
    }
    catch {
        $script:Message = "Error: $_"
        $script:MessageType = "Error"
        return $false
    }
}

function Remove-PortProxyRule {
    param(
        [string]$Type,
        [string]$ListenAddress,
        [int]$ListenPort
    )

    try {
        $cmd = "netsh interface portproxy delete $Type listenaddress=$ListenAddress listenport=$ListenPort"
        $result = Invoke-Expression $cmd 2>&1

        if ($LASTEXITCODE -eq 0) {
            $script:Message = "Rule deleted successfully"
            $script:MessageType = "Success"
            return $true
        }
        else {
            $script:Message = "Failed to delete rule: $result"
            $script:MessageType = "Error"
            return $false
        }
    }
    catch {
        $script:Message = "Error: $_"
        $script:MessageType = "Error"
        return $false
    }
}

function Show-InputDialog {
    param(
        [string]$Title,
        [string]$Prompt,
        [string]$Default = ""
    )

    $width = 50
    $height = 5
    $x = [math]::Floor(([Console]::WindowWidth - $width) / 2)
    $y = [math]::Floor(([Console]::WindowHeight - $height) / 2)

    # Clear area
    for ($i = 0; $i -lt $height; $i++) {
        Write-At -X $x -Y ($y + $i) -Text (" " * $width)
    }

    Draw-Box -X $x -Y $y -Width $width -Height $height -Title $Title
    Write-At -X ($x + 2) -Y ($y + 1) -Text $Prompt -ForegroundColor $script:Colors.Normal
    Write-At -X ($x + 2) -Y ($y + 2) -Text ("> " + (" " * ($width - 6))) -ForegroundColor $script:Colors.Key

    [Console]::SetCursorPosition($x + 4, $y + 2)
    [Console]::CursorVisible = $true

    $input = Read-Host

    [Console]::CursorVisible = $false

    if ([string]::IsNullOrWhiteSpace($input) -and $Default) {
        return $Default
    }
    return $input
}

function Show-AddRuleDialog {
    Clear-Screen

    $width = 60
    $height = 18
    $x = [math]::Floor(([Console]::WindowWidth - $width) / 2)
    $y = 1

    Draw-Box -X $x -Y $y -Width $width -Height $height -Title "Add New Port Redirect Rule"

    # Step 1: Select Type
    Write-At -X ($x + 2) -Y ($y + 2) -Text "1. Select Type:" -ForegroundColor $script:Colors.Header
    Write-At -X ($x + 2) -Y ($y + 3) -Text "   (Use Up/Down arrows, Enter to select, Esc to cancel)" -ForegroundColor $script:Colors.Info

    $type = Show-SelectionMenu -Title "Type" -Options $script:ProxyTypes -X ($x + 4) -Y ($y + 4) -DefaultIndex 0

    if (-not $type) {
        $script:Message = "Cancelled"
        $script:MessageType = "Info"
        return
    }

    # Redraw dialog
    Clear-Screen
    Draw-Box -X $x -Y $y -Width $width -Height $height -Title "Add New Port Redirect Rule"
    Write-At -X ($x + 2) -Y ($y + 2) -Text "Type: $type" -ForegroundColor $script:Colors.Success

    # Step 2: Listen Address
    Write-At -X ($x + 2) -Y ($y + 4) -Text "2. Listen Address:" -ForegroundColor $script:Colors.Header
    $listenOptions = @("0.0.0.0 (all interfaces)", "127.0.0.1 (localhost only)", "Custom (enter manually)")
    $listenChoice = Show-SelectionMenu -Title "Listen Address" -Options $listenOptions -X ($x + 4) -Y ($y + 5) -DefaultIndex 0

    if (-not $listenChoice) {
        $script:Message = "Cancelled"
        $script:MessageType = "Info"
        return
    }

    $listenAddr = switch -Regex ($listenChoice) {
        "0\.0\.0\.0" { "0.0.0.0" }
        "127\.0\.0\.1" { "127.0.0.1" }
        default {
            Write-At -X ($x + 4) -Y ($y + 9) -Text "Enter address: " -ForegroundColor $script:Colors.Normal
            [Console]::SetCursorPosition($x + 19, $y + 9)
            [Console]::CursorVisible = $true
            $addr = Read-Host
            [Console]::CursorVisible = $false
            $addr
        }
    }

    if ([string]::IsNullOrWhiteSpace($listenAddr)) {
        $script:Message = "Cancelled - no listen address"
        $script:MessageType = "Info"
        return
    }

    # Redraw dialog
    Clear-Screen
    Draw-Box -X $x -Y $y -Width $width -Height $height -Title "Add New Port Redirect Rule"
    Write-At -X ($x + 2) -Y ($y + 2) -Text "Type: $type" -ForegroundColor $script:Colors.Success
    Write-At -X ($x + 2) -Y ($y + 3) -Text "Listen Address: $listenAddr" -ForegroundColor $script:Colors.Success

    # Step 3: Listen Port
    Write-At -X ($x + 2) -Y ($y + 5) -Text "3. Listen Port:" -ForegroundColor $script:Colors.Header
    Write-At -X ($x + 4) -Y ($y + 6) -Text "> " -ForegroundColor $script:Colors.Key
    [Console]::SetCursorPosition($x + 6, $y + 6)
    [Console]::CursorVisible = $true
    $listenPort = Read-Host
    [Console]::CursorVisible = $false

    if ([string]::IsNullOrWhiteSpace($listenPort)) {
        $script:Message = "Cancelled - no listen port"
        $script:MessageType = "Info"
        return
    }

    # Redraw dialog
    Clear-Screen
    Draw-Box -X $x -Y $y -Width $width -Height $height -Title "Add New Port Redirect Rule"
    Write-At -X ($x + 2) -Y ($y + 2) -Text "Type: $type" -ForegroundColor $script:Colors.Success
    Write-At -X ($x + 2) -Y ($y + 3) -Text "Listen: $listenAddr`:$listenPort" -ForegroundColor $script:Colors.Success

    # Step 4: Connect Address (with WSL2 option)
    Write-At -X ($x + 2) -Y ($y + 5) -Text "4. Connect Address (redirect to):" -ForegroundColor $script:Colors.Header
    Write-At -X ($x + 2) -Y ($y + 6) -Text "   (Use Up/Down arrows, Enter to select)" -ForegroundColor $script:Colors.Info

    $connectAddr = Show-AddressSelectionMenu -Title "Connect Address" -X ($x + 4) -Y ($y + 7)

    if (-not $connectAddr) {
        $script:Message = "Cancelled - no connect address"
        $script:MessageType = "Info"
        return
    }

    # Redraw dialog
    Clear-Screen
    Draw-Box -X $x -Y $y -Width $width -Height $height -Title "Add New Port Redirect Rule"
    Write-At -X ($x + 2) -Y ($y + 2) -Text "Type: $type" -ForegroundColor $script:Colors.Success
    Write-At -X ($x + 2) -Y ($y + 3) -Text "Listen: $listenAddr`:$listenPort" -ForegroundColor $script:Colors.Success
    Write-At -X ($x + 2) -Y ($y + 4) -Text "Connect Address: $connectAddr" -ForegroundColor $script:Colors.Success

    # Step 5: Connect Port
    Write-At -X ($x + 2) -Y ($y + 6) -Text "5. Connect Port:" -ForegroundColor $script:Colors.Header
    Write-At -X ($x + 4) -Y ($y + 7) -Text "(Press Enter to use same as listen port: $listenPort)" -ForegroundColor $script:Colors.Info
    Write-At -X ($x + 4) -Y ($y + 8) -Text "> " -ForegroundColor $script:Colors.Key
    [Console]::SetCursorPosition($x + 6, $y + 8)
    [Console]::CursorVisible = $true
    $connectPort = Read-Host
    [Console]::CursorVisible = $false

    # Default to listen port if empty
    if ([string]::IsNullOrWhiteSpace($connectPort)) {
        $connectPort = $listenPort
    }

    # Redraw dialog for firewall step
    Clear-Screen
    Draw-Box -X $x -Y $y -Width $width -Height $height -Title "Add New Port Redirect Rule"
    Write-At -X ($x + 2) -Y ($y + 2) -Text "Type: $type" -ForegroundColor $script:Colors.Success
    Write-At -X ($x + 2) -Y ($y + 3) -Text "Listen: $listenAddr`:$listenPort" -ForegroundColor $script:Colors.Success
    Write-At -X ($x + 2) -Y ($y + 4) -Text "Connect: $connectAddr`:$connectPort" -ForegroundColor $script:Colors.Success

    # Step 6: Firewall Rule
    Write-At -X ($x + 2) -Y ($y + 6) -Text "6. Create Firewall Rule?" -ForegroundColor $script:Colors.Header
    Write-At -X ($x + 2) -Y ($y + 7) -Text "   (Allows inbound traffic on listen port)" -ForegroundColor $script:Colors.Info

    $fwOptions = @("No firewall rule", "TCP only", "UDP only", "Both TCP and UDP")
    $fwChoice = Show-SelectionMenu -Title "Firewall" -Options $fwOptions -X ($x + 4) -Y ($y + 8) -DefaultIndex 0

    $createFirewall = switch ($fwChoice) {
        "TCP only" { "TCP" }
        "UDP only" { "UDP" }
        "Both TCP and UDP" { "Both" }
        default { "None" }
    }

    # Summary and confirm
    Clear-Screen
    Draw-Box -X $x -Y $y -Width $width -Height 14 -Title "Confirm New Rule"
    Write-At -X ($x + 2) -Y ($y + 2) -Text "Type:            $type" -ForegroundColor $script:Colors.Normal
    Write-At -X ($x + 2) -Y ($y + 3) -Text "Listen Address:  $listenAddr" -ForegroundColor $script:Colors.Normal
    Write-At -X ($x + 2) -Y ($y + 4) -Text "Listen Port:     $listenPort" -ForegroundColor $script:Colors.Normal
    Write-At -X ($x + 2) -Y ($y + 5) -Text "Connect Address: $connectAddr" -ForegroundColor $script:Colors.Normal
    Write-At -X ($x + 2) -Y ($y + 6) -Text "Connect Port:    $connectPort" -ForegroundColor $script:Colors.Normal
    $fwDisplay = if ($createFirewall -eq "None") { "No" } else { "Yes ($createFirewall)" }
    Write-At -X ($x + 2) -Y ($y + 7) -Text "Firewall Rule:   $fwDisplay" -ForegroundColor $script:Colors.Normal
    Write-At -X ($x + 2) -Y ($y + 9) -Text "Create this rule? [Y]es / [N]o" -ForegroundColor $script:Colors.Key

    while ($true) {
        $key = [Console]::ReadKey($true)
        if ($key.Key -eq "Y") {
            break
        }
        if ($key.Key -eq "N" -or $key.Key -eq "Escape") {
            $script:Message = "Cancelled"
            $script:MessageType = "Info"
            return
        }
    }

    try {
        $lp = [int]$listenPort
        $cp = [int]$connectPort
        Add-PortProxyRule -Type $type -ListenAddress $listenAddr -ListenPort $lp -ConnectAddress $connectAddr -ConnectPort $cp

        # Create firewall rule if selected
        if ($createFirewall -ne "None") {
            $fwResult = Add-PortRedirectFirewallRule -ListenAddress $listenAddr -ListenPort $lp -Protocol $createFirewall
            if ($fwResult.Success) {
                $script:Message = "Rule added with firewall: $($fwResult.Message)"
            }
            else {
                $script:Message = "Rule added but firewall failed: $($fwResult.Message)"
                $script:MessageType = "Error"
            }
        }
    }
    catch {
        $script:Message = "Invalid port number"
        $script:MessageType = "Error"
    }
}

function Show-EditRuleDialog {
    param([PSCustomObject]$Rule)

    if (-not $Rule) { return }

    Clear-Screen

    $width = 60
    $height = 16
    $x = [math]::Floor(([Console]::WindowWidth - $width) / 2)
    $y = 1

    Draw-Box -X $x -Y $y -Width $width -Height $height -Title "Edit Port Redirect Rule"

    Write-At -X ($x + 2) -Y ($y + 2) -Text "Type: $($Rule.Type)" -ForegroundColor $script:Colors.Info
    Write-At -X ($x + 2) -Y ($y + 3) -Text "Listen: $($Rule.ListenAddress):$($Rule.ListenPort)" -ForegroundColor $script:Colors.Info
    Write-At -X ($x + 2) -Y ($y + 4) -Text "(Type and Listen are read-only)" -ForegroundColor $script:Colors.Normal

    # Current values
    Write-At -X ($x + 2) -Y ($y + 6) -Text "Current Connect: $($Rule.ConnectAddress):$($Rule.ConnectPort)" -ForegroundColor $script:Colors.Normal

    # New Connect Address
    Write-At -X ($x + 2) -Y ($y + 8) -Text "New Connect Address:" -ForegroundColor $script:Colors.Header
    Write-At -X ($x + 2) -Y ($y + 9) -Text "(Press Esc to keep current: $($Rule.ConnectAddress))" -ForegroundColor $script:Colors.Info

    $connectAddr = Show-AddressSelectionMenu -Title "Connect Address" -X ($x + 4) -Y ($y + 10)

    if (-not $connectAddr) {
        $connectAddr = $Rule.ConnectAddress
    }

    # Redraw for port
    Clear-Screen
    Draw-Box -X $x -Y $y -Width $width -Height $height -Title "Edit Port Redirect Rule"
    Write-At -X ($x + 2) -Y ($y + 2) -Text "Type: $($Rule.Type)" -ForegroundColor $script:Colors.Info
    Write-At -X ($x + 2) -Y ($y + 3) -Text "Listen: $($Rule.ListenAddress):$($Rule.ListenPort)" -ForegroundColor $script:Colors.Info
    Write-At -X ($x + 2) -Y ($y + 5) -Text "New Connect Address: $connectAddr" -ForegroundColor $script:Colors.Success

    # New Connect Port
    Write-At -X ($x + 2) -Y ($y + 7) -Text "New Connect Port:" -ForegroundColor $script:Colors.Header
    Write-At -X ($x + 2) -Y ($y + 8) -Text "(Press Enter to keep current: $($Rule.ConnectPort))" -ForegroundColor $script:Colors.Info
    Write-At -X ($x + 4) -Y ($y + 9) -Text "> " -ForegroundColor $script:Colors.Key
    [Console]::SetCursorPosition($x + 6, $y + 9)
    [Console]::CursorVisible = $true
    $connectPort = Read-Host
    [Console]::CursorVisible = $false

    if ([string]::IsNullOrWhiteSpace($connectPort)) {
        $connectPort = $Rule.ConnectPort
    }

    # Confirm changes
    if ($connectAddr -eq $Rule.ConnectAddress -and [int]$connectPort -eq $Rule.ConnectPort) {
        $script:Message = "No changes made"
        $script:MessageType = "Info"
        return
    }

    Clear-Screen
    Draw-Box -X $x -Y $y -Width $width -Height 10 -Title "Confirm Changes"
    Write-At -X ($x + 2) -Y ($y + 2) -Text "Old: $($Rule.ConnectAddress):$($Rule.ConnectPort)" -ForegroundColor $script:Colors.Normal
    Write-At -X ($x + 2) -Y ($y + 3) -Text "New: $connectAddr`:$connectPort" -ForegroundColor $script:Colors.Success
    Write-At -X ($x + 2) -Y ($y + 5) -Text "Apply changes? [Y]es / [N]o" -ForegroundColor $script:Colors.Key

    while ($true) {
        $key = [Console]::ReadKey($true)
        if ($key.Key -eq "Y") { break }
        if ($key.Key -eq "N" -or $key.Key -eq "Escape") {
            $script:Message = "Edit cancelled"
            $script:MessageType = "Info"
            return
        }
    }

    try {
        $cp = [int]$connectPort

        # Delete old rule and add new one
        if (Remove-PortProxyRule -Type $Rule.Type -ListenAddress $Rule.ListenAddress -ListenPort $Rule.ListenPort) {
            if (Add-PortProxyRule -Type $Rule.Type -ListenAddress $Rule.ListenAddress -ListenPort $Rule.ListenPort -ConnectAddress $connectAddr -ConnectPort $cp) {
                $script:Message = "Rule updated successfully"
                $script:MessageType = "Success"
            }
        }
    }
    catch {
        $script:Message = "Invalid port number"
        $script:MessageType = "Error"
    }
}

function Show-FirewallDialog {
    <#
    .SYNOPSIS
        Dialog for managing firewall rules on an existing NAT rule
    #>
    param([PSCustomObject]$Rule)

    if (-not $Rule) { return }

    Clear-Screen

    $width = 60
    $height = 14
    $x = [math]::Floor(([Console]::WindowWidth - $width) / 2)
    $y = 1

    # Get current firewall status
    $tcpName = Get-FirewallRuleName -ListenAddress $Rule.ListenAddress -ListenPort $Rule.ListenPort -Protocol "TCP"
    $udpName = Get-FirewallRuleName -ListenAddress $Rule.ListenAddress -ListenPort $Rule.ListenPort -Protocol "UDP"

    $tcpRule = $null
    $udpRule = $null
    try { $tcpRule = Get-NetFirewallRule -Name $tcpName -ErrorAction SilentlyContinue } catch {}
    try { $udpRule = Get-NetFirewallRule -Name $udpName -ErrorAction SilentlyContinue } catch {}

    $tcpEnabled = $tcpRule -and $tcpRule.Enabled -eq "True"
    $udpEnabled = $udpRule -and $udpRule.Enabled -eq "True"

    while ($true) {
        Clear-Screen
        Draw-Box -X $x -Y $y -Width $width -Height $height -Title "Firewall Rules"

        Write-At -X ($x + 2) -Y ($y + 2) -Text "NAT Rule: $($Rule.ListenAddress):$($Rule.ListenPort)" -ForegroundColor $script:Colors.Header

        # Show current status
        $tcpStatus = if ($tcpEnabled) { "ENABLED" } else { "disabled" }
        $udpStatus = if ($udpEnabled) { "ENABLED" } else { "disabled" }
        $tcpColor = if ($tcpEnabled) { $script:Colors.Success } else { $script:Colors.Normal }
        $udpColor = if ($udpEnabled) { $script:Colors.Success } else { $script:Colors.Normal }

        Write-At -X ($x + 2) -Y ($y + 4) -Text "TCP: " -ForegroundColor $script:Colors.Normal
        Write-At -X ($x + 7) -Y ($y + 4) -Text $tcpStatus -ForegroundColor $tcpColor
        Write-At -X ($x + 20) -Y ($y + 4) -Text "UDP: " -ForegroundColor $script:Colors.Normal
        Write-At -X ($x + 25) -Y ($y + 4) -Text $udpStatus -ForegroundColor $udpColor

        # Show options
        Write-At -X ($x + 2) -Y ($y + 6) -Text "[1] Add TCP     [2] Add UDP     [3] Add Both" -ForegroundColor $script:Colors.Key
        Write-At -X ($x + 2) -Y ($y + 7) -Text "[4] Remove TCP  [5] Remove UDP  [6] Remove All" -ForegroundColor $script:Colors.Key
        Write-At -X ($x + 2) -Y ($y + 9) -Text "[Esc] Back" -ForegroundColor $script:Colors.Info

        # Show message if any
        if ($script:Message) {
            $msgColor = switch ($script:MessageType) {
                "Success" { $script:Colors.Success }
                "Error" { $script:Colors.Error }
                default { $script:Colors.Info }
            }
            Write-At -X ($x + 2) -Y ($y + 11) -Text $script:Message -ForegroundColor $msgColor
        }

        $key = [Console]::ReadKey($true)
        $script:Message = ""

        switch ($key.KeyChar) {
            "1" {
                $result = Add-PortRedirectFirewallRule -ListenAddress $Rule.ListenAddress -ListenPort $Rule.ListenPort -Protocol "TCP"
                $script:Message = $result.Message
                $script:MessageType = if ($result.Success) { "Success" } else { "Error" }
                # Refresh status
                try { $tcpRule = Get-NetFirewallRule -Name $tcpName -ErrorAction SilentlyContinue } catch {}
                $tcpEnabled = $tcpRule -and $tcpRule.Enabled -eq "True"
            }
            "2" {
                $result = Add-PortRedirectFirewallRule -ListenAddress $Rule.ListenAddress -ListenPort $Rule.ListenPort -Protocol "UDP"
                $script:Message = $result.Message
                $script:MessageType = if ($result.Success) { "Success" } else { "Error" }
                # Refresh status
                try { $udpRule = Get-NetFirewallRule -Name $udpName -ErrorAction SilentlyContinue } catch {}
                $udpEnabled = $udpRule -and $udpRule.Enabled -eq "True"
            }
            "3" {
                $result = Add-PortRedirectFirewallRule -ListenAddress $Rule.ListenAddress -ListenPort $Rule.ListenPort -Protocol "Both"
                $script:Message = $result.Message
                $script:MessageType = if ($result.Success) { "Success" } else { "Error" }
                # Refresh status
                try { $tcpRule = Get-NetFirewallRule -Name $tcpName -ErrorAction SilentlyContinue } catch {}
                try { $udpRule = Get-NetFirewallRule -Name $udpName -ErrorAction SilentlyContinue } catch {}
                $tcpEnabled = $tcpRule -and $tcpRule.Enabled -eq "True"
                $udpEnabled = $udpRule -and $udpRule.Enabled -eq "True"
            }
            "4" {
                $result = Remove-PortRedirectFirewallRule -ListenAddress $Rule.ListenAddress -ListenPort $Rule.ListenPort -Protocol "TCP"
                $script:Message = $result.Message
                $script:MessageType = if ($result.Success) { "Success" } else { "Error" }
                # Refresh status
                try { $tcpRule = Get-NetFirewallRule -Name $tcpName -ErrorAction SilentlyContinue } catch { $tcpRule = $null }
                $tcpEnabled = $tcpRule -and $tcpRule.Enabled -eq "True"
            }
            "5" {
                $result = Remove-PortRedirectFirewallRule -ListenAddress $Rule.ListenAddress -ListenPort $Rule.ListenPort -Protocol "UDP"
                $script:Message = $result.Message
                $script:MessageType = if ($result.Success) { "Success" } else { "Error" }
                # Refresh status
                try { $udpRule = Get-NetFirewallRule -Name $udpName -ErrorAction SilentlyContinue } catch { $udpRule = $null }
                $udpEnabled = $udpRule -and $udpRule.Enabled -eq "True"
            }
            "6" {
                $result = Remove-PortRedirectFirewallRule -ListenAddress $Rule.ListenAddress -ListenPort $Rule.ListenPort -Protocol "Both"
                $script:Message = $result.Message
                $script:MessageType = if ($result.Success) { "Success" } else { "Error" }
                # Refresh status
                $tcpRule = $null
                $udpRule = $null
                $tcpEnabled = $false
                $udpEnabled = $false
            }
        }

        if ($key.Key -eq "Escape") {
            $script:Message = ""
            return
        }
    }
}

function Show-ConfirmDialog {
    param([string]$Title, [string]$Message)

    $width = 50
    $height = 6
    $x = [math]::Floor(([Console]::WindowWidth - $width) / 2)
    $y = [math]::Floor(([Console]::WindowHeight - $height) / 2)

    # Clear area
    for ($i = 0; $i -lt $height; $i++) {
        Write-At -X $x -Y ($y + $i) -Text (" " * $width)
    }

    Draw-Box -X $x -Y $y -Width $width -Height $height -Title $Title
    Write-At -X ($x + 2) -Y ($y + 2) -Text $Message -ForegroundColor $script:Colors.Normal
    Write-At -X ($x + 2) -Y ($y + 3) -Text "[Y]es / [N]o" -ForegroundColor $script:Colors.Key

    while ($true) {
        $key = [Console]::ReadKey($true)
        if ($key.Key -eq "Y") { return $true }
        if ($key.Key -eq "N" -or $key.Key -eq "Escape") { return $false }
    }
}

function Draw-MainScreen {
    Clear-Screen

    $width = [Console]::WindowWidth
    $height = [Console]::WindowHeight

    # Header
    $title = " NAT Port Redirect Manager "
    $titleX = [math]::Floor(($width - $title.Length) / 2)
    Write-At -X 0 -Y 0 -Text ("=" * $width) -ForegroundColor $script:Colors.Border
    Write-At -X $titleX -Y 0 -Text $title -ForegroundColor $script:Colors.Header
    Write-At -X 0 -Y 1 -Text ("=" * $width) -ForegroundColor $script:Colors.Border

    # Rules list header
    $headerY = 3
    $colType = 2
    $colListen = 14
    $colConnect = 42
    $colFirewall = 68

    Write-At -X $colType -Y $headerY -Text "TYPE" -ForegroundColor $script:Colors.Header
    Write-At -X $colListen -Y $headerY -Text "LISTEN ON" -ForegroundColor $script:Colors.Header
    Write-At -X $colConnect -Y $headerY -Text "REDIRECT TO" -ForegroundColor $script:Colors.Header
    Write-At -X $colFirewall -Y $headerY -Text "FW" -ForegroundColor $script:Colors.Header
    Write-At -X 0 -Y ($headerY + 1) -Text ("-" * $width) -ForegroundColor $script:Colors.Border

    # Rules list
    $listStartY = $headerY + 2
    $maxItems = $height - $listStartY - 5

    $script:PortRules = Get-PortProxyRules

    if ($script:PortRules.Count -eq 0) {
        Write-At -X 2 -Y $listStartY -Text "No port redirect rules configured." -ForegroundColor $script:Colors.Info
        Write-At -X 2 -Y ($listStartY + 1) -Text "Press [A] to add a new rule." -ForegroundColor $script:Colors.Normal
    }
    else {
        # Ensure selected index is valid
        if ($script:SelectedIndex -ge $script:PortRules.Count) {
            $script:SelectedIndex = $script:PortRules.Count - 1
        }
        if ($script:SelectedIndex -lt 0) {
            $script:SelectedIndex = 0
        }

        for ($i = 0; $i -lt [math]::Min($script:PortRules.Count, $maxItems); $i++) {
            $rule = $script:PortRules[$i]
            $y = $listStartY + $i

            $typeStr = $rule.Type.PadRight(10)
            $listenStr = "$($rule.ListenAddress):$($rule.ListenPort)".PadRight(24)
            $connectStr = "$($rule.ConnectAddress):$($rule.ConnectPort)".PadRight(22)
            $fwStr = $rule.FirewallStatus.PadRight(4)

            $line = "  $typeStr  $listenStr  $connectStr  $fwStr"
            $line = $line.PadRight($width - 1)

            if ($i -eq $script:SelectedIndex) {
                Write-At -X 0 -Y $y -Text ">" -ForegroundColor $script:Colors.Key
                Write-At -X 1 -Y $y -Text $line -ForegroundColor $script:Colors.Selected -BackgroundColor $script:Colors.SelectedBg
            }
            else {
                Write-At -X 0 -Y $y -Text " " -ForegroundColor $script:Colors.Normal
                Write-At -X 1 -Y $y -Text $line -ForegroundColor $script:Colors.Normal
            }
        }
    }

    # Status/Message bar
    $statusY = $height - 4
    Write-At -X 0 -Y $statusY -Text ("-" * $width) -ForegroundColor $script:Colors.Border

    if ($script:Message) {
        $msgColor = switch ($script:MessageType) {
            "Success" { $script:Colors.Success }
            "Error" { $script:Colors.Error }
            default { $script:Colors.Info }
        }
        Write-At -X 2 -Y ($statusY + 1) -Text $script:Message -ForegroundColor $msgColor
    }

    # Help bar
    $helpY = $height - 2
    Write-At -X 0 -Y $helpY -Text ("=" * $width) -ForegroundColor $script:Colors.Border
    $helpText = " [A]dd  [R]efresh  [Q]uit "
    if ($script:PortRules.Count -gt 0) {
        $helpText = " [Up/Down] Navigate  [A]dd  [E]dit  [D]elete  [F]irewall  [R]efresh  [Q]uit "
    }
    $helpX = [math]::Floor(($width - $helpText.Length) / 2)
    Write-At -X $helpX -Y ($helpY) -Text $helpText -ForegroundColor $script:Colors.Key
}

function Main {
    # Check for admin privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Host "This script requires Administrator privileges." -ForegroundColor Red
        Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Yellow
        return
    }

    try {
        [Console]::CursorVisible = $false

        while ($script:Running) {
            Draw-MainScreen

            $key = [Console]::ReadKey($true)
            $script:Message = ""

            switch ($key.Key) {
                "Q" {
                    $script:Running = $false
                }
                "Escape" {
                    $script:Running = $false
                }
                "UpArrow" {
                    if ($script:SelectedIndex -gt 0) {
                        $script:SelectedIndex--
                    }
                }
                "DownArrow" {
                    if ($script:SelectedIndex -lt $script:PortRules.Count - 1) {
                        $script:SelectedIndex++
                    }
                }
                "A" {
                    Show-AddRuleDialog
                }
                "E" {
                    if ($script:PortRules.Count -gt 0) {
                        $selectedRule = $script:PortRules[$script:SelectedIndex]
                        Show-EditRuleDialog -Rule $selectedRule
                    }
                    else {
                        $script:Message = "No rules to edit"
                        $script:MessageType = "Info"
                    }
                }
                "F" {
                    if ($script:PortRules.Count -gt 0) {
                        $selectedRule = $script:PortRules[$script:SelectedIndex]
                        Show-FirewallDialog -Rule $selectedRule
                    }
                    else {
                        $script:Message = "No rules to manage firewall for"
                        $script:MessageType = "Info"
                    }
                }
                "D" {
                    if ($script:PortRules.Count -gt 0) {
                        $selectedRule = $script:PortRules[$script:SelectedIndex]
                        $hasFirewall = $selectedRule.FirewallStatus -ne "-"
                        $confirmMsg = "Delete $($selectedRule.ListenAddress):$($selectedRule.ListenPort)?"
                        if ($hasFirewall) {
                            $confirmMsg += " (FW: $($selectedRule.FirewallStatus))"
                        }

                        if (Show-ConfirmDialog -Title "Confirm Delete" -Message $confirmMsg) {
                            # Remove associated firewall rules first
                            if ($hasFirewall) {
                                Remove-PortRedirectFirewallRule -ListenAddress $selectedRule.ListenAddress -ListenPort $selectedRule.ListenPort -Protocol "Both"
                            }
                            # Then remove the NAT rule
                            Remove-PortProxyRule -Type $selectedRule.Type -ListenAddress $selectedRule.ListenAddress -ListenPort $selectedRule.ListenPort
                        }
                        else {
                            $script:Message = "Delete cancelled"
                            $script:MessageType = "Info"
                        }
                    }
                    else {
                        $script:Message = "No rules to delete"
                        $script:MessageType = "Info"
                    }
                }
                "R" {
                    $script:Message = "Refreshed"
                    $script:MessageType = "Info"
                }
            }
        }
    }
    finally {
        # Restore console
        [Console]::CursorVisible = $true
        Clear-Screen
        Write-Host "Goodbye!" -ForegroundColor $script:Colors.Header
    }
}

# Run the application
Main
