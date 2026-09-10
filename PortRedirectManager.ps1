<#
.SYNOPSIS
    NAT Port Redirect Manager - TUI and CLI for Windows "netsh interface portproxy" rules with firewall integration.

.DESCRIPTION
    Manage Windows port-proxy (NAT redirect) rules and the matching inbound Windows Firewall rules from a
    keyboard-driven terminal UI, or headlessly from scripts. Built for WSL2 users who expose services running
    inside WSL to their LAN, but works for any port redirect.

    Without parameters the interactive TUI starts (needs an elevated PowerShell). With -List, -Add, -Remove or
    -Repoint the script runs headlessly, which is convenient for automation and scheduled tasks.

    Firewall rules created by this tool are named  PortRedirect_<ListenAddress>_<ListenPort>_<TCP|UDP>.

.PARAMETER List
    Print the current port-proxy rules as objects (pipe to Format-Table, ConvertTo-Json, Where-Object...).
    Does not require elevation.

.PARAMETER Add
    Add a rule headlessly. Requires -ListenPort and -ConnectAddress; -ConnectPort defaults to -ListenPort.

.PARAMETER Remove
    Remove the rule(s) listening on -ListenAddress:-ListenPort (and their PortRedirect_* firewall rules).

.PARAMETER Repoint
    Change the connect address of every rule that currently targets -From so that it targets -To.
    Use this after the WSL2 IP changed, or to migrate rules to a hostname.

.PARAMETER RemoveOrphans
    Delete PortRedirect_* firewall rules whose port-proxy rule no longer exists.

.PARAMETER NoElevate
    Do not ask for administrator rights (UAC) when the session is not elevated; fail with a message instead.
    Without this switch the script relaunches itself elevated: the TUI opens in a new elevated window and this
    window waits for it; headless commands run elevated in the background and print their output here.

.PARAMETER Type
    Proxy type: v4tov4 (default), v4tov6, v6tov4 or v6tov6.

.PARAMETER ListenAddress
    Address to listen on. Defaults to 0.0.0.0 (all IPv4 interfaces).

.PARAMETER ListenPort
    Port(s) to listen on (1-65535). -Add and -Remove accept lists and ranges: -ListenPort 8080,8443 or
    -ListenPort 3000-3003 or -ListenPort (3000..3003). Each port gets its own rule with the same target and
    the same port on the target.

.PARAMETER ConnectAddress
    Destination IP address or hostname. The keyword "wsl" resolves to the current WSL2 IPv4 address.
    A hostname is stored verbatim by netsh and resolved on every connection, so a dynamic-DNS name that
    follows your WSL2 IP makes rules that never go stale.

.PARAMETER ConnectPort
    Destination port (1-65535). Defaults to the listen port. Only valid with a single -ListenPort.

.PARAMETER Firewall
    Whether -Add creates an inbound TCP firewall rule for the listen port: TCP (default) or None.
    Port-proxy forwards TCP only, so no UDP rule is ever created. Loopback listeners never need one.

.PARAMETER From
    With -Repoint: the connect address the rules currently point to (exact, case-insensitive match).

.PARAMETER To
    With -Repoint: the new connect address or hostname. The keyword "wsl" resolves to the current WSL2 IP.

.EXAMPLE
    .\PortRedirectManager.ps1
    Start the interactive TUI (run from an elevated PowerShell).

.EXAMPLE
    .\PortRedirectManager.ps1 -List | Format-Table
    List all rules. Works without elevation.

.EXAMPLE
    .\PortRedirectManager.ps1 -Add -ListenPort 3000 -ConnectAddress wsl
    Forward 0.0.0.0:3000 to port 3000 on the current WSL2 IP and open TCP 3000 in the firewall.

.EXAMPLE
    .\PortRedirectManager.ps1 -Add -ListenPort 3000-3003 -ConnectAddress my-wsl.lan.example -Firewall None
    Create four rules that forward to a hostname (resolved by netsh on every connection), without firewall rules.

.EXAMPLE
    .\PortRedirectManager.ps1 -Repoint -From 192.0.2.50 -To wsl
    Re-point every rule that targets 192.0.2.50 to the current WSL2 IP.

.EXAMPLE
    .\PortRedirectManager.ps1 -Remove -ListenPort 3000 -WhatIf
    Show what -Remove would do without changing anything.

.NOTES
    Version 2.1.0. Requires Windows 10/11 and Windows PowerShell 5.1 or PowerShell 7+.
    Everything except -List needs administrator rights; the script asks for them (UAC) when needed, or
    fails with a message when -NoElevate is given. Port-proxy rules only work while the "IP Helper"
    (iphlpsvc) service is running; the TUI shows its state and can start it.

.LINK
    https://github.com/oriolrius/nat-port-manager
#>
#Requires -Version 5.1
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Switches select the parameter set; they are consumed through $PSCmdlet.ParameterSetName')]
[CmdletBinding(DefaultParameterSetName = 'Tui', SupportsShouldProcess = $true)]
param(
    [Parameter(ParameterSetName = 'List', Mandatory = $true)]
    [switch]$List,

    [Parameter(ParameterSetName = 'Add', Mandatory = $true)]
    [switch]$Add,

    [Parameter(ParameterSetName = 'Remove', Mandatory = $true)]
    [switch]$Remove,

    [Parameter(ParameterSetName = 'Repoint', Mandatory = $true)]
    [switch]$Repoint,

    [Parameter(ParameterSetName = 'Orphans', Mandatory = $true)]
    [switch]$RemoveOrphans,

    [Parameter(ParameterSetName = 'Add')]
    [Parameter(ParameterSetName = 'Remove')]
    [ValidateSet('v4tov4', 'v4tov6', 'v6tov4', 'v6tov6')]
    [string]$Type,

    [Parameter(ParameterSetName = 'Add')]
    [Parameter(ParameterSetName = 'Remove')]
    [string]$ListenAddress = '0.0.0.0',

    [Parameter(ParameterSetName = 'Add', Mandatory = $true)]
    [Parameter(ParameterSetName = 'Remove', Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$ListenPort,

    [Parameter(ParameterSetName = 'Add', Mandatory = $true)]
    [string]$ConnectAddress,

    [Parameter(ParameterSetName = 'Add')]
    [ValidateRange(1, 65535)]
    [int]$ConnectPort,

    [Parameter(ParameterSetName = 'Add')]
    [ValidateSet('TCP', 'None')]
    [string]$Firewall = 'TCP',

    [Parameter(ParameterSetName = 'Repoint', Mandatory = $true)]
    [string]$From,

    [Parameter(ParameterSetName = 'Repoint', Mandatory = $true)]
    [string]$To,

    [switch]$NoElevate,

    # Internal: set by the elevated child to relay its output to the unelevated parent.
    [Parameter(DontShow = $true)]
    [string]$ElevatedOutputFile
)

Set-StrictMode -Version Latest

# =====================================================================================================
#  Constants, theme and state
# =====================================================================================================

$script:Version         = '2.1.0'
$script:ProxyTypes      = @('v4tov4', 'v4tov6', 'v6tov4', 'v6tov6')
$script:RulePrefix      = 'PortRedirect_'
$script:RuleDescription = 'Created by PortRedirectManager for NAT port proxy'
$script:FirewallRegKey  = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
$script:NetshPath       = Join-Path $env:SystemRoot 'System32\netsh.exe'
$script:WslPath         = Join-Path $env:SystemRoot 'System32\wsl.exe'
$script:MaxPortsPerAdd  = 64
$script:SelfPath        = $PSCommandPath   # captured here: inside functions $PSCommandPath depends on the caller
$script:NoElevate       = [bool]$NoElevate  # script-scope copy so functions read the same value in library mode
$script:MinWidth        = 66
$script:MinHeight       = 18

$script:Theme = @{
    Title      = 'Cyan'
    Border     = 'DarkCyan'
    Header     = 'Cyan'
    Normal     = 'Gray'
    Dim        = 'DarkGray'
    Key        = 'Yellow'
    Selected   = 'Black'
    SelectedBg = 'White'
    Success    = 'Green'
    Error      = 'Red'
    Warning    = 'Yellow'
    Info       = 'Cyan'
    Input      = 'White'
    InputBg    = 'DarkBlue'
}

# ANSI SGR foreground code per ConsoleColor name (background = code + 10).
$script:AnsiColor = @{
    Black = 30; DarkRed = 31; DarkGreen = 32; DarkYellow = 33; DarkBlue = 34; DarkMagenta = 35; DarkCyan = 36; Gray = 37
    DarkGray = 90; Red = 91; Green = 92; Yellow = 93; Blue = 94; Magenta = 95; Cyan = 96; White = 97
}

$script:State = @{
    Rules       = @()
    Selected    = 0
    Scroll      = 0
    Message     = ''
    MessageType = 'Info'
    Running     = $true
    NeedsReload = $true
    WslIp       = $null
    WslChecked  = $false
    IpHelper    = 'Unknown'
    Orphans     = @()
    LastLoadMs  = 0
}

$script:Ui = @{
    UseVT     = $false
    Width     = 80
    Height    = 25
    Buffer    = New-Object System.Text.StringBuilder
    Cells     = New-Object System.Collections.Generic.List[object]
    DefaultBg = 'Black'
}

# =====================================================================================================
#  Pure helpers (no side effects; unit tested)
# =====================================================================================================

function Test-IPv4Address {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
    if ($Address -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return $false }
    $ip = $null
    return ([System.Net.IPAddress]::TryParse($Address, [ref]$ip) -and $ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork)
}

function Test-IPv6Address {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address) -or $Address -notmatch ':') { return $false }
    $ip = $null
    return ([System.Net.IPAddress]::TryParse($Address.Trim('[', ']'), [ref]$ip) -and $ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6)
}

function Get-AddressKind {
    <#
    .SYNOPSIS
        Classify an address as IPv4, IPv6 or Hostname; returns $null when it is none of them.
    #>
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return $null }
    $a = $Address.Trim()
    if (Test-IPv4Address $a) { return 'IPv4' }
    if (Test-IPv6Address $a) { return 'IPv6' }
    # Looks like a (broken) numeric literal: never accept it as a hostname ("3000", "256.1.1.1", "1.2").
    if ($a -match '^[\d.]+$' -or $a -match '[:\[\]]') { return $null }
    if ([uri]::CheckHostName($a) -eq [UriHostNameType]::Dns) { return 'Hostname' }
    return $null
}

function Test-AddressForRole {
    <#
    .SYNOPSIS
        Validate an address for the listen or connect side of a proxy type. Returns $null when valid,
        otherwise a human-readable error.
    #>
    param(
        [string]$Address,
        [string]$Type,
        [ValidateSet('Listen', 'Connect')][string]$Role
    )
    $kind = Get-AddressKind $Address
    if (-not $kind) { return "'$Address' is not a valid IP address or hostname" }
    if ($kind -eq 'Hostname') { return $null }
    $side = if ($Role -eq 'Listen') { $Type.Substring(0, 2) } else { $Type.Substring(4, 2) }
    $wanted = if ($side -eq 'v4') { 'IPv4' } else { 'IPv6' }
    if ($kind -ne $wanted) { return "$Role address must be $wanted for type $Type (got $kind '$Address')" }
    return $null
}

function Test-LoopbackAddress {
    param([string]$Address)
    $a = "$Address".Trim().Trim('[', ']')
    return ($a -match '^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$' -or $a -eq '::1' -or $a -ieq 'localhost')
}

function Test-WildcardAddress {
    param([string]$Address)
    $a = "$Address".Trim().Trim('[', ']')
    return ($a -eq '0.0.0.0' -or $a -eq '::')
}

function ConvertTo-PortList {
    <#
    .SYNOPSIS
        Parse "80", "80,443", "3000-3003" or a mix into a sorted list of unique ports. Throws on invalid input.
    #>
    param([string]$Text)
    $ports = New-Object System.Collections.Generic.List[int]
    foreach ($token in ("$Text" -split '[,;\s]+')) {
        $t = $token.Trim()
        if ($t.Length -eq 0) { continue }
        if ($t -match '^(\d{1,5})-(\d{1,5})$') {
            $from = [int]$Matches[1]
            $to = [int]$Matches[2]
            if (-not (Test-PortNumber $from) -or -not (Test-PortNumber $to) -or $from -gt $to) { throw "'$t' is not a valid port range (1-65535, low-high)" }
            for ($n = $from; $n -le $to; $n++) { if (-not $ports.Contains($n)) { $ports.Add($n) } }
        }
        elseif (Test-PortNumber $t) {
            $n = [int]$t
            if (-not $ports.Contains($n)) { $ports.Add($n) }
        }
        else {
            throw "'$t' is not a valid port (1-65535)"
        }
    }
    if ($ports.Count -eq 0) { throw 'No port given' }
    if ($ports.Count -gt $script:MaxPortsPerAdd) { throw "Too many ports ($($ports.Count)); the limit is $($script:MaxPortsPerAdd) per operation" }
    $ports.Sort()
    return $ports.ToArray()
}

function ConvertFrom-FirewallRuleName {
    <#
    .SYNOPSIS
        Split "PortRedirect_<addr>_<port>_<proto>" into its parts; $null when the name does not match.
    #>
    param([string]$Name)
    if ("$Name" -match "^$([regex]::Escape($script:RulePrefix))(.+)_(\d{1,5})_(TCP|UDP)$") {
        return [pscustomobject]@{ Name = $Name; ListenAddress = $Matches[1]; ListenPort = [int]$Matches[2]; Protocol = $Matches[3] }
    }
    return $null
}

function Get-OrphanFirewallRule {
    <#
    .SYNOPSIS
        PortRedirect_* firewall rules whose listen endpoint has no port-proxy rule any more.
    #>
    param([object[]]$Rules, [hashtable]$Table)
    $endpoints = @{}
    foreach ($r in @($Rules)) { $endpoints["$($r.ListenAddress)_$($r.ListenPort)"] = $true }
    $orphans = @()
    foreach ($name in @($Table.Keys | Sort-Object)) {
        $parsed = ConvertFrom-FirewallRuleName -Name $name
        if ($null -eq $parsed) { continue }
        if (-not $endpoints.ContainsKey("$($parsed.ListenAddress)_$($parsed.ListenPort)")) { $orphans += $parsed }
    }
    return $orphans
}

function Test-PortNumber {
    param([string]$Text)
    $n = 0
    if (-not [int]::TryParse("$Text".Trim(), [ref]$n)) { return $false }
    return ($n -ge 1 -and $n -le 65535)
}

function Format-Endpoint {
    param([string]$Address, [int]$Port)
    if ($Address -match ':') { return "[$Address]:$Port" }
    return "$Address`:$Port"
}

function Limit-Text {
    param([string]$Text, [int]$Width)
    if ($null -eq $Text) { $Text = '' }
    if ($Width -le 0) { return '' }
    if ($Text.Length -le $Width) { return $Text }
    if ($Width -eq 1) { return '~' }
    return $Text.Substring(0, $Width - 1) + '~'
}

function Get-FirewallRuleName {
    param([string]$ListenAddress, [int]$ListenPort, [string]$Protocol = 'TCP')
    return "$($script:RulePrefix)$($ListenAddress)_$($ListenPort)_$($Protocol.ToUpper())"
}

function New-PortProxyRuleObject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory object only')]
    [OutputType('PortRedirectManager.Rule')]
    param(
        [string]$Type,
        [string]$ListenAddress,
        [int]$ListenPort,
        [string]$ConnectAddress,
        [int]$ConnectPort,
        [string]$Firewall = '-'
    )
    $rule = [pscustomobject]@{
        PSTypeName     = 'PortRedirectManager.Rule'
        Type           = $Type
        ListenAddress  = $ListenAddress
        ListenPort     = $ListenPort
        ConnectAddress = $ConnectAddress
        ConnectPort    = $ConnectPort
        Firewall       = $Firewall
    }
    # Plain values (not script properties): they must keep working after the script scope is gone.
    $rule | Add-Member -MemberType NoteProperty -Name Listen -Value (Format-Endpoint -Address $ListenAddress -Port $ListenPort)
    $rule | Add-Member -MemberType NoteProperty -Name Connect -Value (Format-Endpoint -Address $ConnectAddress -Port $ConnectPort)
    $display = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet', [string[]]@('Type', 'Listen', 'Connect', 'Firewall'))
    $rule | Add-Member -MemberType MemberSet -Name PSStandardMembers -Value ([System.Management.Automation.PSMemberInfo[]]@($display))
    return $rule
}

function ConvertFrom-PortProxyOutput {
    <#
    .SYNOPSIS
        Parse the text of "netsh interface portproxy show all" into rule objects.
    .DESCRIPTION
        Locale independent: the section headers are recognised by the two "ipv4"/"ipv6" tokens they contain
        ("Listen on ipv4:   Connect to ipv4:" in English, "Escuchar en ipv4: Conectar a ipv4:" in Spanish...).
        Data rows are "<address> <port> <address> <port>".
    #>
    param([string[]]$Lines)
    $type = $null
    foreach ($raw in @($Lines)) {
        if ($null -eq $raw) { continue }
        $line = ([string]$raw).Replace("`r", '').Trim()
        if ($line.Length -eq 0) { continue }
        if ($null -ne $type -and $line -match '^(\S+)\s+(\d+)\s+(\S+)\s+(\d+)$') {
            New-PortProxyRuleObject -Type $type -ListenAddress $Matches[1] -ListenPort ([int]$Matches[2]) -ConnectAddress $Matches[3] -ConnectPort ([int]$Matches[4])
            continue
        }
        if ($line -match '(?i)ipv([46])\b.*ipv([46])\b') {
            $type = "v$($Matches[1])tov$($Matches[2])"
        }
    }
}

function ConvertFrom-FirewallRuleValue {
    <#
    .SYNOPSIS
        Parse one value of the FirewallRules registry key
        ("v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3000|Name=...|Desc=...|").
    #>
    param([string]$Name, [string]$Value)
    $fields = @{}
    foreach ($part in "$Value".Split('|')) {
        $i = $part.IndexOf('=')
        if ($i -gt 0) { $fields[$part.Substring(0, $i)] = $part.Substring($i + 1) }
    }
    $protocol = switch ("$($fields['Protocol'])") {
        '6'     { 'TCP' }
        '17'    { 'UDP' }
        default { "$($fields['Protocol'])" }
    }
    return [pscustomobject]@{
        Name        = $Name
        Enabled     = ("$($fields['Active'])" -eq 'TRUE')
        Protocol    = $protocol
        LocalPort   = "$($fields['LPort'])"
        DisplayName = "$($fields['Name'])"
        Direction   = "$($fields['Dir'])"
    }
}

function Get-FirewallStatusText {
    <#
    .SYNOPSIS
        T/U = enabled TCP/UDP rule, t/u = rule present but disabled, - = no rule.
    #>
    param([hashtable]$Table, [string]$ListenAddress, [int]$ListenPort)
    $status = ''
    foreach ($proto in @('TCP', 'UDP')) {
        $name = Get-FirewallRuleName -ListenAddress $ListenAddress -ListenPort $ListenPort -Protocol $proto
        if ($Table.ContainsKey($name)) {
            $letter = $proto.Substring(0, 1)
            $status += $(if ($Table[$name].Enabled) { $letter } else { $letter.ToLower() })
        }
    }
    if ($status.Length -eq 0) { return '-' }
    return $status
}

function Get-ColumnLayout {
    param([int]$Width)
    $typeW = 7
    $fwW = 3
    $listenW = 22
    # marker(1) + gaps: type, 2, listen, 2, connect, 2, fw, trailing 1
    $connectW = $Width - (1 + $typeW + 2 + $listenW + 2 + 2 + $fwW + 1)
    if ($connectW -lt 14) {
        $listenW = [math]::Max(14, $listenW + $connectW - 14)
        $connectW = 14
    }
    return @{
        TypeX = 1; TypeW = $typeW
        ListenX = 1 + $typeW + 2; ListenW = $listenW
        ConnectX = 1 + $typeW + 2 + $listenW + 2; ConnectW = $connectW
        FwX = 1 + $typeW + 2 + $listenW + 2 + $connectW + 2; FwW = $fwW
    }
}

function Format-RuleRow {
    param($Rule, [hashtable]$Layout)
    $type = (Limit-Text $Rule.Type $Layout.TypeW).PadRight($Layout.TypeW)
    $listen = (Limit-Text (Format-Endpoint -Address $Rule.ListenAddress -Port $Rule.ListenPort) $Layout.ListenW).PadRight($Layout.ListenW)
    $connect = (Limit-Text (Format-Endpoint -Address $Rule.ConnectAddress -Port $Rule.ConnectPort) $Layout.ConnectW).PadRight($Layout.ConnectW)
    $fw = (Limit-Text $Rule.Firewall $Layout.FwW).PadRight($Layout.FwW)
    return "$type  $listen  $connect  $fw"
}

# =====================================================================================================
#  System access layer (netsh, firewall, WSL, services)
# =====================================================================================================

function Test-IsElevated {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        return ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        Write-Verbose "Elevation check failed: $_"
        return $false
    }
}

function Invoke-Netsh {
    <#
    .SYNOPSIS
        Run "netsh interface portproxy <arguments>" with an argument array (no string building, no
        Invoke-Expression) and return Success/ExitCode/Output.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [switch]$ExpectNoOutput   # add/set/delete print nothing on success, and netsh may exit 0 on failure
    )
    $ErrorActionPreference = 'Continue'   # stderr from a native command must not throw under -ErrorAction Stop
    $lines = @(& $script:NetshPath interface portproxy @Arguments 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = $LASTEXITCODE
    $text = (@($lines | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 }) -join ' ')
    $success = ($exitCode -eq 0)
    if ($ExpectNoOutput -and $text.Length -gt 0) { $success = $false }
    return [pscustomobject]@{
        Success  = $success
        ExitCode = $exitCode
        Output   = $text
        Lines    = $lines
    }
}

function Find-PortProxyRuleInTable {
    <#
    .SYNOPSIS
        Re-read one proxy table from netsh and return the rule for a listen endpoint, or $null.
    #>
    param([string]$Type, [string]$ListenAddress, [int]$ListenPort)
    $result = Invoke-Netsh -Arguments @('show', $Type)
    if (-not $result.Success) { return $null }
    foreach ($rule in @(ConvertFrom-PortProxyOutput -Lines $result.Lines)) {
        if ($rule.ListenPort -eq $ListenPort -and $rule.ListenAddress -eq $ListenAddress) { return $rule }
    }
    return $null
}

function Get-NetshFailureResult {
    param([string]$Message)
    return [pscustomobject]@{ Success = $false; ExitCode = -1; Output = $Message; Lines = @() }
}

function Get-PortRedirectFirewallTable {
    <#
    .SYNOPSIS
        Return a hashtable RuleName -> firewall rule info for every PortRedirect_* rule.
    .DESCRIPTION
        Reads the local firewall policy from the registry, which takes a few tens of milliseconds, instead
        of Get-NetFirewallRule, which takes well over a second. Falls back to the cmdlet if the registry
        is unreadable.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    $table = @{}
    try {
        $props = Get-ItemProperty -Path $script:FirewallRegKey -ErrorAction Stop
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like "$($script:RulePrefix)*") {
                $table[$p.Name] = ConvertFrom-FirewallRuleValue -Name $p.Name -Value ([string]$p.Value)
            }
        }
        return $table
    }
    catch {
        Write-Verbose "Firewall registry read failed ($_); falling back to Get-NetFirewallRule"
    }
    try {
        foreach ($r in @(Get-NetFirewallRule -Name "$($script:RulePrefix)*" -ErrorAction SilentlyContinue)) {
            $table[$r.Name] = [pscustomobject]@{
                Name        = $r.Name
                Enabled     = ("$($r.Enabled)" -eq 'True')
                Protocol    = $null
                LocalPort   = $null
                DisplayName = $r.DisplayName
                Direction   = "$($r.Direction)"
            }
        }
    }
    catch {
        Write-Verbose "Get-NetFirewallRule failed: $_"
    }
    return $table
}

function Get-PortProxyRule {
    <#
    .SYNOPSIS
        Read all port-proxy rules and annotate each with its firewall status.
    #>
    [CmdletBinding()]
    [OutputType('PortRedirectManager.Rule', [object[]])]
    param()
    $result = Invoke-Netsh -Arguments @('show', 'all')
    if (-not $result.Success) {
        throw "netsh interface portproxy show all failed (exit $($result.ExitCode)): $($result.Output)"
    }
    $rules = @(ConvertFrom-PortProxyOutput -Lines $result.Lines | Sort-Object -Property Type, ListenAddress, ListenPort)
    if ($rules.Count -gt 0) {
        $fw = Get-PortRedirectFirewallTable
        foreach ($rule in $rules) {
            $rule.Firewall = Get-FirewallStatusText -Table $fw -ListenAddress $rule.ListenAddress -ListenPort $rule.ListenPort
        }
    }
    return $rules
}

function Add-PortProxyRule {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$Type = 'v4tov4',
        [Parameter(Mandatory = $true)][string]$ListenAddress,
        [Parameter(Mandatory = $true)][int]$ListenPort,
        [Parameter(Mandatory = $true)][string]$ConnectAddress,
        [Parameter(Mandatory = $true)][int]$ConnectPort
    )
    $target = "$Type $(Format-Endpoint $ListenAddress $ListenPort) -> $(Format-Endpoint $ConnectAddress $ConnectPort)"
    if (-not $PSCmdlet.ShouldProcess($target, 'Add port-proxy rule')) {
        return [pscustomobject]@{ Success = $true; ExitCode = 0; Output = 'skipped (WhatIf)'; Lines = @() }
    }
    $result = Invoke-Netsh -ExpectNoOutput -Arguments @('add', $Type, "listenaddress=$ListenAddress", "listenport=$ListenPort", "connectaddress=$ConnectAddress", "connectport=$ConnectPort")
    if (-not $result.Success) { return $result }
    $stored = Find-PortProxyRuleInTable -Type $Type -ListenAddress $ListenAddress -ListenPort $ListenPort
    if ($null -eq $stored -or $stored.ConnectAddress -ne $ConnectAddress -or $stored.ConnectPort -ne $ConnectPort) {
        return Get-NetshFailureResult 'netsh reported no error but the rule is not in the table'
    }
    return $result
}

function Set-PortProxyRule {
    <#
    .SYNOPSIS
        Update the target of an existing rule in place (netsh "set"), so a failure never loses the rule.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$Type = 'v4tov4',
        [Parameter(Mandatory = $true)][string]$ListenAddress,
        [Parameter(Mandatory = $true)][int]$ListenPort,
        [Parameter(Mandatory = $true)][string]$ConnectAddress,
        [Parameter(Mandatory = $true)][int]$ConnectPort
    )
    $target = "$Type $(Format-Endpoint $ListenAddress $ListenPort) -> $(Format-Endpoint $ConnectAddress $ConnectPort)"
    if (-not $PSCmdlet.ShouldProcess($target, 'Update port-proxy rule')) {
        return [pscustomobject]@{ Success = $true; ExitCode = 0; Output = 'skipped (WhatIf)'; Lines = @() }
    }
    $result = Invoke-Netsh -ExpectNoOutput -Arguments @('set', $Type, "listenaddress=$ListenAddress", "listenport=$ListenPort", "connectaddress=$ConnectAddress", "connectport=$ConnectPort")
    if (-not $result.Success) { return $result }
    $stored = Find-PortProxyRuleInTable -Type $Type -ListenAddress $ListenAddress -ListenPort $ListenPort
    if ($null -eq $stored -or $stored.ConnectAddress -ne $ConnectAddress -or $stored.ConnectPort -ne $ConnectPort) {
        return Get-NetshFailureResult 'netsh reported no error but the rule was not updated'
    }
    return $result
}

function Remove-PortProxyRule {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$Type = 'v4tov4',
        [Parameter(Mandatory = $true)][string]$ListenAddress,
        [Parameter(Mandatory = $true)][int]$ListenPort
    )
    $target = "$Type $(Format-Endpoint $ListenAddress $ListenPort)"
    if (-not $PSCmdlet.ShouldProcess($target, 'Delete port-proxy rule')) {
        return [pscustomobject]@{ Success = $true; ExitCode = 0; Output = 'skipped (WhatIf)'; Lines = @() }
    }
    $result = Invoke-Netsh -ExpectNoOutput -Arguments @('delete', $Type, "listenaddress=$ListenAddress", "listenport=$ListenPort")
    if (-not $result.Success) { return $result }
    if ($null -ne (Find-PortProxyRuleInTable -Type $Type -ListenAddress $ListenAddress -ListenPort $ListenPort)) {
        return Get-NetshFailureResult 'netsh reported no error but the rule is still in the table'
    }
    return $result
}

function Add-PortRedirectFirewallRule {
    <#
    .SYNOPSIS
        Create inbound allow rule(s) for a listen port. Protocol: TCP, UDP or Both.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$ListenAddress,
        [Parameter(Mandatory = $true)][int]$ListenPort,
        [ValidateSet('TCP', 'UDP', 'Both')][string]$Protocol = 'TCP'
    )
    if (Test-LoopbackAddress $ListenAddress) {
        return [pscustomobject]@{ Success = $true; Message = 'loopback listener, no firewall rule needed' }
    }
    $protocols = if ($Protocol -eq 'Both') { @('TCP', 'UDP') } else { @($Protocol) }
    $existing = Get-PortRedirectFirewallTable
    $success = $true
    $messages = @()
    foreach ($proto in $protocols) {
        $name = Get-FirewallRuleName -ListenAddress $ListenAddress -ListenPort $ListenPort -Protocol $proto
        if ($existing.ContainsKey($name)) {
            $messages += "$proto rule already exists"
            continue
        }
        if (-not $PSCmdlet.ShouldProcess($name, 'Create inbound firewall rule')) {
            $messages += "$proto rule skipped (WhatIf)"
            continue
        }
        try {
            $params = @{
                Name        = $name
                DisplayName = "Port Redirect: $(Format-Endpoint $ListenAddress $ListenPort) ($proto)"
                Description = $script:RuleDescription
                Direction   = 'Inbound'
                Action      = 'Allow'
                Protocol    = $proto
                LocalPort   = $ListenPort
                Profile     = 'Any'
                Enabled     = 'True'
                ErrorAction = 'Stop'
            }
            # A rule for a specific listen address only needs to allow traffic to that address.
            if (-not (Test-WildcardAddress $ListenAddress)) { $params['LocalAddress'] = $ListenAddress }
            $null = New-NetFirewallRule @params
            $messages += "$proto rule created"
        }
        catch {
            $success = $false
            $messages += "$proto rule failed: $($_.Exception.Message)"
        }
    }
    return [pscustomobject]@{ Success = $success; Message = ($messages -join '; ') }
}

function Remove-PortRedirectFirewallRule {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$ListenAddress,
        [Parameter(Mandatory = $true)][int]$ListenPort,
        [ValidateSet('TCP', 'UDP', 'Both')][string]$Protocol = 'Both'
    )
    $protocols = if ($Protocol -eq 'Both') { @('TCP', 'UDP') } else { @($Protocol) }
    $existing = Get-PortRedirectFirewallTable
    $success = $true
    $messages = @()
    foreach ($proto in $protocols) {
        $name = Get-FirewallRuleName -ListenAddress $ListenAddress -ListenPort $ListenPort -Protocol $proto
        if (-not $existing.ContainsKey($name)) {
            $messages += "$proto rule not present"
            continue
        }
        if (-not $PSCmdlet.ShouldProcess($name, 'Remove firewall rule')) {
            $messages += "$proto rule skipped (WhatIf)"
            continue
        }
        try {
            Remove-NetFirewallRule -Name $name -ErrorAction Stop
            $messages += "$proto rule removed"
        }
        catch {
            $success = $false
            $messages += "$proto rule failed: $($_.Exception.Message)"
        }
    }
    return [pscustomobject]@{ Success = $success; Message = ($messages -join '; ') }
}

function Remove-OrphanFirewallRule {
    <#
    .SYNOPSIS
        Delete PortRedirect_* firewall rules that have no port-proxy rule. Returns @{ Removed; Failed; Names }.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([object[]]$Orphans)
    $removed = 0
    $failed = @()
    foreach ($o in @($Orphans)) {
        if (-not $PSCmdlet.ShouldProcess($o.Name, 'Remove orphaned firewall rule')) { continue }
        try {
            Remove-NetFirewallRule -Name $o.Name -ErrorAction Stop
            $removed++
        }
        catch {
            $failed += "$($o.Name): $($_.Exception.Message)"
        }
    }
    return [pscustomobject]@{ Removed = $removed; Failed = $failed }
}

function Invoke-WslCommand {
    <#
    .SYNOPSIS
        Run wsl.exe and return its output lines. wsl.exe prints its own messages as UTF-16, which shows up
        as interleaved NULs when captured; they are stripped here.
    #>
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $ErrorActionPreference = 'Continue'
    return @(& $script:WslPath @Arguments 2>$null | ForEach-Object { ([string]$_) -replace "`0", '' })
}

function Test-WslRunning {
    try {
        $out = Invoke-WslCommand -Arguments @('-l', '--running', '-q')
        return [bool](@($out | Where-Object { ("$_" -replace "`0", '').Trim().Length -gt 0 }).Count -gt 0)
    }
    catch {
        Write-Verbose "wsl.exe not available: $_"
        return $false
    }
}

function Get-WslIPAddress {
    <#
    .SYNOPSIS
        First IPv4 address of the running WSL2 distribution (cached; -Refresh re-queries).
        Never starts a stopped distribution.
    #>
    [CmdletBinding()]
    param([switch]$Refresh)
    if ($script:State.WslChecked -and -not $Refresh) { return $script:State.WslIp }
    $script:State.WslChecked = $true
    $script:State.WslIp = $null
    try {
        if (-not (Test-WslRunning)) { return $null }
        $out = Invoke-WslCommand -Arguments @('--exec', 'hostname', '-I')   # --exec: no login shell, no profile scripts
        $tokens = @((($out -join ' ') -split '\s+') | Where-Object { $_.Length -gt 0 })
        $script:State.WslIp = @($tokens | Where-Object { Test-IPv4Address $_ } | Select-Object -First 1)[0]
    }
    catch {
        Write-Verbose "WSL IP detection failed: $_"
    }
    return $script:State.WslIp
}

function Get-IpHelperStatus {
    try { return [string](Get-Service -Name iphlpsvc -ErrorAction Stop).Status }
    catch { return 'Unknown' }
}

function Start-IpHelperService {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([switch]$Restart)
    $action = if ($Restart) { 'Restart service' } else { 'Start service' }
    if ($PSCmdlet.ShouldProcess('iphlpsvc (IP Helper)', $action)) {
        if ($Restart) { Restart-Service -Name iphlpsvc -Force -ErrorAction Stop }
        else { Start-Service -Name iphlpsvc -ErrorAction Stop }
    }
}

function Resolve-TargetAddress {
    <#
    .SYNOPSIS
        Expand the "wsl" keyword to the current WSL2 IP; otherwise return the trimmed address.
    #>
    param([string]$Address)
    $a = "$Address".Trim()
    if ($a -match '^(?i)wsl2?$') {
        $ip = Get-WslIPAddress -Refresh
        if (-not $ip) { throw 'Could not detect the WSL2 IP address. Is a WSL2 distribution running?' }
        return $ip
    }
    return $a.Trim('[', ']')
}

# =====================================================================================================
#  Console access layer (the only functions that touch the console; mocked in tests)
# =====================================================================================================

function Get-ConsoleSize {
    try { return @{ Width = [Console]::WindowWidth; Height = [Console]::WindowHeight } }
    catch { return @{ Width = 80; Height = 25 } }
}

function Test-VirtualTerminalSupport {
    if ($env:PRM_NO_VT) { return $false }
    try { return [bool]$Host.UI.SupportsVirtualTerminal }
    catch { return $false }
}

function Write-ConsoleRaw {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'TUI renderer: the console is the product')]
    param([string]$Text)
    [Console]::Write($Text)
}

function Read-TuiKey {
    return [Console]::ReadKey($true)
}

function Test-KeyAvailable {
    try { return [Console]::KeyAvailable }
    catch { return $true }
}

function Clear-Console {
    try { [Console]::Clear() }
    catch { Write-Verbose "Console clear failed: $_" }
}

function Set-CursorVisible {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Console cursor only')]
    param([bool]$Visible)
    if ($script:Ui.UseVT) {
        Write-ConsoleRaw $(if ($Visible) { "$([char]27)[?25h" } else { "$([char]27)[?25l" })
        return
    }
    try { [Console]::CursorVisible = $Visible }
    catch { Write-Verbose "Cursor visibility not supported: $_" }
}

function Set-CursorPosition {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Console cursor only')]
    param([int]$X, [int]$Y)
    if ($script:Ui.UseVT) {
        Write-ConsoleRaw ("$([char]27)[{0};{1}H" -f ($Y + 1), ($X + 1))
        return
    }
    try { [Console]::SetCursorPosition($X, $Y) }
    catch { Write-Verbose "SetCursorPosition failed: $_" }
}

# =====================================================================================================
#  Frame renderer: every screen is composed off-screen and written in one go (no flicker)
# =====================================================================================================

function Initialize-Frame {
    $size = Get-ConsoleSize
    $script:Ui.Width = [int]$size.Width
    $script:Ui.Height = [int]$size.Height
    if ($script:Ui.UseVT) {
        $null = $script:Ui.Buffer.Clear()
        $esc = [char]27
        for ($y = 0; $y -lt $script:Ui.Height - 1; $y++) {
            $null = $script:Ui.Buffer.Append($esc).Append('[').Append($y + 1).Append(';1H').Append($esc).Append('[0m').Append($esc).Append('[2K')
        }
    }
    else {
        $script:Ui.Cells.Clear()
        $blank = ' ' * $script:Ui.Width
        for ($y = 0; $y -lt $script:Ui.Height - 1; $y++) {
            $script:Ui.Cells.Add(@{ X = 0; Y = $y; Text = $blank; Fg = $script:Theme.Normal; Bg = '' })
        }
    }
}

function Write-At {
    <#
    .SYNOPSIS
        Queue text at (X, Y) for the current frame. Text is clipped to the window; the last row is never
        used because writing its last cell scrolls the console.
    #>
    param(
        [int]$X,
        [int]$Y,
        [string]$Text,
        [string]$Fg = 'Gray',
        [string]$Bg = ''
    )
    if ([string]::IsNullOrEmpty($Text)) { return }
    $w = $script:Ui.Width
    $h = $script:Ui.Height
    if ($Y -lt 0 -or $Y -ge $h - 1 -or $X -ge $w) { return }
    if ($X -lt 0) {
        if (-$X -ge $Text.Length) { return }
        $Text = $Text.Substring(-$X)
        $X = 0
    }
    if ($X + $Text.Length -gt $w) { $Text = $Text.Substring(0, $w - $X) }
    if ($script:Ui.UseVT) {
        $fgCode = if ($script:AnsiColor.ContainsKey($Fg)) { $script:AnsiColor[$Fg] } else { 39 }
        $bgCode = if ($Bg -and $script:AnsiColor.ContainsKey($Bg)) { $script:AnsiColor[$Bg] + 10 } else { 49 }
        $esc = [char]27
        $null = $script:Ui.Buffer.Append($esc).Append('[').Append($Y + 1).Append(';').Append($X + 1).Append('H')
        $null = $script:Ui.Buffer.Append($esc).Append('[').Append($fgCode).Append(';').Append($bgCode).Append('m').Append($Text)
    }
    else {
        $script:Ui.Cells.Add(@{ X = $X; Y = $Y; Text = $Text; Fg = $Fg; Bg = $Bg })
    }
}

function Show-Frame {
    if ($script:Ui.UseVT) {
        $null = $script:Ui.Buffer.Append([char]27).Append('[0m')
        Write-ConsoleRaw $script:Ui.Buffer.ToString()
        return
    }
    foreach ($cell in $script:Ui.Cells) {
        try {
            [Console]::SetCursorPosition($cell.X, $cell.Y)
            $bg = if ($cell.Bg) { $cell.Bg } else { $script:Ui.DefaultBg }
            $Host.UI.Write([ConsoleColor]$cell.Fg, [ConsoleColor]$bg, $cell.Text)
        }
        catch {
            Write-Verbose "Cell write failed at $($cell.X),$($cell.Y): $_"
        }
    }
}

function Write-Box {
    param(
        [int]$X,
        [int]$Y,
        [int]$Width,
        [int]$Height,
        [string]$Title = '',
        [string]$Color = $script:Theme.Border
    )
    if ($Width -lt 2 -or $Height -lt 2) { return }
    $h = [string][char]0x2500
    $v = [string][char]0x2502
    $top = [string][char]0x250C + ($h * ($Width - 2)) + [string][char]0x2510
    $bottom = [string][char]0x2514 + ($h * ($Width - 2)) + [string][char]0x2518
    $middle = $v + (' ' * ($Width - 2)) + $v
    Write-At -X $X -Y $Y -Text $top -Fg $Color
    for ($i = 1; $i -lt $Height - 1; $i++) {
        Write-At -X $X -Y ($Y + $i) -Text $middle -Fg $Color
    }
    Write-At -X $X -Y ($Y + $Height - 1) -Text $bottom -Fg $Color
    if ($Title) {
        $t = " $Title "
        $tx = $X + [math]::Max(1, [math]::Floor(($Width - $t.Length) / 2))
        Write-At -X $tx -Y $Y -Text $t -Fg $script:Theme.Title
    }
}

function Write-Centered {
    param([int]$Y, [string]$Text, [string]$Fg = 'Gray', [string]$Bg = '')
    $x = [math]::Max(0, [math]::Floor(($script:Ui.Width - $Text.Length) / 2))
    Write-At -X $x -Y $Y -Text $Text -Fg $Fg -Bg $Bg
}

function Set-Message {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'UI state only')]
    param([string]$Text, [ValidateSet('Info', 'Success', 'Error', 'Warning')][string]$Type = 'Info')
    $script:State.Message = $Text
    $script:State.MessageType = $Type
}

function Get-MessageColor {
    switch ($script:State.MessageType) {
        'Success' { return $script:Theme.Success }
        'Error'   { return $script:Theme.Error }
        'Warning' { return $script:Theme.Warning }
        default   { return $script:Theme.Info }
    }
}

# =====================================================================================================
#  Input widgets
# =====================================================================================================

function Test-CancelKey {
    param([ConsoleKeyInfo]$Key)
    if ($Key.Key -eq [ConsoleKey]::Escape) { return $true }
    if ($Key.Key -eq [ConsoleKey]::C -and (($Key.Modifiers -band [ConsoleModifiers]::Control) -ne 0)) { return $true }
    return $false
}

function Write-DialogFrame {
    <#
    .SYNOPSIS
        Backdrop for wizard steps: a box with the answers collected so far, a prompt and an error line.
        $Dialog: @{ X; Y; W; H; Title; Answers (ordered); Prompt; Error }
    #>
    param([hashtable]$Dialog)
    Write-Box -X $Dialog.X -Y $Dialog.Y -Width $Dialog.W -Height $Dialog.H -Title $Dialog.Title
    $row = $Dialog.Y + 2
    foreach ($key in @($Dialog.Answers.Keys)) {
        $label = "$key`:"
        Write-At -X ($Dialog.X + 2) -Y $row -Text ("{0,-17} {1}" -f $label, (Limit-Text "$($Dialog.Answers[$key])" ($Dialog.W - 22))) -Fg $script:Theme.Success
        $row++
    }
    if ($Dialog.Prompt) {
        Write-At -X ($Dialog.X + 2) -Y ($row + 1) -Text (Limit-Text $Dialog.Prompt ($Dialog.W - 4)) -Fg $script:Theme.Header
    }
    if ($Dialog.Error) {
        Write-At -X ($Dialog.X + 2) -Y ($Dialog.Y + $Dialog.H - 2) -Text (Limit-Text $Dialog.Error ($Dialog.W - 4)) -Fg $script:Theme.Error
    }
    Write-At -X ($Dialog.X + 2) -Y ($Dialog.Y + $Dialog.H - 3) -Text 'Up/Down move  Enter select  Esc cancel' -Fg $script:Theme.Dim
}

function Initialize-Dialog {
    param([string]$Title, [int]$Width = 64, [int]$Height = 17)
    $w = [math]::Min($Width, [math]::Max(20, $script:Ui.Width - 2))
    $x = [math]::Max(0, [math]::Floor(($script:Ui.Width - $w) / 2))
    return @{
        X       = [int]$x
        Y       = 1
        W       = [int]$w
        H       = $Height
        Title   = $Title
        Answers = [ordered]@{}
        Prompt  = ''
        Error   = ''
    }
}

function Get-DialogStepY {
    param([hashtable]$Dialog)
    return $Dialog.Y + 2 + $Dialog.Answers.Count + 3
}

function Show-Menu {
    <#
    .SYNOPSIS
        Vertical selection menu. Returns the selected index, or $null when cancelled.
    #>
    param(
        [string]$Title,
        [string[]]$Options,
        [int]$X,
        [int]$Y,
        [int]$Default = 0,
        [scriptblock]$Backdrop,
        $Context
    )
    if (-not $Options -or $Options.Count -eq 0) { return $null }
    $idx = [math]::Max(0, [math]::Min($Default, $Options.Count - 1))
    $longest = ($Options | Measure-Object -Property Length -Maximum).Maximum
    $w = [math]::Max($longest + 6, $Title.Length + 6)
    $w = [math]::Min($w, [math]::Max(10, $script:Ui.Width - $X - 1))
    $h = $Options.Count + 2
    while ($true) {
        Initialize-Frame
        if ($Backdrop) { & $Backdrop $Context }
        Write-Box -X $X -Y $Y -Width $w -Height $h -Title $Title
        for ($i = 0; $i -lt $Options.Count; $i++) {
            $selected = ($i -eq $idx)
            $prefix = if ($selected) { '> ' } else { '  ' }
            $text = ($prefix + $Options[$i]).PadRight($w - 2)
            if ($selected) {
                Write-At -X ($X + 1) -Y ($Y + 1 + $i) -Text $text -Fg $script:Theme.Selected -Bg $script:Theme.SelectedBg
            }
            else {
                Write-At -X ($X + 1) -Y ($Y + 1 + $i) -Text $text -Fg $script:Theme.Normal
            }
        }
        Show-Frame
        $key = Read-TuiKey
        if (Test-CancelKey $key) { return $null }
        switch ($key.Key) {
            'UpArrow'   { $idx = if ($idx -gt 0) { $idx - 1 } else { $Options.Count - 1 } }
            'DownArrow' { $idx = if ($idx -lt $Options.Count - 1) { $idx + 1 } else { 0 } }
            'Home'      { $idx = 0 }
            'End'       { $idx = $Options.Count - 1 }
            'Enter'     { return $idx }
            default {
                if ("$($key.KeyChar)" -match '^[1-9]$') {
                    $n = [int]"$($key.KeyChar)" - 1
                    if ($n -lt $Options.Count) { return $n }
                }
            }
        }
    }
}

function Read-TuiLine {
    <#
    .SYNOPSIS
        Single-line text input with Backspace, Enter (accept) and Esc (cancel -> $null).
    #>
    param(
        [int]$X,
        [int]$Y,
        [int]$Width = 30,
        [string]$Label = '',
        [string]$Default = '',
        [scriptblock]$Backdrop,
        $Context
    )
    $text = "$Default"
    $pristine = ($text.Length -gt 0)   # a pre-filled default is replaced by the first keystroke
    $fieldX = if ($Label) { $X + $Label.Length + 1 } else { $X }
    $Width = [math]::Max(4, [math]::Min($Width, $script:Ui.Width - $fieldX - 1))
    while ($true) {
        Initialize-Frame
        if ($Backdrop) { & $Backdrop $Context }
        if ($Label) { Write-At -X $X -Y $Y -Text $Label -Fg $script:Theme.Header }
        $shown = $text
        if ($shown.Length -gt $Width - 1) { $shown = $shown.Substring($shown.Length - ($Width - 1)) }
        Write-At -X $fieldX -Y $Y -Text $shown.PadRight($Width) -Fg $script:Theme.Input -Bg $script:Theme.InputBg
        Show-Frame
        Set-CursorPosition -X ($fieldX + $shown.Length) -Y $Y
        Set-CursorVisible $true
        $key = Read-TuiKey
        Set-CursorVisible $false
        if (Test-CancelKey $key) { return $null }
        switch ($key.Key) {
            'Enter'     { return $text.Trim() }
            'Backspace' {
                if ($pristine) { $text = '' }
                elseif ($text.Length -gt 0) { $text = $text.Substring(0, $text.Length - 1) }
            }
            default {
                $c = $key.KeyChar
                if ($c -and -not [char]::IsControl($c) -and $text.Length -lt 253) {
                    if ($pristine) { $text = '' }
                    $text += $c
                }
            }
        }
        $pristine = $false
    }
}

function Show-Confirm {
    <#
    .SYNOPSIS
        Yes/No question. Returns $true for Y, $false for N/Esc.
    #>
    param(
        [string]$Title,
        [string[]]$Lines,
        [scriptblock]$Backdrop,
        $Context,
        [string]$Question = 'Proceed?  [Y]es / [N]o'
    )
    $longest = [math]::Max(($Lines | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum, $Question.Length)
    $w = [math]::Min([math]::Max(40, $longest + 6), [math]::Max(20, $script:Ui.Width - 2))
    $h = $Lines.Count + 5
    $x = [math]::Max(0, [math]::Floor(($script:Ui.Width - $w) / 2))
    $y = [math]::Max(1, [math]::Floor(($script:Ui.Height - $h) / 2))
    while ($true) {
        Initialize-Frame
        if ($Backdrop) { & $Backdrop $Context }
        Write-Box -X $x -Y $y -Width $w -Height $h -Title $Title
        for ($i = 0; $i -lt $Lines.Count; $i++) {
            Write-At -X ($x + 2) -Y ($y + 2 + $i) -Text (Limit-Text $Lines[$i] ($w - 4)) -Fg $script:Theme.Normal
        }
        Write-At -X ($x + 2) -Y ($y + $h - 2) -Text $Question -Fg $script:Theme.Key
        Show-Frame
        $key = Read-TuiKey
        if (Test-CancelKey $key) { return $false }
        if ($key.Key -eq [ConsoleKey]::Y) { return $true }
        if ($key.Key -eq [ConsoleKey]::N) { return $false }
    }
}

function Show-Notice {
    <#
    .SYNOPSIS
        Full-screen text page (help, errors); waits for a key.
    #>
    param([string]$Title, [string[]]$Lines)
    $w = [math]::Min([math]::Max(50, (($Lines | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum) + 6), [math]::Max(20, $script:Ui.Width - 2))
    $h = [math]::Min($Lines.Count + 4, $script:Ui.Height - 2)
    $x = [math]::Max(0, [math]::Floor(($script:Ui.Width - $w) / 2))
    Initialize-Frame
    Write-Box -X $x -Y 1 -Width $w -Height $h -Title $Title
    for ($i = 0; $i -lt [math]::Min($Lines.Count, $h - 4); $i++) {
        $line = $Lines[$i]
        $color = if ($line -match '^\s*\[') { $script:Theme.Key } elseif ($line -match '^[A-Z ]+:$') { $script:Theme.Header } else { $script:Theme.Normal }
        Write-At -X ($x + 2) -Y (2 + $i) -Text (Limit-Text $line ($w - 4)) -Fg $color
    }
    Write-At -X ($x + 2) -Y ($h - 1) -Text 'Press any key to continue' -Fg $script:Theme.Dim
    Show-Frame
    $null = Read-TuiKey
}

# =====================================================================================================
#  Screens and dialogs
# =====================================================================================================

function Get-ListCapacity {
    return [math]::Max(1, $script:Ui.Height - 8)
}

function Sync-RuleTable {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $script:State.Rules = @(Get-PortProxyRule)
    }
    catch {
        $script:State.Rules = @()
        Set-Message -Text "Could not read rules: $($_.Exception.Message)" -Type Error
    }
    $script:State.IpHelper = Get-IpHelperStatus
    try { $script:State.Orphans = @(Get-OrphanFirewallRule -Rules $script:State.Rules -Table (Get-PortRedirectFirewallTable)) }
    catch { $script:State.Orphans = @() }
    $script:State.LastLoadMs = $sw.ElapsedMilliseconds
    $script:State.NeedsReload = $false
    $count = $script:State.Rules.Count
    if ($script:State.Selected -ge $count) { $script:State.Selected = [math]::Max(0, $count - 1) }
    if ($script:State.Selected -lt 0) { $script:State.Selected = 0 }
}

function Get-SelectedRule {
    if ($script:State.Rules.Count -eq 0) { return $null }
    return $script:State.Rules[$script:State.Selected]
}

function Show-MainScreen {
    Initialize-Frame
    $w = $script:Ui.Width
    $h = $script:Ui.Height
    $rules = $script:State.Rules
    $count = $rules.Count

    # Title bar
    Write-At -X 0 -Y 0 -Text ('=' * $w) -Fg $script:Theme.Border
    Write-Centered -Y 0 -Text ' NAT Port Redirect Manager ' -Fg $script:Theme.Title

    # Info line
    $wslIp = Get-WslIPAddress
    $wsl = if ($wslIp) { $wslIp } else { 'not detected' }
    $wslColor = if ($wslIp) { $script:Theme.Normal } else { $script:Theme.Dim }
    Write-At -X 1 -Y 1 -Text 'WSL2 IP: ' -Fg $script:Theme.Dim
    Write-At -X 10 -Y 1 -Text $wsl -Fg $wslColor
    $ipHelper = $script:State.IpHelper
    $helperText = if ($ipHelper -eq 'Running') { 'Running' } else { "$ipHelper (rules inactive; press S)" }
    $helperColor = if ($ipHelper -eq 'Running') { $script:Theme.Success } else { $script:Theme.Error }
    $helperX = [math]::Max(12 + $wsl.Length, 28)
    Write-At -X $helperX -Y 1 -Text 'IP Helper: ' -Fg $script:Theme.Dim
    Write-At -X ($helperX + 11) -Y 1 -Text $helperText -Fg $helperColor
    $orphanCount = @($script:State.Orphans).Count
    $loadText = "$count rule$(if ($count -eq 1) { '' } else { 's' })  $($script:State.LastLoadMs) ms "
    if ($orphanCount -gt 0) { $loadText = "$orphanCount orphan FW rule$(if ($orphanCount -eq 1) { '' } else { 's' }) [O]  " + $loadText }
    Write-At -X ($w - $loadText.Length - 1) -Y 1 -Text $loadText -Fg $(if ($orphanCount -gt 0) { $script:Theme.Warning } else { $script:Theme.Dim })

    # Column headers
    $layout = Get-ColumnLayout -Width $w
    Write-At -X $layout.TypeX -Y 2 -Text 'TYPE' -Fg $script:Theme.Header
    Write-At -X $layout.ListenX -Y 2 -Text 'LISTEN ON' -Fg $script:Theme.Header
    Write-At -X $layout.ConnectX -Y 2 -Text 'REDIRECT TO' -Fg $script:Theme.Header
    Write-At -X $layout.FwX -Y 2 -Text 'FW' -Fg $script:Theme.Header
    Write-At -X 0 -Y 3 -Text ('-' * $w) -Fg $script:Theme.Border

    $listTop = 4
    $capacity = Get-ListCapacity
    if ($count -eq 0) {
        Write-At -X 2 -Y $listTop -Text 'No port redirect rules configured.' -Fg $script:Theme.Info
        Write-At -X 2 -Y ($listTop + 1) -Text 'Press [A] to add a rule, [?] for help.' -Fg $script:Theme.Normal
        $script:State.Scroll = 0
    }
    else {
        if ($script:State.Selected -lt $script:State.Scroll) { $script:State.Scroll = $script:State.Selected }
        if ($script:State.Selected -ge $script:State.Scroll + $capacity) { $script:State.Scroll = $script:State.Selected - $capacity + 1 }
        $script:State.Scroll = [math]::Max(0, [math]::Min($script:State.Scroll, [math]::Max(0, $count - $capacity)))

        $visible = [math]::Min($count - $script:State.Scroll, $capacity)
        for ($i = 0; $i -lt $visible; $i++) {
            $ruleIndex = $script:State.Scroll + $i
            $rule = $rules[$ruleIndex]
            $y = $listTop + $i
            $line = (Format-RuleRow -Rule $rule -Layout $layout).PadRight($w - 1)
            if ($ruleIndex -eq $script:State.Selected) {
                Write-At -X 0 -Y $y -Text '>' -Fg $script:Theme.Key
                Write-At -X 1 -Y $y -Text $line -Fg $script:Theme.Selected -Bg $script:Theme.SelectedBg
            }
            else {
                Write-At -X 1 -Y $y -Text $line -Fg $script:Theme.Normal
            }
        }
        if ($script:State.Scroll -gt 0) {
            Write-At -X ($w - 4) -Y $listTop -Text ' ^ ' -Fg $script:Theme.Info
        }
        if ($script:State.Scroll + $capacity -lt $count) {
            Write-At -X ($w - 4) -Y ($listTop + $visible - 1) -Text ' v ' -Fg $script:Theme.Info
        }
        $pos = " $($script:State.Selected + 1)/$count "
        Write-At -X ($w - $pos.Length - 1) -Y 2 -Text $pos -Fg $script:Theme.Info
    }

    # Status and help bars
    $statusY = $h - 4
    Write-At -X 0 -Y $statusY -Text ('-' * $w) -Fg $script:Theme.Border
    if ($script:State.Message) {
        Write-At -X 1 -Y ($statusY + 1) -Text (Limit-Text $script:State.Message ($w - 2)) -Fg (Get-MessageColor)
    }
    Write-At -X 0 -Y ($h - 2) -Text ('=' * $w) -Fg $script:Theme.Border
    $help = if ($count -gt 0) {
        ' Up/Dn PgUp/Dn Home/End  [A]dd [E]dit [D]el [F]irewall [P] Re-point [O]rphans [R]efresh [?] Help [Q]uit '
    }
    else {
        ' [A]dd  [R]efresh  [?] Help  [Q]uit '
    }
    Write-Centered -Y ($h - 2) -Text (Limit-Text $help $w) -Fg $script:Theme.Key
    Show-Frame
}

function Show-TooSmallScreen {
    Initialize-Frame
    Write-At -X 0 -Y 0 -Text "Terminal too small ($($script:Ui.Width)x$($script:Ui.Height))." -Fg $script:Theme.Error
    Write-At -X 0 -Y 1 -Text "Need at least $($script:MinWidth)x$($script:MinHeight). Resize the window, or press Q to quit." -Fg $script:Theme.Normal
    Show-Frame
}

function Show-HelpScreen {
    $lines = @(
        "NAT Port Redirect Manager $($script:Version)"
        ''
        'KEYS:'
        '  [Up/Down] [PgUp/PgDn] [Home/End]   move selection'
        '  [A]  add a rule (wizard)            [E]  edit the target of the selected rule'
        '  [D]  delete selected rule + its firewall rules'
        '  [F]  add/remove firewall rules for the selected rule'
        '  [P]  re-point every rule with one target to a new address (e.g. new WSL2 IP)'
        '  [O]  remove orphaned PortRedirect_* firewall rules (no matching proxy rule)'
        '  [R]  reload rules and re-detect the WSL2 IP'
        '  [S]  start the IP Helper service, or restart it (forces hostnames to re-resolve)'
        '  [Q] / [Esc] / [Ctrl+C]  quit'
        ''
        'FW COLUMN:'
        '  T / U  enabled TCP / UDP inbound rule      t / u  rule exists but is disabled'
        '  -      no PortRedirect_* firewall rule for that listen port'
        ''
        'TIPS:'
        '  * WSL2 gets a new IP on every restart. Use [P] to re-point all rules at once, or use a'
        '    hostname as the target: netsh stores it as text and resolves it on each connection.'
        '  * Port-proxy forwards TCP only; the tool creates TCP firewall rules (U/u = legacy UDP rules).'
        '  * Port-proxy rules do nothing while the IP Helper (iphlpsvc) service is stopped.'
        '  * The listen port prompt accepts lists and ranges: 8080,8443 or 3000-3003.'
        '  * Headless use:  -List   -Add ...   -Remove ...   -Repoint -From X -To wsl   (see Get-Help)'
    )
    Show-Notice -Title 'Help' -Lines $lines
}

function Get-ConnectAddressChoice {
    param([string]$Type)
    $options = New-Object System.Collections.Generic.List[object]
    $wslIp = Get-WslIPAddress
    $connectV6 = $Type.EndsWith('v6')
    if ($wslIp -and -not $connectV6) {
        $options.Add(@{ Label = "WSL2 ($wslIp)"; Value = $wslIp })
    }
    else {
        $options.Add(@{ Label = 'WSL2 (not detected - is a distro running?)'; Value = '' })
    }
    if ($connectV6) {
        $options.Add(@{ Label = 'localhost (::1)'; Value = '::1' })
    }
    else {
        $options.Add(@{ Label = 'localhost (127.0.0.1)'; Value = '127.0.0.1' })
    }
    $options.Add(@{ Label = 'Hostname or IP address (type it)'; Value = $null })
    return , $options   # the comma keeps the List intact (PowerShell would otherwise unroll it into a fixed array)
}

function Read-AddressStep {
    <#
    .SYNOPSIS
        Shared "choose or type an address" step with validation. Returns the address or $null on cancel.
    #>
    param(
        [hashtable]$Dialog,
        [string]$Title,
        [System.Collections.Generic.List[object]]$Options,
        [string]$Type,
        [ValidateSet('Listen', 'Connect')][string]$Role,
        [string]$Default = ''
    )
    $backdrop = { param($d) Write-DialogFrame $d }
    while ($true) {
        $Dialog.Error = ''
        $y = Get-DialogStepY $Dialog
        $labels = [string[]]@($Options | ForEach-Object { $_.Label })
        $choice = Show-Menu -Title $Title -Options $labels -X ($Dialog.X + 4) -Y $y -Backdrop $backdrop -Context $Dialog
        if ($null -eq $choice) { return $null }
        $picked = $Options[$choice]
        if ($picked.Value -eq '') {
            $Dialog.Error = 'WSL2 IP not detected: start your distribution and press R, or type an address.'
            continue
        }
        $address = $picked.Value
        if ($null -eq $address) {
            while ($true) {
                $typed = Read-TuiLine -X ($Dialog.X + 4) -Y $y -Width 40 -Label "$Role address:" -Default $Default -Backdrop $backdrop -Context $Dialog
                if ($null -eq $typed) { $address = $null; break }
                $typed = $typed.Trim('[', ']')
                $err = Test-AddressForRole -Address $typed -Type $Type -Role $Role
                if ($err) { $Dialog.Error = $err; continue }
                $address = $typed
                break
            }
            if ($null -eq $address) { continue }   # back to the menu
        }
        else {
            $err = Test-AddressForRole -Address $address -Type $Type -Role $Role
            if ($err) { $Dialog.Error = $err; continue }
        }
        $Dialog.Error = ''
        return $address
    }
}

function Read-PortStep {
    param([hashtable]$Dialog, [string]$Label, [string]$Default = '')
    $backdrop = { param($d) Write-DialogFrame $d }
    while ($true) {
        $y = Get-DialogStepY $Dialog
        $typed = Read-TuiLine -X ($Dialog.X + 4) -Y $y -Width 12 -Label $Label -Default $Default -Backdrop $backdrop -Context $Dialog
        if ($null -eq $typed) { return $null }
        if ($typed -eq '' -and $Default) { $typed = $Default }
        if (-not (Test-PortNumber $typed)) {
            $Dialog.Error = "'$typed' is not a valid port (1-65535)"
            continue
        }
        $Dialog.Error = ''
        return [int]$typed
    }
}

function Find-Rule {
    param([string]$Type, [string]$ListenAddress, [int]$ListenPort)
    foreach ($r in $script:State.Rules) {
        if ($r.ListenPort -eq $ListenPort -and $r.ListenAddress -eq $ListenAddress -and (-not $Type -or $r.Type -eq $Type)) { return $r }
    }
    return $null
}

function Show-AddRuleDialog {
    $dialog = Initialize-Dialog -Title 'Add Port Redirect Rule'
    $backdrop = { param($d) Write-DialogFrame $d }

    # 1. Type
    $dialog.Prompt = '1. Proxy type'
    $choice = Show-Menu -Title 'Type' -Options $script:ProxyTypes -X ($dialog.X + 4) -Y (Get-DialogStepY $dialog) -Backdrop $backdrop -Context $dialog
    if ($null -eq $choice) { Set-Message 'Add cancelled'; return }
    $type = $script:ProxyTypes[$choice]
    $dialog.Answers['Type'] = $type

    # 2. Listen address
    $dialog.Prompt = '2. Listen address'
    $listenV6 = $type.StartsWith('v6')
    $listenOptions = New-Object System.Collections.Generic.List[object]
    if ($listenV6) {
        $listenOptions.Add(@{ Label = ':: (all IPv6 interfaces)'; Value = '::' })
        $listenOptions.Add(@{ Label = '::1 (IPv6 localhost only)'; Value = '::1' })
    }
    else {
        $listenOptions.Add(@{ Label = '0.0.0.0 (all interfaces)'; Value = '0.0.0.0' })
        $listenOptions.Add(@{ Label = '127.0.0.1 (localhost only)'; Value = '127.0.0.1' })
    }
    $listenOptions.Add(@{ Label = 'Specific address (type it)'; Value = $null })
    $listenAddress = Read-AddressStep -Dialog $dialog -Title 'Listen address' -Options $listenOptions -Type $type -Role Listen
    if ($null -eq $listenAddress) { Set-Message 'Add cancelled'; return }
    $dialog.Answers['Listen address'] = $listenAddress

    # 3. Listen port(s)
    $dialog.Prompt = '3. Listen port  (a list or range is fine: 8080,8443 or 3000-3003)'
    $listenPorts = $null
    while ($true) {
        $typed = Read-TuiLine -X ($dialog.X + 4) -Y (Get-DialogStepY $dialog) -Width 24 -Label 'Listen port(s):' -Backdrop $backdrop -Context $dialog
        if ($null -eq $typed) { Set-Message 'Add cancelled'; return }
        try { $listenPorts = @(ConvertTo-PortList -Text $typed) }
        catch { $dialog.Error = $_.Exception.Message; continue }
        $dup = @($listenPorts | Where-Object { Find-Rule -Type $type -ListenAddress $listenAddress -ListenPort $_ })
        if ($dup.Count -gt 0) {
            $dialog.Error = "A $type rule for $(Format-Endpoint $listenAddress $dup[0]) already exists (use Edit)."
            continue
        }
        $dialog.Error = ''
        break
    }
    $listenPort = $listenPorts[0]
    $dialog.Answers[$(if ($listenPorts.Count -gt 1) { 'Listen ports' } else { 'Listen port' })] = ($listenPorts -join ', ')

    # 4. Connect address
    $dialog.Prompt = '4. Redirect to (connect address)'
    $connectAddress = Read-AddressStep -Dialog $dialog -Title 'Connect address' -Options (Get-ConnectAddressChoice -Type $type) -Type $type -Role Connect
    if ($null -eq $connectAddress) { Set-Message 'Add cancelled'; return }
    $dialog.Answers['Connect address'] = $connectAddress

    # 5. Connect port (single port only; several listen ports always map to the same port on the target)
    $connectPort = $listenPort
    if ($listenPorts.Count -eq 1) {
        $dialog.Prompt = '5. Connect port (Enter = same as listen port)'
        $connectPort = Read-PortStep -Dialog $dialog -Label 'Connect port:' -Default "$listenPort"
        if ($null -eq $connectPort) { Set-Message 'Add cancelled'; return }
        $dialog.Answers['Connect port'] = $connectPort
    }
    else {
        $dialog.Answers['Connect port'] = 'same as listen port'
    }

    # 6. Firewall (port-proxy forwards TCP only, so only a TCP rule makes sense; loopback needs none)
    $firewall = 'None'
    if (Test-LoopbackAddress $listenAddress) {
        $dialog.Answers['Firewall'] = 'not needed (loopback listener)'
    }
    else {
        $dialog.Prompt = '6. Inbound firewall rule for the listen port'
        $fwOptions = @('TCP rule (recommended for LAN access)', 'No firewall rule')
        $choice = Show-Menu -Title 'Firewall' -Options $fwOptions -X ($dialog.X + 4) -Y (Get-DialogStepY $dialog) -Backdrop $backdrop -Context $dialog
        if ($null -eq $choice) { Set-Message 'Add cancelled'; return }
        $firewall = if ($choice -eq 0) { 'TCP' } else { 'None' }
        $dialog.Answers['Firewall'] = $fwOptions[$choice]
    }
    $dialog.Prompt = ''

    # 7. Confirm and apply
    $summary = @()
    foreach ($port in $listenPorts) {
        $cp = if ($listenPorts.Count -eq 1) { $connectPort } else { $port }
        $summary += "$type  $(Format-Endpoint $listenAddress $port)  ->  $(Format-Endpoint $connectAddress $cp)"
    }
    $summary += "Firewall: $($dialog.Answers['Firewall'])"
    $title = if ($listenPorts.Count -eq 1) { 'Create this rule?' } else { "Create these $($listenPorts.Count) rules?" }
    if (-not (Show-Confirm -Title $title -Lines $summary -Backdrop $backdrop -Context $dialog)) {
        Set-Message 'Add cancelled'
        return
    }
    $added = 0
    $problems = @()
    foreach ($port in $listenPorts) {
        $cp = if ($listenPorts.Count -eq 1) { $connectPort } else { $port }
        $result = Add-PortProxyRule -Type $type -ListenAddress $listenAddress -ListenPort $port -ConnectAddress $connectAddress -ConnectPort $cp
        if (-not $result.Success) { $problems += "$port`: $($result.Output)"; continue }
        $added++
        if ($firewall -eq 'TCP') {
            $fw = Add-PortRedirectFirewallRule -ListenAddress $listenAddress -ListenPort $port -Protocol TCP
            if (-not $fw.Success) { $problems += "$port firewall: $($fw.Message)" }
        }
    }
    $what = if ($listenPorts.Count -eq 1) { "Rule added: $(Format-Endpoint $listenAddress $listenPort) -> $(Format-Endpoint $connectAddress $connectPort)" } else { "$added of $($listenPorts.Count) rules added" }
    if ($problems.Count -eq 0) {
        $fwNote = if ($firewall -eq 'TCP') { '; TCP firewall rule created' } else { '' }
        Set-Message -Text "$what$fwNote" -Type Success
    }
    else {
        Set-Message -Text "$what; problems: $($problems -join ' | ')" -Type Error
    }
}

function Show-EditRuleDialog {
    param($Rule)
    if (-not $Rule) { return }
    $dialog = Initialize-Dialog -Title 'Edit Port Redirect Rule' -Height 16
    $backdrop = { param($d) Write-DialogFrame $d }
    $dialog.Answers['Type'] = $Rule.Type
    $dialog.Answers['Listen'] = Format-Endpoint $Rule.ListenAddress $Rule.ListenPort
    $dialog.Answers['Current target'] = Format-Endpoint $Rule.ConnectAddress $Rule.ConnectPort

    $dialog.Prompt = 'New connect address'
    $options = Get-ConnectAddressChoice -Type $Rule.Type
    $options.Insert(0, @{ Label = "Keep $($Rule.ConnectAddress)"; Value = $Rule.ConnectAddress })
    $connectAddress = Read-AddressStep -Dialog $dialog -Title 'Connect address' -Options $options -Type $Rule.Type -Role Connect -Default $Rule.ConnectAddress
    if ($null -eq $connectAddress) { Set-Message 'Edit cancelled'; return }
    $dialog.Answers['New address'] = $connectAddress

    $dialog.Prompt = "New connect port (Enter = keep $($Rule.ConnectPort))"
    $connectPort = Read-PortStep -Dialog $dialog -Label 'Connect port:' -Default "$($Rule.ConnectPort)"
    if ($null -eq $connectPort) { Set-Message 'Edit cancelled'; return }
    $dialog.Answers['New port'] = $connectPort
    $dialog.Prompt = ''

    if ($connectAddress -eq $Rule.ConnectAddress -and $connectPort -eq $Rule.ConnectPort) {
        Set-Message 'No changes made'
        return
    }
    $summary = @(
        "Rule:  $($Rule.Type)  $(Format-Endpoint $Rule.ListenAddress $Rule.ListenPort)"
        "Old:   $(Format-Endpoint $Rule.ConnectAddress $Rule.ConnectPort)"
        "New:   $(Format-Endpoint $connectAddress $connectPort)"
    )
    if (-not (Show-Confirm -Title 'Apply changes?' -Lines $summary -Backdrop $backdrop -Context $dialog)) {
        Set-Message 'Edit cancelled'
        return
    }
    $result = Set-PortProxyRule -Type $Rule.Type -ListenAddress $Rule.ListenAddress -ListenPort $Rule.ListenPort -ConnectAddress $connectAddress -ConnectPort $connectPort
    if ($result.Success) {
        Set-Message -Text "Rule updated: now -> $(Format-Endpoint $connectAddress $connectPort)" -Type Success
    }
    else {
        Set-Message -Text "netsh failed: $($result.Output)" -Type Error
    }
}

function Show-FirewallDialog {
    param($Rule)
    if (-not $Rule) { return }
    $w = 60
    $h = 13
    $x = [math]::Max(0, [math]::Floor(($script:Ui.Width - $w) / 2))
    $y = 1
    $tcpName = Get-FirewallRuleName -ListenAddress $Rule.ListenAddress -ListenPort $Rule.ListenPort -Protocol TCP
    $udpName = Get-FirewallRuleName -ListenAddress $Rule.ListenAddress -ListenPort $Rule.ListenPort -Protocol UDP
    $actions = @{
        '1' = @{ Verb = 'Add'; Protocol = 'TCP' }
        '2' = @{ Verb = 'Add'; Protocol = 'UDP' }
        '3' = @{ Verb = 'Add'; Protocol = 'Both' }
        '4' = @{ Verb = 'Remove'; Protocol = 'TCP' }
        '5' = @{ Verb = 'Remove'; Protocol = 'UDP' }
        '6' = @{ Verb = 'Remove'; Protocol = 'Both' }
    }
    $message = ''
    $messageColor = $script:Theme.Info
    while ($true) {
        $table = Get-PortRedirectFirewallTable
        $status = @{}
        foreach ($pair in @(@('TCP', $tcpName), @('UDP', $udpName))) {
            $proto = $pair[0]
            $name = $pair[1]
            if (-not $table.ContainsKey($name)) { $status[$proto] = @{ Text = 'none'; Color = $script:Theme.Dim } }
            elseif ($table[$name].Enabled) { $status[$proto] = @{ Text = 'ENABLED'; Color = $script:Theme.Success } }
            else { $status[$proto] = @{ Text = 'disabled'; Color = $script:Theme.Warning } }
        }
        Initialize-Frame
        Write-Box -X $x -Y $y -Width $w -Height $h -Title 'Firewall Rules'
        Write-At -X ($x + 2) -Y ($y + 2) -Text "Listen endpoint: $(Format-Endpoint $Rule.ListenAddress $Rule.ListenPort)" -Fg $script:Theme.Header
        Write-At -X ($x + 2) -Y ($y + 4) -Text 'TCP: ' -Fg $script:Theme.Normal
        Write-At -X ($x + 7) -Y ($y + 4) -Text $status['TCP'].Text -Fg $status['TCP'].Color
        Write-At -X ($x + 22) -Y ($y + 4) -Text 'UDP: ' -Fg $script:Theme.Normal
        Write-At -X ($x + 27) -Y ($y + 4) -Text $status['UDP'].Text -Fg $status['UDP'].Color
        Write-At -X ($x + 2) -Y ($y + 6) -Text '[1] Add TCP     [2] Add UDP*    [3] Add both*' -Fg $script:Theme.Key
        Write-At -X ($x + 2) -Y ($y + 7) -Text '[4] Remove TCP  [5] Remove UDP  [6] Remove both' -Fg $script:Theme.Key
        Write-At -X ($x + 2) -Y ($y + 8) -Text '* port-proxy forwards TCP only; UDP rules are for other services' -Fg $script:Theme.Dim
        Write-At -X ($x + 2) -Y ($y + 9) -Text '[Esc] Back' -Fg $script:Theme.Dim
        if ($message) { Write-At -X ($x + 2) -Y ($y + 11) -Text (Limit-Text $message ($w - 4)) -Fg $messageColor }
        Show-Frame

        $key = Read-TuiKey
        if (Test-CancelKey $key) { return }
        $char = "$($key.KeyChar)"
        if (-not $actions.ContainsKey($char)) { continue }
        $action = $actions[$char]
        if ($action.Verb -eq 'Add') {
            $result = Add-PortRedirectFirewallRule -ListenAddress $Rule.ListenAddress -ListenPort $Rule.ListenPort -Protocol $action.Protocol
        }
        else {
            $result = Remove-PortRedirectFirewallRule -ListenAddress $Rule.ListenAddress -ListenPort $Rule.ListenPort -Protocol $action.Protocol
        }
        $message = $result.Message
        $messageColor = if ($result.Success) { $script:Theme.Success } else { $script:Theme.Error }
        $script:State.NeedsReload = $true
    }
}

function Invoke-DeleteSelectedRule {
    $rule = Get-SelectedRule
    if (-not $rule) { Set-Message 'No rules to delete'; return }
    $lines = @("$($rule.Type)  $(Format-Endpoint $rule.ListenAddress $rule.ListenPort)  ->  $(Format-Endpoint $rule.ConnectAddress $rule.ConnectPort)")
    $hasFirewall = ($rule.Firewall -ne '-')
    if ($hasFirewall) { $lines += "Its PortRedirect_* firewall rules ($($rule.Firewall)) will be removed too." }
    if (-not (Show-Confirm -Title 'Delete this rule?' -Lines $lines)) {
        Set-Message 'Delete cancelled'
        return
    }
    $result = Remove-PortProxyRule -Type $rule.Type -ListenAddress $rule.ListenAddress -ListenPort $rule.ListenPort
    $script:State.NeedsReload = $true
    if (-not $result.Success) {
        Set-Message -Text "netsh failed: $($result.Output)" -Type Error
        return
    }
    $parts = @("Deleted $($rule.Type) $(Format-Endpoint $rule.ListenAddress $rule.ListenPort)")
    if ($hasFirewall) {
        # Another proxy type may still listen on the same endpoint and need the same firewall rule.
        $shared = @($script:State.Rules | Where-Object { $_.ListenAddress -eq $rule.ListenAddress -and $_.ListenPort -eq $rule.ListenPort -and $_.Type -ne $rule.Type })
        if ($shared.Count -gt 0) {
            $parts += "firewall rules kept ($($shared[0].Type) still listens there)"
        }
        else {
            $fw = Remove-PortRedirectFirewallRule -ListenAddress $rule.ListenAddress -ListenPort $rule.ListenPort -Protocol Both
            $parts += "firewall: $($fw.Message)"
        }
    }
    Set-Message -Text ($parts -join '; ') -Type Success
}

function Invoke-OrphanCleanup {
    $orphans = @($script:State.Orphans)
    if ($orphans.Count -eq 0) { Set-Message 'No orphaned firewall rules'; return }
    $lines = @("$($orphans.Count) PortRedirect_* firewall rule(s) have no port-proxy rule:")
    $lines += @($orphans | Select-Object -First 8 | ForEach-Object { "  $($_.Name)" })
    if ($orphans.Count -gt 8) { $lines += "  ... and $($orphans.Count - 8) more" }
    if (-not (Show-Confirm -Title 'Remove orphaned firewall rules?' -Lines $lines)) { Set-Message 'Cancelled'; return }
    $result = Remove-OrphanFirewallRule -Orphans $orphans
    $script:State.NeedsReload = $true
    if ($result.Failed.Count -eq 0) { Set-Message -Text "Removed $($result.Removed) orphaned firewall rule(s)" -Type Success }
    else { Set-Message -Text "Removed $($result.Removed); failed: $($result.Failed[0])" -Type Error }
}

function Show-RepointDialog {
    if ($script:State.Rules.Count -eq 0) { Set-Message 'No rules to re-point'; return }
    $dialog = Initialize-Dialog -Title 'Re-point Rules' -Height 15
    $backdrop = { param($d) Write-DialogFrame $d }

    $groups = @($script:State.Rules | Group-Object -Property ConnectAddress | Sort-Object -Property Count -Descending)
    $labels = [string[]]@($groups | ForEach-Object { "$($_.Name)  ($($_.Count) rule$(if ($_.Count -eq 1) { '' } else { 's' }))" })
    $dialog.Prompt = 'Rules currently pointing to'
    $choice = Show-Menu -Title 'From' -Options $labels -X ($dialog.X + 4) -Y (Get-DialogStepY $dialog) -Backdrop $backdrop -Context $dialog
    if ($null -eq $choice) { Set-Message 'Re-point cancelled'; return }
    $from = $groups[$choice].Name
    $targets = @($groups[$choice].Group)
    $dialog.Answers['From'] = "$from ($($targets.Count))"

    # All selected rules share the connect family unless mixed; validate per rule below.
    $type = $targets[0].Type
    $dialog.Prompt = 'New target address'
    $to = Read-AddressStep -Dialog $dialog -Title 'To' -Options (Get-ConnectAddressChoice -Type $type) -Type $type -Role Connect
    if ($null -eq $to) { Set-Message 'Re-point cancelled'; return }
    if ($to -eq $from) { Set-Message 'Target is unchanged'; return }
    $dialog.Answers['To'] = $to
    $dialog.Prompt = ''

    $lines = @("Re-point $($targets.Count) rule(s):  $from  ->  $to")
    $lines += @($targets | Select-Object -First 6 | ForEach-Object { "  $($_.Type)  $(Format-Endpoint $_.ListenAddress $_.ListenPort)" })
    if ($targets.Count -gt 6) { $lines += "  ... and $($targets.Count - 6) more" }
    if (-not (Show-Confirm -Title 'Apply?' -Lines $lines -Backdrop $backdrop -Context $dialog)) {
        Set-Message 'Re-point cancelled'
        return
    }
    $ok = 0
    $failed = @()
    foreach ($rule in $targets) {
        $err = Test-AddressForRole -Address $to -Type $rule.Type -Role Connect
        if ($err) { $failed += "$(Format-Endpoint $rule.ListenAddress $rule.ListenPort): $err"; continue }
        $result = Set-PortProxyRule -Type $rule.Type -ListenAddress $rule.ListenAddress -ListenPort $rule.ListenPort -ConnectAddress $to -ConnectPort $rule.ConnectPort
        if ($result.Success) { $ok++ } else { $failed += "$(Format-Endpoint $rule.ListenAddress $rule.ListenPort): $($result.Output)" }
    }
    $script:State.NeedsReload = $true
    if ($failed.Count -eq 0) {
        Set-Message -Text "Re-pointed $ok rule(s) to $to" -Type Success
    }
    else {
        Set-Message -Text "Re-pointed $ok, failed $($failed.Count): $($failed[0])" -Type Error
    }
}

function Invoke-StartIpHelper {
    $running = ($script:State.IpHelper -eq 'Running')
    $lines = if ($running) {
        @('IP Helper is running. Restarting it reloads the port-proxy table and', 'forces hostname targets to be resolved again. Restart it now?')
    }
    else {
        @('Port-proxy rules only work while the IP Helper (iphlpsvc)', 'service is running. Start it now?')
    }
    $title = if ($running) { 'Restart IP Helper?' } else { 'Start IP Helper?' }
    if (-not (Show-Confirm -Title $title -Lines $lines)) { return }
    try {
        Start-IpHelperService -Restart:$running
        Set-Message -Text $(if ($running) { 'IP Helper service restarted' } else { 'IP Helper service started' }) -Type Success
    }
    catch {
        Set-Message -Text "Could not $(if ($running) { 'restart' } else { 'start' }) IP Helper: $($_.Exception.Message)" -Type Error
    }
    $script:State.NeedsReload = $true
}

function Move-Selection {
    param([int]$Delta, [switch]$Absolute)
    $count = $script:State.Rules.Count
    if ($count -eq 0) { $script:State.Selected = 0; return }
    $target = if ($Absolute) { $Delta } else { $script:State.Selected + $Delta }
    $script:State.Selected = [math]::Max(0, [math]::Min($count - 1, $target))
}

function Invoke-KeyAction {
    param([ConsoleKeyInfo]$Key)
    if (Test-CancelKey $Key) { $script:State.Running = $false; return }
    if ("$($Key.KeyChar)" -eq '?') { Show-HelpScreen; return }
    $page = Get-ListCapacity
    switch ($Key.Key) {
        'Q'         { $script:State.Running = $false }
        'UpArrow'   { Move-Selection -Delta -1 }
        'DownArrow' { Move-Selection -Delta 1 }
        'PageUp'    { Move-Selection -Delta (-$page) }
        'PageDown'  { Move-Selection -Delta $page }
        'Home'      { Move-Selection -Delta 0 -Absolute }
        'End'       { Move-Selection -Delta ($script:State.Rules.Count - 1) -Absolute }
        'F1'        { Show-HelpScreen }
        'H'         { Show-HelpScreen }
        'A'         { Show-AddRuleDialog; $script:State.NeedsReload = $true }
        'E'         {
            $rule = Get-SelectedRule
            if ($rule) { Show-EditRuleDialog -Rule $rule; $script:State.NeedsReload = $true } else { Set-Message 'No rules to edit' }
        }
        'D'         { Invoke-DeleteSelectedRule }
        'F'         {
            $rule = Get-SelectedRule
            if ($rule) { Show-FirewallDialog -Rule $rule } else { Set-Message 'No rules to manage firewall for' }
        }
        'P'         { Show-RepointDialog }
        'O'         { Invoke-OrphanCleanup }
        'S'         { Invoke-StartIpHelper }
        'R'         {
            $script:State.NeedsReload = $true
            $null = Get-WslIPAddress -Refresh
            Set-Message 'Refreshed'
        }
    }
}

function Wait-TuiKey {
    <#
    .SYNOPSIS
        Block until a key is pressed, or return $null when the window was resized meanwhile.
    #>
    $size = Get-ConsoleSize
    while ($true) {
        if (Test-KeyAvailable) { return Read-TuiKey }
        Start-Sleep -Milliseconds 40
        $now = Get-ConsoleSize
        if ($now.Width -ne $size.Width -or $now.Height -ne $size.Height) { return $null }
    }
}

function Invoke-MainLoop {
    Clear-Console
    $lastSize = Get-ConsoleSize
    $null = Get-WslIPAddress
    while ($script:State.Running) {
        if ($script:State.NeedsReload) { Sync-RuleTable }
        $size = Get-ConsoleSize
        if ($size.Width -ne $lastSize.Width -or $size.Height -ne $lastSize.Height) {
            Clear-Console
            $lastSize = $size
        }
        $tooSmall = ($size.Width -lt $script:MinWidth -or $size.Height -lt $script:MinHeight)
        if ($tooSmall) { Show-TooSmallScreen } else { Show-MainScreen }
        $key = Wait-TuiKey
        if ($null -eq $key) { continue }
        if ($tooSmall) {
            if ($key.Key -eq [ConsoleKey]::Q -or (Test-CancelKey $key)) { $script:State.Running = $false }
            continue
        }
        $script:State.Message = ''
        Invoke-KeyAction -Key $key
    }
}

function Test-InteractiveConsole {
    try {
        if ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) { return $false }
        if ($Host.Name -eq 'Windows PowerShell ISE Host') { return $false }
        $null = [Console]::WindowWidth
        return $true
    }
    catch {
        return $false
    }
}

function Invoke-Tui {
    if (-not (Test-InteractiveConsole)) {
        Write-Warning 'The interactive manager needs a real console window (not the ISE, not redirected input/output).'
        Write-Warning 'For scripting use -List, -Add, -Remove, -Repoint or -RemoveOrphans (see Get-Help).'
        return 1
    }
    if (-not (Test-IsElevated)) {
        if (-not $script:NoElevate) {
            Write-Information -MessageData 'Not running as administrator: asking for elevation (UAC). The manager opens in a new elevated window; this window waits until it closes.' -InformationAction Continue
            try {
                Invoke-SelfElevated -ArgumentList (Get-SelfElevationArgument)
                return 0
            }
            catch {
                Write-Warning "Elevation failed or was refused: $($_.Exception.Message)"
            }
        }
        Write-Warning 'The interactive manager changes system settings and needs an elevated PowerShell (Run as Administrator).'
        Write-Warning 'Read-only listing works without elevation:  .\PortRedirectManager.ps1 -List'
        return 1
    }
    $script:Ui.UseVT = Test-VirtualTerminalSupport
    try {
        $bg = [string]$Host.UI.RawUI.BackgroundColor
        if ($script:AnsiColor.ContainsKey($bg)) { $script:Ui.DefaultBg = $bg }
    }
    catch {
        Write-Verbose "Could not read console background: $_"
    }
    $previousCtrlC = $null
    try {
        $previousCtrlC = [Console]::TreatControlCAsInput
        [Console]::TreatControlCAsInput = $true
    }
    catch {
        Write-Verbose "TreatControlCAsInput not supported: $_"
    }
    try {
        Set-CursorVisible $false
        Invoke-MainLoop
    }
    finally {
        Set-CursorVisible $true
        if ($script:Ui.UseVT) { Write-ConsoleRaw "$([char]27)[0m" }
        if ($null -ne $previousCtrlC) {
            try { [Console]::TreatControlCAsInput = $previousCtrlC } catch { Write-Verbose "Could not restore Ctrl+C handling: $_" }
        }
        Clear-Console
    }
    return 0
}

# =====================================================================================================
#  Self-elevation (UAC): relaunch this script elevated instead of asking the user for a new console
# =====================================================================================================

function Get-SelfElevationArgument {
    <#
    .SYNOPSIS
        Build the argument list for an elevated relaunch of this script from the bound parameters.
    #>
    param([hashtable]$Bound = @{}, [string]$OutputFile = '')
    $skip = @('NoElevate', 'ElevatedOutputFile', 'WhatIf', 'Confirm', 'Verbose', 'Debug', 'ErrorAction', 'WarningAction',
        'InformationAction', 'ErrorVariable', 'WarningVariable', 'InformationVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable',
        'ProgressAction')
    $list = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $script:SelfPath))
    foreach ($name in @($Bound.Keys | Sort-Object)) {
        if ($skip -contains $name) { continue }
        $value = $Bound[$name]
        if ($value -is [switch] -or $value -is [bool]) {
            if ([bool]$value) { $list += "-$name" }
            continue
        }
        $joined = (@($value) | ForEach-Object { "$_" }) -join ','
        $list += "-$name"
        $list += ('"{0}"' -f ($joined -replace '"', ''))
    }
    $list += '-NoElevate'
    if ($OutputFile) { $list += '-ElevatedOutputFile'; $list += ('"{0}"' -f $OutputFile) }
    return $list
}

function Invoke-SelfElevated {
    <#
    .SYNOPSIS
        Start this PowerShell executable elevated (UAC prompt) with the given arguments and wait for it.
        Throws when the prompt is refused or the launch fails.
    #>
    param([string[]]$ArgumentList)
    $exe = (Get-Process -Id $PID).Path
    $null = Start-Process -FilePath $exe -ArgumentList $ArgumentList -Verb RunAs -Wait -PassThru -ErrorAction Stop
}

function Invoke-ElevatedRelay {
    <#
    .SYNOPSIS
        Run the current headless command in an elevated child and print its output here. Returns the exit code.
    #>
    param([hashtable]$Bound)
    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        Write-Verbose 'Not elevated: asking for administrator rights (UAC) and relaying the output.'
        Invoke-SelfElevated -ArgumentList (Get-SelfElevationArgument -Bound $Bound -OutputFile $tmp)
        $lines = @(Get-Content -LiteralPath $tmp -ErrorAction SilentlyContinue)
        if ($lines.Count -eq 0) { throw 'The elevated run produced no output (was the UAC prompt cancelled?)' }
        $code = 1
        foreach ($line in $lines) {
            if ($line -match '^__EXIT__ (\d+)$') { $code = [int]$Matches[1] }
            elseif ($line -match '^__ERROR__ (.*)$') { Write-Error -Message $Matches[1] -ErrorAction Continue }
            else { Write-Output $line }
        }
        return $code
    }
    finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-HeadlessRelayChild {
    <#
    .SYNOPSIS
        Elevated child side: run the command, write every output line plus errors and the exit code to the file.
    #>
    param([scriptblock]$Command, [string]$OutputFile)
    $lines = @()
    $code = 0
    try {
        $lines = @(& $Command | ForEach-Object { "$_" })
    }
    catch {
        $lines += "__ERROR__ $($_.Exception.Message)"
        $code = 1
    }
    $lines += "__EXIT__ $code"
    Set-Content -LiteralPath $OutputFile -Value $lines -Encoding UTF8
    return $code
}

# =====================================================================================================
#  Headless (CLI) mode
# =====================================================================================================

function Get-HeadlessVerb {
    param([string]$Done, [string]$Simulated)
    if ($WhatIfPreference) { return $Simulated }
    return $Done
}

function Assert-Elevated {
    if ($WhatIfPreference) { return }   # -WhatIf changes nothing, so it may run unelevated
    if (-not (Test-IsElevated)) {
        throw 'This operation changes system settings and needs an elevated PowerShell (Run as Administrator).'
    }
}

function Invoke-HeadlessAdd {
    param([string]$Type, [string]$ListenAddress, [string[]]$ListenPort, [string]$ConnectAddress, [int]$ConnectPort, [string]$Firewall)
    Assert-Elevated
    if (-not $Type) { $Type = 'v4tov4' }
    $ports = @(ConvertTo-PortList -Text ($ListenPort -join ','))
    if ($ports.Count -gt 1 -and $ConnectPort) { throw '-ConnectPort can only be used with a single -ListenPort' }
    $listen = $ListenAddress.Trim().Trim('[', ']')
    $target = Resolve-TargetAddress $ConnectAddress
    foreach ($check in @(@($listen, 'Listen'), @($target, 'Connect'))) {
        $err = Test-AddressForRole -Address $check[0] -Type $Type -Role $check[1]
        if ($err) { throw $err }
    }
    $script:State.Rules = @(Get-PortProxyRule)
    foreach ($port in $ports) {
        if (Find-Rule -Type $Type -ListenAddress $listen -ListenPort $port) {
            throw "A $Type rule for $(Format-Endpoint $listen $port) already exists. Use -Repoint or remove it first."
        }
    }
    $failed = 0
    foreach ($port in $ports) {
        $cp = if ($ConnectPort) { $ConnectPort } else { $port }
        $result = Add-PortProxyRule -Type $Type -ListenAddress $listen -ListenPort $port -ConnectAddress $target -ConnectPort $cp
        if (-not $result.Success) { $failed++; Write-Output "Failed $(Format-Endpoint $listen $port): $($result.Output)"; continue }
        Write-Output "$(Get-HeadlessVerb 'Added' 'Would add') $Type $(Format-Endpoint $listen $port) -> $(Format-Endpoint $target $cp)"
        if ($Firewall -eq 'TCP') {
            $fw = Add-PortRedirectFirewallRule -ListenAddress $listen -ListenPort $port -Protocol TCP
            Write-Output "Firewall: $($fw.Message)"
            if (-not $fw.Success) { $failed++ }
        }
    }
    if ($failed -gt 0) { throw "$failed operation(s) failed" }
}

function Invoke-HeadlessRemove {
    param([string]$Type, [string]$ListenAddress, [string[]]$ListenPort)
    Assert-Elevated
    $listen = $ListenAddress.Trim().Trim('[', ']')
    $ports = @(ConvertTo-PortList -Text ($ListenPort -join ','))
    $script:State.Rules = @(Get-PortProxyRule)
    $found = @($script:State.Rules | Where-Object { $_.ListenAddress -eq $listen -and $ports -contains $_.ListenPort -and (-not $Type -or $_.Type -eq $Type) })
    if ($found.Count -eq 0) { throw "No rule listens on $listen port(s) $($ports -join ', ')$(if ($Type) { " ($Type)" })" }
    $failed = 0
    foreach ($rule in $found) {
        $result = Remove-PortProxyRule -Type $rule.Type -ListenAddress $rule.ListenAddress -ListenPort $rule.ListenPort
        if (-not $result.Success) {
            $failed++
            Write-Output "Failed to remove $($rule.Type) $(Format-Endpoint $rule.ListenAddress $rule.ListenPort): $($result.Output)"
            continue
        }
        Write-Output "$(Get-HeadlessVerb 'Removed' 'Would remove') $($rule.Type) $(Format-Endpoint $rule.ListenAddress $rule.ListenPort)"
        if ($rule.Firewall -ne '-') {
            $shared = @($found | Where-Object { $_.ListenAddress -eq $rule.ListenAddress -and $_.ListenPort -eq $rule.ListenPort -and $_.Type -ne $rule.Type })
            $others = @($script:State.Rules | Where-Object { $_.ListenAddress -eq $rule.ListenAddress -and $_.ListenPort -eq $rule.ListenPort -and $_.Type -ne $rule.Type })
            if ($others.Count -gt $shared.Count) { Write-Output 'Firewall: rules kept (another proxy type still listens there)'; continue }
            $fw = Remove-PortRedirectFirewallRule -ListenAddress $rule.ListenAddress -ListenPort $rule.ListenPort -Protocol Both
            Write-Output "Firewall: $($fw.Message)"
        }
    }
    if ($failed -gt 0) { throw "$failed rule(s) could not be removed" }
}

function Invoke-HeadlessOrphanCleanup {
    Assert-Elevated
    $rules = @(Get-PortProxyRule)
    $orphans = @(Get-OrphanFirewallRule -Rules $rules -Table (Get-PortRedirectFirewallTable))
    if ($orphans.Count -eq 0) { Write-Output 'No orphaned PortRedirect_* firewall rules.'; return }
    $result = Remove-OrphanFirewallRule -Orphans $orphans
    foreach ($o in $orphans) { Write-Output "$(Get-HeadlessVerb 'Removed' 'Would remove') $($o.Name)" }
    if ($result.Failed.Count -gt 0) { throw "Could not remove: $($result.Failed -join '; ')" }
}

function Invoke-HeadlessRepoint {
    param([string]$From, [string]$To)
    Assert-Elevated
    $from = "$From".Trim().Trim('[', ']')
    $to = Resolve-TargetAddress $To
    $script:State.Rules = @(Get-PortProxyRule)
    $targets = @($script:State.Rules | Where-Object { $_.ConnectAddress -eq $from })
    if ($targets.Count -eq 0) { Write-Output "No rule points to $from; nothing to do."; return }
    if ($to -eq $from) { Write-Output "Rules already point to $to; nothing to do."; return }
    $failed = 0
    foreach ($rule in $targets) {
        $err = Test-AddressForRole -Address $to -Type $rule.Type -Role Connect
        if ($err) { $failed++; Write-Output "Skipped $(Format-Endpoint $rule.ListenAddress $rule.ListenPort): $err"; continue }
        $result = Set-PortProxyRule -Type $rule.Type -ListenAddress $rule.ListenAddress -ListenPort $rule.ListenPort -ConnectAddress $to -ConnectPort $rule.ConnectPort
        if ($result.Success) { Write-Output "$(Get-HeadlessVerb 'Re-pointed' 'Would re-point') $(Format-Endpoint $rule.ListenAddress $rule.ListenPort) -> $(Format-Endpoint $to $rule.ConnectPort)" }
        else { $failed++; Write-Output "Failed $(Format-Endpoint $rule.ListenAddress $rule.ListenPort): $($result.Output)" }
    }
    Write-Output "Done: $($targets.Count - $failed) $(Get-HeadlessVerb 're-pointed' 'would be re-pointed'), $failed failed."
    if ($failed -gt 0) { throw "$failed rule(s) could not be re-pointed" }
}

# =====================================================================================================
#  Entry point
# =====================================================================================================

# When dot-sourced (tests, reuse of the functions) define everything and stop here.
if ($MyInvocation.InvocationName -eq '.') { return }

# Note: "exit" is only used on failure. Calling it after emitting objects would discard PowerShell's
# deferred table output, so the success path simply lets the script end (exit code 0).
$setName = $PSCmdlet.ParameterSetName
$headless = switch ($setName) {
    'Add'     { { Invoke-HeadlessAdd -Type $Type -ListenAddress $ListenAddress -ListenPort $ListenPort -ConnectAddress $ConnectAddress -ConnectPort $ConnectPort -Firewall $Firewall } }
    'Remove'  { { Invoke-HeadlessRemove -Type $Type -ListenAddress $ListenAddress -ListenPort $ListenPort } }
    'Repoint' { { Invoke-HeadlessRepoint -From $From -To $To } }
    'Orphans' { { Invoke-HeadlessOrphanCleanup } }
    default   { $null }
}
try {
    if ($setName -eq 'List') {
        Get-PortProxyRule
    }
    elseif ($null -ne $headless) {
        if ($ElevatedOutputFile) {
            # We are the elevated child of an unelevated parent: relay everything through the file.
            exit (Invoke-HeadlessRelayChild -Command $headless -OutputFile $ElevatedOutputFile)
        }
        if (-not $WhatIfPreference -and -not $NoElevate -and -not (Test-IsElevated)) {
            $code = Invoke-ElevatedRelay -Bound $PSBoundParameters
            if ($code -ne 0) { exit $code }
        }
        else {
            & $headless
        }
    }
    else {
        if ((Invoke-Tui) -ne 0) { exit 1 }
    }
}
catch {
    Write-Error -Message $_.Exception.Message -ErrorAction Continue
    exit 1
}
