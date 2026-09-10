# Pester 5 tests for PortRedirectManager.ps1
# Run:  Invoke-Pester -Path .\tests
# The script is dot-sourced in "library mode" (no TUI, no netsh); every system boundary is mocked.
# netsh is replaced by an in-memory fake table so add/set/delete and their post-state checks are exercised.

BeforeAll {
    $scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'PortRedirectManager.ps1'
    . $scriptPath

    # Stubs so the firewall cmdlets can be mocked even where the NetSecurity module is absent.
    foreach ($name in @('New-NetFirewallRule', 'Remove-NetFirewallRule', 'Get-NetFirewallRule')) {
        if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
            Set-Item -Path "function:global:$name" -Value { param($Name) throw "stub $Name" }
        }
    }

    $script:EnglishShowAll = @(
        ''
        'Listen on ipv4:             Connect to ipv4:'
        ''
        'Address         Port        Address         Port'
        '--------------- ----------  --------------- ----------'
        '0.0.0.0         3000        192.0.2.10      3000'
        '0.0.0.0         8080        wsl.example     8080'
        '127.0.0.1       2200        192.0.2.10      22'
        ''
        'Listen on ipv6:             Connect to ipv4:'
        ''
        'Address         Port        Address         Port'
        '--------------- ----------  --------------- ----------'
        '::              443         192.0.2.10      8443'
        ''
    )

    $script:SpanishShowAll = @(
        ''
        'Escuchar en ipv4:           Conectar a ipv6:'
        ''
        'Direccion       Puerto      Direccion       Puerto'
        '--------------- ----------  --------------- ----------'
        '0.0.0.0         5000        2001:db8::10    5000'
        ''
    )

    # ---- in-memory fake of "netsh interface portproxy" ----
    function Initialize-FakeNetsh {
        param([string[]]$Lines = $script:EnglishShowAll)
        $script:FakeTable = New-Object System.Collections.Generic.List[object]
        foreach ($r in @(ConvertFrom-PortProxyOutput -Lines $Lines)) {
            $script:FakeTable.Add(@{ Type = $r.Type; LA = $r.ListenAddress; LP = $r.ListenPort; CA = $r.ConnectAddress; CP = $r.ConnectPort })
        }
    }

    function Get-FakeNetshTable {
        param([string]$Type)
        $lines = @()
        foreach ($t in @('v4tov4', 'v4tov6', 'v6tov4', 'v6tov6')) {
            if ($Type -ne 'all' -and $t -ne $Type) { continue }
            $rows = @($script:FakeTable | Where-Object { $_.Type -eq $t })
            if ($rows.Count -eq 0) { continue }
            $lines += "Listen on ipv$($t[1]):             Connect to ipv$($t[5]):"
            $lines += 'Address         Port        Address         Port'
            $lines += '--------------- ----------  --------------- ----------'
            foreach ($r in $rows) { $lines += ('{0,-15} {1,-11} {2,-15} {3}' -f $r.LA, $r.LP, $r.CA, $r.CP) }
            $lines += ''
        }
        return $lines
    }

    function Invoke-FakeNetsh {
        param([string[]]$Arguments, [switch]$ExpectNoOutput)
        $verb = $Arguments[0]
        if ($ExpectNoOutput -and $verb -eq 'show') { throw 'fake netsh: show must not be called with -ExpectNoOutput' }
        $kv = @{}
        foreach ($a in $Arguments) { if ($a -match '^(\w+)=(.+)$') { $kv[$Matches[1]] = $Matches[2] } }
        $ok = [pscustomobject]@{ Success = $true; ExitCode = 0; Output = ''; Lines = @() }
        switch ($verb) {
            'show' { $ok.Lines = Get-FakeNetshTable -Type $Arguments[1]; return $ok }
            'add' {
                $script:FakeTable.Add(@{ Type = $Arguments[1]; LA = $kv['listenaddress']; LP = [int]$kv['listenport']; CA = $kv['connectaddress']; CP = [int]$kv['connectport'] })
                return $ok
            }
            'set' {
                $row = $script:FakeTable | Where-Object { $_.Type -eq $Arguments[1] -and $_.LA -eq $kv['listenaddress'] -and $_.LP -eq [int]$kv['listenport'] } | Select-Object -First 1
                if (-not $row) { return [pscustomobject]@{ Success = $false; ExitCode = 1; Output = 'The system cannot find the file specified.'; Lines = @() } }
                $row.CA = $kv['connectaddress']; $row.CP = [int]$kv['connectport']
                return $ok
            }
            'delete' {
                $before = $script:FakeTable.Count
                $keep = @($script:FakeTable | Where-Object { -not ($_.Type -eq $Arguments[1] -and $_.LA -eq $kv['listenaddress'] -and $_.LP -eq [int]$kv['listenport']) })
                $script:FakeTable = New-Object System.Collections.Generic.List[object]
                foreach ($k in $keep) { $script:FakeTable.Add($k) }
                if ($script:FakeTable.Count -eq $before) { return [pscustomobject]@{ Success = $false; ExitCode = 1; Output = 'The system cannot find the file specified.'; Lines = @() } }
                return $ok
            }
        }
        throw "fake netsh: unknown verb $verb"
    }

    function Get-TestKey {
        param([string]$Char = "`0", [ConsoleKey]$Key, [switch]$Ctrl)
        if (-not $PSBoundParameters.ContainsKey('Key')) {
            $upper = ([string]$Char).ToUpper()
            if ($upper -match '^[A-Z]$') { $Key = [ConsoleKey]$upper }
            elseif ($upper -eq ' ') { $Key = [ConsoleKey]::Spacebar }
            else { $Key = [ConsoleKey]::NoName }
        }
        return New-Object System.ConsoleKeyInfo([char]$Char, $Key, $false, $false, [bool]$Ctrl)
    }

    function Get-KeySequence {
        # "abc" -> letter keys; tokens in braces: {Enter} {Esc} {Up} {Down} {PgUp} {PgDn} {Home} {End} {Back} {CtrlC}
        param([string]$Spec)
        $keys = New-Object System.Collections.Generic.List[object]
        $i = 0
        while ($i -lt $Spec.Length) {
            $c = $Spec[$i]
            if ($c -eq '{') {
                $end = $Spec.IndexOf('}', $i)
                $token = $Spec.Substring($i + 1, $end - $i - 1)
                $i = $end + 1
                switch ($token) {
                    'Enter' { $keys.Add((Get-TestKey -Char "`r" -Key Enter)) }
                    'Esc'   { $keys.Add((Get-TestKey -Char ([char]27) -Key Escape)) }
                    'Up'    { $keys.Add((Get-TestKey -Key UpArrow)) }
                    'Down'  { $keys.Add((Get-TestKey -Key DownArrow)) }
                    'PgUp'  { $keys.Add((Get-TestKey -Key PageUp)) }
                    'PgDn'  { $keys.Add((Get-TestKey -Key PageDown)) }
                    'Home'  { $keys.Add((Get-TestKey -Key Home)) }
                    'End'   { $keys.Add((Get-TestKey -Key End)) }
                    'Back'  { $keys.Add((Get-TestKey -Char "`b" -Key Backspace)) }
                    'CtrlC' { $keys.Add((Get-TestKey -Char ([char]3) -Key C -Ctrl)) }
                    default { throw "unknown key token {$token}" }
                }
                continue
            }
            if ($c -match '[0-9]') { $keys.Add((Get-TestKey -Char $c -Key ([ConsoleKey]"D$c"))) }
            elseif ($c -eq '.')    { $keys.Add((Get-TestKey -Char '.' -Key OemPeriod)) }
            elseif ($c -eq ',')    { $keys.Add((Get-TestKey -Char ',' -Key OemComma)) }
            elseif ($c -eq ':')    { $keys.Add((Get-TestKey -Char ':' -Key Oem1)) }
            elseif ($c -eq '?')    { $keys.Add((Get-TestKey -Char '?' -Key Oem2)) }
            elseif ($c -eq '-')    { $keys.Add((Get-TestKey -Char '-' -Key OemMinus)) }
            else                   { $keys.Add((Get-TestKey -Char $c)) }
            $i++
        }
        return $keys
    }

    function Get-PlainText {
        param([string]$Text)
        return ($Text -replace ([string][char]27 + '\[[0-9;?]*[A-Za-z]'), '')
    }

    function Initialize-TuiState {
        $script:State.Rules = @()
        $script:State.Selected = 0
        $script:State.Scroll = 0
        $script:State.Message = ''
        $script:State.Running = $true
        $script:State.NeedsReload = $true
        $script:State.WslIp = $null
        $script:State.WslChecked = $false
        $script:State.Orphans = @()
        $script:Ui.UseVT = $true
        $script:Frames = New-Object System.Collections.Generic.List[string]
        $script:Keys = New-Object System.Collections.Generic.Queue[object]
    }
}

Describe 'Address and port validation' {
    It 'accepts proper IPv4 literals' {
        Test-IPv4Address '0.0.0.0' | Should -BeTrue
        Test-IPv4Address '192.0.2.10' | Should -BeTrue
    }
    It 'rejects malformed or numeric-looking values as IPv4' {
        Test-IPv4Address '3000' | Should -BeFalse
        Test-IPv4Address '256.1.1.1' | Should -BeFalse
        Test-IPv4Address '1.2.3' | Should -BeFalse
        Test-IPv4Address '' | Should -BeFalse
    }
    It 'detects IPv6 literals, with or without brackets' {
        Test-IPv6Address '::' | Should -BeTrue
        Test-IPv6Address '[::1]' | Should -BeTrue
        Test-IPv6Address '192.0.2.10' | Should -BeFalse
    }
    It 'classifies addresses' {
        Get-AddressKind '192.0.2.10' | Should -Be 'IPv4'
        Get-AddressKind '2001:db8::1' | Should -Be 'IPv6'
        Get-AddressKind 'wsl.example' | Should -Be 'Hostname'
        Get-AddressKind 'localhost' | Should -Be 'Hostname'
        Get-AddressKind '3000' | Should -BeNullOrEmpty
        Get-AddressKind '256.1.1.1' | Should -BeNullOrEmpty
        Get-AddressKind 'my host' | Should -BeNullOrEmpty
        Get-AddressKind '' | Should -BeNullOrEmpty
    }
    It 'validates address family per proxy type and role' {
        Test-AddressForRole -Address '0.0.0.0' -Type v4tov4 -Role Listen | Should -BeNullOrEmpty
        Test-AddressForRole -Address '::' -Type v4tov4 -Role Listen | Should -Match 'must be IPv4'
        Test-AddressForRole -Address '2001:db8::1' -Type v4tov6 -Role Connect | Should -BeNullOrEmpty
        Test-AddressForRole -Address '192.0.2.10' -Type v4tov6 -Role Connect | Should -Match 'must be IPv6'
        Test-AddressForRole -Address 'host.example' -Type v6tov6 -Role Connect | Should -BeNullOrEmpty
        Test-AddressForRole -Address 'not valid!' -Type v4tov4 -Role Connect | Should -Match 'not a valid'
    }
    It 'validates port numbers' {
        Test-PortNumber '1' | Should -BeTrue
        Test-PortNumber ' 65535 ' | Should -BeTrue
        Test-PortNumber '0' | Should -BeFalse
        Test-PortNumber '65536' | Should -BeFalse
        Test-PortNumber 'abc' | Should -BeFalse
        Test-PortNumber '' | Should -BeFalse
    }
    It 'recognises loopback and wildcard listeners' {
        Test-LoopbackAddress '127.0.0.1' | Should -BeTrue
        Test-LoopbackAddress '127.5.5.5' | Should -BeTrue
        Test-LoopbackAddress '[::1]' | Should -BeTrue
        Test-LoopbackAddress '0.0.0.0' | Should -BeFalse
        Test-WildcardAddress '0.0.0.0' | Should -BeTrue
        Test-WildcardAddress '::' | Should -BeTrue
        Test-WildcardAddress '192.0.2.1' | Should -BeFalse
    }
    It 'parses port lists and ranges' {
        (@(ConvertTo-PortList '80') -join ',') | Should -Be '80'
        (@(ConvertTo-PortList '443, 80,80') -join ',') | Should -Be '80,443'
        (@(ConvertTo-PortList '3000-3003 8443') -join ',') | Should -Be '3000,3001,3002,3003,8443'
        { ConvertTo-PortList '' } | Should -Throw '*No port*'
        { ConvertTo-PortList '70000' } | Should -Throw '*not a valid port*'
        { ConvertTo-PortList '3003-3000' } | Should -Throw '*range*'
        { ConvertTo-PortList '1-65535' } | Should -Throw '*Too many*'
    }
}

Describe 'Formatting helpers' {
    It 'formats endpoints, bracketing IPv6' {
        Format-Endpoint -Address '0.0.0.0' -Port 80 | Should -Be '0.0.0.0:80'
        Format-Endpoint -Address '::1' -Port 80 | Should -Be '[::1]:80'
    }
    It 'truncates long text with a marker' {
        Limit-Text 'abcdefghij' 5 | Should -Be 'abcd~'
        Limit-Text 'abc' 5 | Should -Be 'abc'
        Limit-Text 'abc' 0 | Should -Be ''
        Limit-Text $null 3 | Should -Be ''
    }
    It 'builds and parses firewall rule names with the historical convention' {
        Get-FirewallRuleName -ListenAddress '0.0.0.0' -ListenPort 3000 -Protocol 'tcp' | Should -Be 'PortRedirect_0.0.0.0_3000_TCP'
        $p = ConvertFrom-FirewallRuleName 'PortRedirect_0.0.0.0_3000_TCP'
        $p.ListenAddress | Should -Be '0.0.0.0'
        $p.ListenPort | Should -Be 3000
        $p.Protocol | Should -Be 'TCP'
        (ConvertFrom-FirewallRuleName 'PortRedirect_::_443_UDP').ListenAddress | Should -Be '::'
        ConvertFrom-FirewallRuleName 'SomethingElse' | Should -BeNullOrEmpty
    }
    It 'keeps the connect column readable on narrow terminals' {
        $layout = Get-ColumnLayout -Width 66
        $layout.ConnectW | Should -BeGreaterOrEqual 14
        ($layout.FwX + $layout.FwW) | Should -BeLessOrEqual 66
    }
    It 'renders a rule row within the layout and truncates long hosts' {
        $rule = New-PortProxyRuleObject -Type v4tov4 -ListenAddress '0.0.0.0' -ListenPort 80 -ConnectAddress ('a' * 60 + '.example') -ConnectPort 8080 -Firewall 'T'
        $layout = Get-ColumnLayout -Width 80
        $row = Format-RuleRow -Rule $rule -Layout $layout
        $row.Length | Should -BeLessOrEqual 79
        $row | Should -Match '~'
        $row | Should -Match 'T\s*$'
    }
}

Describe 'netsh output parsing' {
    It 'parses English "show all" output including IPv6 sections and hostnames' {
        $rules = @(ConvertFrom-PortProxyOutput -Lines $script:EnglishShowAll)
        $rules.Count | Should -Be 4
        $rules[0].Type | Should -Be 'v4tov4'
        $rules[0].ListenPort | Should -Be 3000
        $rules[1].ConnectAddress | Should -Be 'wsl.example'
        $rules[2].ConnectPort | Should -Be 22
        $rules[3].Type | Should -Be 'v6tov4'
        $rules[3].ListenAddress | Should -Be '::'
        $rules[3].Listen | Should -Be '[::]:443'
    }
    It 'is locale independent (localized headers)' {
        $rules = @(ConvertFrom-PortProxyOutput -Lines $script:SpanishShowAll)
        $rules.Count | Should -Be 1
        $rules[0].Type | Should -Be 'v4tov6'
        $rules[0].ConnectAddress | Should -Be '2001:db8::10'
    }
    It 'ignores rows before any section header and tolerates CRLF and garbage' {
        $lines = @("0.0.0.0 1 1.1.1.1 1", "Listen on ipv4:  Connect to ipv4:`r", "junk line", "0.0.0.0         2   192.0.2.1   2`r", $null, '')
        $rules = @(ConvertFrom-PortProxyOutput -Lines $lines)
        $rules.Count | Should -Be 1
        $rules[0].ListenPort | Should -Be 2
    }
    It 'returns nothing for empty output' {
        @(ConvertFrom-PortProxyOutput -Lines @()).Count | Should -Be 0
        @(ConvertFrom-PortProxyOutput -Lines $null).Count | Should -Be 0
    }
    It 'exposes a 4-column default view while keeping all properties' {
        $rule = @(ConvertFrom-PortProxyOutput -Lines $script:EnglishShowAll)[0]
        $rule.PSStandardMembers.DefaultDisplayPropertySet.ReferencedPropertyNames | Should -Be @('Type', 'Listen', 'Connect', 'Firewall')
        ($rule | ConvertTo-Json | ConvertFrom-Json).ListenPort | Should -Be 3000
    }
}

Describe 'Firewall registry parsing, status and orphans' {
    It 'parses a registry rule value' {
        $fw = ConvertFrom-FirewallRuleValue -Name 'PortRedirect_0.0.0.0_3000_UDP' -Value 'v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|LPort=3000|Name=Port Redirect: x|Desc=d|'
        $fw.Enabled | Should -BeFalse
        $fw.Protocol | Should -Be 'UDP'
        $fw.LocalPort | Should -Be '3000'
        $fw.DisplayName | Should -Be 'Port Redirect: x'
    }
    It 'tolerates malformed values' {
        $fw = ConvertFrom-FirewallRuleValue -Name 'x' -Value ''
        $fw.Enabled | Should -BeFalse
        $fw.Protocol | Should -Be ''
    }
    It 'summarises status as T/U (enabled), t/u (disabled) or -' {
        $table = @{
            'PortRedirect_0.0.0.0_3000_TCP' = [pscustomobject]@{ Enabled = $true }
            'PortRedirect_0.0.0.0_3000_UDP' = [pscustomobject]@{ Enabled = $false }
            'PortRedirect_0.0.0.0_4000_UDP' = [pscustomobject]@{ Enabled = $true }
        }
        Get-FirewallStatusText -Table $table -ListenAddress '0.0.0.0' -ListenPort 3000 | Should -Be 'Tu'
        Get-FirewallStatusText -Table $table -ListenAddress '0.0.0.0' -ListenPort 4000 | Should -Be 'U'
        Get-FirewallStatusText -Table $table -ListenAddress '0.0.0.0' -ListenPort 5000 | Should -Be '-'
    }
    It 'finds firewall rules whose proxy rule is gone' {
        $rules = @(ConvertFrom-PortProxyOutput -Lines $script:EnglishShowAll)
        $table = @{
            'PortRedirect_0.0.0.0_3000_TCP' = [pscustomobject]@{ Enabled = $true }
            'PortRedirect_0.0.0.0_9999_TCP' = [pscustomobject]@{ Enabled = $true }
            'PortRedirect_::_443_UDP'       = [pscustomobject]@{ Enabled = $false }
            'PortRedirect_garbage'          = [pscustomobject]@{ Enabled = $true }
        }
        $orphans = @(Get-OrphanFirewallRule -Rules $rules -Table $table)
        $orphans.Count | Should -Be 1
        $orphans[0].Name | Should -Be 'PortRedirect_0.0.0.0_9999_TCP'
    }
    It 'reads the registry first and falls back to Get-NetFirewallRule' {
        Mock Get-ItemProperty { throw 'no registry' }
        Mock Get-NetFirewallRule { [pscustomobject]@{ Name = 'PortRedirect_0.0.0.0_1_TCP'; Enabled = 'True'; DisplayName = 'x'; Direction = 'Inbound' } }
        $table = Get-PortRedirectFirewallTable
        $table.Keys | Should -Contain 'PortRedirect_0.0.0.0_1_TCP'
        $table['PortRedirect_0.0.0.0_1_TCP'].Enabled | Should -BeTrue
        Should -Invoke Get-NetFirewallRule -Times 1 -Exactly
    }
    It 'filters registry values by the PortRedirect_ prefix' {
        Mock Get-ItemProperty {
            [pscustomobject]@{
                'PortRedirect_0.0.0.0_1_TCP' = 'v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=1|Name=n|'
                'SomethingElse'               = 'v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=2|Name=n|'
                'PSPath'                      = 'x'
            }
        }
        $table = Get-PortRedirectFirewallTable
        $table.Count | Should -Be 1
        $table['PortRedirect_0.0.0.0_1_TCP'].Protocol | Should -Be 'TCP'
    }
}

Describe 'System layer with a fake netsh' {
    BeforeEach {
        Initialize-FakeNetsh
        Mock Invoke-Netsh { Invoke-FakeNetsh -Arguments $Arguments -ExpectNoOutput:$ExpectNoOutput }
        Mock Get-PortRedirectFirewallTable { @{ 'PortRedirect_0.0.0.0_3000_TCP' = [pscustomobject]@{ Enabled = $true } } }
    }
    It 'Get-PortProxyRule merges firewall status into parsed rules and sorts them' {
        Initialize-FakeNetsh -Lines @('Listen on ipv4: Connect to ipv4:', '0.0.0.0 9 192.0.2.1 9', '0.0.0.0 3000 192.0.2.10 3000', 'Listen on ipv6: Connect to ipv4:', ':: 443 192.0.2.10 8443')
        $rules = @(Get-PortProxyRule)
        $rules.Count | Should -Be 3
        $rules[0].ListenPort | Should -Be 9
        $rules[1].Firewall | Should -Be 'T'
        $rules[0].Firewall | Should -Be '-'
        $rules[2].Type | Should -Be 'v6tov4'
        Should -Invoke Invoke-Netsh -Times 1 -Exactly -ParameterFilter { ($Arguments -join ' ') -eq 'show all' }
    }
    It 'Get-PortProxyRule throws when netsh fails' {
        Mock Invoke-Netsh { [pscustomobject]@{ Success = $false; ExitCode = 1; Output = 'boom'; Lines = @() } }
        { Get-PortProxyRule } | Should -Throw '*boom*'
    }
    It 'Add/Set/Remove pass an argument array and verify the table afterwards' {
        $r = Add-PortProxyRule -Type v4tov4 -ListenAddress '0.0.0.0' -ListenPort 4000 -ConnectAddress 'wsl.example' -ConnectPort 4001
        $r.Success | Should -BeTrue
        Should -Invoke Invoke-Netsh -Times 1 -Exactly -ParameterFilter { ($Arguments -join ' ') -eq 'add v4tov4 listenaddress=0.0.0.0 listenport=4000 connectaddress=wsl.example connectport=4001' -and $ExpectNoOutput }
        Should -Invoke Invoke-Netsh -Times 1 -Exactly -ParameterFilter { ($Arguments -join ' ') -eq 'show v4tov4' }
        $r = Set-PortProxyRule -Type v6tov4 -ListenAddress '::' -ListenPort 443 -ConnectAddress '192.0.2.10' -ConnectPort 8443
        $r.Success | Should -BeTrue
        Should -Invoke Invoke-Netsh -Times 1 -Exactly -ParameterFilter { ($Arguments -join ' ') -eq 'set v6tov4 listenaddress=:: listenport=443 connectaddress=192.0.2.10 connectport=8443' }
        $r = Remove-PortProxyRule -Type v4tov4 -ListenAddress '0.0.0.0' -ListenPort 3000
        $r.Success | Should -BeTrue
        Should -Invoke Invoke-Netsh -Times 1 -Exactly -ParameterFilter { ($Arguments -join ' ') -eq 'delete v4tov4 listenaddress=0.0.0.0 listenport=3000' }
        @($script:FakeTable | Where-Object { $_.LP -eq 3000 }).Count | Should -Be 0
    }
    It 'treats netsh output as failure even with exit code 0, and detects a missing post-state' {
        Mock Invoke-Netsh { [pscustomobject]@{ Success = (-not $ExpectNoOutput); ExitCode = 0; Output = 'The syntax supplied for this command is not valid.'; Lines = @() } }
        $r = Add-PortProxyRule -ListenAddress '0.0.0.0' -ListenPort 5 -ConnectAddress '192.0.2.1' -ConnectPort 5
        $r.Success | Should -BeFalse
        $r.Output | Should -Match 'syntax'
        # netsh silent but the table does not change:
        Mock Invoke-Netsh { if ($Arguments[0] -eq 'show') { return [pscustomobject]@{ Success = $true; ExitCode = 0; Output = ''; Lines = $script:EnglishShowAll } }; [pscustomobject]@{ Success = $true; ExitCode = 0; Output = ''; Lines = @() } }
        $r = Add-PortProxyRule -ListenAddress '0.0.0.0' -ListenPort 5 -ConnectAddress '192.0.2.1' -ConnectPort 5
        $r.Success | Should -BeFalse
        $r.Output | Should -Match 'not in the table'
        $r = Remove-PortProxyRule -ListenAddress '0.0.0.0' -ListenPort 3000
        $r.Success | Should -BeFalse
        $r.Output | Should -Match 'still in the table'
    }
    It 'honours -WhatIf without touching netsh' {
        $r = Add-PortProxyRule -ListenAddress '0.0.0.0' -ListenPort 1 -ConnectAddress '192.0.2.1' -ConnectPort 1 -WhatIf
        $r.Success | Should -BeTrue
        Should -Invoke Invoke-Netsh -Times 0 -Exactly
    }
    It 'creates firewall rules only when missing, scoped to specific listen addresses' {
        Mock New-NetFirewallRule { }
        $r = Add-PortRedirectFirewallRule -ListenAddress '0.0.0.0' -ListenPort 3000 -Protocol Both
        $r.Success | Should -BeTrue
        $r.Message | Should -Match 'TCP rule already exists'
        $r.Message | Should -Match 'UDP rule created'
        Should -Invoke New-NetFirewallRule -Times 1 -Exactly -ParameterFilter { $Name -eq 'PortRedirect_0.0.0.0_3000_UDP' -and $Protocol -eq 'UDP' -and $LocalPort -eq 3000 -and -not $PSBoundParameters.ContainsKey('LocalAddress') }
        $r = Add-PortRedirectFirewallRule -ListenAddress '192.0.2.7' -ListenPort 3001 -Protocol TCP
        Should -Invoke New-NetFirewallRule -Times 1 -Exactly -ParameterFilter { $Name -eq 'PortRedirect_192.0.2.7_3001_TCP' -and $LocalAddress -eq '192.0.2.7' }
    }
    It 'never creates firewall rules for loopback listeners' {
        Mock New-NetFirewallRule { }
        $r = Add-PortRedirectFirewallRule -ListenAddress '127.0.0.1' -ListenPort 3000 -Protocol TCP
        $r.Success | Should -BeTrue
        $r.Message | Should -Match 'loopback'
        Should -Invoke New-NetFirewallRule -Times 0 -Exactly
    }
    It 'reports firewall creation failures' {
        Mock New-NetFirewallRule { throw 'denied' }
        $r = Add-PortRedirectFirewallRule -ListenAddress '0.0.0.0' -ListenPort 4000 -Protocol TCP
        $r.Success | Should -BeFalse
        $r.Message | Should -Match 'denied'
    }
    It 'removes only existing firewall rules' {
        Mock Remove-NetFirewallRule { }
        $r = Remove-PortRedirectFirewallRule -ListenAddress '0.0.0.0' -ListenPort 3000 -Protocol Both
        $r.Message | Should -Match 'TCP rule removed'
        $r.Message | Should -Match 'UDP rule not present'
        Should -Invoke Remove-NetFirewallRule -Times 1 -Exactly -ParameterFilter { $Name -eq 'PortRedirect_0.0.0.0_3000_TCP' }
    }
    It 'removes orphaned firewall rules and reports failures' {
        Mock Remove-NetFirewallRule { if ($Name -match '_2_') { throw 'locked' } }
        $orphans = @([pscustomobject]@{ Name = 'PortRedirect_0.0.0.0_1_TCP' }, [pscustomobject]@{ Name = 'PortRedirect_0.0.0.0_2_TCP' })
        $r = Remove-OrphanFirewallRule -Orphans $orphans
        $r.Removed | Should -Be 1
        $r.Failed.Count | Should -Be 1
        $r.Failed[0] | Should -Match 'locked'
    }
}

Describe 'WSL detection' {
    BeforeEach { $script:State.WslChecked = $false; $script:State.WslIp = $null }
    It 'returns the first IPv4 of "hostname -I" when a distro runs' {
        Mock Invoke-WslCommand {
            if ($Arguments[0] -eq '-l') { return @('Ubuntu', '') }
            return @('192.0.2.50 198.51.100.1 fd00::1')
        }
        Get-WslIPAddress | Should -Be '192.0.2.50'
        Get-WslIPAddress | Should -Be '192.0.2.50'
        Should -Invoke Invoke-WslCommand -Times 2 -Exactly   # cached on the second call
        Get-WslIPAddress -Refresh | Should -Be '192.0.2.50'
        Should -Invoke Invoke-WslCommand -Times 4 -Exactly
        Should -Invoke Invoke-WslCommand -Times 2 -Exactly -ParameterFilter { $Arguments[0] -eq '--exec' -and $Arguments[1] -eq 'hostname' }
    }
    It 'does not start a stopped distribution' {
        Mock Invoke-WslCommand { if ($Arguments[0] -eq '-l') { return @('', "`0") }; throw 'must not be called' }
        Get-WslIPAddress | Should -BeNullOrEmpty
        Should -Invoke Invoke-WslCommand -Times 1 -Exactly
    }
    It 'survives a missing wsl.exe' {
        Mock Invoke-WslCommand { throw 'not found' }
        Get-WslIPAddress | Should -BeNullOrEmpty
    }
    It 'resolves the wsl keyword and strips brackets from literals' {
        Mock Get-WslIPAddress { '192.0.2.50' }
        Resolve-TargetAddress 'WSL' | Should -Be '192.0.2.50'
        Resolve-TargetAddress ' wsl2 ' | Should -Be '192.0.2.50'
        Resolve-TargetAddress '[::1]' | Should -Be '::1'
        Resolve-TargetAddress 'host.example' | Should -Be 'host.example'
    }
    It 'fails clearly when the wsl keyword cannot be resolved' {
        Mock Get-WslIPAddress { $null }
        { Resolve-TargetAddress 'wsl' } | Should -Throw '*WSL2 IP*'
    }
}

Describe 'Headless commands' {
    BeforeEach {
        Initialize-FakeNetsh
        Mock Test-IsElevated { $true }
        Mock Invoke-Netsh { Invoke-FakeNetsh -Arguments $Arguments -ExpectNoOutput:$ExpectNoOutput }
        Mock Get-PortRedirectFirewallTable { @{ 'PortRedirect_0.0.0.0_3000_TCP' = [pscustomobject]@{ Enabled = $true } } }
        Mock New-NetFirewallRule { }
        Mock Remove-NetFirewallRule { }
    }
    It 'Add creates the rule and the TCP firewall rule by default' {
        $out = @(Invoke-HeadlessAdd -Type '' -ListenAddress '0.0.0.0' -ListenPort 9000 -ConnectAddress '192.0.2.77' -ConnectPort 0 -Firewall TCP)
        $out[0] | Should -Be 'Added v4tov4 0.0.0.0:9000 -> 192.0.2.77:9000'
        $out[1] | Should -Match 'TCP rule created'
        Should -Invoke Invoke-Netsh -Times 1 -Exactly -ParameterFilter { $Arguments[0] -eq 'add' -and ($Arguments -contains 'connectport=9000') }
    }
    It 'Add accepts several listen ports (list, range, or both) and maps each to the same port on the target' {
        $out = @(Invoke-HeadlessAdd -Type '' -ListenAddress '0.0.0.0' -ListenPort @('7001,7002', '7001') -ConnectAddress '192.0.2.77' -ConnectPort 0 -Firewall None)
        ($out -join "`n") | Should -Match 'Added v4tov4 0.0.0.0:7001 -> 192.0.2.77:7001'
        ($out -join "`n") | Should -Match 'Added v4tov4 0.0.0.0:7002 -> 192.0.2.77:7002'
        Should -Invoke Invoke-Netsh -Times 2 -Exactly -ParameterFilter { $Arguments[0] -eq 'add' }
        Should -Invoke New-NetFirewallRule -Times 0 -Exactly
        { Invoke-HeadlessAdd -Type '' -ListenAddress '0.0.0.0' -ListenPort '7003-7004' -ConnectAddress '192.0.2.77' -ConnectPort 80 -Firewall None } | Should -Throw '*single*'
        { Invoke-HeadlessAdd -Type '' -ListenAddress '0.0.0.0' -ListenPort 'abc' -ConnectAddress '192.0.2.77' -ConnectPort 0 -Firewall None } | Should -Throw '*not a valid port*'
    }
    It 'Add refuses duplicates and bad addresses' {
        { Invoke-HeadlessAdd -Type 'v4tov4' -ListenAddress '0.0.0.0' -ListenPort 3000 -ConnectAddress '192.0.2.77' -ConnectPort 0 -Firewall None } | Should -Throw '*already exists*'
        { Invoke-HeadlessAdd -Type 'v4tov4' -ListenAddress '0.0.0.0' -ListenPort 9001 -ConnectAddress '::1' -ConnectPort 0 -Firewall None } | Should -Throw '*must be IPv4*'
        Should -Invoke Invoke-Netsh -Times 0 -Exactly -ParameterFilter { $Arguments[0] -eq 'add' }
    }
    It 'Add requires elevation unless -WhatIf' {
        Mock Test-IsElevated { $false }
        { Invoke-HeadlessAdd -Type '' -ListenAddress '0.0.0.0' -ListenPort 9002 -ConnectAddress '192.0.2.1' -ConnectPort 0 -Firewall None } | Should -Throw '*elevated*'
    }
    It 'Remove deletes the proxy rule first and then its firewall rules' {
        $out = @(Invoke-HeadlessRemove -Type '' -ListenAddress '0.0.0.0' -ListenPort 3000)
        $out[0] | Should -Match 'Removed v4tov4 0.0.0.0:3000'
        $out[1] | Should -Match 'TCP rule removed'
        Should -Invoke Remove-NetFirewallRule -Times 1 -Exactly
        Should -Invoke Invoke-Netsh -Times 1 -Exactly -ParameterFilter { $Arguments[0] -eq 'delete' -and $Arguments[1] -eq 'v4tov4' }
    }
    It 'Remove keeps the firewall rule when the netsh delete fails' {
        Mock Invoke-Netsh { if ($Arguments[0] -eq 'delete') { return [pscustomobject]@{ Success = $false; ExitCode = 1; Output = 'nope'; Lines = @() } }; Invoke-FakeNetsh -Arguments $Arguments }
        { Invoke-HeadlessRemove -Type '' -ListenAddress '0.0.0.0' -ListenPort 3000 } | Should -Throw '*could not be removed*'
        Should -Invoke Remove-NetFirewallRule -Times 0 -Exactly
    }
    It 'Remove fails when nothing matches' {
        { Invoke-HeadlessRemove -Type '' -ListenAddress '0.0.0.0' -ListenPort 1 } | Should -Throw '*No rule listens*'
    }
    It 'Repoint updates every rule with the old target, skipping family mismatches' {
        $out = @(Invoke-HeadlessRepoint -From '192.0.2.10' -To '192.0.2.99')
        Should -Invoke Invoke-Netsh -Times 3 -Exactly -ParameterFilter { $Arguments[0] -eq 'set' -and ($Arguments -contains 'connectaddress=192.0.2.99') }
        $out[-1] | Should -Match '3 re-pointed, 0 failed'
        Mock Get-WslIPAddress { '192.0.2.50' }
        $out = @(Invoke-HeadlessRepoint -From 'wsl.example' -To 'wsl')
        Should -Invoke Invoke-Netsh -Times 1 -Exactly -ParameterFilter { $Arguments[0] -eq 'set' -and ($Arguments -contains 'connectaddress=192.0.2.50') }
    }
    It 'Repoint is a no-op when nothing points to the source' {
        $out = @(Invoke-HeadlessRepoint -From '203.0.113.1' -To '192.0.2.99')
        $out[0] | Should -Match 'nothing to do'
        Should -Invoke Invoke-Netsh -Times 0 -Exactly -ParameterFilter { $Arguments[0] -eq 'set' }
    }
    It 'Remove accepts a port list' {
        $out = @(Invoke-HeadlessRemove -Type '' -ListenAddress '0.0.0.0' -ListenPort '3000,8080')
        ($out -join "`n") | Should -Match 'Removed v4tov4 0.0.0.0:3000'
        ($out -join "`n") | Should -Match 'Removed v4tov4 0.0.0.0:8080'
        Should -Invoke Invoke-Netsh -Times 2 -Exactly -ParameterFilter { $Arguments[0] -eq 'delete' }
    }
    It 'RemoveOrphans reports when there is nothing to do' {
        $out = @(Invoke-HeadlessOrphanCleanup)
        $out[0] | Should -Match 'No orphaned'
        Should -Invoke Remove-NetFirewallRule -Times 0 -Exactly
    }
    It 'RemoveOrphans deletes only firewall rules without a proxy rule' {
        Mock Get-PortRedirectFirewallTable { @{ 'PortRedirect_0.0.0.0_3000_TCP' = [pscustomobject]@{ Enabled = $true }; 'PortRedirect_0.0.0.0_9999_TCP' = [pscustomobject]@{ Enabled = $true } } }
        $out = @(Invoke-HeadlessOrphanCleanup)
        $out[0] | Should -Be 'Removed PortRedirect_0.0.0.0_9999_TCP'
        Should -Invoke Remove-NetFirewallRule -Times 1 -Exactly -ParameterFilter { $Name -eq 'PortRedirect_0.0.0.0_9999_TCP' }
    }
}

Describe 'TUI (rendered off-screen with scripted keys)' {
    BeforeEach {
        Initialize-TuiState
        Initialize-FakeNetsh
        Mock Get-ConsoleSize { @{ Width = 100; Height = 30 } }
        Mock Clear-Console { }
        Mock Test-KeyAvailable { $true }
        Mock Write-ConsoleRaw { $script:Frames.Add($Text) }
        Mock Read-TuiKey { if ($script:Keys.Count -eq 0) { throw 'test key queue exhausted' }; $script:Keys.Dequeue() }
        Mock Get-IpHelperStatus { 'Running' }
        Mock Get-WslIPAddress { '192.0.2.50' }
        Mock Invoke-Netsh { Invoke-FakeNetsh -Arguments $Arguments -ExpectNoOutput:$ExpectNoOutput }
        Mock Get-PortRedirectFirewallTable { @{ 'PortRedirect_0.0.0.0_3000_TCP' = [pscustomobject]@{ Enabled = $true } } }
        Mock New-NetFirewallRule { }
        Mock Remove-NetFirewallRule { }
    }

    It 'renders the rule list and does not reload rules on navigation' {
        foreach ($k in (Get-KeySequence '{Down}{Down}{Up}{End}{Home}{PgDn}q')) { $script:Keys.Enqueue($k) }
        Invoke-MainLoop
        $text = Get-PlainText ($script:Frames -join "`n")
        $text | Should -Match 'NAT Port Redirect Manager'
        $text | Should -Match '0\.0\.0\.0:3000\s+192\.0\.2\.10:3000\s+T'
        $text | Should -Match 'wsl\.example:8080'
        $text | Should -Match '\[::\]:443'
        $text | Should -Match 'WSL2 IP: 192\.0\.2\.50'
        $script:State.Running | Should -BeFalse
        Should -Invoke Invoke-Netsh -Times 1 -Exactly -ParameterFilter { ($Arguments -join ' ') -eq 'show all' }
    }

    It 'quits on Esc and on Ctrl+C' {
        $script:Keys.Enqueue((Get-KeySequence '{Esc}')[0])
        Invoke-MainLoop
        $script:State.Running | Should -BeFalse
        Initialize-TuiState
        $script:Keys.Enqueue((Get-KeySequence '{CtrlC}')[0])
        Invoke-MainLoop
        $script:State.Running | Should -BeFalse
    }

    It 'scrolls a long list and keeps the selection visible' {
        $many = 1..60 | ForEach-Object { "0.0.0.0         $($_ + 10000)       192.0.2.10      $($_ + 10000)" }
        Initialize-FakeNetsh -Lines (@('Listen on ipv4: Connect to ipv4:') + $many)
        foreach ($k in (Get-KeySequence '{End}q')) { $script:Keys.Enqueue($k) }
        Invoke-MainLoop
        $script:State.Selected | Should -Be 59
        $last = Get-PlainText $script:Frames[-1]
        $last | Should -Match '0\.0\.0\.0:10060'
        $last | Should -Match ' 60/60 '
        $last | Should -Match '\^'
    }

    It 'shows a message instead of crashing on a tiny terminal' {
        Mock Get-ConsoleSize { @{ Width = 40; Height = 10 } }
        foreach ($k in (Get-KeySequence 'aq')) { $script:Keys.Enqueue($k) }
        Invoke-MainLoop
        (Get-PlainText ($script:Frames -join "`n")) | Should -Match 'Terminal too small'
        Should -Invoke Invoke-Netsh -Times 0 -Exactly -ParameterFilter { $Arguments[0] -eq 'add' }
    }

    It 'adds a rule through the wizard (WSL2 target, TCP firewall)' {
        # a, type v4tov4, listen 0.0.0.0, port 5555, connect WSL2, connect port default, firewall TCP (first option), confirm, quit
        foreach ($k in (Get-KeySequence 'a{Enter}{Enter}5555{Enter}{Enter}{Enter}{Enter}yq')) { $script:Keys.Enqueue($k) }
        Invoke-MainLoop
        Should -Invoke Invoke-Netsh -Times 1 -Exactly -ParameterFilter { ($Arguments -join ' ') -eq 'add v4tov4 listenaddress=0.0.0.0 listenport=5555 connectaddress=192.0.2.50 connectport=5555' }
        Should -Invoke New-NetFirewallRule -Times 1 -Exactly -ParameterFilter { $Name -eq 'PortRedirect_0.0.0.0_5555_TCP' }
        (Get-PlainText ($script:Frames -join "`n")) | Should -Match 'Rule added: 0\.0\.0\.0:5555 -> 192\.0\.2\.50:5555; TCP firewall rule created'
    }

    It 'adds several rules at once from a port list and skips the connect-port step' {
        foreach ($k in (Get-KeySequence 'a{Enter}{Enter}7000-7002,7010{Enter}{Enter}{Enter}yq')) { $script:Keys.Enqueue($k) }
        Invoke-MainLoop
        Should -Invoke Invoke-Netsh -Times 4 -Exactly -ParameterFilter { $Arguments[0] -eq 'add' }
        Should -Invoke Invoke-Netsh -Times 1 -Exactly -ParameterFilter { ($Arguments -join ' ') -eq 'add v4tov4 listenaddress=0.0.0.0 listenport=7010 connectaddress=192.0.2.50 connectport=7010' }
        Should -Invoke New-NetFirewallRule -Times 4 -Exactly
        (Get-PlainText ($script:Frames -join "`n")) | Should -Match '4 of 4 rules added'
    }

    It 'skips the firewall step for loopback listeners' {
        # listen option 2 = 127.0.0.1
        foreach ($k in (Get-KeySequence 'a{Enter}{Down}{Enter}5556{Enter}{Enter}{Enter}yq')) { $script:Keys.Enqueue($k) }
        Invoke-MainLoop
        Should -Invoke Invoke-Netsh -Times 1 -Exactly -ParameterFilter { ($Arguments -join ' ') -eq 'add v4tov4 listenaddress=127.0.0.1 listenport=5556 connectaddress=192.0.2.50 connectport=5556' }
        Should -Invoke New-NetFirewallRule -Times 0 -Exactly
        (Get-PlainText ($script:Frames -join "`n")) | Should -Match 'not needed \(loopback listener\)'
    }

    It 'rejects duplicates and bad ports in the wizard, and cancels with Esc' {
        foreach ($k in (Get-KeySequence 'a{Enter}{Enter}3000{Enter}abc{Enter}{Esc}q')) { $script:Keys.Enqueue($k) }
        Invoke-MainLoop
        $text = Get-PlainText ($script:Frames -join "`n")
        $text | Should -Match 'already exists'
        $text | Should -Match "'abc' is not a valid port"
        $text | Should -Match 'Add cancelled'
        Should -Invoke Invoke-Netsh -Times 0 -Exactly -ParameterFilter { $Arguments[0] -eq 'add' }
    }

    It 'validates typed connect addresses against the proxy type' {
        # connect: option 3 = type it -> '::1' (rejected) -> 'host.example' ok; port default; firewall TCP; confirm
        foreach ($k in (Get-KeySequence 'a{Enter}{Enter}6000{Enter}3::1{Enter}host.example{Enter}{Enter}{Enter}yq')) { $script:Keys.Enqueue($k) }
        Invoke-MainLoop
        (Get-PlainText ($script:Frames -join "`n")) | Should -Match 'must be IPv4'
        Should -Invoke Invoke-Netsh -Times 1 -Exactly -ParameterFilter { ($Arguments -join ' ') -eq 'add v4tov4 listenaddress=0.0.0.0 listenport=6000 connectaddress=host.example connectport=6000' }
    }

    It 'reports a netsh failure from the wizard without creating firewall rules' {
        Mock Invoke-Netsh { if ($Arguments[0] -eq 'add') { return [pscustomobject]@{ Success = $false; ExitCode = 0; Output = 'The parameter is incorrect.'; Lines = @() } }; Invoke-FakeNetsh -Arguments $Arguments }
        foreach ($k in (Get-KeySequence 'a{Enter}{Enter}5557{Enter}{Enter}{Enter}{Enter}yq')) { $script:Keys.Enqueue($k) }
        Invoke-MainLoop
        Should -Invoke New-NetFirewallRule -Times 0 -Exactly
        (Get-PlainText ($script:Frames -join "`n")) | Should -Match 'problems: 5557: The parameter is incorrect'
    }

    It 'edits the target of the selected rule with netsh set' {
        # select second rule (0.0.0.0:8080 -> wsl.example), e, choose "Keep", type new port 9090, confirm
        foreach ($k in (Get-KeySequence '{Down}e{Enter}9090{Enter}yq')) { $script:Keys.Enqueue($k) }
        Invoke-MainLoop
        Should -Invoke Invoke-Netsh -Times 1 -Exactly -ParameterFilter { ($Arguments -join ' ') -eq 'set v4tov4 listenaddress=0.0.0.0 listenport=8080 connectaddress=wsl.example connectport=9090' }
        (Get-PlainText ($script:Frames -join "`n")) | Should -Match 'Rule updated'
    }

    It 'reports "No changes" when the edit keeps everything' {
        foreach ($k in (Get-KeySequence 'e{Enter}{Enter}q')) { $script:Keys.Enqueue($k) }
        Invoke-MainLoop
        (Get-PlainText ($script:Frames -join "`n")) | Should -Match 'No changes made'
        Should -Invoke Invoke-Netsh -Times 0 -Exactly -ParameterFilter { $Arguments[0] -eq 'set' }
    }

    It 'deletes the selected rule and then its firewall rules after confirmation' {
        foreach ($k in (Get-KeySequence 'dnd yq')) { $script:Keys.Enqueue($k) }   # first delete cancelled with n, 2nd confirmed (space ignored)
        Invoke-MainLoop
        Should -Invoke Invoke-Netsh -Times 1 -Exactly -ParameterFilter { ($Arguments -join ' ') -eq 'delete v4tov4 listenaddress=0.0.0.0 listenport=3000' }
        Should -Invoke Remove-NetFirewallRule -Times 1 -Exactly -ParameterFilter { $Name -eq 'PortRedirect_0.0.0.0_3000_TCP' }
        $text = Get-PlainText ($script:Frames -join "`n")
        $text | Should -Match 'Delete cancelled'
        $text | Should -Match 'Deleted v4tov4 0\.0\.0\.0:3000; firewall: TCP rule removed'
        Should -Invoke Invoke-Netsh -Times 2 -Exactly -ParameterFilter { ($Arguments -join ' ') -eq 'show all' }   # initial load + reload after delete
    }

    It 'keeps the firewall rule when another proxy type still listens on the same endpoint' {
        Initialize-FakeNetsh -Lines @('Listen on ipv4: Connect to ipv4:', '0.0.0.0 3000 192.0.2.10 3000', 'Listen on ipv4: Connect to ipv6:', '0.0.0.0 3000 2001:db8::1 3000')
        foreach ($k in (Get-KeySequence 'dyq')) { $script:Keys.Enqueue($k) }
        Invoke-MainLoop
        Should -Invoke Invoke-Netsh -Times 1 -Exactly -ParameterFilter { $Arguments[0] -eq 'delete' }
        Should -Invoke Remove-NetFirewallRule -Times 0 -Exactly
        (Get-PlainText ($script:Frames -join "`n")) | Should -Match 'firewall rules kept'
    }

    It 're-points every rule with the chosen target to the WSL2 IP' {
        # p, From: first group (192.0.2.10, 3 rules), To: WSL2 (first option), confirm
        foreach ($k in (Get-KeySequence 'p{Enter}{Enter}yq')) { $script:Keys.Enqueue($k) }
        Invoke-MainLoop
        Should -Invoke Invoke-Netsh -Times 3 -Exactly -ParameterFilter { $Arguments[0] -eq 'set' -and ($Arguments -contains 'connectaddress=192.0.2.50') }
        (Get-PlainText ($script:Frames -join "`n")) | Should -Match 'Re-pointed 3 rule'
    }

    It 'manages firewall rules from the firewall dialog' {
        foreach ($k in (Get-KeySequence 'f2{Esc}q')) { $script:Keys.Enqueue($k) }
        Invoke-MainLoop
        Should -Invoke New-NetFirewallRule -Times 1 -Exactly -ParameterFilter { $Name -eq 'PortRedirect_0.0.0.0_3000_UDP' }
    }

    It 'shows orphaned firewall rules in the header and removes them with O' {
        Mock Get-PortRedirectFirewallTable { @{ 'PortRedirect_0.0.0.0_3000_TCP' = [pscustomobject]@{ Enabled = $true }; 'PortRedirect_0.0.0.0_9999_TCP' = [pscustomobject]@{ Enabled = $true } } }
        foreach ($k in (Get-KeySequence 'oyq')) { $script:Keys.Enqueue($k) }
        Invoke-MainLoop
        $text = Get-PlainText ($script:Frames -join "`n")
        $text | Should -Match '1 orphan FW rule \[O\]'
        $text | Should -Match 'Removed 1 orphaned'
        Should -Invoke Remove-NetFirewallRule -Times 1 -Exactly -ParameterFilter { $Name -eq 'PortRedirect_0.0.0.0_9999_TCP' }
    }

    It 'shows the help screen' {
        foreach ($k in (Get-KeySequence '?{Enter}q')) { $script:Keys.Enqueue($k) }
        Invoke-MainLoop
        (Get-PlainText ($script:Frames -join "`n")) | Should -Match 'FW COLUMN'
    }

    It 'offers to start a stopped IP Helper service and to restart a running one' {
        Mock Get-IpHelperStatus { 'Stopped' }
        Mock Start-IpHelperService { }
        foreach ($k in (Get-KeySequence 'syq')) { $script:Keys.Enqueue($k) }
        Invoke-MainLoop
        Should -Invoke Start-IpHelperService -Times 1 -Exactly -ParameterFilter { -not $Restart }
        (Get-PlainText ($script:Frames -join "`n")) | Should -Match 'rules inactive'
        Initialize-TuiState
        Mock Get-IpHelperStatus { 'Running' }
        foreach ($k in (Get-KeySequence 'syq')) { $script:Keys.Enqueue($k) }
        Invoke-MainLoop
        Should -Invoke Start-IpHelperService -Times 1 -Exactly -ParameterFilter { $Restart }
    }

    It 'renders through the non-VT fallback path without errors' {
        $script:Ui.UseVT = $false
        Mock Read-TuiKey { (Get-KeySequence 'q')[0] }
        { Invoke-MainLoop } | Should -Not -Throw
    }
}
