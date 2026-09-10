# NAT Port Redirect Manager

[![CI](https://github.com/oriolrius/nat-port-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/oriolrius/nat-port-manager/actions/workflows/ci.yml)
![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%20%7C%207-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-green)

A fast, single-file PowerShell tool for managing Windows **port-proxy (NAT redirect) rules** together with the
matching **Windows Firewall** rules. It has a keyboard-driven terminal UI and a headless CLI for scripts.

Built for **WSL2** users who want to reach services running inside WSL from other machines on the LAN, but it
works for any `netsh interface portproxy` redirect.

```
========================== NAT Port Redirect Manager ==========================
 WSL2 IP: 192.0.2.50        IP Helper: Running                    4 rules  138 ms
 TYPE     LISTEN ON               REDIRECT TO                               FW
-------------------------------------------------------------------------------
> v4tov4   0.0.0.0:3000            192.0.2.50:3000                           T
  v4tov4   0.0.0.0:8080            wsl.lan.example:8080                      T
  v4tov4   127.0.0.1:2200          192.0.2.50:22                             -
  v6tov4   [::]:443                192.0.2.50:8443                           t
-------------------------------------------------------------------------------
 Rule added: 0.0.0.0:3000 -> 192.0.2.50:3000; TCP firewall rule created
===============================================================================
 Up/Dn PgUp/Dn Home/End  [A]dd [E]dit [D]el [F]irewall [P] Re-point [O]rphans [R]efresh [?] Help [Q]uit
```

## Highlights

- **Fast.** Rules are read once and cached; navigation never touches `netsh`. Firewall status comes from the
  local policy store in a few tens of milliseconds instead of the multi-second `Get-NetFirewallRule` query.
  Each screen is composed off-screen and written in a single call, so there is no flicker.
- **Safe.** `netsh` is called with an argument array (no string building, no `Invoke-Expression`), addresses and
  ports are validated against the proxy type, every change is verified against the table afterwards (netsh can
  exit 0 on failure), edits use `netsh ... set` so a failed update never loses a rule, firewall rules are scoped
  to the listen address and never created for loopback listeners, and every headless command supports `-WhatIf`.
- **WSL2-aware.** Detects the current WSL2 IP without starting a stopped distribution, re-points every stale
  rule in one go, and supports hostnames as targets so rules can follow a changing IP automatically.
- **Scriptable.** `-List` returns objects for the pipeline; `-Add`, `-Remove`, `-Repoint` and `-RemoveOrphans` run
  without any UI. `-Add` takes port lists and ranges, so one call replaces a loop of `netsh` commands.
- **Robust.** Works on Windows PowerShell 5.1 and PowerShell 7, in Windows Terminal and the classic console,
  with non-English Windows locales, small windows, and IPv6 rules.
- **Self-elevating.** Started from a normal console, it asks for administrator rights (UAC) itself: the TUI
  opens in a new elevated window and headless commands print their output back into the original one.

## Requirements

- Windows 10 or 11
- Windows PowerShell 5.1 or PowerShell 7+
- Administrator rights for anything that changes rules. You do not need to open an elevated console: the
  script asks for elevation (UAC) when required, or fails with a message if you pass `-NoElevate`.
  `-List` and `-WhatIf` never need elevation.
- The **IP Helper** service (`iphlpsvc`) must be running for port-proxy rules to have any effect. The TUI shows
  its state and can start it.

## Installation

Download `PortRedirectManager.ps1` (or clone the repository) and run it:

```powershell
powershell -ExecutionPolicy Bypass -File .\PortRedirectManager.ps1
```

From a non-elevated console a UAC prompt appears and the manager opens in a new elevated window (Windows
cannot elevate a running process in place); the original window waits until you quit the manager.

## Interactive mode

| Key | Action |
|-----|--------|
| `Up` / `Down`, `PgUp` / `PgDn`, `Home` / `End` | Move the selection |
| `A` | Add rules (guided wizard with WSL2 auto-detection; the port prompt takes lists and ranges such as `3000-3003,8443`) |
| `E` | Edit the target address/port of the selected rule (in place, via `netsh set`) |
| `D` | Delete the selected rule and its `PortRedirect_*` firewall rules |
| `F` | Add or remove TCP/UDP firewall rules for the selected rule |
| `P` | Re-point every rule that targets one address to a new address (for example the new WSL2 IP) |
| `O` | Remove orphaned `PortRedirect_*` firewall rules (their proxy rule no longer exists) |
| `R` | Reload the rules and re-detect the WSL2 IP |
| `S` | Start the IP Helper service when it is stopped, or restart it to force hostname targets to re-resolve |
| `?` / `F1` | Help |
| `Q` / `Esc` / `Ctrl+C` | Quit |

Inside wizards, `Esc` cancels, `Enter` accepts, and menu items can be picked with their number.

**FW column**

| Value | Meaning |
|-------|---------|
| `T` | Enabled inbound TCP rule for the listen port |
| `t` | Rule exists but is disabled |
| `U` / `u` | A UDP rule created by an older version (port-proxy forwards TCP only; remove it with `F` unless another service needs it) |
| `-` | No `PortRedirect_*` firewall rule |

## Headless mode

Everything the TUI does can be scripted. Failures print an error and exit with code 1.

```powershell
# List rules as objects (no elevation needed)
.\PortRedirectManager.ps1 -List
.\PortRedirectManager.ps1 -List | Where-Object ListenPort -eq 3000
.\PortRedirectManager.ps1 -List | ConvertTo-Json

# Forward 0.0.0.0:3000 to port 3000 on the current WSL2 IP; a TCP firewall rule is created by default
.\PortRedirectManager.ps1 -Add -ListenPort 3000 -ConnectAddress wsl

# Several ports in one go (same port on the target), no firewall rules
.\PortRedirectManager.ps1 -Add -ListenPort 8080,8443 -ConnectAddress my-wsl.lan.example -Firewall None
.\PortRedirectManager.ps1 -Add -ListenPort 3000-3003 -ConnectAddress wsl

# Forward to an explicit host or IP on a different port
.\PortRedirectManager.ps1 -Add -ListenPort 8443 -ConnectAddress 192.0.2.10 -ConnectPort 443

# Remove rules (and their firewall rules)
.\PortRedirectManager.ps1 -Remove -ListenPort 3000
.\PortRedirectManager.ps1 -Remove -ListenPort 3000-3003

# After a WSL restart: move every rule that pointed at the old IP to the new one
.\PortRedirectManager.ps1 -Repoint -From 192.0.2.50 -To wsl

# Delete PortRedirect_* firewall rules whose proxy rule is gone
.\PortRedirectManager.ps1 -RemoveOrphans

# Dry run any of the above
.\PortRedirectManager.ps1 -Remove -ListenPort 3000 -WhatIf
```

| Parameter | Notes |
|-----------|-------|
| `-Type` | `v4tov4` (default), `v4tov6`, `v6tov4`, `v6tov6` |
| `-ListenAddress` | Defaults to `0.0.0.0` (all IPv4 interfaces) |
| `-ListenPort` | One or more ports: `3000`, `8080,8443`, `3000-3003`, or `(3000..3003)` from PowerShell |
| `-ConnectAddress`, `-To` | IP, hostname, or the keyword `wsl` for the current WSL2 IPv4 address |
| `-ConnectPort` | Defaults to the listen port; only allowed with a single listen port |
| `-Firewall` | `TCP` (default) or `None`. Port-proxy forwards TCP only, so no UDP rule is ever created |
| `-NoElevate` | Never show a UAC prompt; fail with a message when not elevated |

Run `Get-Help .\PortRedirectManager.ps1 -Full` for the complete reference.

## Working with WSL2

**The IP changes.** WSL2 gets a new address on every restart, so rules that point at an IP go stale.
Two ways to deal with it:

1. **Re-point** the rules after each restart: press `P` in the TUI, or run
   `.\PortRedirectManager.ps1 -Repoint -From <old ip> -To wsl` from a scheduled task or a startup script.
2. **Use a hostname as the target.** `netsh` stores a hostname verbatim and resolves it on every new
   connection. If you keep a DNS record (or a `hosts` entry that you update) pointing at the WSL2 IP, rules
   targeting that name never go stale. Pick *Hostname or IP address* in the wizard, or pass
   `-ConnectAddress my-wsl.lan.example` on the command line.

**Firewall.** A port-proxy rule listening on `0.0.0.0` only becomes reachable from other machines when
Windows Firewall allows inbound traffic on that port. The wizard creates the rule for you; the `F` key manages
it later. Rules apply to all profiles (that is the point of exposing a port on the LAN), are limited to the
listen address when it is a specific one, and are never created for loopback listeners. They are named
`PortRedirect_<ListenAddress>_<ListenPort>_<TCP|UDP>`, so they are easy to find:

```powershell
Get-NetFirewallRule -Name 'PortRedirect_*' | Format-Table Name, Enabled
```

**IP Helper.** Port-proxy is implemented by the IP Helper service. If it is stopped, rules exist but nothing
listens. The TUI warns you and `S` starts it. Restarting it (also `S`) makes hostname targets resolve again.

## TCP only: what about UDP?

**`netsh portproxy` cannot forward UDP.** Every `add`/`set`/`delete` variant accepts a single protocol value,
`[[protocol=]tcp]` ("Currently only TCP is supported"); entries are stored only under
`HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\<type>\tcp`, and the IP Helper service opens TCP listeners
only. An inbound UDP firewall rule for such a port opens nothing behind it: with no UDP socket bound, datagrams
are silently dropped. That is why this tool creates TCP firewall rules only.

**Recommended: WSL2 mirrored networking** (Windows 11 22H2 build 22621.2359+ and WSL 2.0.5+, check with
`wsl --version`). WSL then shares the host's interfaces and IP addresses, so a service bound to `0.0.0.0`
inside WSL is reachable from the LAN directly, TCP or UDP, with no proxy at all:

1. In `%USERPROFILE%\.wslconfig` (or the *WSL Settings* app):
   ```ini
   [wsl2]
   networkingMode=mirrored
   ```
2. Free the port on Windows if a port-proxy rule holds it (delete it with `D` or `-Remove`).
3. Allow the port in the Hyper-V firewall (elevated PowerShell; WSL's default inbound action is Block):
   ```powershell
   New-NetFirewallHyperVRule -Name "WSL-UDP-5000" -DisplayName "WSL UDP 5000" -Direction Inbound `
       -VMCreatorId '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' -Protocol UDP -LocalPorts 5000
   ```
4. `wsl --shutdown`, start WSL again, confirm `wslinfo --networking-mode` prints `mirrored`, bind the service
   to `0.0.0.0` and test from another machine.

Caveats: Windows and Linux share one port space (a Linux bind fails if Windows already listens there);
UDP 68 and a few Windows service ports (TCP 135, 1900, 2869, 3702, 5004, 5357, 5358) are never steered to WSL;
multicast and broadcast reception is the most-reported weak spot; Docker Desktop published ports and some
VPN clients need extra care. See [Microsoft's WSL networking docs](https://learn.microsoft.com/windows/wsl/networking)
and the [Hyper-V firewall reference](https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/hyper-v-firewall).

**Fallback in NAT mode:** run a small UDP relay on the Windows side that listens on the port and forwards each
datagram to the WSL IP (a few dozen lines with `System.Net.Sockets.UdpClient`, or a tool such as
`neosmart/udpproxy`), and open the port with `F` -> *Add UDP* in the TUI. The service then sees the relay's
address instead of the client's, and the relay must be restarted when the WSL IP changes. WinNAT static
mappings (`Add-NetNatStaticMapping`) are not an option: WSL's NAT is an HNS/ICS network, not a NetNat instance.

## Troubleshooting

| Symptom | What to check |
|---------|---------------|
| No UAC prompt, "needs an elevated PowerShell" | You passed `-NoElevate`, or the session cannot show UAC (service, SSH, redirected console). Start PowerShell with *Run as Administrator* |
| Rule exists but the port is closed | IP Helper service stopped (`S`), or no firewall rule (`F`), or the target is not listening |
| Works from the Windows host but not from the LAN | The listen address must be `0.0.0.0` (not `127.0.0.1`) and a firewall rule must exist |
| WSL2 IP "not detected" | No distribution is running (`wsl -l --running`); the tool never starts one for you. Press `R` after starting it |
| Garbled box characters | Use Windows Terminal or a TrueType console font; set `PRM_NO_VT=1` to force the plain rendering path |
| Rules target an old IP after a restart | Press `P` (or run `-Repoint`), or switch the target to a hostname |

## Development

The script can be dot-sourced without starting the UI, which is how the tests load it:

```powershell
Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser
Install-Module PSScriptAnalyzer -Scope CurrentUser
Invoke-Pester -Path .\tests
Invoke-ScriptAnalyzer -Path .\PortRedirectManager.ps1 -Severity Warning
```

The test suite mocks every system boundary (`netsh`, firewall cmdlets, `wsl.exe`, the console) and drives the
TUI with scripted keystrokes, so it runs on any machine without touching real rules. CI runs it on Windows
PowerShell 5.1 and PowerShell 7.

## License

MIT. See [LICENSE](LICENSE).
