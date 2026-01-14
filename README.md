# NAT Port Redirect Manager

A terminal user interface (TUI) for managing Windows NAT port proxy rules with integrated firewall management. Particularly useful for WSL2 port forwarding.

## Requirements

- Windows 10/11
- Administrator privileges
- PowerShell 5.1+

## Usage

```powershell
powershell -ExecutionPolicy Bypass -File C:\tools\PortRedirectManager.ps1
```

## Features

### Port Proxy Management
- Create, edit, and delete NAT port redirect rules
- Support for all proxy types: v4tov4, v4tov6, v6tov4, v6tov6
- Auto-detect WSL2 IP address for easy configuration
- Visual list of all configured rules

### Firewall Integration
- Create inbound firewall rules alongside NAT rules
- Manage firewall rules for existing NAT entries
- Automatic cleanup of firewall rules when deleting NAT rules
- Support for TCP, UDP, or both protocols

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Up/Down` | Navigate rules list |
| `A` | Add new port redirect rule |
| `E` | Edit selected rule |
| `D` | Delete selected rule (with firewall cleanup) |
| `F` | Manage firewall rules for selected entry |
| `R` | Refresh rules list |
| `Q` / `Esc` | Quit |

## Main Screen

```
==================== NAT Port Redirect Manager ====================

TYPE        LISTEN ON                 REDIRECT TO               FW
----------  ------------------------  ------------------------  ----
> v4tov4    0.0.0.0:3000              172.25.245.23:3000        T
  v4tov4    0.0.0.0:8080              172.25.245.23:8080        TU
  v4tov4    0.0.0.0:22                172.25.245.23:22          -

------------------------------------------------------------------
[Up/Down] Navigate  [A]dd  [E]dit  [D]elete  [F]irewall  [R]efresh  [Q]uit
```

**FW Column Legend:**
- `-` = No firewall rule
- `T` = TCP rule enabled
- `U` = UDP rule enabled
- `TU` = Both TCP and UDP enabled

## Adding a Rule

The add wizard guides you through:

1. **Type** - Select proxy type (v4tov4, etc.)
2. **Listen Address** - Where to listen (0.0.0.0 for all interfaces)
3. **Listen Port** - Port to listen on
4. **Connect Address** - Destination (with WSL2 auto-detect option)
5. **Connect Port** - Destination port (defaults to listen port)
6. **Firewall Rule** - Optionally create inbound firewall rule:
   - No firewall rule
   - TCP only
   - UDP only
   - Both TCP and UDP

## Firewall Management

Press `F` on any rule to open the firewall dialog:

```
+----------------------------------------------------------+
|                    Firewall Rules                         |
+----------------------------------------------------------+
| NAT Rule: 0.0.0.0:3000                                   |
|                                                           |
| TCP: ENABLED           UDP: disabled                      |
|                                                           |
| [1] Add TCP     [2] Add UDP     [3] Add Both             |
| [4] Remove TCP  [5] Remove UDP  [6] Remove All           |
|                                                           |
| [Esc] Back                                                |
+----------------------------------------------------------+
```

## Firewall Rule Naming

Firewall rules are created with the naming convention:
```
PortRedirect_{ListenAddress}_{ListenPort}_{Protocol}
```

Example: `PortRedirect_0.0.0.0_3000_TCP`

## Verifying Firewall Rules

To view created firewall rules outside the TUI:

```powershell
Get-NetFirewallRule -Name "PortRedirect_*" | Format-Table Name, DisplayName, Enabled
```

## Common Use Cases

### Expose WSL2 Service to LAN

1. Press `A` to add rule
2. Select `v4tov4`
3. Listen Address: `0.0.0.0` (all interfaces)
4. Listen Port: `3000`
5. Connect Address: Select `WSL2` (auto-detected)
6. Connect Port: Press Enter (same as listen)
7. Firewall: Select `TCP only`

### Forward Multiple Ports

Repeat the add process for each port you need to forward (e.g., 80, 443, 3000, 8080).

## Troubleshooting

**"This script requires Administrator privileges"**
- Right-click PowerShell and select "Run as Administrator"

**Firewall rules not working**
- Ensure Windows Firewall service is running
- Check if Group Policy restricts firewall changes

**WSL2 IP not detected**
- Ensure WSL2 is running: `wsl hostname -I`
- The IP changes on each WSL restart; update rules accordingly
