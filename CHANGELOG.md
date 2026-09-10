# Changelog

## 2.1.0

### New
- Self-elevation: started without administrator rights, the script asks for them (UAC) and relaunches itself;
  the TUI opens in a new elevated window and this window waits for it, headless commands run elevated and
  relay their output back. `-NoElevate` disables it.

### Docs
- README section "TCP only: what about UDP?": why `netsh portproxy` cannot forward UDP, the WSL2 mirrored
  networking recipe (with the Hyper-V firewall rule), and a relay-based fallback for NAT mode.
- Local-only material is kept in an ignored `private/` folder.

## 2.0.0

### Performance
- Rules are loaded once and cached; navigating the list no longer runs `netsh` and the firewall query on
  every keystroke (previously about two seconds per key).
- Firewall status is read from the local policy store in the registry (tens of milliseconds) with
  `Get-NetFirewallRule` as a fallback.
- Screens are composed off-screen and written in one call (ANSI when the host supports it, with a plain
  fallback), removing the flicker of clearing and redrawing cell by cell.
- The WSL2 IP is detected only when a distribution is running, so a stopped distribution is never started.

### New
- Headless CLI: `-List` (objects, no elevation needed), `-Add`, `-Remove`, `-Repoint`, `-RemoveOrphans`, all
  with `-WhatIf`. `-Add` and `-Remove` accept several ports.
- Re-point (`P`): move every rule that targets one address to a new address, e.g. after the WSL2 IP changed.
- The wizard's port prompt accepts lists and ranges (`8080,8443`, `3000-3003`) and creates one rule per port.
- Orphan detection (`O`): firewall rules whose proxy rule is gone are counted in the header and can be removed.
- `wsl` keyword for the target address resolves to the current WSL2 IP.
- IP Helper service status in the header, with `S` to start it when stopped or restart it when running.
- The rule list is sorted by type, listen address and port.
- Help screen (`?` / `F1`), digit shortcuts in menus, `Ctrl+C` handled like `Esc`.
- FW column distinguishes enabled (`T`/`U`) from disabled (`t`/`u`) firewall rules.
- Pester test suite that drives the TUI with scripted keys and mocks every system boundary; CI workflow.

### Changed
- Port-proxy forwards TCP only, so the wizard and `-Add` create TCP firewall rules only (`-Firewall TCP|None`,
  default `TCP`). Existing UDP rules are still shown (`U`/`u`) and can be removed from the firewall dialog.
- Firewall rules for a specific listen address are limited to that address; loopback listeners get none.
- Deleting a rule removes the proxy entry first and its firewall rules afterwards, and keeps them when another
  proxy type still listens on the same endpoint.

### Fixed
- `netsh` can exit 0 on failure (it just prints usage); success now also requires empty output and the rule
  is verified in the table after every add, set and delete.
- Command injection surface: `netsh` is called with an argument array instead of `Invoke-Expression`.
- Editing a rule uses `netsh ... set`; a failed update no longer deletes the rule.
- Firewall rules were created even when the `netsh add` failed, and the failure message was overwritten.
- Return values that leaked onto the screen (`True`, hashtables) from uncaptured calls.
- Section detection in `netsh` output relied on English headers; it now keys off the `ipv4`/`ipv6` tokens.
- Unhandled exceptions on non-numeric ports in the edit dialog and on very small terminal windows.
- Long target hostnames pushed columns off screen; columns are now truncated to the layout.
- Duplicate listen endpoints, invalid addresses and address-family mismatches are rejected with a message.

## 1.0.0
- Initial release: TUI for `netsh interface portproxy` with firewall rule integration and WSL2 IP detection.
