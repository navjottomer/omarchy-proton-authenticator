# Authenticator (navjottomer.proton-authenticator)

Omarchy bar widget for Proton Authenticator TOTP codes. Forked from
[mapski/omarchy.proton.auth.git-plugin](https://github.com/mapski/omarchy.proton.auth.git-plugin)
(MIT). The vault reader (`bin/protonauth_list.py`) and clipboard check
(`bin/protonauth-clipcheck`) are the upstream code with small changes; the
panel is rewritten.

## Use

Open it from the bar icon or the hotkey, then:

| Key | Action |
|---|---|
| type | filter accounts |
| Enter | copy the current code |
| Shift+Enter | copy the next code |
| Up/Down, Ctrl+J/K, PgUp/PgDn | move |
| Ctrl+P / right-click | pin or unpin (pinned accounts sort first) |
| Esc | close |

Right-click the bar icon to reload from the vault.

IPC: `omarchy shell navjottomer.proton-authenticator toggle`
(also `open`, `close`, `refresh`, `clearClipboard`).

## Settings (shell.json layout entry)

| Key | Default | |
|---|---|---|
| `sortMode` | `recent` | after pinned: `recent` (last copied first, then A–Z), `alpha` or `vault` (app order) |
| `closeOnCopy` | `true` | close the panel after copying |
| `notifyOnCopy` | `true` | desktop notification naming the account |
| `clipboardClearSec` | `20` | clear the copied code if still on the clipboard; `0` = never |
| `demoMode` | `false` | fake accounts, never reads the vault |

## How it differs from upstream

- The helper returns 10 codes per entry (about 5 minutes). The panel picks the
  current one from its own clock, so the vault is decrypted about every 5
  minutes while open instead of every second. Seeds still never leave the
  helper; only codes do. Codes are dropped when the panel closes.
- Search box has focus on open; the shell's key catcher is not used, so
  letters like `j`, `k`, `x` reach the search box.
- Compact rows, a countdown bar instead of a canvas ring per row, a scrolling
  list with a visible scrollbar.
- Pins and last-used times: `~/.local/state/navjottomer.proton-authenticator/prefs.json`
  (entry ids only).

## Requirements

`proton-authenticator-bin`, `python-cryptography`, `python-pyotp`, `libsecret`,
`wl-clipboard`, `libnotify`.
