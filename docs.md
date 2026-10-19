# glyx user guide

glyx is a local-first password manager. Your vault is a directory of encrypted files that you own and can sync with any tool you trust. There is no account, no telemetry, and no network service outside your machine.

This guide covers the three frontends:

- **CLI** (`glyx`), including a full-screen TUI (`glyx tui`)
- **GUI** (the WebUI served by the local daemon)
- **Desktop** (`glyx-tauri`, the GUI plus automatic daemon start and a global quick-copy shortcut)

The browser extension, the Git credential helper, and clipboard fill are also covered.

---

## 1. Install and first run

With Nix:

```sh
nix run .#default -- --help        # run the CLI without installing
nix profile install .#default      # CLI and daemon
nix profile install .#bundle       # CLI, daemon, and desktop app
nix build .#release-bundle         # tarball with checksums
```

From a dev checkout:

```sh
nix develop
cargo nextest run
pnpm --dir apps/webui build
```

First run:

```sh
glyx
```

With no arguments, `glyx` opens the vault picker. It lists vaults you have created or added. If you have none, it offers to add one from a custom location or to create a new vault. The selection is saved in the app config and stays active until you choose another vault.

Create a vault non-interactively:

```sh
glyx vault init ~/vaults/main.glyx --preset balanced --keyfile ~/keys/main.key
```

Omit `--keyfile` to create a password-only vault:

```sh
glyx vault init ~/vaults/simple.glyx --preset mobile
```

The vault id is printed on creation. Keep the keyfile (if you use one) somewhere separate, such as a USB stick. If you lose a required keyfile, the vault cannot be recovered.

---

## 2. Core concepts

**Vault directory.** `VAULT.toml` plus `keyslots/`, `items/`, `blobs/`, `history/`, `conflicts/`, and a local SQLite index. Sync the whole directory, never individual files.

**Format version 2.** `VAULT.toml` records `format_version = 2` and `keyfile_required`. Version 1 vaults are not supported; recreate them.

**Password and keyfile.** The password is mandatory. The keyfile is optional. Unlock derives a key from `password + keyfile` (or `password` alone) with Argon2id, then unwraps the random data key. Cipher is XChaCha20-Poly1305 by default, AES-256-GCM is an option.

**Sessions.** `unlock` can remember the data key for a bounded time so later commands skip the password. Session material lives under `0600` in the runtime directory and is wiped by `lock`.

**Daemon.** The daemon owns the unlocked vault and serves the API and GUI on `127.0.0.1` with a bearer token. It can run without a vault selected, which is how onboarding works. A single daemon switches between vaults.

**App config.** `~/.config/glyx/config.toml` (override with `GLYX_CONFIG`). It stores the selected vault, known vaults, session defaults, daemon behavior, and the auto-materialize setting.

**Auto-materialize.** By default, unlocking writes tracked secrets to their files (exports and injections). Turn this off if you prefer to unlock each target explicitly.

---

## 3. Vaults

### Picker

```sh
glyx                 # picker
glyx vault select    # same picker
```

Options in the picker:

- a listed vault (marked current), select it
- add a vault from a custom location (for example copied from another device)
- create and configure a new vault (path, name, preset, cipher, password, optional keyfile)

When no vaults are listed, only the last two actions are offered.

### Resolution order

Commands find the vault in this order:

1. `--vault <path>`
2. `GLYX_VAULT` environment variable
3. the selected vault in the app config

### Register and forget

The picker registers custom vaults and can also remove one ("Remove a vault from the list"). The GUI onboarding page has the same actions, including Forget. Forgetting only removes the registry entry and wipes any session ticket; the vault files are untouched.

```sh
glyx vault forget                 # forget the selected vault
glyx vault forget ~/vaults/old.glyx
```

### Rekey

Change password, keyfile, cipher, or KDF preset without creating a new vault:

```sh
glyx --keyfile ~/keys/main.key vault rekey --new-keyfile ~/keys/main2.key
glyx --keyfile ~/keys/main.key vault rekey --no-keyfile          # drop the keyfile
glyx --keyfile ~/keys/main.key vault rekey --cipher aesgcm
glyx --keyfile ~/keys/main.key vault rekey --preset hardened
```

Old keyslots are retired unless you pass `--keep-old-slots`. GUI: Settings has a Rotate credentials section (the vault must be unlocked).

---

## 4. Unlock, lock, and sessions

```sh
glyx unlock                 # prompt password (+ keyfile if required)
glyx unlock --ttl 60        # remember for 60 minutes
glyx unlock --with-pin      # also set a short PIN for later unlocks
glyx unlock --no-materialize
glyx lock
```

Global flags:

```sh
--vault <path>
--keyfile <path>
--password-env <VAR>
--no-session
--json
```

`--password-env` reads the password from an environment variable for scripts. Never put secrets on the command line.

`lock` wipes session tickets and tears down the agent: it restores locked forms, shreds non-keep exports, and closes the SSH socket. In the GUI, Lock does the same.

PIN sessions: `unlock --with-pin` prompts for a PIN (minimum 4 characters) and stores the data key under a PIN-derived key. Later commands prompt for the PIN instead of the full password.

Session TTL and mode are configurable in the GUI Settings page or in the config file:

```toml
mode = "session"        # "oneshot" or "session"
session_ttl_min = 15
```

Threat model: session mode stores the data key under `0600` in your runtime directory, similar to how `ssh-agent` holds keys in memory. One-shot mode does not write session material; `unlock` you run explicitly still writes it for its TTL.

---

## 5. CLI TUI

```sh
glyx tui
```

A full-screen interface for the most common work. All normal CLI commands remain available.

**Item list**

- type to search by name or type
- Up/Down to move, Enter to open
- `a` add an item
- `v` open the vault picker (create, add, or switch), then relaunch `glyx tui`
- `l` lock and quit
- `q` quit
- `?` help

**Item detail**

- `r` show or hide secret values
- `c` copy the first secret field to the clipboard (auto-clears in 15 seconds)
- `t` show a TOTP code
- `m` render a note (`{{glyx:...}}` references resolved, secrets masked)
- `e` edit
- `d` delete (tombstone, sync-safe)
- Esc back

**Add or edit form**

- Tab/Up/Down move between fields, Left/Right change the item type (when adding)
- Tags are comma separated; folder moves the item
- Ctrl+G generates a password into the focused secret field
- type to edit, Enter on the last field to save, Esc to cancel
- optional keyfile and daemon requirements are the same as the CLI

Secrets are masked in the TUI and are not written to your shell history.

---

## 6. Items

Supported types:

| Type | Fields |
|------|--------|
| `login` | username, password, url, notes |
| `passkey` | credential id, public key, relying party, username |
| `totp` | seed or `otpauth://` URI, period, digits |
| `identity` | name, email, phone, address, and related fields |
| `card` | cardholder, number, expiry, cvc |
| `note` | markdown body |
| `file` | blob address, filename, mime |
| `ssh_key` | private, public, kind, comment |
| `generic_key` | key, value, notes |

### CLI

```sh
glyx add login --name github --field username=you --generate password
glyx add note --name server --body-file server.md
glyx add login --name github --interactive
glyx ls
glyx ls --type login --tag work
glyx show github
glyx show github --reveal
glyx show server --render
glyx edit github --rename work-github --field url=https://github.com
glyx edit github --folder work --tag important --remove-tag old
glyx edit server --body-file server.md
glyx edit github --delete-field notes
glyx rm github
```

`--generate name[:length]` creates a strong random value. `--json` returns machine-readable output; JSON always includes values, so be careful with logs.

### GUI

- `/items` lists items with search plus type, folder, and tag filters and a deleted (tombstone) toggle; Lock is in the top bar
- `/items/<id>` shows fields. Edit opens the same form used for adding, with per-field Generate for secret fields. Copy copies a field to the clipboard through the daemon.
- `/add` chooses a type and renders that type's fields
- notes render markdown and support secret references (see section 8)

### Desktop

The desktop app is the same GUI with two extras:

- it starts the daemon automatically for the selected vault
- `Ctrl+Shift+G` opens a quick-search palette. Type to filter, Enter copies the password, Esc closes.

---

## 7. TOTP

Store a seed or paste an `otpauth://` URI in the `seed` field of a `totp` item:

```sh
glyx add totp --name github --field seed=otpauth://totp/GitHub:you?secret=...&issuer=GitHub
glyx totp github
```

TOTP uses SHA1, 30 second steps, and 6 digits by default. The code is printed (or returned as JSON). GUI: open the item and press TOTP code. TUI: press `t` in the item detail.

---

## 8. Notes

Notes are markdown items. Reference a secret from another item with:

```text
password for github is {{glyx:<item-id>/password}}
```

The reference resolves at render time, not at storage time. Non-secret fields always show. Secret fields show `••••` unless you reveal. Missing items or fields render as `[missing id/field]`.

```sh
glyx show server --render           # secrets masked
glyx show server --render --reveal  # secrets shown
```

GUI: `/items/<note-id>` renders markdown. Edit switches to a textarea with a live preview. The renderer escapes HTML first, so notes cannot inject scripts.

External markdown folders are covered with injection below. Point glyx at an Obsidian-style folder and references resolve in those files on unlock.

---

## 9. SSH keys

Generate a key pair into a new item:

```sh
glyx ssh gen --name deploy --kind ed25519 --comment you@host
```

Export a key to a file (ledger-tracked, shredded on lock unless `--keep`):

```sh
glyx ssh export deploy --to ~/.ssh/id_glyx
```

Use the agent (sign-only, Ed25519):

```sh
eval $(glyx ssh agent-env)
ssh-add -L
```

The agent socket lives only while the daemon is unlocked. Private material never touches disk through the agent path. GUI: choose the `ssh_key` type on the Add page and press Generate SSH key pair. Copy the public key from the item. Settings can show the current agent socket path (the same value as `glyx ssh agent-env`).

---

## 10. Full-file exports

Exports materialize a field, blob, or SSH key into a whole file:

```sh
glyx export add ~/.aws/credentials --item aws --field secret_key
glyx export add ~/.ssh/id_glyx --ssh deploy --keep
glyx export add ./artifact.bin --blob blake3-<hex>
glyx export ls
glyx export recall ~/.aws/credentials     # wipe and forget
glyx export enforce [--force]
glyx export tamper
```

Files without `--keep` are shredded on lock and re-created on unlock. `--force` overwrites a file that changed since the last unlock. `export tamper` lists findings.

GUI: the Exports page adds exports (field, blob, or SSH), lists them, and has Unlock, Lock, Move, and Recall per target. When tamper is detected it offers Force re-materialize and Keep (stop tracking without wiping).

---

## 11. Injection (files, folders, pointers)

Injection edits a tracked text file in place, replacing placeholders with secrets while unlocked and restoring the locked form when locked.

Author a reference in the file:

```text
user = abc
password = {{glyx:<item-id>/password}}
```

Track the file:

```sh
glyx inject add project/.env
```

Locked forms (`--form`):

- `encrypted-pointer` (default): `__GLYXENC:V1:...__`, opaque and bound to the target path
- `masked`: `ENC[12 hex]`, fixed size, one-way
- `ref`: keeps `{{glyx:<id>/<field>}}` visible (default for folders)

Unlock substitutes values. Lock restores the locked form:

```text
user = abc
password = __GLYXENC:V1:AbC...__
```

The encrypted pointer is safe to commit. On unlock, glyx resolves it from the token itself, so it works even if the local tracking database is lost, as long as the file path and vault are the same. If the file moved, the pointer stays locked and glyx will not guess.

### Folders

Track a folder of markdown notes:

```sh
glyx inject add ~/Obsidian --glob '*.md'
glyx inject scan
```

On unlock, references in matching files resolve. On lock, they return to `{{glyx:...}}` placeholders, so notes stay readable. Hidden entries, symlinks, non-UTF-8 files, and files larger than 5 MiB are skipped.

### Per-target control

By default, unlock materializes all tracked targets. To change that:

```sh
# turn off automatic materialization: set auto_materialize = false in the app config,
# or use the GUI Settings toggle ("Lock until I unlock each")
glyx unlock --no-materialize    # override for one unlock

glyx inject unlock <target> [--force]
glyx inject lock <target>
glyx inject move <old> <new>
```

`inject move` re-points the ledger entry and re-seals pointers for the new path, so the moved file unlocks normally. A folder target scopes its children.

CLI `inject ls` lists folders first, then files. GUI: the Exports page shows tracked folders, exports, and injected files, each with Unlock, Lock, Move, and Forget or Recall. Settings toggles auto-materialize.

### Tampering and merge

If a file changes while locked, unlock reports it instead of overwriting. Merge three ways:

```sh
glyx export merge project/.env --ours
glyx export merge project/.env --theirs
glyx export merge project/.env --pick 2:theirs
glyx export merge project/.env --interactive
```

Hunks are line-based. Clean hunks apply automatically. Real conflicts need an explicit pick. Conflict markers are never written.

---

## 12. Sync and conflicts

Point any file sync you trust at the vault directory (Syncthing, Nextcloud, rsync, a USB copy). glyx merges field by field:

```sh
glyx sync                        # heal file-sync conflict copies
glyx sync /mnt/usb/other.glyx    # pairwise merge from another copy
glyx sync-status
glyx conflicts
glyx conflicts show site --reveal
glyx conflicts resolve site --mine
glyx conflicts resolve site --theirs
glyx conflicts resolve site --field city=Bergen
glyx gc --dry-run
glyx gc --older-than 30d
```

Rules: the newer field wins, tombstones win over edits, and true same-field races keep a deterministic winner and record both sides under `conflicts/`. Nothing is silently dropped.

GC purges old tombstones. A device offline longer than the GC window can resurrect a deleted item on its next sync.

GUI: Conflicts lists races, shows mine versus theirs, and resolves. Settings has Sync now, GC (with a configurable window), Doctor (with an optional index rebuild while locked), and pairwise sync where you enter the other vault path plus its keyfile or password.

---

## 13. Browser extension

The extension needs a running daemon.

```sh
glyx extension install              # Chrome manifests
glyx extension install --firefox    # Firefox manifest
glyx extension allow <extension-id> # Chrome id from chrome://extensions
glyx extension status
```

Load `apps/extension` in the browser. The extension ranks candidates by registrable domain and fills forms through input events. It never auto-submits. Its native host reads the selected vault and the daemon record.

---

## 14. Git credential helper

```sh
glyx git setup
glyx git status
```

`git setup` symlinks `git-credential-glyx` and sets `credential.helper`. Credentials come from `GLYX_VAULT` and `GLYX_KEYFILE`/`GLYX_PASSWORD`, or from an active session. Host matching is exact or subdomain, case-insensitive.

---

## 15. Clipboard fill

```sh
glyx fill github
glyx fill github --field username --timeout 30
glyx fill github --dry-run
```

The value is copied and cleared after the timeout if it is still on the clipboard. `--dry-run` resolves without touching the clipboard. In the GUI, item detail has Copy buttons that use the daemon's clipboard. The desktop quick palette (`Ctrl+Shift+G`) copies the password with auto-clear.

---

## 16. Daemon and GUI

```sh
glyx daemon start [--idle-lock-min N]
glyx daemon status
glyx daemon stop
```

`daemon start` reuses a live daemon or starts one. It does not need a vault argument; it uses the selected vault, or starts empty for onboarding. The record is `daemon.json` in the runtime directory (port, pid, token, selected vault), readable only by you.

The daemon serves the GUI on loopback with token auth. Open the printed URL, enter the token from `daemon.json`, and use the pages:

- `/` unlock with password, keyfile, or PIN; when unlocking with a password you can also set a PIN
- `/items` and `/items/<id>` browse, reveal, copy, edit, delete, TOTP
- `/add` create any item type
- `/conflicts` compare and resolve
- `/exports` exports, injections, folders, per-target lock/unlock/move, merge
- `/onboarding` select, add, create, or forget vaults
- `/settings` session mode and TTL, auto-materialize, daemon behavior, rekey, sync, GC, doctor

Secrets are kept in memory only and never written to `localStorage`.

---

## 17. Desktop app

`glyx-tauri` (or `nix run .#glyx-desktop`) starts the daemon for the selected vault, injects the URL and token into the WebView, and opens the GUI. It closes the daemon on exit by default.

Settings:

- **When the desktop app closes**: stop the daemon (default, more private) or keep it running (keeps the browser extension, Git helper, and SSH agent alive)
- **On unlock**: materialize all tracked files (default) or lock until you unlock each

`Ctrl+Shift+G` shows the quick palette from any app. Type to search, Enter copies the password, Esc closes. The clipboard clears after 15 seconds if unchanged.

---

## 18. Configuration reference

Location: `~/.config/glyx/config.toml`, or `GLYX_CONFIG`.

```toml
mode = "oneshot"            # "oneshot" or "session"
session_ttl_min = 15        # 1..480
daemon_on_exit = "stop"     # "stop" or "keep"
auto_materialize = true     # false = unlock tracked targets individually
current_vault = "/home/you/vaults/main.glyx"

[[vaults]]
path = "/home/you/vaults/main.glyx"
name = "Personal"
vault_id = "0191..."
keyfile = "/home/you/keys/main.key"
last_used_ms = 1790000000000
```

Only the keyfile path is stored, never key bytes.

Change these from the CLI:

```sh
glyx config                        # show current settings
glyx config set mode session
glyx config set session_ttl_min 30
glyx config set auto_materialize false
glyx config set daemon_on_exit keep
```

The GUI Settings page edits the same values.

Runtime directory: `GLYX_RUNTIME_DIR`, else `$XDG_RUNTIME_DIR/glyx`, else a temp directory. It holds session tickets, `daemon.json`, the SSH socket, and the local agent ledger (`agent-ledger.sqlite`, never synced).

---

## 19. Troubleshooting

**"no vault selected"**: run `glyx` to pick one, or pass `--vault` or set `GLYX_VAULT`.

**"this vault requires a keyfile"**: pass `--keyfile`, or store the path when selecting the vault.

**Daemon locked (409) in the GUI**: unlock on `/` or via `glyx unlock`.

**TUI refuses to start**: another process (often the daemon) holds the vault open. Stop the daemon or use the GUI. The TUI opens the vault directly like other CLI commands.

**Extension cannot find the vault**: ensure the daemon is running and a vault is selected, then reinstall the native host with `glyx extension install`.

**Injected file was edited while locked**: `glyx export tamper`, then merge or `export enforce --force`.

**Vault format error**: version 1 vaults are not supported. Recreate the vault.

**Clipboard unavailable**: install a clipboard backend for your session (`wl-clipboard` or X11 tools). `glyx doctor` reports the backend.

---

## 20. Security notes

- The vault is encrypted at rest. The password is mandatory; a keyfile adds a second factor.
- Lock wipes sessions, restores locked forms, shreds non-keep exports, and closes the SSH agent.
- Pointers are bound to their target path and fail closed if copied elsewhere.
- The daemon listens on loopback only and requires a bearer token stored under `0600`.
- The GUI keeps secrets in memory only. It never writes them to browser storage.
- Session files hold the data key under `0600` until the TTL expires. Use one-shot mode or short TTLs if that tradeoff is not acceptable.
- Commit only locked forms (`__GLYXENC:...__` or `ENC[...]`), never unresolved values. Review files before committing.
- Back up the vault and your keyfile separately. Without them, recovery is impossible by design.
