# glyx user guide

glyx is a local-first password manager. Your vault is a directory of encrypted files that you own and can sync with any tool you trust. There is no account, no telemetry, and no network service outside your machine.

This guide covers the user-facing frontends:

- **CLI** (`glyx`), including a full-screen TUI (`glyx tui`)
- **WebUI** (pages served by the local daemon)
- **Desktop** (`glyx-tauri`, the WebUI plus tray, deep links, notifications, autostart, and a global quick-copy shortcut)
- **Android** (`glyx-tauri` mobile, M6c paused)
- **Browser extension** (search, login/TOTP fill, and lock; requires an unlocked daemon)
- **Git credential helper** (`git-credential-glyx`)

### Frontends at a glance

| Capability | CLI | TUI | WebUI | Desktop | Android | Ext | Git |
|---|---|---|---|---|---|---|---|
| Vault create/select/rekey | Yes | Partial | Yes | Inherited | Partial | No | Partial |
| Unlock/lock/PIN | Yes | Partial | Yes | Inherited | Inherited | Partial* | Partial |
| Item create/edit/delete | Yes | Yes | Yes | Inherited | Inherited | No | Partial |
| Notes/TOTP | Yes | Yes | Yes | Inherited | Inherited | Partial | No |
| Clipboard copy | Yes | Partial | Partial | Inherited | No | No | No |
| Web form fill | No | No | No | No | Planned | Yes | No |
| SSH keys/agent | Yes | No | Partial | Inherited | Partial | No | No |
| Favorites/recents/library/bulk/duplicates | Yes | No | Yes | Inherited | Inherited | No | No |
| Devices/health/audit/generator | Yes | No | Yes | Inherited | Inherited | No | No |
| Exports/injection | Yes | No | Yes | Inherited | Inherited | No | No |
| Sync/conflicts/GC/doctor | Yes | No | Partial | Inherited | Inherited | No | No |
| Desktop extras | No | No | No | Yes | No | No | No |
| OS autofill/biometrics | No | No | No | No | Planned | No | No |
| Extension/Git setup | Yes | No | No | No | No | No | No |

`Inherited` means Desktop and Android reuse the WebUI pages (Android currently
lacks clipboard, autofill, and biometrics). `Partial` details, known gaps, and
code anchors live in `local/feature-parity.md` (local only).

`*` The extension can Lock but cannot unlock; it requires the daemon to already
be unlocked. The Git helper uses `GLYX_*` env vars or an active session and has
no lock/PIN UI.

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

The Linux desktop tray uses the system StatusNotifierItem/AppIndicator library (`libayatana-appindicator3` or the legacy `libappindicator3`). Nix builds embed the library path in the binary. On non-Nix systems install the matching package; when running a `cargo`-built `glyx-tauri` directly, use `nix develop` or provide the library path yourself.

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

The WebUI unlock page has an **Advanced** section for a per-unlock TTL and for overriding materialization (`use setting`, `yes`, `no`). These map to the daemon `ttl_min` and `materialize` fields; the CLI equivalents are `--ttl` and `--no-materialize`.

Session TTL and mode are configurable in the GUI Settings page or in the config file:

```toml
mode = "session"        # "oneshot" or "session"
session_ttl_min = 15
idle_lock_min = 15      # daemon idle auto-lock; 0 disables
```

Threat model: session mode stores the data key under `0600` in your runtime directory, similar to how `ssh-agent` holds keys in memory. One-shot mode does not write session material; `unlock` you run explicitly still writes it for its TTL.

---

## 5. CLI TUI

```sh
glyx tui
```

A full-screen interface for the most common work. All normal CLI commands remain available outside the TUI. The TUI intentionally omits exports, injections, sync, conflicts, SSH generation, doctor, and settings; use the CLI or WebUI for those.

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
| `passkey` | relying_party, user_handle, credential_id, private_key |
| `totp` | seed or `otpauth://` URI, period, digits |
| `identity` | full_name, email, phone, address |
| `card` | number, holder, expiry, cvc |
| `note` | markdown body |
| `file` | blob address, filename |
| `ssh_key` | private, public, comment (plus `kind` from `ssh gen`) |
| `generic_key` | material, kind |

These are template suggestions. `--field key=value` can add extra fields, and
the TUI/WebUI forms show the same template. Any item can carry one encrypted
attachment in its reserved `blob` field (25 MiB max).

### CLI

```sh
glyx add login --name github --field username=you --generate password
glyx add note --name server --body-file server.md
glyx add login --name github --interactive
glyx ls
glyx ls --type login --tag work
glyx ls --query github
glyx ls --favorite --sort name --limit 20 --offset 0
glyx favorite github
glyx recents
glyx library
glyx tag rename old new
glyx tag rm old
glyx folder rename Work Archive
glyx folder rm Archive
glyx duplicates
glyx bulk favorite --folder work
glyx bulk add-tag important --folder work
glyx bulk move-folder Archive --folder work
glyx bulk delete --id old-login --yes
glyx devices
glyx devices label this Laptop
glyx health --min-length 12 --max-age-days 365
glyx audit --limit 50 --event item_reveal
glyx gen --length 32
glyx gen --length 20 --no-symbols --allow-ambiguous
glyx show github
glyx show github --reveal
glyx show server --render
glyx history github
glyx history github --show 1729450000000-0.json --reveal
glyx history github --compare 1729450000000-0.json
glyx restore github --rev 1
glyx edit github --rename work-github --field url=https://github.com
glyx edit github --folder work --tag important --remove-tag old
glyx edit server --body-file server.md
glyx edit github --delete-field notes
glyx rm github
```

`--generate name[:length]` creates a strong random value. `--json` returns machine-readable output; JSON always includes values, so be careful with logs.

`ls --query` searches names, folders, tags, and non-secret fields; `--favorite` filters stars and `--sort` accepts `updated`, `name`, `type`, or `favorite` (add `--reverse` to flip; `--limit`/`--offset` page the result). `favorite` toggles the synced star. `recents` lists the last 20 items opened on this device; recents are stored only in the local config and are never synced.

Tags and folders are metadata on each item. `tag rename`/`folder rename` rewrite every live item; `tag rm` removes the tag everywhere and `folder rm` moves its items to the root. `bulk` accepts repeatable `--id` selectors (id, prefix, or exact name) plus an optional `--folder` selector; the selectors combine. `bulk delete` requires `--yes`. `duplicates` groups live items by normalized name and by login URL + username, flags identical passwords without printing them, and never returns secret values.

The WebUI items page mirrors this workflow: recents, star toggles, favorites filter, sort and pagination, folder/tag pickers, multi-select bulk actions, and a Library panel for renaming/deleting tags and folders. The duplicates page groups suspects and supports bulk deletion; it shows only whether passwords match, never the values.

`devices` derives known devices from item, history, and conflict clocks. Last seen means the newest write activity observed in the vault, not online presence; labels are local to this device. `health` reports weak (`<12` chars or `<60` bits), reused, old (`>365` days), and missing-TOTP login items without printing secrets. `audit` reads the local append-only JSONL log; it records event IDs and field names only, never item names or values. `gen` supports class toggles and ambiguity control; the WebUI has `/devices`, `/health`, `/audit`, and `/generator` pages.

`history` lists earlier revisions (newest first); `--show` previews one, `--compare` lists changed fields without printing values, and `restore` brings one back as a new revision, so past revisions are never rewritten. `gen` prints a standalone password and does not touch the vault.

### Attachments

```sh
glyx add file --name report --field filename=report.pdf --attach report.pdf
glyx edit report --attach report-v2.pdf
glyx blob ls
glyx blob get blake3-… --out report.pdf
glyx blob gc            # list unreferenced blobs
glyx blob gc --purge    # delete them
```

Attachments are sealed with the vault key before they touch disk, with a
25 MiB per-file limit. The original filename is not stored. GC scans current
items, history, conflicts, and tracked exports; if any scan fails it refuses to
purge.

### GUI

- `/items` lists items with server-side search plus type, folder, and tag filters and a deleted (tombstone) toggle; Lock is in the top bar
- `/items/<id>` shows fields. Edit opens the same form used for adding, with per-field Generate for secret fields. Copy copies a field to the clipboard through the daemon; the clear timeout is configurable on the item page.
- **History** on the item page lists earlier revisions with Preview, Reveal, Compare, and Restore. Comparing lists changed field names without disclosing values. Restoring always creates a new revision.
- **Attachment** on the item page uploads, downloads, or removes the encrypted blob.
- TOTP code is available for any item that has a `seed` field, not only `totp` items.
- `/add` chooses a type and renders that type's fields
- notes render markdown and support secret references (see section 8)

### Desktop

The desktop app is the same GUI plus platform glue:

- it starts the daemon automatically for the selected vault and stops it on exit by default
- `Ctrl+Shift+G` opens a quick-search palette. Type to filter, Enter copies the password, Esc closes
- Settings controls whether closing the app stops or keeps the daemon

### Backup and restore

Backups require a locked vault so the snapshot is consistent. The archive is a
`tar.gz` of encrypted vault artifacts plus `VAULT.toml`; the plaintext SQLite
index, lock file, `device.id`, and a registered keyfile are excluded.

```sh
glyx vault backup ~/backups/main-2026-10-20.tar.gz
glyx vault restore ~/backups/main-2026-10-20.tar.gz ~/vaults/restored.glyx
```

Restore requires a destination that does not exist. It rejects absolute paths,
`..`, symlinks, hardlinks, special files, oversized archives, and unexpected
top-level entries, extracts to a private temporary directory, then renames it
into place. A fresh device id is generated and the index is rebuilt from
envelopes on first unlock, with the HLC floor restored from items, history, and
conflicts. GUI: Settings → Backup (lock first). The archive is not additionally
encrypted; treat it as sensitive even though item contents are encrypted.

---

## 7. TOTP

Store a seed or paste an `otpauth://` URI in the `seed` field of a `totp` item:

```sh
glyx add totp --name github --field seed=otpauth://totp/GitHub:you?secret=...&issuer=GitHub
glyx totp github
```

TOTP uses SHA1, 30 second steps, and 6 digits by default. The code is printed (or returned as JSON). GUI: open any item with a `seed` field and press TOTP code. TUI: press `t` in the item detail.

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

GUI: the Exports page adds exports (field, blob, or SSH) with a `perm` field, has a dedicated **Export an SSH key** form (item, target, perm), and lists tracked targets with Unlock, Lock, Move, and Recall. When tamper is detected it offers Force re-materialize and Keep (stop tracking without wiping).

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

Health checks: `glyx doctor` reports vault state; `--rebuild-index` rebuilds the SQLite index from envelope headers (the vault must be locked), and `--with-unlock` additionally decrypts every item and blob. GUI Settings has Doctor with index-rebuild and with-unlock toggles.

GUI: Conflicts lists races, shows mine versus theirs, and resolves. Settings has Sync now, GC (with a configurable window), Doctor (with optional index-rebuild and with-unlock), pairwise sync where you enter the other vault path plus its keyfile or password, and the idle auto-lock interval.

---

## 13. Browser extension

The extension needs a running daemon with an unlocked vault. It has no unlock screen of its own.

```sh
glyx extension install              # Chrome manifests
glyx extension install --firefox    # Firefox manifest
glyx extension allow <extension-id> # Chrome id from chrome://extensions
glyx extension status
```

Load `apps/extension` in the browser. The popup searches items (ranking
candidates by registrable domain), has a Fill button for username/password, a
TOTP button, and a Lock button. Filling sets input values and dispatches
`input`/`change` events; it never auto-submits a form.

The native host exposes only `status`, `search`, `fill`, `totp`, and `lock`.
The extension cannot unlock the vault, create/edit/delete/reveal items, or
manage vaults, exports, sync, or SSH.

---

## 14. Git credential helper

```sh
glyx git setup
glyx git status
```

`git setup` symlinks `git-credential-glyx` and sets `credential.helper`. The
helper opens the vault directly, not through the daemon: credentials come from
`GLYX_VAULT` and `GLYX_KEYFILE`/`GLYX_PASSWORD`, or from an active session.

- `get` matches a `login` item by URL host (exact or subdomain, case-insensitive)
  and optional username, then prints `username=` and `password=`.
- `store` updates the matching login's password, or creates a new login item
  named after the host.
- `erase` tombstones the matching login.

It has no UI and does not expose any other vault operations.

---

## 15. Clipboard fill

```sh
glyx fill github
glyx fill github --field username --timeout 30
glyx fill github --dry-run
```

The value is copied and cleared after the timeout if it is still on the clipboard. `--dry-run` resolves without touching the clipboard. In the GUI, item detail has Copy buttons that use the daemon's clipboard. The desktop quick palette (`Ctrl+Shift+G`) copies the password with auto-clear.

On Android, clipboard access is unavailable in the current shell; Copy/Fill
return an error until the `AutofillService` integration lands. The extension
does not use the clipboard: it fills page inputs directly.

---

## 16. Daemon and GUI

```sh
glyx daemon start [--idle-lock-min N]
glyx daemon status
glyx daemon stop
```

`daemon start` reuses a live daemon or starts one. It does not need a vault argument; it uses the selected vault, or starts empty for onboarding. `--idle-lock-min` overrides the persisted `idle_lock_min` setting for that daemon instance. The record is `daemon.json` in the runtime directory (port, pid, token, selected vault), readable only by you.

The daemon serves the GUI on loopback with token auth. Open the printed URL, enter the token from `daemon.json`, and use the pages:

- `/` unlock with password, keyfile, or PIN, with an Advanced section for per-unlock TTL and materialization; when unlocking with a password you can also set a PIN
- `/items` and `/items/<id>` browse, search, reveal, copy, edit, delete, TOTP, and restore history
- `/add` create any item type
- `/conflicts` compare and resolve
- `/exports` exports with perm, SSH key export, injections, folders, per-target lock/unlock/move, merge
- `/onboarding` select, add, create, or forget vaults
- `/settings` session mode and TTL, idle auto-lock, auto-materialize, daemon behavior, rekey (including keeping old slots), sync, GC, doctor (rebuild + with-unlock), pairwise sync, and the SSH agent socket

Secrets are kept in memory only and never written to `localStorage`.

---

## 17. Desktop app

`glyx-tauri` (or `nix run .#glyx-desktop`) starts the daemon for the selected vault, injects the URL and token into the WebView, and opens the GUI. It closes the daemon on exit by default.

With no vault selected, the desktop opens onboarding instead of failing to connect: it lists known vaults and offers **Open existing vault**, **Create new vault**, and **Restore from backup**. Folder/keyfile/archive selection uses native dialogs on desktop and text paths in the browser WebUI. Creating a vault auto-unlocks it and opens the item list. If the external daemon cannot be started, the desktop falls back to an in-process daemon and shows a retryable error card instead of a blank connection error.

Desktop behavior (Linux):

- **Tray**: Show, Quick search, Lock vault, Quit. Closing the window hides it to the tray by default; turn this off in Settings to make close quit.
- **Single instance**: a second launch focuses the running window instead of starting another copy.
- **Deep links**: `glyx://unlock` opens the unlock page, `glyx://items/<id>` opens an item, `glyx://settings` opens Settings, `glyx://lock` locks, and `glyx://quick` opens the palette. The installed desktop file registers the scheme.
- **Autostart**: opt-in; starts minimized to the tray. The shortcut is configurable in Settings (default `Ctrl+Shift+G`).
- **Notifications**: daemon start/stop, idle auto-lock, and tamper detection. Toggle them in Settings.
- **Window state**: size and position persist across launches.
- Locking is manual or on exit; there is no OS suspend hook.

Settings:

- **When the desktop app closes**: stop the daemon (default, more private) or keep it running (keeps the browser extension, Git helper, and SSH agent alive)
- **On unlock**: materialize all tracked files (default) or lock until you unlock each
- **Desktop**: close-to-tray, start on login, notifications, and the quick-search shortcut

`Ctrl+Shift+G` (configurable) shows the quick palette from any app. Type to search. Enter copies the password, Shift+Enter the username, Alt+Enter the current TOTP, Ctrl+Enter opens the item, and Ctrl+N opens the add page; the row buttons do the same. Esc closes. Password and username copies clear after 15 seconds if unchanged.

Desktop-only preferences live in `~/.config/glyx/desktop.json` (or next to `GLYX_CONFIG`), separate from the CLI/daemon config.

---

## 18. Configuration reference

Location: `~/.config/glyx/config.toml`, or `GLYX_CONFIG`. Desktop-only preferences are stored in `desktop.json` beside it.

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
glyx config set idle_lock_min 15
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

**Android Copy/Fill fails**: expected in the current M6c shell; the Android clipboard backend is intentionally unavailable until `AutofillService` lands.

**Android APK build fails**: use `nix develop .#android-fhs` (not the plain `.#android` shell). The FHS shell sets the AAPT2 override and `/usr/bin`; build arm64 only with `-t aarch64` unless the disk has several GB free.

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

---

## 21. Android (M6c paused)

The Android app is the Tauri-mobile shell from `crates/glyx-tauri` plus the same
WebUI. It is not feature-complete yet.

What works today:

- the app starts an in-process daemon on loopback with a random token and injects
  the URL/token into the WebView, so the normal WebUI pages open without manual
  configuration
- vault onboarding, item browsing/editing, notes, TOTP display, exports,
  injection, sync, conflicts, GC, and doctor through the WebUI
- a debug APK builds successfully (arm64); `adb install` is the remaining device step

Known limitations:

- clipboard Copy/Fill is unavailable; `AutofillService` is not implemented yet
- no biometric/Keystore unlock yet
- no storage-access-framework picker; vault and export paths are typed text
- no lock-on-background yet
- the browser extension and Git helper are desktop-only

Build from the repository:

```sh
nix develop .#android-fhs
cd crates/glyx-tauri
cargo tauri android build --debug --apk -t aarch64
adb install -r gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk
```

Omitting `-t aarch64` builds all four ABIs and needs several GB of disk space.
The Android scaffold lives in `crates/glyx-tauri/gen/android`; do not re-run
`cargo tauri android init` or the pinned Build-Tools/Gradle settings are lost.

Next milestones: `AutofillService` (map app/domain to items), biometric unlock
via an Android Keystore keyslot, then mobile polish (lock on background, safe
areas, icons, file picker).
