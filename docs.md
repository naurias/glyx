# glyx user guide

glyx is a local-first password manager. Your vault is a single encrypted `.glyx` file that you own and can sync with any tool you trust. There is no account, no telemetry, and no network service outside your machine.

This guide covers the user-facing frontends:

- **CLI** (`glyx`), including a full-screen TUI (`glyx tui`)
- **WebUI** (pages served by the local daemon)
- **Desktop** (`glyx-tauri`, the WebUI plus tray, deep links, notifications, autostart, and a global quick-copy shortcut)
- **Android** (`glyx-tauri` mobile, M6c autofill + biometrics)
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
| Web form fill | No | No | No | No | Autofill | Yes | No |
| Passkey storage/management | Yes | Partial | Yes | Inherited | Inherited | No | No |
| Passkey WebAuthn | No | No | Manage | Inherited | No | Chromium | No |
| SSH keys/agent | Yes | No | Yes | Inherited | Partial | No | No |
| Favorites/recents/library/bulk/duplicates | Yes | No | Yes | Inherited | Inherited | No | No |
| Devices/health/audit/generator | Yes | No | Yes | Inherited | Inherited | No | No |
| Files & Injection | Yes | No | Yes | Inherited | Inherited | No | No |
| Sync/conflicts/GC/doctor | Yes | No | Partial | Inherited | Inherited | No | No |
| Desktop extras | No | No | No | Yes | No | No | No |
| OS autofill/biometrics | No | No | No | No | Yes | No | No |
| Extension/Git setup | Yes | No | No | No | No | No | No |

`Inherited` means Desktop and Android reuse the WebUI pages (Android currently
lacks clipboard and a native file picker; AutofillService and biometric unlock
are Android-specific). `Partial` details, known gaps, and
code anchors live in `local/feature-parity.md` (local only).

`*` The extension can Lock but cannot unlock; it requires the daemon to already
be unlocked. The Git helper uses `GLYX_*` env vars or an active session and has
no lock/PIN UI.

---

## 1. Install and first run

### With Nix

```sh
nix run .#default -- --help        # run the CLI without installing
nix profile install .#default      # CLI and daemon
nix profile install .#bundle       # CLI, daemon, and desktop app
nix build .#release-bundle         # tarball with checksums
```

### Without Nix (Arch Linux)

Install the system build and runtime packages:

```sh
sudo pacman -S --needed \
  base-devel git pkgconf openssl dbus glib2 gtk3 webkit2gtk-4.1 \
  libsoup3 librsvg libappindicator-gtk3 patchelf \
  nodejs npm rustup wl-clipboard xclip
```

Set up Rust and pnpm:

```sh
rustup default stable
rustup component add rustfmt clippy rust-src

mkdir -p "$HOME/.local/bin"
corepack enable --install-directory "$HOME/.local/bin"
corepack prepare pnpm@9 --activate
export PATH="$HOME/.local/bin:$PATH"
# If Corepack is unavailable: npm install -g pnpm@9

cargo install cargo-nextest cargo-audit --locked
cargo install tauri-cli --version "^2" --locked
```

Build the WebUI first, then the binaries:

```sh
pnpm --dir apps/webui install --frozen-lockfile
pnpm --dir apps/webui build

cargo build --release -p glyx-cli -p glyx-daemon -p glyx-nm
cargo build --release -p glyx-tauri --features glyx-tauri/custom-protocol
```

Install all four binaries together so the CLI can find the daemon and native
host:

```sh
install -Dm755 target/release/glyx ~/.local/bin/glyx
install -Dm755 target/release/glyx-daemon ~/.local/bin/glyx-daemon
install -Dm755 target/release/glyx-native-host ~/.local/bin/glyx-native-host
install -Dm755 target/release/glyx-tauri ~/.local/bin/glyx-tauri
ln -sf glyx ~/.local/bin/git-credential-glyx
```

Android needs JDK 17, Android SDK platform 36, Build-Tools 35 and 36, the NDK,
and `cargo-ndk`; see section 21 and the local build guide in the development
checkout.

### From a dev checkout

NixOS:

```sh
nix develop                # Linux dev and test shell
nix develop .#full         # Linux, cross, and Android tooling in one FHS shell
cargo nextest run
pnpm --dir apps/webui build
```

`.#full` is intended for running an agent such as `opencode` inside a single
shell. For non-interactive use, run `nix run .#full -- <command>`; `nix develop
.#full -c` does not enter the FHS wrapper.

Arch Linux: use the commands above, then run the gates below.

The Linux desktop tray uses the system StatusNotifierItem/AppIndicator library
(`libayatana-appindicator3` or the legacy `libappindicator3`). Nix builds embed
the library path in the binary. On Arch install `libappindicator-gtk3` (or the
AUR `libayatana-appindicator`); the normal loader finds `/usr/lib`. For a
non-standard prefix, set `LD_LIBRARY_PATH`.

### Build and test gates

```sh
cargo nextest run --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo audit
pnpm --dir apps/webui build
```

Current expected count: **120/120 nextest** on `refine-ui-files`. The detailed Arch
component-by-component guide is `local/build-without-nix.md` in the development
checkout; the public summary is in `README.md`.

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

**Single-file vault.** One `.glyx` container holds an encrypted manifest, every item envelope, history, conflicts, and attachments. The container has two fixed 32 KiB header slots; the newest valid slot wins, so a torn write falls back to the previous header. Item and blob payloads are sealed exactly as before, so only the manifest reveals logical names. Saves append changed entries and switch to the inactive header slot; lock and GC compact the file. Sync the file as a whole, never part of it.

**Format version 3.** The encrypted header records `format_version = 3`, the vault id, the cipher suite, and the keyslots. Directory vaults and format 1–2 vaults are rejected; recreate them as a single file.

**Index.** There is no on-disk index. A private in-memory SQLite index is rebuilt from the encrypted manifest and envelopes on every unlock, so copying the file never copies plaintext metadata.

**Backups.** A backup is a direct `0600` copy of the `.glyx` file. Restore verifies the header, then copies the file into a new destination. The device id and keyfile are never part of the vault file.

**Password and keyfile.** The password is mandatory. The keyfile is optional. Unlock derives a key from `password + keyfile` (or `password` alone) with Argon2id, then unwraps the random data key. Cipher is XChaCha20-Poly1305 by default, AES-256-GCM is an option.

**Sessions.** `unlock` can remember the data key for a bounded time so later commands skip the password. Session material lives under `0600` in the runtime directory and is wiped by `lock`.

**Daemon.** The daemon owns the unlocked vault and serves the API and GUI on `127.0.0.1` with a bearer token. It can run without a vault selected, which is how onboarding works. A single daemon switches between vaults.

**App config.** `~/.config/glyx/config.toml` (override with `GLYX_CONFIG`). It stores the selected vault, known vaults, session defaults, daemon behavior, the auto-materialize setting, and the in-place lock-on-exit default.

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
| `login` | username, password, url, notes, plus optional TOTP seed, digits, period |
| `passkey` | relying_party, user_handle, credential_id, private_key, plus optional RP/user metadata, sync flags, and `login_id` |
| `totp` | seed or `otpauth://` URI, period, digits, optional `login_id` |
| `identity` | full_name, email, phone, address |
| `card` | number, holder, expiry, cvc |
| `note` | markdown body |
| `file` | blob address, filename |
| `ssh_key` | private, public, comment (plus `kind` from `ssh gen`) |
| `generic_key` | material, kind |
| `pointer` | arbitrary alias fields, each holding `{{glyx:<id>/<field>}}` |

These are template suggestions. `--field key=value` can add extra fields, and
the TUI/WebUI forms show the same template. Any item can carry one encrypted
attachment in its reserved `blob` field (25 MiB max).

A `pointer` item is a reusable bundle of named aliases. Each field value is a
reference such as `{{glyx:<real-item-id>/<field>}}`. The injection editor
expands the alias to the real reference when inserting it; the engine still
resolves only the real field. Pointer items cannot target another pointer item.

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

Backups require a locked vault so the snapshot is consistent. A backup is a
direct copy of the encrypted `.glyx` file. The device id, app config, keyfile,
and runtime lock/session files are never included.

```sh
glyx vault backup ~/backups/main-2026-10-20.glyx
glyx vault restore ~/backups/main-2026-10-20.glyx ~/vaults/restored.glyx
```

Restore requires a destination that does not exist, verifies the container
header, copies to a private temporary file, then renames it into place. The
in-memory index is rebuilt from envelopes on first unlock, with the HLC floor
restored from items, history, and conflicts. GUI: Settings → Backup (lock
first). The copy is not additionally encrypted; treat it as sensitive even
though item contents are encrypted.

---

## 7. TOTP

Store a seed or paste an `otpauth://` URI in the `seed` field of a `totp` item:

```sh
glyx add totp --name github --field seed=otpauth://totp/GitHub:you?secret=...&issuer=GitHub
glyx totp github
```

A login can carry its own TOTP under the same fields, so one entry covers both
password and code:

```sh
glyx add login --name github --field username=you --generate password \
  --field seed=otpauth://totp/GitHub:you?secret=...&issuer=GitHub
```

Standalone `totp` and `passkey` items remain valid and can be linked to a login:

```sh
glyx link github github-totp
glyx link github github-passkey
glyx related github
glyx unlink github github-totp
glyx passkey ls --login github
```

`login_id` on the child stores the link. Creating a passkey auto-links it when
exactly one login matches the relying-party host and the passkey username;
otherwise link manually. Deleting a login does not cascade-delete children.

TOTP uses SHA1, 30 second steps, and 6 digits by default; `digits` and `period`
override this. The code is printed (or returned as JSON). GUI: open any item
with a `seed` field and press TOTP code; a login shows its own seed and linked
TOTP/passkey items in the same page. TUI: press `t` in the item detail.

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
glyx ssh gen --name deploy --comment you@host --add-to-agent
```

Import an existing OpenSSH private key. Encrypted keys take a passphrase from an
environment variable; the passphrase is used only to decrypt and is never stored:

```sh
GLYX_KEY_PASS='...' glyx ssh import \
  --private-file ~/.ssh/id_ed25519 --passphrase-env GLYX_KEY_PASS \
  --name deploy --add-to-agent
```

List and inspect keys (algorithm, SHA256 fingerprint, agent state):

```sh
glyx ssh ls
glyx ssh show deploy
```

The agent is opt-in per key. New and existing keys start disabled; add or revoke
them without relocking:

```sh
glyx ssh agent status
glyx ssh agent add deploy
glyx ssh agent rm deploy
glyx ssh agent start|stop|reload
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

The agent socket starts on unlock even with zero identities and lives only while
the daemon is unlocked. Private material never touches disk through the agent
path. The WebUI **SSH keys** section shows agent status, per-key fingerprints,
generate/import wizards, add/revoke, reload, and export targets. RSA keys are
export-only for now; the agent supports Ed25519. The item page has an SSH
section, and the TUI shows algorithm, fingerprint, and agent intent (agent
start/stop stays in the CLI/WebUI).

---

## 10. Managed files (full-file exports)

Managed files make the whole file a secret. glyx writes a plaintext copy from a
vault item while unlocked and removes it on lock unless `--keep` is set.

```sh
glyx export add ~/.aws/credentials --item aws --field secret_key
glyx export add ~/Documents/report.pdf --item report   # file item, no --field
glyx export add ~/.ssh/id_glyx --ssh deploy --keep
glyx export add ./artifact.bin --blob blake3-<hex>
glyx export ls
glyx export show ~/.aws/credentials
glyx export keep ~/.aws/credentials [--off]
glyx export move ~/.aws/credentials ~/.config/aws/credentials
glyx export recall ~/.aws/credentials     # wipe and forget
glyx export enforce [--force]
glyx export tamper
```

When `--item` points at a `file` item and no field is given, the source is the
whole attached blob. Files without `--keep` are shredded on lock and re-created
on unlock. `--force` overwrites a file that changed since the last unlock.
`export tamper` lists findings.

GUI: **Files & Injection → Managed files** materializes a file item or a single
field with a native path picker, permissions, and a lock-behavior toggle. The
list supports Materialize, Lock, Keep, Move, and Forget. When tamper is
detected it offers Restore vault copy or Keep file.

---

## 11. In-place injection (files, folders, pointers)

Injection keeps your own file and only swaps marked values. While unlocked glyx
writes plaintext in place; on lock it restores each marked value to the chosen
locked form. The canonical template uses plain readable references, never
secrets, and is stored with the tracking row:

```text
user = abc
password = {{glyx:<item-id>/password}}
```

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

### Lock on crash or exit

The global setting **Lock in-place files on crash or exit** defaults on. Each
tracked file can override it:

```sh
glyx inject policy project/.env --lock-on-exit inherit
glyx inject policy project/.env --lock-on-exit always
glyx inject policy project/.env --lock-on-exit never
```

On a graceful daemon exit (`glyx daemon stop`, desktop close with daemon-stop,
SIGTERM/SIGINT), glyx locks the files selected by the policy. Explicit
`glyx lock` always locks everything. After a hard crash, the next daemon start
restores the stored locked form when the file is unchanged; drifted files are
left untouched and reported. `glyx inject recover` runs the same recovery
manually. If the desktop is configured to keep the daemon running, the daemon
has not exited, so this policy does not fire.

### Pointer aliases

Create a pointer item with aliases to real fields:

```sh
glyx add pointer --name prod_alias \
  --field password='{{glyx:<login-id>/password}}' \
  --field token='{{glyx:<api-id>/token}}'
```

In **Files & Injection → In-place injection**, choose the pointer item and an
alias; the editor inserts the real `{{glyx:<id>/<field>}}` reference. The same
screen can create a normal item with multiple fields, add a field to an
existing item, or create a pointer item and insert its first alias in one step.
CLI `inject add-ref` and `rm-ref` expand pointer aliases the same way.

### Editing references from the CLI

```sh
glyx inject show project/.env [--reveal]
glyx inject preview project/.env [--reveal]
glyx inject add-ref project/.env --line 4 --item github --field password
glyx inject add-ref project/.env --line 4 --item github --field password \
  --form masked --replace
glyx inject rm-ref project/.env --item github --field password
glyx inject form project/.env masked
glyx inject save project/.env --template-file project.env.tpl [--locked]
```

`show` prints the canonical template and resolved references. `preview` renders
both states. `add-ref` and `rm-ref` update the template, re-render the tracked
file, and preserve the expected hash so concurrent edits are rejected rather
than overwritten. Each reference may use its own locked form.

CLI `inject ls` lists folders first, then files. GUI:
**Files & Injection → In-place injection** opens a tracked file in a template
editor with line numbers, reference chips, per-reference locked forms, insert
and remove controls, and an unlocked/locked preview. Managed files and tracked
folders live in sibling tabs, so the whole-file and in-place models are never
mixed. **Browse** opens the native picker on desktop; the browser WebUI asks the
local daemon for a host dialog and falls back to a path prompt when no GUI is
available.

On lock, an unchanged file is restored from the exact locked baseline. If the
file changed while unlocked, glyx routes the difference through the same
three-way merge as tamper handling; it never blindly replaces values.

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

Point any file sync you trust at the `.glyx` file (Syncthing, Nextcloud, rsync, a USB copy). When a sync tool leaves a whole-file `*.sync-conflict-*.glyx` copy next to the vault, glyx merges it on unlock when the vault id matches, then retires the copy. glyx merges field by field:

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
TOTP button, a Passkeys toggle, and a Lock button. Filling sets input values and
dispatches `input`/`change` events; it never auto-submits a form. Passkeys need
Chromium 115+ because the manifest declares `webAuthenticationProxy`; use a
Chromium build for the passkey provider.

The native host exposes `status`, `search`, `fill`, `totp`, `lock`, and the
passkey operations described below. The extension cannot unlock the vault,
create/edit/delete/reveal regular items, or manage vaults, exports, sync, or
SSH.

### Passkeys

Passkeys are stored as synced vault items. The Chromium extension is the desktop
WebAuthn provider; Firefox and Safari do not provide an equivalent extension API.
The WebUI, CLI, and desktop app manage passkey metadata but cannot answer
WebAuthn requests themselves.

1. Open the extension popup and enable **Passkeys**. This attaches the extension
   as the active WebAuthn proxy. Only one extension can hold that role at a time.
2. On a website's passkey registration screen, choose glyx when Chromium asks
   where to save the passkey.
3. Confirm the RP and account in the glyx passkey window. The daemon creates an
   ES256 credential and stores it in the vault; the extension returns the
   attestation to the site.
4. On later sign-ins, choose the glyx passkey in Chromium's passkey picker and
   confirm the account. The daemon signs the challenge.

Passkeys are synced because they are normal vault items (`BE=1`, `BS=1`, sign
count 0). A vault backup/restore carries them. The private key never leaves the
daemon; the extension receives only the WebAuthn response.

Known limits:

- Chromium/Chrome only; Firefox and Safari passkeys are unsupported.
- Cross-origin iframe requests fall back to the browser because Chrome does not
  expose the iframe origin to the proxy.
- Existing passkeys in Chrome, Google Password Manager, or Apple cannot be
  imported; passkeys are non-exportable. glyx can only capture passkeys created
  while it is the selected provider.
- The extension confirmation counts as user verification for this milestone;
  stronger re-authentication is a later hardening step.
- Manage or delete passkeys from **Passkeys** in the WebUI/desktop app or
  `glyx passkey ls|show|rm`. RP ID, credential ID, user handle, algorithm, and
  private key are read-only.

```sh
glyx passkey ls
glyx passkey show example.com
glyx passkey rm example.com
```

A quick Chromium smoke test: load `apps/extension`, run `glyx extension install`,
allow the extension ID, enable **Passkeys** in the popup, then register and sign
in on a WebAuthn test RP. The passkey appears under **Passkeys** in the WebUI.

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

On Android, clipboard Copy/Fill buttons are still unavailable. Use the system
autofill UI instead: glyx registers an `AutofillService` that fills login fields
from the selected vault. The extension does not use the clipboard: it fills page
inputs directly.

---

## 16. Daemon and GUI

```sh
glyx daemon start [--idle-lock-min N]
glyx daemon status
glyx daemon stop
```

`daemon start` reuses a live daemon or starts one. It does not need a vault argument; it uses the selected vault, or starts empty for onboarding. `--idle-lock-min` overrides the persisted `idle_lock_min` setting for that daemon instance. The record is `daemon.json` in the runtime directory (port, pid, token, selected vault), readable only by you.

The daemon serves the GUI on loopback. The static pages are public; every `/v1` API call requires the bearer token. Open the printed URL, enter the token from `daemon.json`, and use the pages:

- `/` unlock with password, keyfile, or PIN, with an Advanced section for per-unlock TTL and materialization; when unlocking with a password you can also set a PIN
- the unlocked shell has a persistent sidebar (Items, Favorites, Recents, Passkeys, Files & Injection, Conflicts, Health, Devices, Audit, Generator, Settings, Vaults) and a top bar with global search, Add item, and Lock
- `/items` and `/items/<id>` browse, filter, bulk-edit, reveal, copy, edit, delete, TOTP, linked items, used-by targets, and restore history; `/library` manages tags/folders
- `/add` pick a type then create it
- `/passkeys` manage passkey metadata and open the linked login
- `/conflicts` compare and resolve
- `/files` splits **Managed files** (whole-file materialization, perm, keep-on-lock) from **In-place injection** (template editor, reference chips, per-reference form, preview, merge); `/exports` redirects here
- `/onboarding` select, add, create, or forget vaults
- `/settings` session mode and TTL, idle auto-lock, auto-materialize, lock in-place files on crash/exit, daemon behavior, rekey (including keeping old slots), sync, GC, doctor (rebuild + with-unlock), pairwise sync, and the SSH agent socket

Secrets are kept in memory only and never written to `localStorage`.

---

## 17. Desktop app

`glyx-tauri` (the installed binary, or `nix run .#glyx-desktop` on NixOS) starts the daemon for the selected vault, injects the URL and token into the WebView, and opens the GUI. It closes the daemon on exit by default.

With no vault selected, the desktop opens onboarding instead of failing to connect: it lists known vaults and offers **Open existing vault**, **Create new vault**, and **Restore from backup**. File/keyfile selection uses native dialogs on desktop and text paths in the browser WebUI; the native picker runs asynchronously so the Linux desktop no longer freezes while a dialog is open. Creating a vault auto-unlocks it and opens the item list. If the external daemon cannot be started, the desktop falls back to an in-process daemon and shows a retryable error card instead of a blank connection error.

On Hyprland, the desktop starts through XWayland (`GDK_BACKEND=x11`) because WebKitGTK/GTK3 can compute a corrupted viewport after a Wayland tile resize. Set `GDK_BACKEND=wayland` explicitly to opt out. The Nix package embeds the production WebUI; `cargo build -p glyx-tauri --features glyx-tauri/custom-protocol` does the same for local Arch/Nix builds after `pnpm --dir apps/webui build`.

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

**Desktop window is blank or a one-character-wide column on Hyprland/Wayland**: this is a WebKitGTK/GTK3 Wayland resize bug. The app forces XWayland on Hyprland automatically; remove any `GDK_BACKEND=wayland` override if you set one.

**TUI refuses to start**: another process (often the daemon) holds the vault open. Stop the daemon or use the GUI. The TUI opens the vault directly like other CLI commands.

**Extension cannot find the vault**: ensure the daemon is running and a vault is selected, then reinstall the native host with `glyx extension install`.

**Injected file was edited while locked**: `glyx export tamper`, then merge or `export enforce --force`.

**Vault format error**: version 1 vaults are not supported. Recreate the vault.

**Clipboard unavailable**: install a clipboard backend for your session (`wl-clipboard` or X11 tools). `glyx doctor` reports the backend.

**Android Copy/Fill fails**: expected; use the Android autofill UI instead. The clipboard backend is not wired into the mobile shell yet.

**Android APK build fails**: on NixOS use `nix develop .#android-fhs` or `nix develop .#full` (not the plain `.#android` shell). The FHS shells set the AAPT2 override and `/usr/bin`. On Arch Linux use JDK 17, Android SDK platform 36, Build-Tools 35 and 36, the NDK, and `cargo-ndk`; no FHS shell is needed. Build arm64 only with `-t aarch64` unless the disk has several GB free.

---

## 20. Security notes

- The vault is encrypted at rest. The password is mandatory; a keyfile adds a second factor.
- Lock wipes sessions, restores locked forms, shreds non-keep exports, and closes the SSH agent.
- Pointers are bound to their target path and fail closed if copied elsewhere.
- The daemon listens on loopback only and requires a bearer token stored under `0600`.
- The GUI keeps secrets in memory only. It never writes them to browser storage.
- Passkey private keys stay in the daemon/vault. The extension receives only the
  WebAuthn attestation or assertion; an explicit extension confirmation counts as
  user verification in M6e.1.
- Session files hold the data key under `0600` until the TTL expires. Use one-shot mode or short TTLs if that tradeoff is not acceptable.
- Commit only locked forms (`__GLYXENC:...__` or `ENC[...]`), never unresolved values. Review files before committing.
- Back up the vault and your keyfile separately. Without them, recovery is impossible by design.

---

## 21. Android (M6c: autofill + biometrics)

The Android app is the Tauri-mobile shell from `crates/glyx-tauri` plus the same
WebUI. It starts an in-process daemon on loopback, stores the URL/token in the
app-private `glyx-mobile.json`, and injects them into the WebView.

What works today:

- vault onboarding, item browsing/editing, notes, TOTP display, exports,
  injection, sync, conflicts, GC, and doctor through the WebUI
- an Android `AutofillService` that maps a web domain or package query to login
  items and fills username/password fields; when the vault is locked or the
  daemon is not running, the autofill UI offers **Unlock glyx**
- biometric unlock using an Android Keystore key: enabling it adds a dedicated
  random keyslot, encrypts the keyslot secret with a non-exportable,
  biometric-bound AES key, and unlocks by decrypting that secret and calling the
  normal `/v1/unlock` endpoint
- an arm64 debug APK builds successfully

Known limitations:

- clipboard Copy/Fill buttons are unavailable; use system autofill
- no storage-access-framework picker; vault and export paths are typed text
- no lock-on-background yet
- biometric unlock is not offered for keyfile-required vaults (the biometric
  secret cannot satisfy the keyfile requirement)
- no Android passkey provider yet; `CredentialProviderService` is planned for
  M6e.2 (Android 14+) and will stay separate from the password `AutofillService`
- the browser extension and Git helper are desktop-only

Build from the repository.

NixOS:

```sh
nix develop .#android-fhs   # or .#full for the combined shell
cd crates/glyx-tauri
cargo tauri android build --debug --apk -t aarch64
adb install -r gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk
```

Arch Linux:

```sh
export ANDROID_HOME="$HOME/Android/Sdk"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/27.0.12077973"
export NDK_HOME="$ANDROID_NDK_HOME"
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk
export PATH="${ANDROID_HOME}/platform-tools:${ANDROID_HOME}/cmdline-tools/latest/bin:${PATH}"

rustup target add aarch64-linux-android
cd crates/glyx-tauri
cargo tauri android build --debug --apk -t aarch64
adb install -r gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk
```

Install Android SDK platform 36, Build-Tools 35 and 36, and the NDK with
`sdkmanager`; see `local/build-without-nix.md` for the full package list.
Replace the NDK version with the one installed on your host.

Omitting `-t aarch64` builds all four ABIs and needs several GB of disk space.
The Android scaffold lives in `crates/glyx-tauri/gen/android`; do not re-run
`cargo tauri android init` or the pinned Build-Tools/Gradle settings are lost.

After installing, enable glyx under **Settings -> System -> Languages & input ->
Autofill service** (wording varies by vendor). Unlock the vault once, open
**Settings**, and enable biometric unlock; the next unlock page and the autofill
unlock flow offer the biometric prompt.

Runtime device verification is still pending because the build host has no
attached emulator/device. The APK, Kotlin compilation, merged manifest, and Rust
cross-check are verified.

Next milestones: Android passkeys (`CredentialProviderService`, M6e.2), lock on
background, SAF picker, safe areas/icons, and device smoke testing.
