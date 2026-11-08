# glyx

Local-first password manager for Linux, Windows, and Android. CLI, full-screen TUI, WebUI, desktop app, and an Android app on one Rust core. No accounts, no telemetry, your vault stays yours.

Full feature guide for every frontend, with examples: **[docs.md](docs.md)**. The frontend capability summary is under **[Frontends at a glance](docs.md#frontends-at-a-glance)**.

> Status: M6e.1 passkeys (committed at `293caf1`). CLI, TUI, WebUI, and desktop share one core with consistent features, notes and external Markdown injection, encrypted attachments, item history reveal/compare/restore, safe backups, favorites/recents, tag and folder management, sorting/pagination, bulk actions, duplicate detection, device labels, password health, a local audit log, a standalone generator, and a polished Linux desktop with no-vault onboarding. M6c Android includes the Tauri-mobile shell, AutofillService, and Android Keystore-backed biometric unlock; APK build is verified, device smoke testing remains. M6e.1 adds synced passkey storage, a Chromium extension WebAuthn provider, and passkey management in the WebUI/CLI/desktop (Chrome manual matrix pending); Android passkeys are M6e.2. The current development host is NixOS; see [Build from source](#build-from-source-linux-without-nix).

## What glyx will do

- Store and autofill logins and TOTPs in the browser; create and use synced passkeys in Chromium via the extension; store identities and cards (autofill for those is not implemented yet).
- Store encrypted attachments (25 MiB), back up and restore vaults, manage SSH and other keys, and keep Markdown notes.
- Project secrets into files or folders while unlocked, wipe them on lock.
- Inject secrets inside tracked files (for example `.env` or compose files) and restore placeholders on lock.
- Stay sync-safe when two devices edit the same vault offline, with smart merge and no silent loss.

## Frontends

| Frontend | What it is |
|---|---|
| CLI | `glyx`: full vault, item, history, sync, export, SSH, daemon, extension, and Git control |
| TUI | `glyx tui`: focused item browser/editor (add/edit, notes, TOTP, first-secret copy) |
| WebUI | Browser pages served by the local daemon on loopback |
| Desktop | `glyx-tauri`: the WebUI plus daemon autostart, tray, deep links, notifications, and a configurable quick palette |
| Android | `glyx-tauri` mobile: in-process daemon, WebUI, AutofillService, and biometric unlock |
| Extension | Chrome/Firefox search, login/TOTP fill, and lock; Chromium also provides synced passkeys. Requires an unlocked daemon. |
| Git | `git-credential-glyx`: HTTPS credential `get/store/erase` |

The detailed matrix, including known gaps, lives in `local/feature-parity.md` (local only).

## Install on NixOS (flake)

This repo is a Nix flake. No system Rust needed.

```sh
# Try it without installing
nix run .#default -- --help

# Install CLI into your profile
nix profile install .#default

# CLI plus desktop entry in one profile
nix profile install .#bundle
```

Prebuilt tarball layout (checksums included):

```sh
nix build .#release-bundle
tar -tzf result
```

## Build from source (Linux, without Nix)

This is the Arch Linux path used by the current development host. NixOS users
can use the flake above. A detailed component-by-component guide is kept in
`local/build-without-nix.md` for the development checkout.

### Arch packages

```sh
sudo pacman -S --needed \
  base-devel git pkgconf openssl dbus glib2 gtk3 webkit2gtk-4.1 \
  libsoup3 librsvg libappindicator-gtk3 patchelf \
  nodejs npm rustup wl-clipboard xclip
```

Install `jdk17-openjdk`, `android-tools`, and the Android SDK/NDK only for
Android builds. The Tauri tray uses `libappindicator-gtk3`; the AUR
`libayatana-appindicator` is an alternative.

### Toolchain

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

### Build order

The WebUI is embedded into the daemon and desktop at compile time, so build it
first:

```sh
pnpm --dir apps/webui install --frozen-lockfile
pnpm --dir apps/webui build

cargo build --release -p glyx-cli -p glyx-daemon -p glyx-nm
cargo build --release -p glyx-tauri --features glyx-tauri/custom-protocol
```

Install the CLI, daemon, native host, and desktop binary together so the CLI
can find its siblings:

```sh
install -Dm755 target/release/glyx ~/.local/bin/glyx
install -Dm755 target/release/glyx-daemon ~/.local/bin/glyx-daemon
install -Dm755 target/release/glyx-native-host ~/.local/bin/glyx-native-host
install -Dm755 target/release/glyx-tauri ~/.local/bin/glyx-tauri
ln -sf glyx ~/.local/bin/git-credential-glyx
```

Then run `glyx daemon start`, `glyx-tauri`, and load `apps/extension` in
Chromium. `glyx extension install` + `glyx extension allow <id>` registers the
native host. Android needs the SDK/NDK; see `docs.md` and
`local/build-without-nix.md`.

## Developer shells

These are NixOS-only. On Arch use the build-from-source commands above.

```sh
nix develop                # Linux dev and test shell
nix develop .#cross        # Windows cross-compile helpers (zig, xwin)
nix develop .#android       # Android SDK/NDK, Gradle, cargo-ndk (scripts only)
nix develop .#android-fhs  # FHS shell for actual APK assembly
nix develop .#full         # all of the above in one FHS shell (agents/opencode)
nix run .#full -- <cmd>    # one-shot command inside the full FHS shell
```

`.#full` is the single-shell option: Linux, cross, and Android tooling in one
FHS environment. Use it interactively when you want one shell for an agent such
as `opencode`; use `nix run .#full -- <cmd>` for one-shot commands.
`nix develop .#full -c` does not enter the FHS wrapper, so use `nix run` for
non-interactive work.

Inside the default or full shell:

```sh
cargo nextest run          # tests (preferred)
cargo test                 # tests (fallback)
cargo clippy -- -D warnings
cargo audit
nix build .#default        # CLI package
nix build .#glyx-desktop   # desktop package
```

## Quickstart

Run `glyx` with no arguments for an interactive picker: choose an existing vault, add one from a custom location (for example copied from another device), or create and configure a new one. Your choice is remembered in `~/.config/glyx/config.toml` until you pick another.

```sh
# Create a vault. Omit --keyfile for a password-only vault.
glyx vault init ~/vaults/main.glyx --preset balanced --keyfile ~/keys/main.key --cipher xchacha
glyx vault init ~/vaults/simple.glyx --preset mobile        # password only

# The picker, also available as an explicit command
glyx
glyx vault select

# Work with items (the selected vault is used automatically)
glyx --keyfile ~/keys/main.key add login --name github --field username=you --generate password
glyx --keyfile ~/keys/main.key ls
glyx --keyfile ~/keys/main.key show github
glyx --keyfile ~/keys/main.key show github --reveal
glyx --keyfile ~/keys/main.key totp github
glyx --keyfile ~/keys/main.key edit github --field url=https://github.com
glyx --keyfile ~/keys/main.key rm old-site

# Stay unlocked for a while instead of typing the password each time
glyx --keyfile ~/keys/main.key unlock --ttl 30
glyx ls
glyx lock

# Rotate credentials or cipher (old password required)
glyx --keyfile ~/keys/main.key vault rekey --new-keyfile ~/keys/main2.key
glyx --keyfile ~/keys/main.key vault rekey --no-keyfile
glyx --keyfile ~/keys/main2.key vault rekey --cipher aesgcm

# Encrypted attachments and backups
glyx add file --name report --attach report.pdf
glyx blob ls
glyx vault backup ~/backups/main.tar.gz
glyx vault restore ~/backups/main.tar.gz ~/vaults/restored.glyx

# Check vault health
glyx doctor --with-unlock --json
```

Passwords come from a hidden prompt, or from `--password-env VAR` for scripts. The vault comes from `--vault`, then `GLYX_VAULT`, then your selected vault; `--no-session` forces a fresh prompt every time. A keyfile is only required if the vault was created with one. Every command also accepts `--json`; `--reveal` shows secrets in human output (JSON always includes values). Deletes are tombstones, kept for sync safety. For an interactive walkthrough use `add --interactive`.

## Sessions and convenience passphrase

`unlock` remembers the vault for a while so scripts and daily use skip the password:

```sh
glyx --keyfile ~/keys/main.key unlock --ttl 30
glyx ls
glyx lock
glyx --keyfile ~/keys/main.key unlock --with-pin   # short passphrase instead
```

Set defaults in `~/.config/glyx/config.toml` (or `GLYX_CONFIG`):

```toml
mode = "session"
session_ttl_min = 15
daemon_on_exit = "stop"
current_vault = "/home/you/vaults/main.glyx"

[[vaults]]
path = "/home/you/vaults/main.glyx"
name = "Personal"
keyfile = "/home/you/keys/main.key"
```

Threat model, stated plainly: a session file holds the data key under `0600` in your runtime dir (up to 8h max), like `ssh-agent` holds keys in RAM. Anyone who can read your files can read an active session. The default stays one-shot (no session files unless you run `unlock`), and `lock` wipes them.

## Vault creation and crypto

At creation you pick a preset; advanced users can tune KDF cost and cipher:

| Preset   | KDF                        | Cipher               |
|----------|----------------------------|----------------------|
| Balanced | Argon2id, 256 MiB, t=3     | XChaCha20-Poly1305   |
| Hardened | Argon2id, 1 GiB, t=4       | XChaCha20-Poly1305   |
| Mobile   | Argon2id, 64 MiB, t=3      | XChaCha20-Poly1305   |
| Custom   | Your m/t/p within safe floors | XChaCha20 or AES-256-GCM |

Unlock needs a password, mandatory. A keyfile (a 32 byte random file you keep apart from the vault, for example on USB) is optional but strongly recommended and can be enabled at creation or later with `glyx vault rekey --new-keyfile`; drop it again with `--no-keyfile`. Without a keyfile the password alone protects the vault. Losing a required keyfile makes the vault unrecoverable, by design. Rekeying later (`glyx vault rekey`) changes password, keyfile, or cipher without a new vault.

## File projection and injection

Two ways to let apps use secrets while the vault is unlocked. Files you do not mark `--keep` are shredded when the vault locks; `--keep` files (real exports) stay but are re-synced on unlock:

```sh
# Managed file: a file item, field, blob, or SSH key lands at a path
glyx export add ~/.aws/credentials --item aws --field secret_key
glyx export add ~/Documents/report.pdf --item report
glyx export add ~/.ssh/id_glyx --ssh deploy --keep
glyx export ls
glyx export show ~/.aws/credentials
glyx export keep ~/.aws/credentials    # survive lock (--off to revert)
glyx export recall ~/.aws/credentials
glyx export enforce [--force]

# In-place injection: author {{glyx:<id>/<field>}} refs, they resolve on unlock
glyx inject add ~/project/.env
glyx inject add ~/notes/todo.md --form masked

# Whole folders (for example an Obsidian vault); refs stay readable while locked
glyx inject add ~/Obsidian --glob '*.md'
glyx inject scan
glyx inject rm ~/Obsidian

# Inspect and edit references without hand-authoring them
glyx inject show ~/project/.env
glyx inject preview ~/project/.env
glyx inject add-ref ~/project/.env --line 4 --item github --field password
glyx inject rm-ref ~/project/.env --item github --field password
glyx inject form ~/project/.env masked
```

The WebUI splits these into **Files & Injection → Managed files** and
**In-place injection**. The injection editor opens the canonical reference
template, lets you insert references from any item field, choose a locked form
per reference, and preview both states before saving.

Locked files show opaque encrypted pointers by default (`__GLYXENC:V1:…`, bound to their target path so copying them elsewhere fails closed). Where tooling must parse locked files, `--form masked` writes fixed-size `ENC[…]` tags instead. If a file changed while locked, unlock reports it instead of overwriting: `glyx export tamper`, then combine, keep, or overwrite:

```sh
glyx export merge ~/project/.env --ours     # take vault side for all conflicts
glyx export merge ~/project/.env --theirs   # keep on-disk side for all conflicts
glyx export merge ~/project/.env --pick 2:theirs
glyx export merge ~/project/.env --interactive   # walk each hunk
```

The merge shows base (locked), theirs (on-disk), and ours (fresh vault values) per hunk; clean hunks apply automatically, adjacent edits form a single hunk like git, and true conflicts need an explicit pick — nothing is ever silently dropped or auto-merged across a real conflict.

## Notes

Notes are markdown items. Reference secrets from an item with `{{glyx:<id>/<field>}}`: the app renders the note with the current value, masking secret fields until you reveal them, so values are never baked into the stored note.

```sh
glyx add note --name server --body-file server.md
glyx show server                 # raw body
glyx show server --render         # refs resolved, secrets masked
glyx show server --render --reveal
```

The same refs work in files you track outside the vault: point glyx at a folder of `*.md` files (for example an Obsidian vault) and it substitutes values on unlock, restoring the readable `{{glyx:...}}` placeholders on lock. `glyx inject scan` picks up newly added notes.

## SSH agent

```sh
glyx ssh gen --name deploy --comment you@host --add-to-agent
GLYX_KEY_PASS='...' glyx ssh import --private-file ~/.ssh/id_ed25519 --passphrase-env GLYX_KEY_PASS
glyx ssh ls                                   # algorithm, SHA256 fingerprint, agent state
glyx ssh agent add deploy                     # opt-in per key, reloads without relocking
glyx ssh export deploy --to ~/.ssh/id_glyx   # file export, ledger-tracked
eval $(glyx ssh agent-env)                    # daemon socket, sign-only
ssh-add -L                                    # lists glyx:<name> identities
```

The agent is opt-in per key, starts on unlock even with zero identities, and
serves Ed25519 keys while the daemon is unlocked; it vanishes on lock and private
material never touches disk through this path. RSA keys are export-only for now.
The WebUI **SSH keys** page covers generation, import (file or paste, optional
passphrase), fingerprints, add/revoke, reload, and per-key export targets.

## Sync

Point any file sync you trust (Syncthing, Nextcloud, plain copy) at the vault folder. When the same item changes on two devices, glyx merges field by field on the next unlock or `sync`:

```sh
glyx sync                        # heal file-sync conflict copies in place
glyx sync /mnt/usb/other.glyx    # pairwise merge from another vault copy
glyx conflicts                   # list same-field races the merge recorded
glyx conflicts show site         # compare both versions
glyx conflicts resolve site --theirs
glyx conflicts resolve site --field city=Bergen
glyx sync-status                 # envelopes, tombstones, conflicts, last merge
glyx gc --dry-run                # preview tombstone purge
glyx gc --older-than 30d         # purge tombstones older than 30 days
```

Rules: newer fields win, tombstones win over edits, true same-field races keep a deterministic winner and record both sides under `conflicts/` for you to resolve. Nothing is silently dropped. Note the one caveat: purging a tombstone older than the GC window means a device offline longer than that window can resurrect the deleted item on its next sync. A self-hostable LAN relay is planned later with the same merge rules and end to end encryption.

## Daemon, WebUI, desktop

The daemon owns the unlocked vault and serves the API plus the WebUI on loopback only. It can run without a vault so you can onboard, then switch the active vault in place:

```sh
glyx daemon start                 # uses your selected vault, or starts empty
glyx daemon status
```

Open the printed address in a browser, paste the token from the runtime dir (`daemon.json`), then manage vaults and unlock items, TOTP codes, conflicts, sync, GC, and doctor from the UI. Secrets stay in memory only and never touch `localStorage`. The desktop app (`glyx-tauri`, or `nix run .#glyx-desktop`) hosts the same UI: it starts the daemon for you, wires the URL and token automatically, and ships with onboarding for choosing, adding, or creating a vault. By default it stops the daemon it started when you close the app; change that under Settings. `daemon stop` (or Lock in the UI) drops the key.

```sh
nix profile install .#bundle   # NixOS: CLI, daemon, and desktop in one profile
```

## Browser fill, Git, clipboard

Desktop secret storage stays with gnome-keyring; glyx covers browsers, Git, and the terminal:

```sh
# Browser extension (Chrome + Firefox, needs a running daemon)
glyx --vault ~/vaults/main.glyx extension install --firefox
glyx --vault ~/vaults/main.glyx extension install   # Chrome manifests
# load apps/extension in the browser, then for Chrome:
glyx extension allow <id-from-chrome://extensions>

# Git HTTPS credentials (no prompts after one unlock)
glyx git setup
export GLYX_VAULT=~/vaults/main.glyx GLYX_KEYFILE=~/keys/main.key
glyx unlock   # or rely on a session/PIN
git clone https://github.com/you/repo

# Terminal copy with auto-clear (nothing secret on stdout)
glyx fill github
glyx fill github --field username --timeout 30
glyx fill github --dry-run
```

The extension requires the daemon to already be unlocked; it has no unlock screen. Its Fill and TOTP buttons fill the page through input events and never auto-submit. The Git helper matches the URL host to a login item (`store` creates one when missing), and `erase` tombstones it.

The desktop app also registers Ctrl+Shift+G to pop up the vault search.

## Configuration

| Item            | Location                                    |
|-----------------|---------------------------------------------|
| Vault folder    | You choose, for example `~/vaults/main.glyx` |
| Daemon socket   | Loopback only, token in `daemon.json`, token auth |
| Export ledger   | Local only, never synced (`agent-ledger.sqlite`) |
| App config      | `~/.config/glyx/config.toml` (or `GLYX_CONFIG`) |
| Selected vault  | `current_vault` in the app config           |
| Keyfiles        | Anywhere you choose; only the path is stored in the app config |

No network listener leaves your machine in v1 except the planned opt-in relay.

## Layout

```
flake.nix        Nix shells, packages, apps
crates/
  glyx-core      Item/HLC/DeviceId/SecretString types, VAULT.toml spec
  glyx-crypto    Argon2id KDF, XChaCha/AES-GCM, keyslots, BLAKE3
  glyx-store     Vault init/open, envelopes, blobs, index, merge/heal/GC
  glyx-sync      Field-LWW merge, dominance check, header ordering, classifier
  glyx-agent     Export/inject ledger, shred, tamper, SSH agent socket
  glyx-autofill  Clipboard backend + fill helpers (no Secret Service by design)
  glyx-daemon    Axum /v1 API + embedded WebUI, vault onboarding, token auth, idle auto-lock
  glyx-tauri     Tauri desktop + mobile shell; desktop autostarts the daemon, mobile serves it in-process
  glyx-nm        NativeMessaging stdio bridge proxying to the daemon
  glyx-cli       Full CLI: items, sessions, rekey, sync, conflicts, gc, fill, git, extension
apps/            webui, extension; Android scaffold lives in crates/glyx-tauri/gen/android
local/           Agent/developer docs, Arch build guide, handoff prompt (gitignored)
```

## Roadmap

Milestones M-1 through M7 live in `local/current-roadmap.md` (local only). Public summary: M-1 Nix scaffold (done), M0 foundation (done), M1 items plus sessions plus rekey (done), M2 sync merge (done), M3 daemon plus WebUI plus desktop (done), M4 browser/Git/clipboard fill (done), M5 file agent plus SSH (done), M5.1 three-way file merge (done), M5.2 vault onboarding plus optional keyfiles plus self-starting desktop (done), M5.3 frontend parity plus CLI TUI (done), M5.4 parity gap closure (done), M5.5 parity foundation (done), M5.6 Linux desktop polish (done), M6a notes, M6b external Markdown folders (done), M6c Android shell/scaffold/APK build plus AutofillService and biometric unlock (implemented; device smoke test pending), M6e.1 synced passkeys plus Chromium extension create/get and WebUI/CLI/desktop management (committed at `293caf1`; Chrome manual matrix pending), M6e.2 Android Credential Manager (planned), M6f non-Nix Arch build portability (docs done; host validation pending), M7 hardening and installers.

## License

GPL-3.0-or-later, see `LICENSE`.
