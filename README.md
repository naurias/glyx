# glyx

Local-first password manager for Linux, Windows, and Android. CLI, WebUI, and desktop app on one Rust core. No accounts, no telemetry, your vault stays yours.

> Status: M4 browser fill, Git helper, and clipboard fill work. SSH agent and file injection arrive in M5. This README is a living user guide and grows with each milestone.

## What glyx will do

- Store and autofill passwords, passkeys, TOTPs, identities, and cards.
- Store files, manage SSH and other keys, and keep Markdown notes.
- Project secrets into files or folders while unlocked, wipe them on lock.
- Inject secrets inside tracked files (for example `.env` or compose files) and restore placeholders on lock.
- Stay sync-safe when two devices edit the same vault offline, with smart merge and no silent loss.

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

## Developer shells

```sh
nix develop                # Linux dev and test shell
nix develop .#cross        # Windows cross-compile helpers (zig, xwin)
nix develop .#android       # Android SDK/NDK, Gradle, cargo-ndk (scripts only)
nix develop .#android-fhs  # FHS shell for actual APK assembly
```

Inside the default shell:

```sh
cargo nextest run          # tests (preferred)
cargo test                 # tests (fallback)
cargo clippy -- -D warnings
cargo audit
nix build .#default        # CLI package
nix build .#glyx-desktop   # desktop package (real Tauri binary lands in M3)
```

## Quickstart

```sh
# Create a vault (generates the keyfile when missing)
glyx vault init ~/vaults/main.glyx --preset balanced --keyfile ~/keys/main.key --cipher xchacha

# Work with items (pass --vault once or set GLYX_VAULT)
export GLYX_VAULT=~/vaults/main.glyx
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
glyx --keyfile ~/keys/main2.key vault rekey --cipher aesgcm

# Check vault health
glyx doctor --with-unlock --json
```

Passwords come from a hidden prompt, or from `--password-env VAR` for scripts. The vault is taken from `--vault` or `GLYX_VAULT`; `--no-session` forces a fresh prompt every time. Every command also accepts `--json`; `--reveal` shows secrets in human output (JSON always includes values). Deletes are tombstones, kept for sync safety. For an interactive walkthrough use `add --interactive`.

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

Unlock is password plus keyfile (a 32 byte random file you keep apart from the vault, for example on USB). Lose either and the vault cannot be recovered, by design. Rekeying later (`glyx vault rekey`) changes password, keyfile, or cipher without a new vault.

## File projection and injection (planned, M5)

Two ways to let apps use secrets while the vault is unlocked:

1. Full export: a vault file is copied to a path you choose with `chmod 600`, tracked in a local ledger, and securely deleted on lock or recall.
2. In-place injection: a tracked file keeps a placeholder when locked and gets the real secret while unlocked:

```sh
# locked view
password: __GLYXENC:V1:opaque-blob__

# unlocked view
password: s3cret-value
```

Placeholders default to opaque encrypted pointers so a locked file reveals nothing about which item it points to. If a file changed while the vault was locked, glyx shows a diff on next unlock instead of overwriting silently.

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

The daemon owns the unlocked vault and serves the API plus the WebUI on loopback only:

```sh
glyx --vault ~/vaults/main.glyx daemon start
glyx --vault ~/vaults/main.glyx daemon status
```

Open the printed address in a browser, paste the token from the runtime dir (`daemon-<vault>.json`), unlock, and manage items, TOTP codes, conflicts, sync, GC, and doctor from the UI. Secrets stay in memory only and never touch `localStorage`. The desktop app (`glyx-tauri`, or `nix run .#glyx-desktop`) hosts the same UI. `daemon stop` (or Lock in the UI) drops the key.

```sh
nix profile install .#bundle   # CLI, daemon, and desktop in one profile
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

The desktop app also registers Ctrl+Shift+G to pop up the vault search. Fill never auto-submits web forms.

## Configuration

| Item            | Location (planned)                          |
|-----------------|---------------------------------------------|
| Vault folder    | You choose, for example `~/vaults/main.glyx` |
| Daemon socket   | Loopback only, token auth (M3)              |
| Export ledger   | Local only, never synced (M5)               |
| App config      | XDG config dir (exact path confirmed in M3) |

No network listener leaves your machine in v1 except the planned opt-in relay.

## Layout

```
flake.nix        Nix shells, packages, apps
crates/
  glyx-core      Item/HLC/DeviceId/SecretString types, VAULT.toml spec
  glyx-crypto    Argon2id KDF, XChaCha/AES-GCM, keyslots, BLAKE3
  glyx-store     Vault init/open, envelopes, blobs, index, merge/heal/GC
  glyx-sync      Field-LWW merge, dominance check, header ordering, classifier
  glyx-agent     Export ledger traits (engine in M5)
  glyx-autofill  Clipboard backend + fill helpers (no Secret Service by design)
  glyx-daemon    Axum /v1 API + embedded WebUI, token auth, idle auto-lock
  glyx-tauri     Tauri desktop shell hosting the built WebUI
  glyx-nm        NativeMessaging stdio bridge proxying to the daemon
  glyx-cli       Full CLI: items, sessions, rekey, sync, conflicts, gc, fill, git, extension
apps/            webui, desktop, android, extension (fill in M3+)
local/           Agent and developer docs (gitignored, local only)
```

## Roadmap

Milestones M-1 through M7 live in `local/current-roadmap.md` (local only). Public summary: M-1 Nix scaffold (done), M0 foundation (done), M1 items plus sessions plus rekey (done), M2 sync merge (done), M3 daemon plus WebUI plus desktop (done), M4 browser/Git/clipboard fill (done), M5 file agent plus SSH, M6 Android plus notes, M7 hardening and installers.

## License

GPL-3.0-or-later, see `LICENSE`.
