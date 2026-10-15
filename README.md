# glyx

Local-first password manager for Linux, Windows, and Android. CLI, WebUI, and desktop app on one Rust core. No accounts, no telemetry, your vault stays yours.

> Status: early scaffold (M-1). The CLI currently prints its version only. This README is a living user guide and will grow with each milestone.

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

## Quickstart (planned CLI, M1)

These commands are the target UX and do not all exist yet:

```sh
glyx vault init ~/vaults/main.glyx --preset balanced
glyx unlock
glyx ls
glyx show github --json
glyx add login github --username you --password "?"
glyx totp github
glyx lock
glyx doctor
```

Today only `glyx` (prints version) works. `glyx doctor` will arrive in M1 to check vault health, merge state, and leftover exports.

## Vault creation and crypto (planned, M1)

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

## Sync (planned, M2, relay in Phase 2)

Point any file sync you trust (Syncthing, Nextcloud, plain copy) at the `my.glyx/` folder. Each item carries a sync header so concurrent offline edits merge field by field; true conflicts are kept for you to resolve, never dropped. A self-hostable LAN relay is planned later with the same merge rules and end to end encryption.

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
crates/          Rust core (glyx-core, glyx-crypto, glyx-store,
                 glyx-sync, glyx-agent, glyx-autofill,
                 glyx-daemon, glyx-cli)
apps/            webui, desktop, android, extension (fill in M3+)
local/           Agent and developer docs (gitignored, local only)
```

## Roadmap

Milestones M-1 through M7 live in `local/current-roadmap.md` (local only). Public summary: M-1 Nix scaffold (done), M0 workspace spec, M1 core plus CLI, M2 sync merge, M3 daemon plus WebUI plus desktop, M4 autofill, M5 file agent plus SSH, M6 Android plus notes, M7 hardening and installers.

## License

GPL-3.0-or-later. See LICENSE when added (planned M0).
