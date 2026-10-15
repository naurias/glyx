{
  description = "glyx - local-first password manager (Rust + Tauri)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        version =
          let
            toml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
            base = toml.workspace.package.version or "0.1.0";
            rev = self.shortRev or self.dirtyShortRev or "nogit";
          in
          "${base}+g${rev}";

        rustToolchain = with pkgs; [
          cargo
          rustc
          clippy
          rustfmt
          rust-analyzer
        ];

        # Scoped package set for Android tooling. The SDK is proprietary, so
        # license acceptance and unfree permission live here only; the default
        # shell and packages stay fully free.
        pkgsAndroid = import nixpkgs {
          inherit system;
          config = {
            android_sdk.accept_license = true;
            allowUnfree = true;
          };
        };
        androidSdk = pkgsAndroid.androidenv.composeAndroidPackages {
          platformVersions = [ "36" "37.0" ];
          buildToolsVersions = [ "36.0.0" ];
          includeNDK = true;
        };
        androidFhsEnv = pkgsAndroid.buildFHSEnv {
          name = "glyx-android-env";
          targetPkgs = pkgs: [
            pkgs.rustup
            pkgs.stdenv.cc
            pkgs.pkg-config
            pkgs.jdk17
            pkgs.gradle
            androidSdk.androidsdk
            androidSdk.platform-tools
            pkgs.nodejs_22
            pkgs.pnpm
            pkgs.glibc
            pkgs.zlib
            pkgs.stdenv.cc.cc.lib
            pkgs.which
          ];
          runScript = pkgs.writeShellScript "enter-glyx-android-env" ''
            export ANDROID_HOME="${androidSdk.androidsdk}/libexec/android-sdk"
            export ANDROID_SDK_ROOT="$ANDROID_HOME"
            export ANDROID_NDK_ROOT="$ANDROID_HOME/ndk-bundle"
            export ANDROID_NDK_HOME="$ANDROID_NDK_ROOT"
            export JAVA_HOME="${pkgsAndroid.jdk17}/lib/openjdk"
            export RUSTUP_HOME="$HOME/.rustup-glyx"
            export PATH="$ANDROID_HOME/platform-tools:$PATH"
            echo "glyx Android FHS shell (standard loader contract; exit leaves nix develop)"
            echo "Android SDK: $ANDROID_HOME"
            exec bash
          '';
        };

        linuxTauriDeps = with pkgs; [
          pkg-config
          openssl
          dbus
          gtk3
          glib
          webkitgtk_4_1
          libsoup_3
          librsvg
          libappindicator-gtk3
          patchelf
        ];
      in
      {
        # M-1: CLI (+ daemon lib) only. WebUI embedding via pnpm lands in M3;
        # see TODO below. Desktop package below reuses this binary until the
        # Tauri crate lands.
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "glyx";
          inherit version;
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          buildInputs = [ pkgs.openssl ];
          nativeBuildInputs = [ pkgs.pkg-config ];
          cargoBuildFlags = [
            "--bin"
            "glyx"
          ];
          cargoTestFlags = [
            "-p"
            "glyx-core"
            "-p"
            "glyx-crypto"
          ];
          # TODO(M3): add pnpmDeps + preBuild `(cd apps/webui && pnpm build)`
          # with EMBED_UI=1 once apps/webui exists, mirroring liber-rs.
          meta = with pkgs.lib; {
            description = "glyx local-first password manager CLI";
            homepage = "https://github.com/glyx/glyx";
            license = licenses.gpl3Plus;
            mainProgram = "glyx";
          };
        };

        # Desktop app stub: same binary with GApps wrapping + .desktop entry.
        # Becomes the real Tauri binary in M3 (crates/glyx-tauri or apps/desktop).
        packages.glyx-desktop = pkgs.rustPlatform.buildRustPackage {
          pname = "glyx-desktop";
          inherit version;
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          buildInputs = linuxTauriDeps;
          nativeBuildInputs = [
            pkgs.pkg-config
            pkgs.wrapGAppsHook3
          ];
          cargoBuildFlags = [
            "--bin"
            "glyx"
          ];
          cargoTestFlags = [
            "-p"
            "glyx-core"
          ];
          postInstall = ''
            mkdir -p $out/share/applications $out/share/icons/hicolor/32x32/apps $out/share/icons/hicolor/128x128/apps
            cat > $out/share/applications/glyx.desktop <<EOF
            [Desktop Entry]
            Type=Application
            Name=glyx
            Comment=Local-first password manager
            Exec=glyx
            Icon=glyx
            Categories=Utility;Security;
            Terminal=false
            EOF
          '';
        };

        packages.release-bundle =
          let
            cli = self.packages.${system}.default;
            desktop = self.packages.${system}.glyx-desktop;
          in
          pkgs.runCommand "glyx-${version}-${system}"
            {
              nativeBuildInputs = [ pkgs.gnutar ];
            }
            ''
              mkdir -p bundle/glyx-${version}
              cp ${cli}/bin/glyx bundle/glyx-${version}/
              cp ${desktop}/bin/.glyx-wrapped bundle/glyx-${version}/glyx-desktop 2>/dev/null || cp ${desktop}/bin/glyx bundle/glyx-${version}/glyx-desktop
              cat > bundle/glyx-${version}/INSTALL.txt <<EOF
              glyx ${version} (${system})
              Run from this directory or add it to PATH:
                ./glyx                  CLI + vault management
                ./glyx-desktop          desktop entry (Tauri binary lands in M3)
              Verify with: (cd glyx-${version} && sha256sum -c SHA256SUMS)
              EOF
              (cd bundle/glyx-${version} && sha256sum glyx glyx-desktop > SHA256SUMS)
              (cd bundle && tar -czf $out glyx-${version})
            '';

        packages.bundle = pkgs.symlinkJoin {
          name = "glyx-bundle-${version}";
          paths = [
            self.packages.${system}.default
            self.packages.${system}.glyx-desktop
          ];
          meta = with pkgs.lib; {
            description = "glyx password manager: CLI and desktop in one install";
            homepage = "https://github.com/glyx/glyx";
            license = licenses.gpl3Plus;
            mainProgram = "glyx";
            platforms = platforms.linux;
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs =
            rustToolchain
            ++ (with pkgs; [
              cargo-nextest
              cargo-audit
              cargo-zigbuild
              cargo-xwin
              cargo-ndk
              rustup
              zig
              nodejs_22
              pnpm
              sqlite
              pkg-config
            ])
            ++ linuxTauriDeps;
          shellHook = ''
            export RUSTUP_HOME="$HOME/.rustup-glyx"
            echo "glyx dev shell (Linux test-only)"
            echo "cargo $(cargo --version 2>/dev/null || echo missing)"
            echo "Extra targets via: rustup toolchain install stable --target <triple>"
            echo "Android work: use .#android or .#android-fhs instead"
            echo "Build: nix build .#default | .#glyx-desktop | .#bundle"
          '';
        };

        devShells.cross = pkgs.mkShell {
          buildInputs =
            rustToolchain
            ++ (with pkgs; [
              zig
              cargo-zigbuild
              cargo-xwin
              rustup
              pkgsCross.mingwW64.stdenv.cc
            ]);
          shellHook = ''
            export RUSTUP_HOME="$HOME/.rustup-glyx"
            echo "glyx cross shell: cargo zigbuild / cargo xwin available"
            echo "macOS outputs are compile-check only (no signing)."
          '';
        };

        devShells.android = pkgsAndroid.mkShell {
          buildInputs = with pkgsAndroid; [
            rustup
            jdk17
            gradle
            androidSdk.androidsdk
            androidSdk.platform-tools
            nodejs_22
            pnpm
            cargo-ndk
          ];
          ANDROID_HOME = "${androidSdk.androidsdk}/libexec/android-sdk";
          ANDROID_SDK_ROOT = "${androidSdk.androidsdk}/libexec/android-sdk";
          shellHook = ''
            export RUSTUP_HOME="$HOME/.rustup-glyx"
            export ANDROID_NDK_ROOT="$ANDROID_HOME/ndk-bundle"
            export ANDROID_NDK_HOME="$ANDROID_NDK_ROOT"
            export PATH="$ANDROID_HOME/platform-tools:$PATH"
            echo "Android SDK: $ANDROID_HOME"
            echo "Note: APK assembly needs the FHS shell (nix develop .#android-fhs);"
            echo "this shell is for Rust/JS builds, scripts, and sdkmanager only."
          '';
        };

        packages.android-fhs = androidFhsEnv;

        devShells.android-fhs = pkgs.mkShell {
          buildInputs = [ androidFhsEnv ];
          shellHook = ''
            exec ${androidFhsEnv}/bin/glyx-android-env
          '';
        };

        apps.default = flake-utils.lib.mkApp {
          drv = self.packages.${system}.default;
          exePath = "/bin/glyx";
        };
        apps.bundle = flake-utils.lib.mkApp {
          drv = self.packages.${system}.bundle;
          exePath = "/bin/glyx";
        };
        apps.glyx-desktop = flake-utils.lib.mkApp {
          drv = self.packages.${system}.glyx-desktop;
          exePath = "/bin/glyx";
        };
      }
    );
}
