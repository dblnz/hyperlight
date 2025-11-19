{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.nixpkgs-mozilla.url = "github:mozilla/nixpkgs-mozilla/master";
  outputs = { self, nixpkgs, nixpkgs-mozilla, ... } @ inputs:
    let
      # Use flatbuffers 25.9.23 until nixpkgs updates it
      flatbuffersOverlay = final: prev: let
        version = "25.9.23";
      in {
          flatbuffers = prev.flatbuffers.overrideAttrs (old: {
          inherit version;
          src = prev.fetchFromGitHub {
              owner = "google";
              repo = "flatbuffers";
              rev = "v${version}";
              hash = "sha256-A9nWfgcuVW3x9MDFeviCUK/oGcWJQwadI8LqNR8BlQw=";
          };
          });
      };
    in
    {
      devShells.x86_64-linux.default =
        let pkgs = import nixpkgs {
              system = "x86_64-linux";
              overlays = [ (import (nixpkgs-mozilla + "/rust-overlay.nix")) flatbuffersOverlay ];
            };
        in with pkgs; let
          # Work around the nixpkgs-mozilla equivalent of
          # https://github.com/NixOS/nixpkgs/issues/278508 and an
          # incompatibility between nixpkgs-mozilla and makeRustPlatform
          rustChannelOf = args: let
            orig = pkgs.rustChannelOf args;
            patchRustPkg = pkg: (pkg.overrideAttrs (oA: {
              buildCommand = builtins.replaceStrings
                [ "rustc,rustdoc" ]
                [ "rustc,rustdoc,clippy-driver,cargo-clippy" ]
                oA.buildCommand;
            })) // {
              targetPlatforms = [ "x86_64-linux" ];
              badTargetPlatforms = [ ];
            };
            overrideRustPkg = pkg: lib.makeOverridable (origArgs:
              patchRustPkg (pkg.override origArgs)
            ) {};
          in builtins.mapAttrs (_: overrideRustPkg) orig;

          customisedRustChannelOf = args:
            lib.flip builtins.mapAttrs (rustChannelOf args) (_: pkg: pkg.override {
              targets = [
                "x86_64-unknown-linux-gnu"
                "x86_64-pc-windows-msvc" "x86_64-unknown-none"
                "wasm32-wasip1" "wasm32-wasip2" "wasm32-unknown-unknown"
              ];
              extensions = [ "rust-src" ];
            });

          # Hyperlight needs a variety of toolchains, since we use Nightly
          # for rustfmt and old toolchains to verify MSRV
          toolchains = lib.mapAttrs (_: customisedRustChannelOf) {
            stable = {
              # Stay on 1.89
              date = "2025-08-07";
              channel = "stable";
              sha256 = "sha256-+9FmLhAOezBZCOziO0Qct1NOrfpjNsXxc/8I0c7BdKE=";
            };
            nightly = {
              date = "2025-08-07";
              channel = "nightly";
              sha256 = "sha256-jX+pQa3zzuCnR1fRZ0Z4L2hXLP3JoGOcpbL4vI853EA=";
            };
            "1.85" = {
              date = "2025-02-20";
              channel = "stable";
              sha256 = "sha256-AJ6LX/Q/Er9kS15bn9iflkUwcgYqRQxiOIL2ToVAXaU=";
            };
            "1.86" = {
              date = "2025-04-03";
              channel = "stable";
              sha256 = "sha256-X/4ZBHO3iW0fOenQ3foEvscgAPJYl2abspaBThDOukI=";
            };
            "1.91.1" = {
              date = "2025-11-10";
              channel = "stable";
              sha256 = "sha256-SDu4snEWjuZU475PERvu+iO50Mi39KVjqCeJeNvpguU=";
            };
          };

          rust-platform = makeRustPlatform {
            cargo = toolchains.stable.rust;
            rustc = toolchains.stable.rust;
          };

          # Hyperlight scripts use cargo in a bunch of ways that don't
          # make sense for Nix cargo, including the `rustup +toolchain`
          # syntax to use a specific toolchain and `cargo install`, so we
          # build wrappers for rustc and cargo that enable this.  The
          # scripts also use `rustup toolchain install` in some cases, in
          # order to work in CI, so we provide a fake rustup that does
          # nothing as well.
          rustup-like-wrapper = name: pkgs.writeShellScriptBin name
            (let
              clause = name: toolchain:
                "+${name}) base=\"${toolchain.rust}\"; shift 1; ;;";
              clauses = lib.strings.concatStringsSep "\n"
                (lib.mapAttrsToList clause toolchains);
            in ''
          base="${toolchains.stable.rust}"
          case "$1" in
            ${clauses}
            install) exit 0; ;;
          esac
          export PATH="$base/bin:$PATH"
          exec "$base/bin/${name}" "$@"
        '');
          fake-rustup = pkgs.symlinkJoin {
            name = "fake-rustup";
            paths = [
              (pkgs.writeShellScriptBin "rustup" "")
              (rustup-like-wrapper "rustc")
              (rustup-like-wrapper "cargo")
            ];
          };

          buildRustPackageClang = rust-platform.buildRustPackage.override { stdenv = clangStdenv; };
        in (buildRustPackageClang rec {
          pname = "hyperlight";
          version = "0.0.0";
          src = lib.cleanSource ./.;
          cargoHash = "sha256-7Op6f0MWTAM4ElARNnypz72BxUnKcvrUafKDKGaxqL8=";

          nativeBuildInputs = [
            azure-cli
            cmake
            dotnet-sdk_9
            ffmpeg
            flatbuffers
            gdb
            gh
            just
            jaq
            jq
            lld
            llvmPackages_18.llvm
            mkvtoolnix
            pkg-config
            valgrind
            wasm-tools
            zlib
          ];
          buildInputs = [
            cairo
            openssl
            pango
          ];

          auditable = false;

          LIBCLANG_PATH = "${pkgs.llvmPackages_18.libclang.lib}/lib";
          # Use unwrapped clang for compiling guests
          HYPERLIGHT_GUEST_clang = "${clang.cc}/bin/clang";

          RUST_NIGHTLY = "${toolchains.nightly.rust}";
          # Set this through shellHook rather than nativeBuildInputs to be
          # really sure that it overrides the real cargo.
          shellHook = ''
            export PATH="${fake-rustup}/bin:$PATH"
            export LD_LIBRARY_PATH=${stdenv.cc.cc.lib}/lib:${zlib}/lib:$LD_LIBRARY_PATH
          '';
        }).overrideAttrs(oA: {
          hardeningDisable = [ "all" ];
        });
    };
}
