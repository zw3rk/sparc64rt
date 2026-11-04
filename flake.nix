# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
{
  description = "sparc64rt — SPARC V9 64-bit (sparc64 + VIS) to AArch64 Linux user-mode binary translator";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs, ... }:
    let
      systems = [ "aarch64-darwin" "aarch64-linux" "x86_64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      devShells = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          a64Musl = pkgs.pkgsCross.aarch64-multiplatform-musl;
        in {
          default = pkgs.mkShell {
            packages = [ pkgs.gnumake a64Musl.stdenv.cc ];
            shellHook = ''
              echo "sparc64rt development shell (${system})"
            '';
          };
        });

      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          a64Musl = if system == "aarch64-linux"
                    then pkgs.pkgsMusl
                    else pkgs.pkgsCross.aarch64-multiplatform-musl;
        in {
          default = self.packages.${system}.sparc64rt;
          sparc64rt = a64Musl.stdenv.mkDerivation {
            pname = "sparc64rt";
            version = "0.1.0";
            src = pkgs.lib.cleanSource ./.;
            strictDeps = true;
            nativeBuildInputs = [ pkgs.gnumake ];
            dontStrip = true;
            enableParallelBuilding = true;
            buildPhase = ''
              runHook preBuild
              CC_BIN="${a64Musl.stdenv.cc.targetPrefix}gcc"
              command -v "$CC_BIN" >/dev/null 2>&1 || CC_BIN="${a64Musl.stdenv.cc.targetPrefix}cc"
              make build A64_CC="$CC_BIN"
              runHook postBuild
            '';
            installPhase = ''
              runHook preInstall
              mkdir -p "$out/bin" "$out/share/licenses/sparc64rt"
              cp _build/sparc64rt "$out/bin/sparc64rt"
              ln -sf sparc64rt "$out/bin/sparc64rt-binfmt-p"
              cp LICENSE "$out/share/licenses/sparc64rt/Apache-2.0.txt"
              runHook postInstall
            '';
            meta = {
              description = "Standalone static-PIE SPARC V9 64-bit -> AArch64 Linux user-mode translator";
              mainProgram = "sparc64rt";
              license = pkgs.lib.licenses.asl20;
              platforms = [ "aarch64-linux" ];
            };
          };
        });

      checks = forAllSystems (system: {
        sparc64rt = self.packages.${system}.sparc64rt;
      });

      hydraJobs = forAllSystems (system: {
        sparc64rt = self.packages.${system}.sparc64rt;
      });
    };
}
