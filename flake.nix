# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
{
  description = "sparc64rt - SPARC V9 64-bit (sparc64) to AArch64 Linux user-mode translator";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs, ... }:
    let
      systems = [ "aarch64-darwin" "aarch64-linux" "x86_64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      devShells = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system};
            a64Musl = pkgs.pkgsCross.aarch64-multiplatform-musl;
        in {
          default = pkgs.mkShell {
            packages = [ pkgs.gnumake a64Musl.stdenv.cc ];
            shellHook = ''
              echo "sparc64rt development shell (build: make build)"
            '';
          };
        });

      packages = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system};
            a64Musl = pkgs.pkgsCross.aarch64-multiplatform-musl;
        in {
          default = self.packages.${system}.sparc64rt;
          sparc64rt = a64Musl.stdenv.mkDerivation {
            pname = "sparc64rt";
            version = "0.0.0-phase0";
            src = pkgs.lib.cleanSource ./.;
            strictDeps = true;
            nativeBuildInputs = [ pkgs.gnumake ];
            dontStrip = true;
            buildPhase = ''
              runHook preBuild
              make build A64_CC="${a64Musl.stdenv.cc.targetPrefix}gcc"
              runHook postBuild
            '';
            installPhase = ''
              runHook preInstall
              mkdir -p "$out/bin" "$out/share/licenses/sparc64rt"
              cp _build/sparc64rt "$out/bin/sparc64rt"
              cp LICENSE "$out/share/licenses/sparc64rt/Apache-2.0.txt"
              runHook postInstall
            '';
            meta = {
              description = "Static-PIE AArch64 Linux SPARC V9 64-bit user-mode translator";
              license = pkgs.lib.licenses.asl20;
              platforms = [ "aarch64-linux" ];
            };
          };
        });
    };
}
