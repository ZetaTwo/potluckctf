{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-23.11";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
    let
      overlays = [ (import rust-overlay) ];
      pkgs = import nixpkgs {
        inherit system overlays;
      };
      lib = pkgs.lib;
      clangVersion = lib.versions.major (lib.getVersion pkgs.llvmPackages.clang);
    in
    {
      devShell = with pkgs;
        mkShell {
          nativeBuildInputs = [
            # nix develop shells will by default include a bash in the $PATH,
            # however this bash will be a non-interactive bash. The deviates from
            # how nix-shell works. This fix was taken from:
            #    https://discourse.nixos.org/t/interactive-bash-with-nix-develop-flake/15486
            bashInteractive

            # rust. compile to wasm and linux
            (rust-bin.stable.latest.default.override {
              extensions = [ "rust-src" ];
              targets = [ "wasm32-unknown-unknown" "x86_64-unknown-linux-gnu" ];
            })

            # Build dependencies
            pkg-config llvmPackages.bintools openssl cmake zstd jq

            # vulkan and bevy stuff
            vulkan-tools shaderc renderdoc
            xorg.libX11 xorg.libXcursor xorg.libXrandr xorg.libXi
            udev alsa-lib

            # Tools
            cargo-flamegraph
            tracy
          ];

          # Append a library path for stuff loaded using dlopen
          APPEND_LIBRARY_PATH = lib.makeLibraryPath [
            vulkan-loader
          ];

          VK_LAYER_PATH = "${vulkan-validation-layers}/share/vulkan/explicit_layer.d";
          RUST_SRC_PATH = "${rust.packages.stable.rustPlatform.rustLibSrc}";
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          BINDGEN_EXTRA_CLANG_ARGS = "-idirafter ${llvmPackages.clang-unwrapped.lib}/lib/clang/${clangVersion}/include";

          shellHook = ''
            export LD_LIBRARY_PATH="''${LD_LIBRARY_PATH:+''${LD_LIBRARY_PATH}:}$APPEND_LIBRARY_PATH"
            unset APPEND_LIBRARY_PATH
            # nix develop shells will by default overwrite the $SHELL variable with a
            # non-interactive version of bash. The deviates from how nix-shell works.
            # This fix was taken from:
            #    https://discourse.nixos.org/t/interactive-bash-with-nix-develop-flake/15486
            #
            # See also: nixpkgs#5131 nixpkgs#6091
            export SHELL=${bashInteractive}/bin/bash
          '';
        };
    });
}
