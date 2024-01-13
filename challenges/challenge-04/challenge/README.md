# Release build

To build the final challenge, run `cargo build --release --features embed`. The
`embed` feature causes the binary to embed all resources it needs instead of
using the ones from disk.

# Development build

To run a development version, you can just do `cargo run --release`, however
you probably want to add some features:

The `bevy/file_watcher` causes bevy to reload automatically when files change.
It **mostly** works as intended, though we have experienced that sometimes you
still need to reload the binary to reload the files.

You probably also want the `wirelang`, which causes the world to be loaded from
`world.wirelang` instead of `world.wiremap`. The `world.wiremap` is a compiled
version of `world.wirelang`.

# Building on mac

We had some last-minute troubles compiling on mac, and we made a very jank fix
to get the binaries shipped.

To use our very jank fix, you need to uncomment these lines in the bottom of
`Cargo.toml`:

```toml
# [patch.crates-io]
# ttf2mesh-sys = { path = "ttf2mesh-sys" }
```

# Compiling `world.wirelang` into `world.wiremap`

To compile the wirelang into a wiremap, run these commands:

```bash
cargo run --example interpret < ./crates/charming-circuit-challenge/assets/world.wirelang
mv foo.wiremap ./crates/charming-circuit-challenge/assets/world.wiremap`
```

# A note on nix files

The nix files were not used in compilation, since we compiled on ubuntu and a
mac laptop. They were however used in development, since all the challenge
makers are daily driving NixOS.
