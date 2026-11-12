# Arch Linux package

This directory contains the Arch Linux packaging files for the NetView 1.0.0 release.

## Build locally

From this directory:

```bash
makepkg --verifysource
makepkg
```

Install the resulting package with:

```bash
sudo pacman -U netview-1.0.0-1-any.pkg.tar.zst
```

The runtime dependencies are provided by Arch Linux. `wireshark-cli` is optional and supplies `dumpcap` for live capture; opening saved PCAP/PCAPNG files does not require it.

## AUR publication

The AUR package must be published in a separate Git repository named `netview` under the package maintainer's AUR account. Copy `PKGBUILD` and `.SRCINFO` from this directory into that repository, then push them to its `master` branch.

The maintainer email in `PKGBUILD` must be replaced before publication. Regenerate `.SRCINFO` with `makepkg --printsrcinfo` after any PKGBUILD change.
