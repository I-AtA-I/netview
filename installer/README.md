# Windows installer

This installer packages the already-built Nuitka standalone folder. It does not run Nuitka again.

## Prerequisites

- Windows x64
- A successful standalone build at `src/netview/NetView.dist`
- Inno Setup 6.7.x (the installer script uses Inno Setup 6 syntax)

Install Inno Setup 6 from its official download page:
https://jrsoftware.org/isdl.php

## Build

Run this from the repository root in PowerShell:

```powershell
$iscc = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
if (-not (Test-Path $iscc)) {
    $iscc = "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
}
if (-not (Test-Path $iscc)) {
    throw "Inno Setup 6 compiler (ISCC.exe) was not found."
}

& $iscc ".\installer\NetView.iss"
if ($LASTEXITCODE -ne 0) {
    throw "Inno Setup compilation failed with exit code $LASTEXITCODE."
}
```

Output:

`dist/installer/NetView-Setup-1.0.0-x64.exe`

The installed application is named `NetView.exe`, although the current Nuitka standalone build produces `app.exe`. The installer renames that file when copying it; the original `NetView.dist` build folder is left untouched.

## Install behavior

- Per-user installation under `%LOCALAPPDATA%\Programs\NetView`; no administrator rights are requested.
- Creates a Start Menu shortcut.
- Offers an optional Desktop shortcut.
- Includes the files from `NetView.dist` and the project's MIT `LICENSE`.
- Does not download or install third-party software.

## Runtime prerequisites

Opening existing PCAP/PCAPNG files does not require a capture driver. Live capture still requires Wireshark's `dumpcap.exe` and Npcap to be installed separately. The installer deliberately does not install drivers or bundle Wireshark.

## Release checklist

This is currently a local packaging/test path, not a public-release approval. Before distributing the installer:

- Audit the licences and required notices for all bundled dependencies. In particular, Scapy 2.8.0 declares GPL-2.0-only; review the implications for distributing the compiled application or consider a compatible alternative.
- Test installation, upgrade, launch, and uninstall on a clean Windows x64 machine.
- For Microsoft Store submission of an EXE installer, meet the current Store requirements, including a silent-install path, an offline installer, and the required Authenticode signing of the installer and bundled PE files.
