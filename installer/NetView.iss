#define AppName "NetView"
#define AppVersion "1.0.1"
#define AppExeName "NetView.exe"
#define BuildDir AddBackslash(SourcePath) + "..\src\netview\NetView.dist"
#define OutputDirectory AddBackslash(SourcePath) + "..\dist\installer"
#define LicensePath AddBackslash(SourcePath) + "..\LICENSE"
#define IconPath AddBackslash(SourcePath) + "..\assets\netview.ico"

[Setup]
AppId=NetView
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisherURL=https://github.com/I-AtA-I/netview
AppSupportURL=https://github.com/I-AtA-I/netview
AppUpdatesURL=https://github.com/I-AtA-I/netview/releases
DefaultDirName={localappdata}\Programs\NetView
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
SetupIconFile={#IconPath}
UninstallDisplayIcon={app}\{#AppExeName}
OutputDir={#OutputDirectory}
OutputBaseFilename=NetView-Setup-{#AppVersion}-x64
VersionInfoVersion=1.0.1.0
VersionInfoDescription=NetView Setup
VersionInfoProductName=NetView
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "{#BuildDir}\app.exe"; DestDir: "{app}"; DestName: "{#AppExeName}"; Flags: ignoreversion
Source: "{#BuildDir}\*"; DestDir: "{app}"; Excludes: "app.exe"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#LicensePath}"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Launch NetView"; WorkingDir: "{app}"; Flags: postinstall nowait skipifsilent
