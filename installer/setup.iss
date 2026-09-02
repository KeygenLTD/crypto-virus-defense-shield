; Crypto Virus Defense Shield - Installer
; Inno Setup 6
; Build: iscc setup.iss  -> dist/CVDS-Setup-0.3.0.exe

#define MyAppName "Crypto Virus Defense Shield"
#define MyAppVersion "0.3.0"
#define MyAppPublisher "KeygenLTD"
#define MyAppURL "https://github.com/KeygenLTD/crypto-virus-defense-shield"
#define MyAppExeName "CryptoVirusDefenseShield.exe"
#define MyCleanupExeName "CVDSEmergencyCleanup.exe"

[Setup]
AppId={{A1B2C3D4-5678-90AB-CDEF-1234567890AB}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DisableDirPage=no
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
OutputDir=..\dist
OutputBaseFilename=CVDS-Setup-{#MyAppVersion}
Compression=lzma
SolidCompression=yes
WizardStyle=modern
WizardImageFile=assets\wizard.bmp
WizardSmallImageFile=assets\header.bmp
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}
CloseApplications=yes
CloseApplicationsFilter={#MyAppExeName};{#MyCleanupExeName}
PrivilegesRequired=admin

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "tr"; MessagesFile: "compiler:Languages\Turkish.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "Run at Windows startup (recommended)"; GroupDescription: "Autostart:"; Flags: checkedonce
Name: "entryshield"; Description: "Enable Defender Entry Shield - balanced (recommended)"; GroupDescription: "Ransomware prevention:"; Flags: checkedonce
Name: "cfa"; Description: "Enable Defender Controlled Folder Access (recommended)"; GroupDescription: "Ransomware prevention:"; Flags: checkedonce

[Files]
Source: "..\dist\CryptoVirusDefenseShield.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\CVDSEmergencyCleanup.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "assets\wizard.bmp"; DestDir: "{app}\assets"; Flags: ignoreversion
Source: "..\locales\*"; DestDir: "{app}\locales"; Flags: ignoreversion recursesubdirs
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
Name: "{autoprograms}\{cm:EmergencyCleanup}"; Filename: "{app}\{#MyCleanupExeName}"; WorkingDir: "{app}"
Name: "{autodesktop}\{cm:EmergencyCleanup}"; Filename: "{app}\{#MyCleanupExeName}"; WorkingDir: "{app}"

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "CryptoVirusDefenseShield"; ValueData: """{app}\{#MyAppExeName}"""; Tasks: autostart; Flags: uninsdeletevalue

[Run]
Filename: "{app}\{#MyAppExeName}"; Parameters: "--enable-entry-shield balanced"; StatusMsg: "Configuring Defender Entry Shield..."; Flags: runhidden waituntilterminated; Tasks: entryshield
Filename: "{app}\{#MyAppExeName}"; Parameters: "--enable-cfa"; StatusMsg: "Configuring Defender folder protection..."; Flags: runhidden waituntilterminated; Tasks: cfa
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{cmd}"; Parameters: "/c taskkill /f /im {#MyAppExeName} 2>nul"; Flags: runhidden; RunOnceId: "StopAgent"
Filename: "{app}\{#MyAppExeName}"; Parameters: "--remove-canaries"; Flags: runhidden waituntilterminated skipifdoesntexist; RunOnceId: "RemoveCanaries"

[CustomMessages]
en.EmergencyCleanup=CVDS Emergency Cleanup
tr.EmergencyCleanup=CVDS Acil Temizleme
