; Crypto Virus Defense Shield - Installer
; Inno Setup 6 - Modern wizard with Repair/Remove maintenance
; Build: iscc setup.iss  -> dist/CVDS-Setup-0.2.0.exe

#define MyAppName "Crypto Virus Defense Shield"
#define MyAppVersion "0.2.0"
#define MyAppPublisher "KeygenLTD"
#define MyAppURL "https://github.com/KeygenLTD/crypto-virus-defense-shield"
#define MyAppExeName "CryptoVirusDefenseShield.exe"

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
SetupIconFile=assets\header.bmp
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}
CloseApplications=yes
CloseApplicationsFilter=*.exe
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "tr"; MessagesFile: "compiler:Languages\Turkish.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "Run at Windows startup (recommended)"; GroupDescription: "Autostart:"; Flags: checkedonce

[Files]
Source: "..\dist\CryptoVirusDefenseShield.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "assets\wizard.bmp"; DestDir: "{app}\assets"; Flags: ignoreversion
Source: "..\locales\*"; DestDir: "{app}\locales"; Flags: ignoreversion recursesubdirs
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "CryptoVirusDefenseShield"; ValueData: """{app}\{#MyAppExeName}"""; Tasks: autostart; Flags: uninsdeletevalue

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{cmd}"; Parameters: "/c taskkill /f /im {#MyAppExeName} 2>nul"; Flags: runhidden

[Code]
var
  MaintenancePage: TInputOptionWizardPage;

procedure InitializeWizard;
begin
  // Maintenance mode check - if already installed
  if RegKeyExists(HKEY_LOCAL_MACHINE, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{A1B2C3D4-5678-90AB-CDEF-1234567890AB}_is1') or
     RegKeyExists(HKEY_CURRENT_USER, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{A1B2C3D4-5678-90AB-CDEF-1234567890AB}_is1') then
  begin
    MaintenancePage := CreateInputOptionPage(wpWelcome,
      'Maintenance', 'Choose action',
      'Shield is already installed. What would you like to do?',
      True, False);
    MaintenancePage.Add('Repair (reinstall files)');
    MaintenancePage.Add('Remove (uninstall)');
    MaintenancePage.Add('Reinstall (fresh install)');
    MaintenancePage.SelectedValueIndex := 0;
  end;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  // If maintenance page exists, skip directory page for Remove
  if (MaintenancePage <> nil) and (MaintenancePage.SelectedValueIndex = 1) and (PageID = wpSelectDir) then
    Result := True
  else
    Result := False;
end;

// Simple top animation: move virus icon via timer
var
  AnimTimer: Longint;

procedure AnimTick;
begin
  // Placeholder for animation - Inno doesn't natively animate top banner,
  // but we keep timer for future GIF frame rotation via custom draw.
  // For now WizardImage stays static (shield chasing virus).
end;

function InitializeUninstall(): Boolean;
var
  ResCode: Integer;
begin
  // Kill running exe on uninstall (ignore result)
  Exec('taskkill', '/f /im CryptoVirusDefenseShield.exe', '', SW_HIDE, ewWaitUntilTerminated, ResCode);
  Result := True;
end;
