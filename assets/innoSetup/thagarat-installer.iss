; Inno Setup script for thagarat Installer

[Setup]
AppName=Thagarat
AppVersion=1.0.0
AppPublisher=Muhammad Muazen
AppPublisherURL=https://github.com/MuhammadMuazen/thagarat
AppSupportURL=https://github.com/MuhammadMuazen/thagarat/issues
SourceDir=D:\personal\projects\thagarat\thagarat\target\release\thagarat.exe
OutputDir="D:\personal\projects\thagarat\thagarat\assets\innoSetup\innoOutputDir"
DefaultDirName={pf}\thagarat
DefaultGroupName=thagarat

[Files]
; Install the executable to the Program Files directory
Source: "D:\personal\projects\thagarat\thagarat\target\release\thagarat.exe"; DestDir: "{app}"; Flags: ignoreversion

[Run]
Filename: "{cmd}"; Parameters: "/C copy ""{app}\thagarat.exe"" ""{userdesktop}\thagarat.exe"""; StatusMsg: "Creating desktop shortcut..."; Flags: runhidden
Filename: "{cmd}"; Parameters: "/C copy ""{app}\thagarat.exe"" ""C:\Users\{username}\.local\bin\thagarat.exe"""; StatusMsg: "Copying executable to .local\\bin..."; Flags: runhidden
