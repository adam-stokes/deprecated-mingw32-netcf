; netcf-wininst.nsi
; prompt for dir; copy files
;--------------------------------

; The name of the installer
Name "netcf installer"

; The file to write
OutFile "netcf-setup.exe"

; The default installation directory
InstallDir $PROGRAMFILES\netcf

; Request application privileges for Windows Vista
RequestExecutionLevel user

;--------------------------------

; Pages

Page directory
Page instfiles

;--------------------------------

; The stuff to install
Section "" ;No components page, name is not important

  ; Set output path to the installation directory.
  SetOutPath $INSTDIR
  
  ; Put file there
  File /r *.dll
  File /r *.exe
  
SectionEnd ; end the section
