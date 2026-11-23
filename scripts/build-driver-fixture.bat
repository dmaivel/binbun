@echo off
rem Builds tests\fixtures\driver-x86_64.sys and driver-x86_64.pdb from
rem driver.c (run in a directory holding a copy of it, on Windows with
rem Visual Studio 2026 and the WDK 10.0.28000.0): the compiler and linker
rem flags the WDK's WindowsKernelModeDriver10.0 toolset gives a WDM
rem driver's Debug x64 configuration (among them -cbstring, which puts
rem string literals in .text), reproducibly (/Brepro), the PDB's path in
rem the image a fixed one (/PDBALTPATH). Copy both files to
rem tests\fixtures.
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
set WDK=C:\Program Files (x86)\Windows Kits\10
set WDKV=10.0.28000.0
set INCLUDE=%WDK%\Include\%WDKV%\km\crt;%WDK%\Include\%WDKV%\km;%WDK%\Include\%WDKV%\shared;%INCLUDE%
set KM=%WDK%\Lib\%WDKV%\km\x64
cl /c /Zi /nologo /W4 /WX /Od /Oi /Oy- /D _WIN64 /D _AMD64_ /D AMD64 /D DEPRECATE_DDK_FUNCTIONS=1 /D MSC_NOOPT /D _WIN32_WINNT=0x0A00 /D WINVER=0x0A00 /D WINNT=1 /D NTDDI_VERSION=0xA000012 /D DBG=1 /GF /Gm- /Zp8 /GS /guard:cf /Gy /fp:precise /Zc:wchar_t- /Zc:forScope /Zc:inline /GR- /Gz /wd4748 /wd4603 /wd4627 /wd4986 /wd4987 /FI"%WDK%\Include\%WDKV%\shared\warning.h" /kernel -cbstring -d2epilogunwind /Brepro /Fodriver.obj /Fddriver-vc.pdb driver.c || exit /b 1
link /OUT:driver-x86_64.sys /VERSION:10.0 /INCREMENTAL:NO /NOLOGO /WX /SECTION:INIT,d "%KM%\BufferOverflowFastFailK.lib" "%KM%\ntoskrnl.lib" "%KM%\hal.lib" "%KM%\wmilib.lib" /NODEFAULTLIB /MANIFEST:NO /DEBUG:FULL /PDB:driver-x86_64.pdb /SUBSYSTEM:NATIVE,10.00 /Driver /OPT:REF /OPT:ICF /ENTRY:GsDriverEntry /RELEASE /MERGE:_TEXT=.text;_PAGE=PAGE /MACHINE:X64 /Brepro /PDBALTPATH:C:\binbun\fixtures\driver-x86_64.pdb driver.obj || exit /b 1
