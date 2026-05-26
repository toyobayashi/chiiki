@echo off

set CMAKE_EXE="C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"

%CMAKE_EXE% -Bbuild -H. -G "Visual Studio 17 2022" -A x64
%CMAKE_EXE% --build build --config Release
