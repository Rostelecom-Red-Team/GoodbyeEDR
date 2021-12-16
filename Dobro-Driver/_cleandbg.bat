for /r "." %%a in (.) do (
    pushd "%%a"

rem echo %%a
rem pause

    cd %%a
    rd /s /q .vs
    rd /s /q Debug
    rd /s /q Release

rem rd /s /q x64
rem del /f /q .gitignore
rem del /f /q *.obj
rem del /f /q *.cod
rem del /f /q *.sys
rem del /f /q *.pdb

    popd
)   