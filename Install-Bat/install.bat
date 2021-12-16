@rem on
InfDefaultInstall.exe %CD%\Dobro.inf
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Dobro"
if %ERRORLEVEL% NEQ 0 goto error_install

REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Dobro" /v "ImagePath" /t REG_EXPAND_SZ /d "\??\%CD%\Dobro.sys" /f
if %ERRORLEVEL% NEQ 0 goto error_install

echo.
echo [+] Success install
goto end_install

:error_install
echo.
echo [-] Failed install
goto end_install

:end_install
