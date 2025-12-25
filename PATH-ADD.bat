@echo off
:: Check admin rights
net session >nul 2>&1
if %errorlevel% NEQ 0 (
    echo Requesting admin privileges...
    powershell -command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

set TARGET1=C:\MPyC\bin
set TARGET2=C:\MPyC\Runtime

powershell -command ^
 "$p=[Environment]::GetEnvironmentVariable('PATH','Machine');" ^
 "if(-not $p.Contains('%TARGET1%')){ $p += ';%TARGET1%' };" ^
 "if(-not $p.Contains('%TARGET2%')){ $p += ';%TARGET2%' };" ^
 "[Environment]::SetEnvironmentVariable('PATH',$p,'Machine');"

echo.
echo PATH updated successfully with admin rights.
echo Restart terminal.
pause