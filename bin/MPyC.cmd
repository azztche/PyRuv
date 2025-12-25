@echo off
for %%a in ("%~dp0..\") do set "ROOT=%%~fa"
"%ROOT%\Runtime\Python.exe" "%ROOT%\mpyc-core\__main__.py" %*