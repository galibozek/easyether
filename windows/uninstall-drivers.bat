@echo off
rem Removes the EasyEther (SoftEther SeLow + VPN127 virtual adapter) drivers.
rem Windows asks for administrator rights.
"%~dp0..\easyether.exe" --uninstall-drivers
