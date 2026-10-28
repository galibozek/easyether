@echo off
rem Installs the EasyEther (SoftEther SeLow + VPN127 virtual adapter) drivers.
rem Windows asks for administrator rights. The program also offers this on first start.
"%~dp0..\easyether.exe" --install-drivers
