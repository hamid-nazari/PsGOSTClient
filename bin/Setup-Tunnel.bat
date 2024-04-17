@echo off
pushd %~dp0
pwsh -C "& ./Setup-Tunnel.ps1" || pause