@echo off
:: Скрипт запрашивает повышение прав сам
powershell -Command "Start-Process './zeroseg-guard.exe' -Verb RunAs"
