@echo off
cd /d "%~dp0"
set PYTHONDONTWRITEBYTECODE=1

echo ========================================================
echo MENJALANKAN SERVER TANPA SSL UNTUK DEMO PENGUJIAN
echo ========================================================
python -m launchers.run_demo

pause
