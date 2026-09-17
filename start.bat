@echo off
echo [SOC-SIEM] Instalando dependencias...
pip install -r requirements.txt
echo.
echo [SOC-SIEM] Iniciando servidor...
echo [SOC-SIEM] Acesse: http://localhost:5000
echo.
python app.py
pause
