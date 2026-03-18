@echo off
echo ====================================================
echo   🚀 INICIANDO SOC MULTI-AGENT PLATFORM V2.0
echo ====================================================
echo.

:: Iniciar Backend en una nueva ventana
echo [+] Iniciando API Backend (FastAPI) en puerto 8000 (Abierto a la red)...
start cmd /k "title SOC BACKEND && .venv\Scripts\activate && uvicorn app.api:app --reload --host 0.0.0.0 --port 8000"

:: Esperar un momento
timeout /t 3 /nobreak > nul

:: Iniciar Frontend en una nueva ventana
echo [+] Iniciando Dashboard Frontend (React) en puerto 3000...
start cmd /k "title SOC FRONTEND && cd app/frontend && npm run dev"

echo.
echo ====================================================
echo   ✅ PROCESO DE INICIO COMPLETADO
echo   - Backend: http://localhost:8000/api/health
echo   - Frontend: http://localhost:3000
echo ====================================================
pause
