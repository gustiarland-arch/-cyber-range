@echo off
rem Stops CYBER RANGE. Data (database, evidence, reports) stays in Docker volumes.
cd /d "%~dp0"
docker compose down
pause
