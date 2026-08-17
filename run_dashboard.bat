@echo off
title Analytics Based Cyber Threat Detection System
echo.
echo ==============================================
echo  ANALYTICS BASED CYBER THREAT DETECTION SYSTEM
echo ==============================================
echo.
echo Installing/checking required packages...
python -m pip install -r requirements.txt
echo.
echo Starting dashboard...
python -m streamlit run app.py
pause
