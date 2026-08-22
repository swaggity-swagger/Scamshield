@echo off
setlocal
pushd "%~dp0"
python -m uvicorn app:app --reload
popd
