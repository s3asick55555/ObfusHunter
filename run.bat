@echo off
set FLASK_APP=app
set FLASK_ENV=development
python -m flask run --host=0.0.0.0 --port=5000
