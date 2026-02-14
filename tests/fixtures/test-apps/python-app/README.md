# Python Test App

A minimal, secure Python Flask application for testing security scanners.

## Purpose
This application contains no real vulnerabilities. It's used to test scanner workflows with clean baseline scans.

## Usage
```bash
pip install -r requirements.txt
python app.py
```

## Endpoints
- `GET /` - Index
- `GET /health` - Health check
- `GET /api/data` - Sample data
- `POST /api/echo` - Echo request body
