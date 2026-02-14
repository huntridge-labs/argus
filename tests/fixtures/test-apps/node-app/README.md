# Node.js Test App

A minimal, secure Node.js Express application for testing security scanners.

## Purpose
This application contains no real vulnerabilities. It's used to test scanner workflows with clean baseline scans.

## Usage
```bash
npm install
npm start
```

## Endpoints
- `GET /` - Index
- `GET /health` - Health check
- `GET /api/data` - Sample data
- `POST /api/echo` - Echo request body

## Security Features
- Helmet.js for security headers
- Rate limiting on API endpoints
- JSON payload size limits
- Error handling
