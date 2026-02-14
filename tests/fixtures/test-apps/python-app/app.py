# Minimal Python Test Application
# This is a simple, secure Flask app for testing purposes
# No real vulnerabilities - only synthetic test data

from flask import Flask, jsonify, request
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/')
def index():
    """Simple index endpoint"""
    return jsonify({
        'message': 'Test application running',
        'version': '1.0.0'
    })

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'}), 200

@app.route('/api/data', methods=['GET'])
def get_data():
    """Example data endpoint"""
    data = {
        'items': [
            {'id': 1, 'name': 'Item 1'},
            {'id': 2, 'name': 'Item 2'}
        ]
    }
    return jsonify(data)

@app.route('/api/echo', methods=['POST'])
def echo():
    """Echo endpoint for testing"""
    data = request.get_json()
    logger.info(f"Received echo request")
    return jsonify({'echo': data}), 200

if __name__ == '__main__':
    # Running on localhost only for testing
    app.run(host='127.0.0.1', port=5000, debug=False)
