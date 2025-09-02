#!/usr/bin/env python3
"""
Simple run script for the Secret Sluth Flask application.

This script starts the Flask development server for testing the application.
"""

import os
from app import create_app

# Set Flask environment variables
os.environ['FLASK_ENV'] = 'development'
os.environ['FLASK_DEBUG'] = '1'

# Create the Flask app
app = create_app()

if __name__ == '__main__':
    print("🔐 Starting Secret Sluth...")
    print("📱 Open your browser and go to: http://localhost:5000")
    print("⚠️  Press Ctrl+C to stop the server")
    print("-" * 50)
    
    # Run the Flask app
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        use_reloader=True
    )
