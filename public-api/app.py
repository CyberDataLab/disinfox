from flask import Flask, jsonify, request
import os
import requests

app = Flask(__name__)

# Getting the environment variables
DISINFOX_BACKEND_URL = os.environ.get('DISINFOX_BACKEND_URL')

app.logger.info("Checking connection with DISINFOX backend: " + DISINFOX_BACKEND_URL)
try:
    response = requests.get(DISINFOX_BACKEND_URL)
    response.raise_for_status()
except:
    app.logger.error("The backend" + DISINFOX_BACKEND_URL + " is not reachable")
    exit(1)
app.logger.info("[OK :)] Connection with DISINFOX backend established")


@app.route('/', methods=['GET'])
def index():
    return jsonify({'message': 'Welcome to the DisinfoX API!'})



if __name__ == '__main__':
    app.run(debug=True)