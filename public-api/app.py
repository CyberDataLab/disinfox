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
    return jsonify({'message': 'Welcome to the DISINFOX API!'})

@app.route('/check-auth', methods=['POST'])
def check_auth():
    # Check the Authorization header
    if 'Authorization' not in request.headers:
        return jsonify({'message': 'Please provide an Authorization header with a valid token'}), 401
    token = request.headers['Authorization']
    app.logger.info("Checking token: " + token)
    response = requests.post(DISINFOX_BACKEND_URL + 'check-api-key', data={'api_key': token})
    if response.status_code == 200:
        return jsonify({'message': 'The token is valid'})
    else:
        return jsonify({'message': 'The token is invalid'}), 401


@app.route('/incidents', methods=['GET'])
def incidents():
    # Check the Authorization header
    if 'Authorization' not in request.headers:
        return jsonify({'message': 'Please provide an Authorization header with a valid token'})
    token = request.headers['Authorization']
    response = requests.post(DISINFOX_BACKEND_URL + 'check-api-key', data={'api_key': token})
    newer_than = request.args.get('newer_than', default=None)
    if not newer_than:
        return jsonify({'message': 'Please provide a newer_than parameter, e.g. /incidents?newer_than=2024-11-30T01:35:21.128381Z'})
    app.logger.info("Getting incidents from DISINFOX backend newer than: " + newer_than)
    response = requests.get(DISINFOX_BACKEND_URL + 'incidents', params={'newer_than': newer_than})
    app.logger.info("Response from DISINFOX backend: " + response.text)
    return jsonify(response.json())



if __name__ == '__main__':
    app.run(debug=True)