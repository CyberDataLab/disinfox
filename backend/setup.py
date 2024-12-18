import os
import requests

BACKEND_ROOT = f"http://backend:5000/"
INCIDENTS_DATASET_PATH = 'data/merged_Foulde_DSRM_additions.csv'

if __name__ == '__main__':

    print("[SETUP] Starting setup...")
    try:
        response = requests.get(BACKEND_ROOT + 'users/' + os.environ['TEST_USER_EMAIL'])
        if response.status_code == 200:
            print("[SETUP] Test user already registered... skipping registration")
            exit(0)
    except Exception as e:
        print("[SETUP] Backend not reachable:", e)
        exit(1)

    # Register a test user
    try:
        response = requests.post(BACKEND_ROOT + 'register', json={
            'email': os.environ['TEST_USER_EMAIL'], 
            'password': os.environ['TEST_USER_PASSWORD'],
            'firstName': 'Test',
            'lastName': 'User'
        })
        response.raise_for_status()
    except Exception as e:
        print("[SETUP] Failed to register user:", e)
        exit(1)
    print("[SETUP] User registered successfully")

    # Load the incidents
    try:
        response = requests.get(BACKEND_ROOT + 'incidents')
        if response.json != []:
            print("[SETUP] Incidents already loaded... skipping loading")
            exit(0)
    except Exception as e:
        print("[SETUP] Failed to check if incidents are already loaded:", e)
        exit(1)
    try:
        with open(INCIDENTS_DATASET_PATH, 'r') as f:
            incidents = f.read()
            response = requests.post(BACKEND_ROOT + 'bulk-incident', files={'file': ('incidents.csv', incidents)})
            response.raise_for_status()
    except Exception as e:
        print("[SETUP] Failed to load incidents dataset:", e)
        exit(1)
    print("[SETUP] Incidents dataset loaded successfully")

