import os
import requests
from stix2 import parse, Bundle
import json

BACKEND_ROOT = "http://localhost:5000/"
INCIDENTS_DATASET_PATHS = ['data/merged_Foulde_DSRM_additions.csv']
BACKEND_START_MAX_RETRIES = 5
BACKEND_START_RETRY_INTERVAL = 5

if __name__ == '__main__':

    print("[SETUP] Starting setup...")
    print ("[SETUP] Waiting for backend to be up and running (interval:", BACKEND_START_RETRY_INTERVAL, "s):",end='')
    healthy = False
    for i in range(BACKEND_START_MAX_RETRIES):
        try:
            response = requests.get(BACKEND_ROOT)
            if response.status_code == 200:
                healthy = True
                break
        except Exception as e:
            pass
        print("\\o/..", end='', flush=True)
        os.system("sleep " + str(BACKEND_START_RETRY_INTERVAL))

    print()
    if not healthy:
        print("[SETUP] Backend not reachable after", BACKEND_START_MAX_RETRIES, "retries")
        exit(1)

    print("[SETUP] [OK] Backend is up and running")

    # Check if the test user is already registered
    try:
        response = requests.get(BACKEND_ROOT + 'users/' + os.environ['ADMIN_EMAIL'])
        if response.status_code == 200:
            print("[SETUP] Test user already registered... skipping registration")
            exit(0)
    except Exception as e:
        print("[SETUP] Backend not reachable:", e)
        exit(1)

    # Register a test user
    try:
        response = requests.post(BACKEND_ROOT + 'register', json={
            'email': os.environ['ADMIN_EMAIL'], 
            'password': os.environ['ADMIN_PASSWORD'],
            'firstName': 'Test',
            'lastName': 'User',
            'isAdmin': True
        })
        response.raise_for_status()
    except Exception as e:
        print("[SETUP] Failed to register user:", e)
        exit(1)
    print("[SETUP] [OK] User registered successfully")

    # Load the platform STIX identity
    with open(os.environ.get('PLATFORM_STIX_IDENTITY_PATH', 'platform_stix_identity.json'), 'r') as f:
        identity_json = f.read()
        identity_json = json.loads(identity_json)
        identity = parse(identity_json, allow_custom=True)
        if not identity or identity.type != 'identity':
            print("[SETUP] [ERROR] Invalid platform STIX identity")
            exit(1)

    try:
        response = requests.post(BACKEND_ROOT + 'bulk-incident',
                                files={'file': ('incidents.json', Bundle(objects=[identity]).serialize(), 'application/json')},
                                data={"user": os.environ['ADMIN_EMAIL']}
                                )
        response.raise_for_status()
    except Exception as e:
        print("[SETUP] Failed to load platform STIX identity:", e)
        exit(1)
    print("[SETUP] [OK] Platform STIX identity loaded successfully")
            
    # Load the incidents
    try:
        response = requests.get(BACKEND_ROOT + 'incidents')
        if not response.json:
            print("[SETUP] Incidents already loaded... skipping loading")
            exit(0)
    except Exception as e:
        print("[SETUP] Failed to check if incidents are already loaded:", e)
        exit(1)
    try:
        for dataset_path in INCIDENTS_DATASET_PATHS:
            with open(dataset_path, 'r') as f:
                incidents = f.read()
                extension = dataset_path.split('.')[-1]
                content_type = 'application/json' if extension == 'json' else 'text/csv'
                response = requests.post(BACKEND_ROOT + 'bulk-incident', 
                                        files={'file': ('incidents.' + extension, incidents, content_type)},
                                        data={"user": os.environ['ADMIN_EMAIL']})

                response.raise_for_status()
    except Exception as e:
        print("[SETUP] Failed to load incidents dataset:", e)
        exit(1)
    print("[SETUP] [OK] Incidents dataset loaded successfully")

