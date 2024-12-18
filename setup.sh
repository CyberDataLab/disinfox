#!/bin/bash

echo "[SETUP] Initiating first time setup"


echo "[SETUP] Stopping all running containers"
docker compose down

# Check for the --destroy flag
if [ "$1" == "--destroy" ]; then
    echo "[SETUP] DANGER!!!!!!! --destroy flag detected, destroying database volume"
    echo -n "[SETUP] DANGER!!!!!!! You are about to destroy the database volume. This will delete all data in the database. You have 3 seconds to cancel with CTRL+C. ...3"
    sleep 1
    echo -n "...2"
    sleep 1
    echo -n "...1"
    sleep 1
    echo "...0"
    sleep 1
    echo "[SETUP] Destroying database volume"
    # check if the database is found in the docker volumes
    if [ "$(docker volume ls | grep -c 'disinfox_mongo-data')" -eq 1 ]; then
        docker volume rm disinfox_mongo-data
    fi
    # check if the database has correctly been removed from the docker volumes
    if [ "$(docker volume ls | grep -c 'disinfox_mongo-data')" -eq 0 ]; then
        echo "[SETUP] [OK] Database volume has been removed"
    else
        echo "[SETUP] Database volume has not been removed"
    fi

fi
docker compose up --build -d
echo "[SETUP] Running setup.py to populate the database"
docker compose exec backend python3 setup.py