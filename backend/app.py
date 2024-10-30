from flask import Flask, request, jsonify
from stix2 import parse, ThreatActor, Location, IntrusionSet, Relationship
from uuid import uuid5, UUID
from pymongo import MongoClient
from dotenv import load_dotenv
from os import environ, path
import json

DISARM_MATRIX_PATH = path.join(path.dirname(__file__), 'data', 'DISARM.json')

load_dotenv()
app = Flask(__name__)

# Create a mongoDB connection with the .env file. variables: host, port, username, password, db
client = MongoClient(environ.get("MONGODB_HOST"), int(environ.get("MONGODB_PORT")), username=environ.get("MONGODB_USERNAME"), password=environ.get("MONGODB_PASSWORD"))
db = client[environ.get("MONGODB_DB")]
# Collection to store the STIX2 objects
stix2_objects = db['stix2_objects']

NAMESPACE_UUID = UUID('12345678-1234-5678-1234-567812345678')
# Load the DISARM STIX2 objects from boundle
disarm_stix2 = []
with open(DISARM_MATRIX_PATH, 'r') as f:
    disarm_stix2 = parse(f.read(), allow_custom=True)
if not disarm_stix2:
    print("DISARM.json is empty or invalid")
    exit(1)

disarm_stix2 = disarm_stix2['objects'] # Get the objects from the bundle


# Root informative endpoint
@app.route('/', methods=['GET'])
def home():
    return jsonify({"message": "Welcome to the DISINFOX API. Check the documentation to see the available endpoints"}), 200

# Incident upload endpoint
@app.route('/incidents', methods=['POST'])
def save_incident():
    # Map the JSON fields (non STIX) and build the STIX2 objects and relationships
    incident_data = request.json
    stix_objects = build_stix_objects(incident_data, disarm_stix2)
    # Save the serialized STIX2 objects in the database as a document
    for stix_object in stix_objects:
        serialized = stix_object.serialize()
        stix2_objects.insert_one(json.loads(serialized))

    return jsonify({"message": "Incident saved successfully"}), 201


# Get all the incidents stored in the database
@app.route('/incidents', methods=['GET'])
def get_incidents():
    incidents = []
    for incident in stix2_objects.find():
        incidents.append(incident)
    return jsonify(incidents), 200
'''
# Build a list of STIX2 objects and relationships from the "form" JSON data
'first_seen': seen_date,
'target_countries': target_countries,
'event': event,
'region': region,
'sub_region': sub_region,
'country_of_origin': country_of_origin,
'threat_actors': threat_actor,
'event_description': event_description,
'techniques': techniques,
'channels': channels,
'sources': sources
'''
def build_stix_objects(incident_data, disarm_stix2):
    stix_objects = []

    # Create the Thread actor object
    actor_objects = []
    for actor in incident_data['threat_actors']:
        actor_id = actor
        actor_name = actor
        threat_actor = ThreatActor(
            id="threat-actor--" + str(uuid5(NAMESPACE_UUID, actor_id)),
            name=actor_name,
            threat_actor_types = ["nation-state"],
            labels=["threat-actor"]
        )
        actor_objects.append(threat_actor)
    


    # Create the Location objects representing the target countries
    location_objects = []
    for country in incident_data['target_countries']:
        country_id = country
        country_name = country
        country_object = Location(
            id="location--" + str(uuid5(NAMESPACE_UUID, country_id)),
            name=country_name,
            country=country
        )

    # Get the techniques (DISARM) associated with this incident
    technique_objects = []
    for technique in incident_data['techniques']:
        technique_disarm_id = technique
        # Search in the DISARM dictionary, the STIX ID of the technique to create the relationship
        technique_id = None
        for stix_object in disarm_stix2:
            if (stix_object["type"]!="attack-pattern"):
                continue
            mitre_id = stix_object.get("external_references")[0].get("external_id")
            print(mitre_id)
            if (mitre_id and mitre_id == technique_disarm_id.split(": ")[0]):
                    technique_objects.append(stix_object)
                    break
        if not technique_objects:
            print(f"Technique {technique_disarm_id} not found in DISARM.json")
            continue


    # Create a IntrusionSet object to represent the incident
    intrusion_id = incident_data['event']
    intrusion_name = incident_data['event']
    intrusion_description = incident_data['event_description']
    intrusion_object = IntrusionSet(
        id="intrusion-set--" + str(uuid5(NAMESPACE_UUID, intrusion_id)),
        name=intrusion_name,
        description=intrusion_description,
        labels=["incident", "disinformation"]
    )

    # Add the objects to the list
    stix_objects.append(intrusion_object)
    stix_objects.extend(actor_objects)
    stix_objects.extend(location_objects)
    stix_objects.extend(technique_objects)

    # Create the relationships between the techniques and the intrusion object
    for technique in technique_objects:
        stix_objects.append(Relationship(source_ref=intrusion_object.id, relationship_type="uses", target_ref=technique.id))
    
    # Create the relationships between the actors and the intrusion object
    for actor in actor_objects:
        stix_objects.append(Relationship(source_ref=intrusion_object.id, relationship_type="attributed-to", target_ref=actor.id))

    # Create the relationship between the locations and the intrusion object
    for country in location_objects:
        stix_objects.append(Relationship(source_ref=intrusion_object.id, relationship_type="targets", target_ref=country.id))

    return stix_objects



if __name__ == '__main__':
    app.run(debug=True)