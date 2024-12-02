from flask import Flask, request, jsonify, url_for
from stix2 import parse, ThreatActor, Location, IntrusionSet, Relationship, Bundle
from uuid import uuid5, UUID
from pymongo import MongoClient
from dotenv import load_dotenv
from os import environ, path
import json
from mfulde_dataset_parser import parse_csv_string
import bcrypt
import re

DISARM_MATRIX_PATH = path.join(path.dirname(__file__), 'data', 'DISARM.json')
DEFAULT_PAGE = 1
DEFAULT_LIMIT = 10

load_dotenv()
app = Flask(__name__)

# Create a mongoDB connection with the .env file. variables: host, port, username, password, db
client = MongoClient(environ.get("MONGODB_HOST"), int(environ.get("MONGODB_PORT")), username=environ.get("MONGODB_USERNAME"), password=environ.get("MONGODB_PASSWORD"))
db = client[environ.get("MONGODB_DB")]
# Collection to store the STIX2 objects
stix2_objects = db['stix2_objects']
stix2_objects.create_index("id", unique=True)
users = db['users']

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

@app.route('/register', methods=['POST'])
def register():
    # Regustrer a new user in the database
    user_data = request.json
    app.logger.info(f"Registering user: {user_data}")
    # Basic validation
    email = user_data.get("email")  
    if not email or not user_data.get("password"):
        return jsonify({"message": "Invalid user data"}), 400
    # Check if the user exists
    user = users.find_one({"email": email})
    if user:
        return jsonify({"message": "User already exists"}), 409
    # Hash the password
    hashed = bcrypt.hashpw(user_data["password"].encode('utf-8'), bcrypt.gensalt())
    user_data["password"] = hashed
    # Add favourite incidents list to the user
    user_data["favoriteIncidents"] = []
    # Insert the user in the database
    users.insert_one(user_data)
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    # Login a user
    user_data = request.json
    app.logger.info(f"Logging in user: {user_data}")
    email = user_data.get("email")
    password = user_data.get("password")
    if not email or not password:
        return jsonify({"message": "Invalid user data"}), 400
    # Check if the user exists
    user = users.find_one({"email":email})
    if not user:
        return jsonify({"message": "Invalid credentials"}), 401
    # Check the password
    if bcrypt.checkpw(password.encode('utf-8'), user["password"]):
        return jsonify({"message": "Login successful"}), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401

@app.route('/users/<user_id>', methods=['GET'])
def get_user(user_id):
    # Get a user by its ID
    user = users.find_one({"email": user_id})
    if not user:
        return jsonify({"message": "User not found"}), 404
    user.pop('_id', None)
    user.pop('password', None)
    return jsonify(user), 200

@app.route('/users/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    # Delete a user
    user = users.find_one({"email": user_id})
    if not user:
        return jsonify({"message": "User not found"}), 404
    users.delete_one({"email": user_id})
    return jsonify({"message": "User deleted successfully"}), 200


@app.route('/users/<user_id>/favorites', methods=['GET', 'POST'])
def manage_favourites(user_id):
    # Get the favourite incidents of a user
    user = users.find_one({"email": user_id})
    if not user:
        return jsonify({"message": "User not found"}), 404
    if request.method == 'GET':
        return jsonify(user.get("favoriteIncidents", [])), 200
    # Add an incident to the user's favourite list
    incident_id = request.json.get("incident_id")
    if not incident_id:
        return jsonify({"message": "Invalid incident ID"}), 400
    if incident_id not in user.get("favoriteIncidents", []):
        user["favoriteIncidents"].append(incident_id)
        users.update_one({"email": user_id}, {"$set": {"favoriteIncidents": user["favoriteIncidents"]}})
        return jsonify({"message": "Incident added to favourites"}), 200
    return jsonify({"message": "Incident already in favourites"}), 200

@app.route('/users/<user_id>/favorites/<incident_id>', methods=['GET'])
def check_favourite(user_id, incident_id):
    # Check if an incident is in the user's favourite list
    user = users.find_one({"email": user_id})
    if not user:
        return jsonify({"message": "User not found"}), 404
    if incident_id in user.get("favoriteIncidents", []):
        return jsonify({"message": "Incident in favourites"}), 200
    return jsonify({"message": "Incident not in favourites"}), 404

@app.route('/users/<user_id>/favorites/<incident_id>', methods=['DELETE'])
def remove_favourite(user_id, incident_id):
    # Remove an incident from the user's favourite list
    user = users.find_one({"email": user_id})
    if not user:
        return jsonify({"message": "User not found"}), 404
    if incident_id in user.get("favoriteIncidents", []):
        user["favoriteIncidents"].remove(incident_id)
        users.update_one({"email": user_id}, {"$set": {"favoriteIncidents": user["favoriteIncidents"]}})
        return jsonify({"message": "Incident removed from favourites"}), 200
    return jsonify({"message": "Incident not in favourites"}), 200

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


# Get all the incidents stored in the database with pagination and HATEOAS
@app.route('/incidents', methods=['GET'])
def get_incidents():
    page = request.args.get('page', default=DEFAULT_PAGE, type=int)
    limit = request.args.get('limit', default=DEFAULT_LIMIT, type=int)

    # Query to fetch only "intrusion-set" type incidents
    total_incidents = stix2_objects.count_documents({"type": "intrusion-set"})
    incidents_cursor = stix2_objects.find({"type": "intrusion-set"})
    
    # Apply pagination
    incidents = list(incidents_cursor.skip((page - 1) * limit).limit(limit))
    # Remove the _id field from the documents
    for incident in incidents:
        incident.pop('_id', None)

    # Paginate
    return build_paginated_json(incidents, page, limit, total_incidents, "get_incidents", "incidents"), 200


@app.route('/incidents/<incident_id>', methods=['GET'])
def get_incident(incident_id):
    # Fetch the incident from the database
    incident = stix2_objects.find_one({"id": incident_id})
    if not incident:
        return jsonify({"message": "Incident not found"}), 404
    incident.pop('_id', None)
    return jsonify(incident), 200


@app.route('/bulk-incident', methods=['POST'])
def save_bulk_incidents():
    # Here JSON with a list of incidents or a CSV file with the incidents can be uploaded (it comes from a form)
    ftype = request.files['file'].content_type
    app.logger.info(f"Received file with content type: {ftype}")
    # If CSV (content-type: text/csv) we parse the CSV and build the STIX2 objects
    if ftype in ['text/csv','application/vnd.ms-excel']:
        csv_string = request.files['file'].read().decode('utf-8')
        app.logger.info(f"Received CSV: {csv_string}")
        incidents = parse_csv_string(csv_string)
    elif ftype == 'application/json':
        incidents = request.json
    else:
        return jsonify({"message": "Invalid content type. Only CSV or JSON are accepted"}), 400
    
    app.logger.info(f"Received {len(incidents)} incidents")
    repeated = []
    for incident in incidents:
        stix_objects = build_stix_objects(incident, disarm_stix2)
        for stix_object in stix_objects:
            isRepeated = stix2_objects.find_one({"id": stix_object["id"]})
            if isRepeated:
                app.logger.info(f"Skipping object {stix_object['id']} because it already exists")
                repeated.append(stix_object['id'])
                continue
            serialized = stix_object.serialize()
            stix2_objects.insert_one(json.loads(serialized))

    return jsonify({"message": "Incidents saved successfully", "repeated": repeated}), 201

@app.route('/neighbors/<stix_id>', methods=['GET'])
def neighbors(stix_id):
    related_objects = []

    # Fetch the incident from the database
    incident = stix2_objects.find_one({"id": stix_id})
    app.logger.info(f"Fetching incident {stix_id}. Found: {incident}")
    if not incident:
        return jsonify({"message": "Incident not found"}), 404
    incident.pop('_id', None)
    related_objects.append(incident)

    # We get the relationships that contain the incident as source or target
    relationships = stix2_objects.find({"$or": [{"source_ref": stix_id}, {"target_ref": stix_id}]})
    # Get the other objects related to the incident
    for relationship in relationships:
        app.logger.info(f"Appending relationship: {relationship['id']}")
        # Just search the objects that are not already in the related_objects list (we alredy appended them)
        # Degug this
        app.logger.info(f"Checking if {relationship['source_ref']} is in related_objects: {any(obj['id'] == relationship['source_ref'] for obj in related_objects)}")
        if relationship["source_ref"] and not any(obj["id"] == relationship["source_ref"] for obj in related_objects):
            source_obj = stix2_objects.find_one({"id": relationship["source_ref"]})
            source_obj.pop('_id', None)
            related_objects.append(source_obj)
        app.logger.info(f"Checking if {relationship['target_ref']} is in related_objects: {any(obj['id'] == relationship['target_ref'] for obj in related_objects)}")
        if relationship["target_ref"] and not any(obj["id"] == relationship["target_ref"] for obj in related_objects):
            target_obj = stix2_objects.find_one({"id": relationship["target_ref"]})
            target_obj.pop('_id', None)
            related_objects.append(target_obj)
        relationship.pop('_id', None)
        related_objects.append(relationship)

    bundle = Bundle(objects=related_objects, allow_custom=True)
    return bundle.serialize(), 200, {'Content-Type': 'application/json'}

@app.route('/threat-actors', methods=['GET','POST'])
def threat_actors():
    if request.method == "GET":
        page = request.args.get('page', default=DEFAULT_PAGE, type=int)
        limit = request.args.get('limit', default=DEFAULT_LIMIT, type=int)
        # Query to fetch only "intrusion-set" type incidents
        stix_type = "threat-actor"
        total_threat_actors = stix2_objects.count_documents({"type": stix_type })
        threat_actors_cursor = stix2_objects.find({"type": stix_type })
        app.logger.info(f"Retrieved {total_threat_actors} Threat Actors")
        
        # Apply pagination
        threat_actors = list(threat_actors_cursor.skip((page - 1) * limit).limit(limit))
        # Remove the _id field from the documents
        for ta in threat_actors:
            ta.pop('_id', None)
        return build_paginated_json(threat_actors, page, limit, total_threat_actors, "threat_actors", "threat_actors"), 200
    return "Not implemented", 501
    
@app.route('/threat-actors/<threat_actor_id>', methods=['GET'])
def threat_actor(threat_actor_id):
    threat_actor = stix2_objects.find_one({"id": threat_actor_id})
    if not threat_actor:
        return jsonify({"message": "Threat Actor not found"}), 404
    threat_actor.pop('_id', None)
    return jsonify(threat_actor), 200

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
    # threat_actor or threat_actors
    for actor in incident_data.get('threat_actors',[incident_data.get('threat_actor')]):
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
    for country in incident_data.get('target_countries', [incident_data.get('target_country')]):
        country_id = country
        country_name = country
        country_object = Location(
            id="location--" + str(uuid5(NAMESPACE_UUID, country_id)),
            name=country_name,
            country=country
        )
        location_objects.append(country_object)

    # Get the techniques (DISARM) associated with this incident
    technique_objects = []
    for technique in incident_data['techniques']:
        technique_disarm_id = technique
        # Search in the DISARM dictionary, the STIX ID of the technique to create the relationship
        technique_id = None
        for stix_object in disarm_stix2:
            #print("STIX OBJECT" + stix_object["type"])
            if (stix_object["type"]!="attack-pattern"):
                continue
            mitre_id = stix_object.get("external_references")[0].get("external_id")
            #print(mitre_id)
            if (mitre_id and mitre_id == technique_disarm_id.split(": ")[0]):
                    technique_objects.append(stix_object)
                    break
        if not technique_objects:
            print(f"Technique {technique_disarm_id} not found in DISARM.json")
            continue


    # Create a IntrusionSet object to represent the incident
    intrusion_name = incident_data['event']
    intrusion_description = incident_data['event_description']
    # Transform the year to a date
    incident_first_seen = str(incident_data.get('year')) + "-01-01T00:00:00Z"
    # Eliminar todo excepto caracteres de la a-Z
    normal_name = re.sub(r'[^a-zA-Z0-9]', '', intrusion_name)
    normal_description = re.sub(r'[^a-zA-Z0-9]', '', intrusion_description)

    intrusion_object = IntrusionSet(
        id="intrusion-set--" + str(uuid5(NAMESPACE_UUID, normal_name + "-" + normal_description)),
        name=intrusion_name,
        description=intrusion_description,
        first_seen=incident_first_seen,
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

def build_paginated_json(objects, page, limit, total_objects, endpoint_function, objects_name="objects"):
    # Construct HATEOAS links
    def build_url(page):
        return url_for(endpoint_function, page=page, limit=limit, _external=True)

    # Pagination links
    links = {
        "self": build_url(page),
        "next": build_url(page + 1) if (page * limit) < total_objects else None,
        "prev": build_url(page - 1) if page > 1 else None,
        "first": build_url(1),
        "last": build_url((total_objects // limit) + (1 if total_objects % limit > 0 else 0))
    }

    # Return a JSON response with incidents and pagination links
    return jsonify({
        objects_name: objects,
        "page": page,
        "limit": limit,
        "total_"+objects_name: total_objects,
        "links": links
    })

if __name__ == '__main__':
    app.run(debug=True)