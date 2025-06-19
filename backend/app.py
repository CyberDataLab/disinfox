from flask import Flask, request, jsonify, url_for, abort
from stix2 import parse, ThreatActor, Location, IntrusionSet, Relationship, Bundle
from uuid import uuid5, UUID
from pymongo import MongoClient
from dotenv import load_dotenv
from os import environ, path
import json
from mfulde_dataset_parser import parse_csv_string
import bcrypt
import re
import secrets
from base64 import b64encode, b64decode
import datetime
from iocsearcher.document import open_document
from iocsearcher.searcher import Searcher

DISARM_MATRIX_PATH = path.join(path.dirname(__file__), 'data', 'DISARM.json')
DEFAULT_PAGE = 1
DEFAULT_LIMIT = 10
DEFAULT_SORT_FIELD = "modified"
DEFAULT_SORT_ORDER = "desc"
API_KEY_SEPARATOR = "."
API_KEY_RANDOM_LENGTH = 32
API_KEY_IDENTIFIER = "DISINFOX"
IDENTITY_ID = None
with open(environ.get("PLATFORM_STIX_IDENTITY_PATH", 'platform_stix_identity.json'), 'r') as f:
    identity = parse(f.read(), allow_custom=True)
    IDENTITY_ID = identity["id"]
if not IDENTITY_ID:
    print("Invalid platform STIX identity")
    exit(1)

load_dotenv()
app = Flask(__name__)

# Create a mongoDB connection with the .env file. variables: host, port, username, password, db
client = MongoClient(environ.get("MONGODB_HOST"), int(environ.get("MONGODB_PORT")), username=environ.get("MONGODB_USERNAME"), password=environ.get("MONGODB_PASSWORD"))
db = client[environ.get("MONGODB_DB")]
# Collection to store the STIX2 objects
stix2_objects = db['stix2_objects']
stix2_objects.create_index("id", unique=True)
users = db['users']
users.create_index("email", unique=True)

NAMESPACE_UUID = UUID('12345678-1234-5678-1234-567812345678')
# Load the DISARM STIX2 objects from boundle
disarm_stix2 = []
with open(DISARM_MATRIX_PATH, 'r') as f:
    disarm_stix2 = parse(f.read(), allow_custom=True)
if not disarm_stix2:
    print("DISARM.json is empty or invalid")
    exit(1)

disarm_stix2 = disarm_stix2['objects'] # Get the objects from the bundle

@app.before_request
def before_request():
    if environ.get("READONLY", 0) and request.method != 'GET':
        app.logger.warning(f"Blocked {request.method} to {request.path} in READONLY mode")
        abort(500, description="Server in READONLY mode. Operation not permitted.")


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
    user_data["createdIncidents"] = []
    user_data["api_key"] = build_api_key(email)
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

@app.route('/users/<user_id>/generate-api-key', methods=['POST'])
def generate_api_key(user_id):
    # Generate an API key for a user
    user = users.find_one({"email": user_id})
    if not user:
        return jsonify({"message": "User not found"}), 404
    api_key = build_api_key(user_id)
    users.update_one({"email": user_id}, {"$set": {"api_key": api_key}})
    return jsonify({"message": "API key generated successfully", "api_key": api_key}), 201

@app.route('/check-api-key', methods=['POST'])
def check_api_key():
    # Get the API key from the form data
    # Check if an API key is valid
    api_key = request.form.get("api_key")
    if not api_key:
        app.logger.info("No API key provided")
        return jsonify({'message': 'Please provide the api_key parameter'}), 400
    separated_key = api_key.split(API_KEY_SEPARATOR)
    user = users.find_one({"email": b64decode(separated_key[1]).decode('utf-8')})
    app.logger.info(f"API user found: {user}, comparing {separated_key[0]} with {API_KEY_IDENTIFIER} and {user['api_key']} with {separated_key[2]}")

    if not API_KEY_IDENTIFIER == separated_key[0] or not user or not user["api_key"] == api_key:
        return jsonify({"message": "Invalid API key"}), 401
    return jsonify({"message": "Valid API key"}), 200


# Incident upload endpoint
@app.route('/incidents', methods=['POST'])
def save_incident():
    # Map the JSON fields (non STIX) and build the STIX2 objects and relationships
    incident_data = request.json
    stix_objects, id = build_stix_objects(incident_data, disarm_stix2)
    # Check if the incident already exists
    exist = stix2_objects.find_one({"id": id})
    if exist:
        return jsonify({"message": "Incident already exists (same name and description)"}), 409
    # Save the serialized STIX2 objects in the database as a document
    for stix_object in stix_objects:
        # If the object already exists, skip it
        isRepeated = stix2_objects.find_one({"id": stix_object["id"]})
        if isRepeated:
            continue
        stix2_objects.insert_one(dict(stix_object))
    # Insert the id in the user profile as a created incident
    users.update_one(
        {"email": incident_data.get('user')},
        {"$addToSet": {"createdIncidents": id}}
    )
    return jsonify({"message": "Incident saved successfully"}), 201


# Get all the incidents stored in the database with pagination and HATEOAS
@app.route('/incidents', methods=['GET'])
def get_incidents():
    page = request.args.get('page', default=DEFAULT_PAGE, type=int)
    limit = request.args.get('limit', default=DEFAULT_LIMIT, type=int)
    sort_field = request.args.get('sort', default=DEFAULT_SORT_FIELD, type=str)
    sort_order = request.args.get('order', default=DEFAULT_SORT_ORDER, type=str)
    newer_than = request.args.get('newer_than', default=None, type=str)
    query = request.args.get('q', default="", type=str)

    # query searching the word in the name and description fields
    query_filter = {"type": "intrusion-set", "$or": [{"name": {"$regex": query, "$options": "i"}}, {"description": {"$regex": query, "$options": "i"}}]}
    if newer_than:
        query_filter["modified"] = {"$gt": newer_than}
    
    total_incidents = stix2_objects.count_documents(query_filter)
    incidents_cursor = stix2_objects.find(query_filter)
    
    incidents_cursor.sort(sort_field, -1 if sort_order == "desc" else 1)
    
    # Paginate
    return build_paginated_json(request, incidents_cursor, total_incidents, "incidents"), 200


@app.route('/incidents/<incident_id>', methods=['GET'])
def get_incident(incident_id):
    # Fetch the incident from the database
    incident = stix2_objects.find_one({"id": incident_id})
    if not incident:
        return jsonify({"message": "Incident not found"}), 404
    incident.pop('_id', None)
    return jsonify(incident), 200

@app.route('/incidents/<incident_id>/related', methods=['GET'])
def related_incidents(incident_id):
    # Obtener el incidente central
    central = stix2_objects.find_one({"id": incident_id, "type": "intrusion-set"})
    if not central:
        return jsonify({"message": "Incident not found"}), 404

    # getting the direct relationships of the central incident
    relationships = list(stix2_objects.find({"$or": [{"source_ref": incident_id}, {"target_ref": incident_id}], "type": "relationship"}))

    # target_ref is the id of the object that is directly related to the incident
    # these will shared with the other related incidents
    shared_objects = {}
    for rel in relationships:
        # Get the object id that is related to the incident (the id in the relationship that is not central incident)
        shared_object_id = rel["target_ref"] if rel["source_ref"] == incident_id else rel["source_ref"]
        # maybe the shared object is already in the list
        if shared_object_id in shared_objects:
            continue
        shared_object = stix2_objects.find_one({"id": shared_object_id})
        if not shared_object:
            continue
        shared_objects[shared_object_id] = {
            "id": shared_object["id"],
            "type": shared_object["type"],
            "name": shared_object.get("name", "Unnamed"),
        }

    # search the relationships of the shared objects
    related = {}
    for obj_id in shared_objects.keys():
        # search for direct relationships of the shared object
        rels = list(stix2_objects.find({"$or": [{"source_ref": obj_id}, {"target_ref": obj_id}], "type": "relationship"}))
        for rel in rels:
            # Get the object id that is related to the shared object (the id of the relationship that is not shared object)
            related_incident_id = rel["target_ref"] if rel["source_ref"] == obj_id else rel["source_ref"]
            # Check if the relationship is not the central incident
            if related_incident_id == incident_id:
                continue
            related_obj = stix2_objects.find_one({"id": related_incident_id})
            if not related_obj:
                continue
            if related_obj["id"] in related:
                related[related_obj["id"]]["shared_with"][obj_id] = shared_objects[obj_id]
                continue
            related[related_obj["id"]] = {
                "id": related_obj["id"],
                "type": related_obj["type"],
                "name": related_obj.get("name", "Unnamed"),
                "shared_with": {obj_id: shared_objects[obj_id]},
            }

    return jsonify(list(related.values())), 200


def are_incidents_related(incident1_bundle, incident2_bundle):
    pass

@app.route('/bulk-incident', methods=['POST'])
def save_bulk_incidents():
    """Handles bulk upload of incidents via CSV or JSON, storing 'intrusion-set' IDs in the user profile."""

    file = request.files.get('file')
    if not file:
        return jsonify({"error": "No file provided"}), 400

    ftype = file.content_type
    usermail = request.form.get('user')
    if not usermail:
        return jsonify({"error": "User ID is required"}), 400

    app.logger.info(f"Received file with content type: {ftype}")

    repeated = []  # Dictionary to track repeated objects
    intrusion_ids = []  # List to store the created 'intrusion-set' IDs (for relating to the user)

    # CSV Upload
    if ftype in ['text/csv', 'application/vnd.ms-excel']:
        csv_string = file.read().decode('utf-8')
        incidents = parse_csv_string(csv_string)

        all_stix_objects = []
        for incident in incidents:
            objects, _ = build_stix_objects(incident, disarm_stix2)
            all_stix_objects.extend(objects)
    # JSON (STIX2) Upload
    elif ftype == 'application/json':
        all_stix_objects = json.loads(file.read().decode('utf-8')).get('objects', [])
    else:
        return jsonify({"error": "Unsupported file type"}), 400

    #Check for duplicates and extract intrusion-set IDs in one pass
    for obj in all_stix_objects:
        if stix2_objects.find_one({"id": obj["id"]}):
            repeated.append(obj["id"])
        else:
            stix2_objects.insert_one(dict(obj))
            if obj.get('type') == 'intrusion-set':
                intrusion_ids.append(obj['id'])  # Extract intrusion-set ID
    
    # Update user profile with the intrusion-set IDs
    users.update_one(
        {"email": usermail},
        {"$addToSet": {"createdIncidents": {"$each": intrusion_ids}}
    })

    return jsonify({
        "message": "Bulk upload completed",
        "repeated": repeated
    }), 200


@app.route('/neighbors/<stix_id>', methods=['GET'])
def neighbors(stix_id):
    bundle = search_neighbors(stix_id)
    return bundle.serialize(), 200, {'Content-Type': 'application/json'}

def search_neighbors(stix_id):
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
        #app.logger.info(f"Appending relationship: {relationship['id']}")
        # Just search the objects that are not already in the related_objects list (we alredy appended them)
        # Degug this
        #app.logger.info(f"Checking if {relationship['source_ref']} is in related_objects: {any(obj['id'] == relationship['source_ref'] for obj in related_objects)}")
        if relationship["source_ref"] and not any(obj["id"] == relationship["source_ref"] for obj in related_objects):
            source_obj = stix2_objects.find_one({"id": relationship["source_ref"]})
            source_obj.pop('_id', None)
            related_objects.append(source_obj)
        #app.logger.info(f"Checking if {relationship['target_ref']} is in related_objects: {any(obj['id'] == relationship['target_ref'] for obj in related_objects)}")
        if relationship["target_ref"] and not any(obj["id"] == relationship["target_ref"] for obj in related_objects):
            target_obj = stix2_objects.find_one({"id": relationship["target_ref"]})
            target_obj.pop('_id', None)
            related_objects.append(target_obj)
        relationship.pop('_id', None)
        related_objects.append(relationship)

    # Other relationships as created_by_ref
    created_ref = incident.get("created_by_ref")
    if created_ref:
        creator = stix2_objects.find_one({"id": incident["created_by_ref"]})
        if creator:
            creator.pop('_id', None)
            related_objects.append(creator)

    bundle = Bundle(objects=related_objects, allow_custom=True)
    return bundle

@app.route('/threat-actors', methods=['GET','POST'])
def threat_actors():
    if request.method == "GET":
        query = request.args.get('q', default="", type=str)
        page = request.args.get('page', default=DEFAULT_PAGE, type=int)
        limit = request.args.get('limit', default=DEFAULT_LIMIT, type=int)
        # Query to fetch only "intrusion-set" type incidents
        stix_type = "threat-actor"
        # Now we search threat actors type objects that match the query in the name field

        if query:
            total_threat_actors = stix2_objects.count_documents({"type": stix_type, "name": {"$regex": query, "$options": "i"}})
            threat_actors_cursor = stix2_objects.find({"type": stix_type, "name": {"$regex": query, "$options": "i"}})
        else:
            total_threat_actors = stix2_objects.count_documents({"type": stix_type})
            threat_actors_cursor = stix2_objects.find({"type": stix_type})
        app.logger.info(f"Retrieved {total_threat_actors} Threat Actors")
        
        return build_paginated_json(request, threat_actors_cursor, total_threat_actors, "threat_actors"), 200
    return "Not implemented", 501
    
@app.route('/threat-actors/<threat_actor_id>', methods=['GET'])
def threat_actor(threat_actor_id):
    threat_actor = stix2_objects.find_one({"id": threat_actor_id})
    if not threat_actor:
        return jsonify({"message": "Threat Actor not found"}), 404
    threat_actor.pop('_id', None)
    return jsonify(threat_actor), 200

@app.route('/techniques', methods=['GET'])
def techniques():
    # Get the techniques from the DISARM matrix
    techniques = []
    for stix_object in disarm_stix2:
        if stix_object["type"] == "attack-pattern":
            techniques.append(stix_object)
    bundle = Bundle(objects=techniques, allow_custom=True)
    return bundle.serialize(), 200, {'Content-Type': 'application/json'}

@app.route('/techniques/<technique_id>', methods=['GET'])
def technique(technique_id):
    # Get the technique from the DISARM matrix
    technique = None
    for stix_object in disarm_stix2:
        if stix_object["type"] == "attack-pattern" and stix_object["id"] == technique_id:
            technique = stix_object
            break
    if not technique:
        return jsonify({"message": "Technique not found"}), 404
    return technique.serialize(), 200, {'Content-Type': 'application/json'}

@app.route('/threat-actors/top', methods=['GET'])
def top_threat_actors():
    limit = request.args.get('limit', default=10, type=int)
    # Get the top threat actors by the number of incidents. This is, the amount of attributed-to relationships that have their ID as target_ref.
    # This results in a list with their ID, name and the count of incidents attributed
    top_threat_actors = stix2_objects.aggregate([
        {"$match": {"type": "relationship", "relationship_type": "attributed-to"}},
        {"$group": {"_id": "$target_ref", "count": {"$sum": 1}}},
        {"$lookup": {"from": "stix2_objects", "localField": "_id", "foreignField": "id", "as": "threat_actor"}},
        {"$unwind": "$threat_actor"},
        {"$project": {"_id": 0, "id": "$_id", "name": "$threat_actor.name", "count": 1}},
        {"$sort": {"count": -1}},
        {"$limit": limit}
    ])
    return jsonify(list(top_threat_actors)), 200

@app.route('/locations/top', methods=['GET'])
def top_locations():
    limit = request.args.get('limit', default=10, type=int)
    # Get the top locations by the number of incidents. This is, the amount of targets relationships that have their ID as target_ref.
    # This results in a list with their ID, name and the count of incidents attributed
    top_locations = stix2_objects.aggregate([
        {"$match": {"type": "relationship", "relationship_type": "targets"}},
        {"$group": {"_id": "$target_ref", "count": {"$sum": 1}}},
        {"$lookup": {"from": "stix2_objects", "localField": "_id", "foreignField": "id", "as": "location"}},
        {"$unwind": "$location"},
        {"$project": {"_id": 0, "id": "$_id", "name": "$location.name", "count": 1}},
        {"$sort": {"count": -1}},
        {"$limit": limit}
    ])
    return jsonify(list(top_locations)), 200

@app.route('/stix2-objects', methods=['GET'])
def stix2_objects_endpoint():
    # Fetch all the STIX2 objects stored in the database
    newer_than = request.args.get('newer_than', default=None, type=str)
    newer_than = datetime.datetime.fromisoformat(newer_than.rstrip("Z") + "+00:00") if newer_than else None
    app.logger.info(f"Fetching STIX2 objects newer than {newer_than}")
    # Fetch the incidents from the database
    if newer_than:
        total_objects = stix2_objects.count_documents({"modified": {"$gt": newer_than}})
        objects_cursor = stix2_objects.find({"modified": {"$gt": newer_than}})
    else:
        total_objects = stix2_objects.count_documents({})
        objects_cursor = stix2_objects.find({})
    
    objects = list(objects_cursor)
    # Remove the _id field from the documents
    for object in objects:
        object.pop('_id', None)
    bundle = Bundle(objects=objects, allow_custom=True)
    return bundle.serialize(), 200, {'Content-Type': 'application/json'}

@app.route('/indicators_extraction', methods=['POST'])
def indicators_extraction():
    # Extract indicators from a PDF
    file = request.files.get('file')
    if not file:
        return jsonify({"error": "No file provided"}), 400
    if file.content_type not in ['application/pdf']:
        return jsonify({"error": "Unsupported file type"}), 400
    # Save the file in the server with a random name
    name = secrets.token_hex(16) + ".pdf"
    file_path = path.join(path.dirname(__file__), 'uploads', name)
    file.save(file_path)

    doc = open_document(file_path)
    if doc is None:
        return jsonify({"error": "Unsupported file type"}), 400
    text,_ = doc.get_text()
    searcher = Searcher()
    indicators = searcher.search_data(text)
    # Transform the resulting [(type, value)] list to a dictionary list [{"<type>": ["valueoftype1", "valueoftype2"]}]
    gathered_indicators = {}
    for indicator in indicators:
        if indicator.name not in gathered_indicators:
            gathered_indicators[indicator.name] = []
        gathered_indicators[indicator.name].append(indicator.value)
    # For the TTPs, find the corresponding DISARM technique, inserting "ID: Technique name"
    for ttp in gathered_indicators.get("ttp", []):
        stix_technique = find_stix_disarm_technique(disarm_stix2, ttp)
        gathered_indicators["ttp"].remove(ttp)
        if stix_technique:
            gathered_indicators["ttp"].append(f"{ttp}: {stix_technique['name']}")

    # Remove the file from the filesystem
    file.close()
        
    return jsonify(gathered_indicators), 200
    

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
            labels=["threat-actor"],
            created_by_ref=IDENTITY_ID
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
            country=country,
            created_by_ref=IDENTITY_ID
        )
        location_objects.append(country_object)

    # Get the techniques (DISARM) associated with this incident
    technique_objects = []
    for technique in incident_data.get('techniques', []):
        technique_disarm_id = technique.split(": ")[0]
        # Search in the DISARM dictionary, the STIX ID of the technique to create the relationship
        stix_technique = find_stix_disarm_technique(disarm_stix2, technique_disarm_id)
        if stix_technique:
            technique_objects.append(stix_technique)
        else:
            app.logger.warn(f"Technique {technique_disarm_id} not found in DISARM matrix")


    # Create a IntrusionSet object to represent the incident
    intrusion_name = incident_data['event']
    intrusion_description = incident_data['event_description']
    # Transform the date (dd-mm-yyyy) to a STIX2 datetime format
    incident_first_seen = incident_data.get('date') + "T00:00:00.000Z"
    # Eliminar todo excepto caracteres de la a-Z
    normal_name = re.sub(r'[^a-zA-Z0-9]', '', intrusion_name)
    normal_description = re.sub(r'[^a-zA-Z0-9]', '', intrusion_description)

    intrusion_object = IntrusionSet(
        id="intrusion-set--" + str(uuid5(NAMESPACE_UUID, normal_name + "-" + normal_description)),
        name=intrusion_name,
        description=intrusion_description,
        first_seen=incident_first_seen,
        labels=["incident", "disinformation"],
        created_by_ref=IDENTITY_ID
    )

    # Add the objects to the list
    stix_objects.append(intrusion_object)
    stix_objects.extend(actor_objects)
    stix_objects.extend(location_objects)
    stix_objects.extend(technique_objects)

    # Create the relationships between the techniques and the intrusion object
    for technique in technique_objects:
        stix_objects.append(Relationship(source_ref=intrusion_object.id, relationship_type="uses", target_ref=technique.id, created_by_ref=IDENTITY_ID))
    
    # Create the relationships between the actors and the intrusion object
    for actor in actor_objects:
        stix_objects.append(Relationship(source_ref=intrusion_object.id, relationship_type="attributed-to", target_ref=actor.id, created_by_ref=IDENTITY_ID))

    # Create the relationship between the locations and the intrusion object
    for country in location_objects:
        stix_objects.append(Relationship(source_ref=intrusion_object.id, relationship_type="targets", target_ref=country.id, created_by_ref=IDENTITY_ID))

    return  stix_objects, intrusion_object.id

def find_stix_disarm_technique(disarm_stix2, technique_disarm_id):
    for stix_object in disarm_stix2:
            #print("STIX OBJECT" + stix_object["type"])
        if (stix_object["type"]!="attack-pattern"):
            continue
        mitre_id = stix_object["external_references"][0]["external_id"]
        if (mitre_id and (mitre_id == technique_disarm_id)):
            return stix_object
    app.logger.warn(f"Technique {technique_disarm_id} not found in DISARM matrix")
    return None

def build_paginated_json(request, cursor, total_objects, objects_name="objects"):
    # Pagination parameters
    page = request.args.get('page', default=DEFAULT_PAGE, type=int)
    limit = request.args.get('limit', default=DEFAULT_LIMIT, type=int)

    # Apply pagination
    objects = list(cursor.skip((page - 1) * limit).limit(limit))
    # Remove the _id field from the documents
    for object in objects:
        object.pop('_id', None)
    
    # Construct HATEOAS links
    def build_url(page):
        parameters = request.args.copy()
        parameters['page'] = page
        return url_for(request.endpoint, **parameters, _external=True)

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

def build_api_key(user_id):
    # Random API key
    email64 = b64encode(user_id.encode('utf-8')).decode('utf-8')
    api_key = API_KEY_SEPARATOR.join([API_KEY_IDENTIFIER, email64, secrets.token_urlsafe(API_KEY_RANDOM_LENGTH)])
    return api_key

if __name__ == '__main__':
    app.run(debug=True)