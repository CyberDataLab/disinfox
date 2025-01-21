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

DISARM_MATRIX_PATH = path.join(path.dirname(__file__), 'data', 'DISARM.json')
DEFAULT_PAGE = 1
DEFAULT_LIMIT = 10
DEFAULT_SORT_FIELD = "modified"
DEFAULT_SORT_ORDER = "desc"
API_KEY_SEPARATOR = "."
API_KEY_RANDOM_LENGTH = 32
API_KEY_IDENTIFIER = "DISINFOX"

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

    return jsonify({"message": "Incident saved successfully"}), 201


# Get all the incidents stored in the database with pagination and HATEOAS
@app.route('/incidents', methods=['GET'])
def get_incidents():
    page = request.args.get('page', default=DEFAULT_PAGE, type=int)
    limit = request.args.get('limit', default=DEFAULT_LIMIT, type=int)
    sort_field = request.args.get('sort', default=DEFAULT_SORT_FIELD, type=str)
    sort_order = request.args.get('order', default=DEFAULT_SORT_ORDER, type=str)
    newer_than = request.args.get('newer_than', default=None, type=str)


    # Fetch the incidents from the database
    if newer_than:
        total_incidents = stix2_objects.count_documents({"type": "intrusion-set", "modified": {"$gt": newer_than}})
        incidents_cursor = stix2_objects.find({"type": "intrusion-set", "modified": {"$gt": newer_than}})
    else:
        total_incidents = stix2_objects.count_documents({"type": "intrusion-set"})
        incidents_cursor = stix2_objects.find({"type": "intrusion-set"})
    
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


@app.route('/bulk-incident', methods=['POST'])
def save_bulk_incidents():
    # Here JSON with a list of incidents or a CSV file with the incidents can be uploaded (it comes from a form)
    ftype = request.files['file'].content_type
    app.logger.info(f"Received file with content type: {ftype}")
    stixed_objects = []
    # If CSV (content-type: text/csv) we parse the CSV and build the STIX2 objects
    if ftype in ['text/csv','application/vnd.ms-excel']:
        csv_string = request.files['file'].read().decode('utf-8')
        incidents = parse_csv_string(csv_string)
        for incident in incidents:
            objects, intrusionid = build_stix_objects(incident, disarm_stix2)
            stixed_objects.extend(objects)
    elif ftype == 'application/json':
        stixed_objects = json.loads(request.files['file'].read().decode('utf-8'))['objects']
    else:
        return jsonify({"message": "Invalid content type. Only CSV or STIX2 (JSON) are accepted"}), 400
    
    app.logger.error(f"Received {len(stixed_objects)} objects")
    app.logger.error(f"{stixed_objects}, type: {type(stixed_objects)}")
    repeated = []
    for stix_object in stixed_objects:
        app.logger.error(f"Checking object {stix_object}. Type: {type(stix_object)}")
        isRepeated = stix2_objects.find_one({"id": stix_object["id"]})
        if isRepeated:
            app.logger.info(f"Skipping object {stix_object['id']} because it already exists")
            repeated.append(stix_object['id'])
            continue
        stix2_objects.insert_one(dict(stix_object))

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

@app.route('/stix2-objects', methods=['GET'])
def stix2_objects_endpoint():
    # Fetch all the STIX2 objects stored in the database
    newer_than = request.args.get('newer_than', default=None, type=str)
    # Fetch the incidents from the database
    if newer_than:
        total_objects = stix2_objects.count_documents({"modified": {"$gt": newer_than}})
        objects_cursor = stix2_objects.find({"modified": {"$gt": newer_than}})
    else:
        total_objects = stix2_objects.count_documents({})
        objects_cursor = stix2_objects.find({})
    return build_paginated_json(request, objects_cursor, total_objects), 200


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
    for technique in incident_data.get('techniques', []):
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

    return  stix_objects, intrusion_object.id

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