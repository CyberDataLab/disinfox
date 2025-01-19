from flask import Flask, render_template, request, jsonify, redirect, url_for, abort
import requests
import pycountry
import os
import json
from flask_bootstrap import Bootstrap5
from forms import IncidentForm, FileUploadForm, LoginForm, RegisterForm
from incident_export import export_incident_to_pdf, export_incident_to_word

from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import User, Anonymous
from datetime import timedelta

app = Flask(__name__)
app.config["SECRET_KEY"] = "secretkey"
bootstrap = Bootstrap5(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
app.config["READONLY"] = os.environ.get("READONLY", "False") == "True"


BACKEND_ROOT = f"http://{os.environ.get('BACKEND_HOST', 'localhost')}:{os.environ.get('BACKEND_PORT', '5000')}/"
LISTING_LIMIT = 50
MAX_INDIVIDUAL_SELECTABLE_PAGES = 5


app.logger.info("Starting DISINFOX frontend...")
app.logger.info("Connecting with DISINFOX backend at " + BACKEND_ROOT)
alive = False
try:
    response = requests.get(BACKEND_ROOT)
    if response.status_code == 200:
        alive = True
except:
    pass
if not alive:
    app.logger.error("FAILED")
    exit(1)

login_manager.anonymous_user = Anonymous

@app.errorhandler(500)
def internal_server_error(e):
    if app.config["READONLY"]:
        return render_template("500readonly.html"), 500
    else:
        return jsonify(error=str(e)), 500

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id, BACKEND_ROOT + "users/")

@app.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

@app.route("/", methods=["GET"])
def home():
    return render_template("index.html", last_update=os.environ.get("LAST_UPDATE"))

@app.route("/register", methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if request.method == "GET":
        return render_template("register.html", form=register_form)
    form = register_form.data
    if not register_form.validate_on_submit():
        return "Invalid form: " + str(register_form.errors), 400
    response = requests.post(BACKEND_ROOT + "register", json=form)
    if response.status_code == 201:
        return redirect(url_for("login"), code=302)
    else:
        return "Error registering", 500
    
@app.route("/login", methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if request.method == "GET":
        return render_template("login.html", form=login_form)
    
    form = login_form.data
    if not login_form.validate_on_submit():
        return "Invalid form: " + str(login_form.errors), 400
    
    response = requests.post(BACKEND_ROOT + "login", json=form)
    if response.status_code == 401:
        return "Invalid credentials", 401
    if response.status_code != 200:
        abort(500)
    
    user = User.get(form["email"], BACKEND_ROOT + "users/")
    
    login_user(user)
    return redirect(url_for("home"), code=302)


@app.route("/profile", methods=["GET"])
#@login_required
def profile():
    user_data = {}
    if current_user.is_anonymous:
        user_data = current_user.to_json()
    elif current_user.is_authenticated:
        user_data_response = requests.get(BACKEND_ROOT + "users/" + current_user.email)
        if user_data_response.status_code != 200:
            return abort(500, description="Error getting profile")
        user_data = user_data_response.json()
    # Get the data from the favorite incidents id
    favorites = []
    for incident_id in user_data.get("favoriteIncidents", []):
        response = requests.get(BACKEND_ROOT + "incidents/" + incident_id)
        if response.status_code == 200:
            favorites.append(response.json())
    return render_template("profile.html", user=user_data, favorites=favorites)

@app.route("/profile/delete", methods=["POST"])
@login_required
def delete_profile():
    response = requests.delete(BACKEND_ROOT + "users/" + current_user.email)
    if response.status_code == 200:
        logout_user()
        return redirect(url_for("home"), code=302)
    return abort(500, description="Error deleting profile")
    
@app.route("/profile/generate-api-key", methods=["POST"])
@login_required
def generate_api_key():
    response = requests.post(BACKEND_ROOT + "users/" + current_user.email + "/generate-api-key")
    if response.status_code == 201:
        return redirect(url_for("profile"), code=302)
    return abort(500, description="Error generating API key")


def get_incidents_from_back(page=1):
    try:
        response = requests.get(BACKEND_ROOT + "incidents", params={"page": page, "limit": LISTING_LIMIT})
        if response.status_code == 200:
            incidents_response = response.json()
    except:
        pass
    return incidents_response

@app.route("/incidents", methods=["GET"])
def incidents():
    page = request.args.get("page", 1, type=int)
    incidents_response = get_incidents_from_back(page)
    # Append to the object if they have been favorited by the user
    if current_user.is_authenticated:
        try:
            response = requests.get(BACKEND_ROOT + f"users/{current_user.email}/favorites")
            if response.status_code == 200:
                favorites = response.json()
                for incident in incidents_response.get("incidents", []):
                    incident["favorited"] = incident["id"] in favorites
        except:
            app.logger.error("Error getting favorites")
    elif current_user.is_anonymous:
        for incident in incidents_response.get("incidents", []):
            incident["favorited"] = incident["id"] in current_user.get_favourite_incidents()

    npages = incidents_response.get("total_incidents", 0) // incidents_response.get("limit", LISTING_LIMIT) + 1
    total_incidents = incidents_response.get("total_incidents", 0)
    return render_template("incidents.html", 
                            incidents=incidents_response.get("incidents", []),
                            npages=npages, page=page, total_incidents=total_incidents, max_selectable_pages=MAX_INDIVIDUAL_SELECTABLE_PAGES)

@app.route("/incidents/<incident_id>", methods=["GET"])
#@login_required
def incident(incident_id):
    response = requests.get(BACKEND_ROOT + "incidents/" + incident_id)
    if response.status_code != 200:
        return abort(500, description="Error retrieving incident")
    favorited = False
    if current_user.is_anonymous:
        favorited = incident_id in current_user.get_favourite_incidents()
    elif current_user.is_authenticated:
        if requests.get(BACKEND_ROOT + "users/" + current_user.email + "/favorites/" + incident_id).status_code == 200:
            favorited = True
    incident = response.json()
    return render_template("incident.html", incident=incident, favorited=favorited)

@app.route("/incidents/new", methods=["GET", "POST"])
@login_required
def new_incident():
    incident_form = IncidentForm()
    file_form = FileUploadForm()
    if request.method == "GET":
        return render_template("incidents_new.html", incident_form=incident_form, file_form=file_form)
    
    # detect if the submit form was the file upload form or the incident form
    if file_form.file.data is not None and file_form.validate_on_submit():
        # Sent the contents to the backend directly
        app.logger.info("Uploading file...")
        file = file_form.file.data # raw CSV
        response = requests.post(BACKEND_ROOT + "bulk-incident", files={"file": (file.filename, file, file.content_type)})
        if response.status_code != 201:
            return abort(500, description="Error uploading file")
        return redirect(url_for("incidents"), code=302)

    # get jsoned form data
    form = incident_form.data
    app.logger.info("New manual incident: "+ str(form))  
    if not incident_form.validate_on_submit():
        return "Invalid form: " + str(incident_form.errors), 400 

    backend_request = request.form.to_dict(flat=False)
    backend_request["event"] = backend_request["event"][0]
    backend_request["event_description"] = backend_request["event_description"][0]
    backend_request["date"] = backend_request["date"][0]
    response = requests.post(BACKEND_ROOT + "incidents", json=backend_request)
    if response.status_code == 201:
        # redirect to the incidents page and alert the user
        return  redirect(url_for("incidents"), code=302)
    elif response.status_code == 409:
        return abort(409, description="Incident already exists")
    else:
        return abort(500, description="Error creating incident")
    
@app.route("/incidents/<incident_id>/export", methods=["GET"])
def export_incident(incident_id):
    doc_type = request.args.get("type")
    try:
        response = requests.get(BACKEND_ROOT + f"neighbors/{incident_id}")
        if response.status_code != 200:
            return abort(500, description="Error getting neighbors")
        incident = response.json()
    except:
        return abort(500, description="Error getting incident")
    app.logger.info(incident)
    content_type = ""
    extension = ""
    document_data = None
    if doc_type == "pdf":
        document_data = export_incident_to_pdf(incident)
        if document_data is None:
            return abort(500, description="Error exporting incident")
        content_type = "application/pdf"
        extension = "pdf"
    elif doc_type == "docx":
        document_data = export_incident_to_word(incident)
        if document_data is None:
            return abort(500, description="Error exporting incident")
        content_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        extension = "docx"
    elif doc_type == "stix2":
        document_data = json.dumps(incident, indent=4)
        content_type = "application/json"
        extension = "json"
    else:
        return "Invalid document type", 400

    return document_data, 200, {"Content-Type": content_type, "Content-Disposition": f"attachment; filename=incident_{incident_id}.{extension}"}

@app.route("/incidents/<incident_id>/favorite", methods=["POST"])
#@login_required
def toggle_favorite(incident_id):
    # The backend has DELETE and POST methods for favorites
    favorite = False
    if current_user.is_anonymous:
        if incident_id in current_user.get_favourite_incidents():
            current_user.remove_favourite_incident(incident_id)
            favorite = False
            app.logger.info("fav removed")
        else:
            app.logger.info("fav added")
            current_user.add_favourite_incident(incident_id)
            favorite = True
        app.logger.info("Guest favorites: " + str(current_user.get_favourite_incidents()))
    elif current_user.is_authenticated:
        try:
            response = requests.get(BACKEND_ROOT + f"users/{current_user.email}/favorites/{incident_id}")
            if response.status_code == 200:
                favorite = True
            elif response.status_code == 404:
                favorite = False
            else:
                return abort(500, description="Error getting favorites")
        except:
            return abort(500, description="Error getting favorites")
        
        if favorite:
            response = requests.delete(BACKEND_ROOT + f"users/{current_user.email}/favorites/{incident_id}")
            favorite = False
        else:
            response = requests.post(BACKEND_ROOT + f"users/{current_user.email}/favorites", json={"incident_id": incident_id})
            favorite = True
        if response.status_code != 200:
            return abort(500, description="Error toggling favorite")
        
    return jsonify({"favorite": favorite}), 200

@app.route("/incidents/<incident_id>/remove_favorite", methods=["POST"])
#@login_required
def remove_favorite(incident_id):
    if current_user.is_anonymous:
        current_user.remove_favourite_incident(incident_id)
    elif current_user.is_authenticated:
        response = requests.delete(BACKEND_ROOT + f"users/{current_user.email}/favorites/{incident_id}")
        if response.status_code != 200:
            return abort(500, description="Error deleting favorite")
    return redirect(url_for("profile"), code=302)

@app.route("/threat-actors/", methods=["GET", "POST"])
#@login_required
def threat_actors():
    if request.method == "GET":
        page = request.args.get("page", 1, type=int)
        response = requests.get(BACKEND_ROOT + "threat-actors", params={"page": page, "limit": LISTING_LIMIT})
        if response.status_code != 200:
            abort(500, description="Error retrieving Threat Actors")
        response_json = response.json()
        app.logger.info(response_json)
        npages = response_json.get("total_threat_actors", 0) // response_json.get("limit", LISTING_LIMIT) + 1
        return render_template("threat_actors.html", threat_actors = response_json.get("threat_actors"), 
                    npages=npages, page=page, total_threat_actors=response_json.get("total_threat_actors") , max_selectable_pages=MAX_INDIVIDUAL_SELECTABLE_PAGES)
    return "Not implemented", 400

@app.route("/threat-actors/<ta_id>",  methods=["GET"])
#@login_required
def threat_actor(ta_id):
    response = requests.get(BACKEND_ROOT + "threat-actors/" + ta_id)
    if response.status_code != 200:
        return abort(500, description="Error retrieving Threat Actor")
    return render_template("threat_actor.html", threat_actor=response.json())

@app.route('/api/threat-actors', methods=['GET'])
def get_threat_actors():
    search = request.args.get('query', None)
    if not search:
        return jsonify([]), 400
    
    # get the threat actors from the backend
    response = requests.get(BACKEND_ROOT + "threat-actors", params={"q": search})
    if response.status_code != 200:
        return jsonify([]), 500
    threat_actors = response.json().get("threat_actors", [])

    # return just the name and id of the threat actors
    return jsonify([ta["name"] for ta in threat_actors]), 200

@app.route('/api/incident-details/<incident_id>', methods=['GET'])
#@login_required
def api_incident_detailed_bundle(incident_id):
    incident_stix_bundle = {}
    try:
        response = requests.get(BACKEND_ROOT + f"neighbors/{incident_id}")
        if response.status_code == 200:
            app.logger.info(response.json())
            stix_bundle = response.json()
    except:
        pass
    json_response = stix_bundle
    # json_response = {}
    # for stix_object in incident["bundle"]["objects"]:
    #     if stix_object["type"] == "location":
    #         json_response["location"] = stix_object.get("name", "")
    #     elif stix_object["type"] == "threat-actor":
    #         json_response["threat_actor"] = stix_object.get("name", "")
    # json_response["raw_stix2"] = incident

    return jsonify(stix_bundle), 200

@app.route('/api/threat-actor-details/<threat_actor_id>', methods=['GET'])
#@login_required
def api_threat_actor_detailed_bundle(threat_actor_id):
    incident_stix_bundle = {}
    try:
        response = requests.get(BACKEND_ROOT + f"neighbors/{threat_actor_id}")
        if response.status_code == 200:
            app.logger.info(response.json())
            stix_bundle = response.json()
    except:
        pass
    return jsonify(stix_bundle), 200

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/devs")
def developers():
    return render_template("devs.html")

