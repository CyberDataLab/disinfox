from flask import Flask, render_template, request, jsonify, redirect, url_for
import requests
import pycountry
import os
import json
from flask_bootstrap import Bootstrap5
from forms import IncidentForm, FileUploadForm, LoginForm, RegisterForm
from incident_export import export_incident_to_pdf

from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import User

app = Flask(__name__)
app.config["SECRET_KEY"] = "secretkey"
bootstrap = Bootstrap5(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"



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
    return render_template("index.html")

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
        return "Error logging in", 500
    user = response.json()
    user = User(form["email"])
    login_user(user)
    return redirect(url_for("home"), code=302)

@app.route("/profile", methods=["GET"])
@login_required
def profile():
    user_data = requests.get(BACKEND_ROOT + "users/" + current_user.email)
    if user_data.status_code != 200:
        return "Error getting profile", 500
    # Get the data from the favorite incidents id
    favorites = []
    for incident_id in user_data.json().get("favoriteIncidents", []):
        response = requests.get(BACKEND_ROOT + "incidents/" + incident_id)
        if response.status_code == 200:
            favorites.append(response.json())
    return render_template("profile.html", user=user_data.json(), favorites=favorites)

@app.route("/profile/delete", methods=["POST"])
@login_required
def delete_profile():
    response = requests.delete(BACKEND_ROOT + "users/" + current_user.email)
    if response.status_code == 200:
        logout_user()
        return redirect(url_for("home"), code=302)
    return "Error deleting profile", 500
    
@app.route("/profile/generate-api-key", methods=["POST"])
@login_required
def generate_api_key():
    response = requests.post(BACKEND_ROOT + "users/" + current_user.email + "/generate-api-key")
    if response.status_code == 201:
        return redirect(url_for("profile"), code=302)
    return "Error generating API key", 500


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
    npages = incidents_response.get("total_incidents", 0) // incidents_response.get("limit", LISTING_LIMIT) + 1
    total_incidents = incidents_response.get("total_incidents", 0)
    return render_template("incidents.html", 
                            incidents=incidents_response.get("incidents", []),
                            npages=npages, page=page, total_incidents=total_incidents, max_selectable_pages=MAX_INDIVIDUAL_SELECTABLE_PAGES)

@app.route("/incidents/<incident_id>", methods=["GET"])
@login_required
def incident(incident_id):
    response = requests.get(BACKEND_ROOT + "incidents/" + incident_id)
    if response.status_code != 200:
        return "Error retrieving incident", 500
    favorited = False
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
            return "Error uploading file", 500
        return "File uploaded successfully", 200

    # get jsoned form data
    form = incident_form.data
    app.logger.info(form)   

    backend_request = request.form.to_dict(flat=False)
    backend_request["event"] = backend_request["event"][0]
    backend_request["event_description"] = backend_request["event_description"][0]
    backend_request["date"] = backend_request["date"][0]
    response = requests.post(BACKEND_ROOT + "incidents", json=backend_request)
    if response.status_code == 201:
        # redirect to the incidents page and alert the user
        return  redirect(url_for("incidents"), code=302)
    else:
        return "Error creating incident", 500
    
@app.route("/incidents/<incident_id>/export", methods=["GET"])
def export_incident(incident_id):
    try:
        response = requests.get(BACKEND_ROOT + f"incidents/{incident_id}")
        if response.status_code == 200:
            incident = response.json()
    except:
        pass
    app.logger.info(incident)
    pdf = export_incident_to_pdf(incident)
    if pdf is None:
        return "Error exporting incident", 500
    return pdf, 200, {"Content-Type": "application/pdf", "Content-Disposition": f"attachment; filename=incident_{incident_id}.pdf"}

@app.route("/incidents/<incident_id>/favorite", methods=["POST"])
@login_required
def toggle_favorite(incident_id):
    # The backend has DELETE and POST methods for favorites
    favorite = False
    try:
        response = requests.get(BACKEND_ROOT + f"users/{current_user.email}/favorites/{incident_id}")
        if response.status_code == 200:
            favorite = True
        elif response.status_code == 404:
            favorite = False
        else:
            return "Error getting favorites", 500
    except:
        return "Error getting favorites", 500
    
    if favorite:
        response = requests.delete(BACKEND_ROOT + f"users/{current_user.email}/favorites/{incident_id}")
        favorite = False
    else:
        response = requests.post(BACKEND_ROOT + f"users/{current_user.email}/favorites", json={"incident_id": incident_id})
        favorite = True

    if response.status_code == 200:
        return jsonify({"favorite": favorite}), 200
    return "Error toggling favorite", 500

@app.route("/incidents/<incident_id>/remove_favorite", methods=["POST"])
@login_required
def remove_favorite(incident_id):
    response = requests.delete(BACKEND_ROOT + f"users/{current_user.email}/favorites/{incident_id}")
    if response.status_code != 200:
        return "Error deleting favorite", 500
    return redirect(url_for("profile"), code=302)

@app.route("/threat-actors/", methods=["GET", "POST"])
@login_required
def threat_actors():
    if request.method == "GET":
        page = request.args.get("page", 1, type=int)
        response = requests.get(BACKEND_ROOT + "threat-actors", params={"page": page, "limit": LISTING_LIMIT})
        if response.status_code != 200:
            "Error retrieving Threat Actors", 500
        response_json = response.json()
        app.logger.info(response_json)
        npages = response_json.get("total_threat_actors", 0) // response_json.get("limit", LISTING_LIMIT) + 1
        return render_template("threat_actors.html", threat_actors = response_json.get("threat_actors"), 
                    npages=npages, page=page, total_threat_actors=response_json.get("total_threat_actors") , max_selectable_pages=MAX_INDIVIDUAL_SELECTABLE_PAGES)
    return "Not implemented", 400

@app.route("/threat-actors/<ta_id>",  methods=["GET"])
@login_required
def threat_actor(ta_id):
    response = requests.get(BACKEND_ROOT + "threat-actors/" + ta_id)
    if response.status_code != 200:
        return "Error retrieving Threat Actor", 500
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
@login_required
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
@login_required
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

