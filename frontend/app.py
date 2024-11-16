from flask import Flask, render_template, request, jsonify, redirect, url_for
import requests
import pycountry
import os
import json
from flask_bootstrap import Bootstrap5
from forms import IncidentForm, FileUploadForm

app = Flask(__name__)
app.config["SECRET_KEY"] = "secretkey"
bootstrap = Bootstrap5(app)



BACKEND_ROOT = f"http://{os.environ.get('BACKEND_HOST', 'localhost')}:{os.environ.get('BACKEND_PORT', '5000')}/"
LISTING_LIMIT = 50


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





@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")

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
    npages = incidents_response.get("total_incidents", 0) // incidents_response.get("limit", LISTING_LIMIT) + 1
    total_incidents = incidents_response.get("total_incidents", 0)
    return render_template("incidents.html", 
                            incidents=incidents_response.get("incidents", []),
                            npages=npages, page=page, total_incidents=total_incidents, max_selectable_pages=5)

@app.route("/incidents/<incident_id>", methods=["GET"])
def incident(incident_id):
    incident_stix_bundle = {}
    try:
        response = requests.get(BACKEND_ROOT + f"incidents/{incident_id}")
        if response.status_code == 200:
            app.logger.info(response.json())
            incident_stix_bundle = response.json()
    except:
        pass
    json_response = incident_stix_bundle
    # json_response = {}
    # for stix_object in incident["bundle"]["objects"]:
    #     if stix_object["type"] == "location":
    #         json_response["location"] = stix_object.get("name", "")
    #     elif stix_object["type"] == "threat-actor":
    #         json_response["threat_actor"] = stix_object.get("name", "")
    # json_response["raw_stix2"] = incident

    return jsonify(json_response), 200
    
@app.route("/incidents/new", methods=["GET", "POST"])
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
    


    
@app.route('/api/threat-actors', methods=['GET'])
def get_threat_actors():
    # dummy threat actor example
    threat_actors = ["Russia State", "China State", "Iran State", "North Korea State", "USA State", "Wagner", "APT28", "APT29", "APT30", "APT31", "APT32", "APT33", "APT34", "APT35", "APT36", "APT37", "APT38", "APT39", "APT40", "APT41", "APT42", "APT43", "APT44", "APT45", "APT46", "APT47", "APT48", "APT49", "APT50", "APT51", "APT52", "APT53", "APT54", "APT55", "APT56", "APT57", "APT58", "APT59", "APT60", "APT61", "APT62", "APT63", "APT64", "APT65", "APT66", "APT67", "APT68", "APT69", "APT70", "APT71", "APT72", "APT73", "APT74", "APT75", "APT76", "APT77", "APT78", "APT79", "APT80", "APT81", "APT82", "APT83", "APT84", "APT85", "APT86", "APT87", "APT88", "APT89", "APT90", "APT91", "APT92", "APT93", "APT94", "APT95", "APT96", "APT97", "APT98", "APT99", "APT100"]
    search = request.args.get('search')
    if search:
        threat_actors = [actor for actor in threat_actors if search.lower() in actor.lower()]

    # return a reduced list of threat actors
    return jsonify(threat_actors[:10]), 200


@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/devs")
def developers():
    return render_template("devs.html")

