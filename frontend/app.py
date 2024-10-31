from flask import Flask, render_template, request, jsonify, redirect, url_for
import requests
import pycountry
import os
import json

app = Flask(__name__)

BACKEND_ROOT = "http://localhost:5001/"
DISARM_MATRIX_PATH = os.path.join(os.path.dirname(__file__), "data", "DISARM.json")


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

app.logger.info("Getting the DISARM matrix from file from " + DISARM_MATRIX_PATH)
techniques = []
try:
    with open(DISARM_MATRIX_PATH, "r") as f:
        '''
        transforming {"objects": [{ "type": "attack-pattern", "id": "attack-pattern--21fc4", ..., "external_references": [{"external_id": "T0014"}
        to [{"id": "attack-pattern--T0014", name": "Spearphishing Attachment", disarm_id: "T0014", description: "A threat actor "}]
        '''
        disarm_stix2 = json.loads(f.read())
        for obj in disarm_stix2["objects"]:
            if obj["type"] == "attack-pattern":
                technique = {}
                technique["id"] = obj["id"]
                technique["name"] = obj["name"]
                technique["disarm_id"] = obj["external_references"][0]["external_id"]
                technique["description"] = obj["description"]
                techniques.append(technique)
except:
    pass
if not techniques:
    app.logger.error("FAILED")
    exit(1)


available_countries = [country.name for country in pycountry.countries]

@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")

def get_incidents_from_back():
    incidents = []
    try:
        response = requests.get(BACKEND_ROOT + "incidents")
        if response.status_code == 200:
            incidents = response.json()["incidents"]
    except:
        pass
    return incidents

@app.route("/incidents", methods=["GET"])
def incidents():
    incidents = get_incidents_from_back()
    return render_template("incidents.html", incidents=incidents)
    
@app.route("/incidents/new", methods=["GET", "POST"])
def new_incident():
    if request.method == "GET":
        return render_template("incidents_new.html", countries=available_countries, techniques=techniques)
    
    # check if the fields are filled
    if not request.form["event"] or not request.form["event_description"] or not request.form["target_countries"] or not request.form["techniques"] or not request.form["sources"]:
        return "Please fill all the fields: title, description, countries, technique, sources", 400

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

