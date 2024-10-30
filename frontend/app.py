from flask import Flask, render_template, request, jsonify
import requests
import pycountry

app = Flask(__name__)

BACKEND_ROOT = "http://backend:5000/"

app.logger.info("Starting DISINFOX frontend...")
app.logger.info("Connecting with DISINFOX backend...", end="")
alive = False
try:
    response = requests.get(BACKEND_ROOT)
    if response.status_code == 200:
        alive = True
except:
    pass
app.logger.info("OK" if alive else "FAILED")

available_countries = [country.name for country in pycountry.countries]

@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")

def get_incidents_from_back():
    return []

@app.route("/incidents", methods=["GET"])
def incidents():
    incidents = get_incidents_from_back()
    return render_template("incidents.html", incidents=incidents)
    
@app.route("/incidents/new", methods=["GET", "POST"])
def new_incident():
    if request.method == "GET":
        return render_template("incidents_new.html", countries=available_countries)
    
    # process the form data

    app.logger.info("Incident saved successfully"+ str(request.form))
    return "OK"
    

    
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

