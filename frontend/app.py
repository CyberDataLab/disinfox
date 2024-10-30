from flask import Flask, render_template, request

app = Flask(__name__)

@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")

def get_incidents_from_back():
    pass

@app.route("/incidents", methods=["GET", "POST"])
def incidents():
    if request.method == "GET":
        # Retrieve incidents from backend
        incidents = get_incidents_from_back()
        return render_template("incidents.html", incidents=incidents)
    
@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/devs")
def developers():
    return render_template("devs.html")