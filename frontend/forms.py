from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap
from wtforms import StringField, TextAreaField, DateField, SelectMultipleField, SubmitField, FileField, PasswordField, EmailField, SelectField
from wtforms.validators import DataRequired
from flask_wtf.file import FileAllowed, FileRequired
import pycountry
import os
import json

DISARM_MATRIX_PATH = os.path.join(os.path.dirname(__file__), "data", "DISARM.json")


available_countries = [country.name for country in pycountry.countries]

app = Flask(__name__)
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

displayed_techniques = [f"{technique['disarm_id']}: {technique['name']}" for technique in techniques]

class NonValidatingSelectField(SelectMultipleField):
    """
    Attempt to make an open ended select multiple field that can accept dynamic
    choices added by the browser.
    """
    def pre_validate(self, form):
        pass

class IncidentForm(FlaskForm):
    event = StringField('Incident name *', validators=[DataRequired()], id="event", name="event")
    description = TextAreaField('Description *', validators=[DataRequired()], id="event_description", name="event_description")
    date = DateField('Date *', validators=[DataRequired()], id="date", name="date")
    target_countries = SelectMultipleField('Target countries *', choices=available_countries, validators=[DataRequired()], coerce=str, id="target_countries", render_kw={"multiple": "multiple"}, description="Select at least one country")
    # the threat actor field choices is given dynamically
    threat_actors = NonValidatingSelectField('Threat actors *', validators=[DataRequired()], coerce=str, id="threat_actors", render_kw={"multiple": "multiple"}, description="Select multiple threat actors, if unknown, select 'Unknown'")
    techniques = SelectMultipleField('Techniques', choices=displayed_techniques, coerce=str, id="techniques", render_kw={"multiple": "multiple"}, description="Select multiple techniques")
    # now the sources, when constructed, a list of strings will be passed
    sources = NonValidatingSelectField('Sources', choices=[], coerce=str, id="sources", render_kw={"multiple": "multiple"}, description="Select multiple sources")
    submit = SubmitField('Submit Incident')

class FileBulkIncidentForm(FlaskForm):
    file = FileField('Upload File', 
                     validators=[FileRequired(), FileAllowed(['json', 'csv'], 'Only JSON and CSV files are accepted')],
                     id="file", name="file")

class FileSourceForm(FlaskForm):
    file = FileField('Upload File', 
                     validators=[FileRequired(), FileAllowed(['pdf'], 'Only PDF files are accepted')],
                     id="file", name="file")

class RegisterForm(FlaskForm):
    firstName = StringField('First Name', validators=[DataRequired()])
    lastName = StringField('Last Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

