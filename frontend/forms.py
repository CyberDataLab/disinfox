from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap
from wtforms import StringField, TextAreaField, DateField, SelectMultipleField, SubmitField, FileField
from wtforms.validators import DataRequired
from flask_wtf.file import FileAllowed, FileRequired


class IncidentForm(FlaskForm):
    event = StringField('Incident name', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    date = DateField('Date', validators=[DataRequired()])
    target_countries = SelectMultipleField('Target countries', choices=[])
    threat_actors = SelectMultipleField('Threat actors', choices=[])
    techniques = SelectMultipleField('Techniques', choices=[])
    sources = SelectMultipleField('Sources', choices=[
        ('source1', 'Source 1'),
        ('source2', 'Source 2'),
        ('source3', 'Source 3'),
    ])
    submit = SubmitField('Submit Incident')

class FileUploadForm(FlaskForm):
    file = FileField('Upload File', validators=[FileRequired(), FileAllowed(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'], 'Allowed file types: txt, pdf, png, jpg, jpeg, gif')])
    submit = SubmitField('Upload File')
