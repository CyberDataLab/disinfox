from flask_login import UserMixin, AnonymousUserMixin
import requests
from flask import session

class Anonymous(AnonymousUserMixin):
    def __init__(self):
        self.email = 'guest@example.org'
        self.firstName = 'Nice'
        self.lastName = 'Guest'
    def get_favourite_incidents(self):
        return session.get('favoriteIncidents', [])
    def add_favourite_incident(self, incident_id):
        favoriteIncidents = self.get_favourite_incidents()
        if incident_id in favoriteIncidents:
            return False
        favoriteIncidents.append(incident_id)
        session['favoriteIncidents'] = favoriteIncidents
        return True
    def remove_favourite_incident(self, incident_id):
        favoriteIncidents = self.get_favourite_incidents()
        if incident_id not in favoriteIncidents:
            return False
        favoriteIncidents.remove(incident_id)
        session['favoriteIncidents'] = favoriteIncidents
        return True
    def to_json(self):
        return {
            'email': self.email,
            'firstName': self.firstName,
            'lastName': self.lastName,
            'favoriteIncidents': self.get_favourite_incidents()
        }

class User(UserMixin):
    def __init__(self, email, first_name=None, last_name=None):
        self.email = email
        self.firstName = first_name
        self.lastName = last_name

    def __repr__(self):
        return f'<User {self.username}>'
    
    def get_id(self):
        return self.email
    
    def is_authenticated(self):
        return True
    
    def is_active(self):
        return True
    
    def is_anonymous(self):
        return False
    
    @staticmethod
    def get(user_id, api_user_root):
        response = requests.get(f"{api_user_root}{user_id}")
        if response.status_code == 200:
            user_data = response.json()
            return User(user_data["email"], user_data["firstName"], user_data["lastName"])
        else:
            return None
