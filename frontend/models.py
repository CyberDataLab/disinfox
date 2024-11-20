from flask_login import UserMixin
import requests

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
