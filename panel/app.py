from flask import Flask, render_template, redirect, url_for, flash, request
import requests
import os
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Replace with a secure key

BACKEND_ROOT = f"http://{os.environ.get('BACKEND_HOST', 'localhost')}:{os.environ.get('BACKEND_PORT', '5000')}/"

app.logger.info("Starting DISINFOX panel")
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

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class AdminUser(UserMixin):
    def __init__(self, id):
        self.id = id

    @staticmethod
    def get(user_id):
        try:
            resp = requests.get(BACKEND_ROOT + f'users/{user_id}')
            resp.raise_for_status()
            user_data = resp.json()
            return AdminUser(user_data['email'])
        except Exception as e:
            app.logger.error(f"Error fetching user {user_id}: {e}")
            return None

@login_manager.user_loader
def load_user(user_id):
    return AdminUser.get(user_id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        try:
            resp = requests.post(BACKEND_ROOT + 'login', json={'email': username, 'password': password})
            data = resp.json()
            if resp.status_code == 200:
                user = AdminUser(username)
                user_data = requests.get(BACKEND_ROOT + f'users/{username}').json()
                if not user_data.get('isAdmin', False):
                    flash('You do not have admin privileges.')
                    return redirect(url_for('login'))
                login_user(user)
                flash('Logged in successfully.')
                return redirect(url_for('index'))
            else:
                flash('Invalid credentials.')
        except Exception as e:
            flash(f"Login error: {e}")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
        try:
                resp = requests.get(BACKEND_ROOT + 'users')

                resp.raise_for_status()
                users = resp.json()
        except Exception as e:
                users = []
                flash(f"Error fetching users: {e}")
        return render_template("panel.html", users=users)

@app.route('/users/<user_id>', methods=['POST'])
@login_required
def verify_user(user_id):
        verify = request.form.get('verify')
        if verify is None:
                flash("No action specified.")
                return redirect(url_for('index'))
        verify = verify.lower() == 'true'
        try:
                resp = requests.get(BACKEND_ROOT + f'users/{user_id}')
                resp.raise_for_status()
                user = resp.json()
                if not user:
                        flash(f"User {user_id} not found.")
                        return redirect(url_for('index'))
                user['verified'] = verify
                resp = requests.put(BACKEND_ROOT + f'users/{user_id}', json=user)
                resp.raise_for_status()
                flash(f"User {user_id} {'verified' if verify else 'unverified'} successfully.")
        except Exception as e:
                flash(f"Error verifying user: {e}")
        return redirect(url_for('index'))


if __name__ == '__main__':
        app.run(debug=True)