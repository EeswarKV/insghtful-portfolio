from urllib.parse import quote_plus, urlencode
from flask import Flask, render_template, redirect, url_for, session
import flask
from src.models import User, db
from src.dashboard import get_portfolio_data
from src.modify_entry import edit_portfolio_entry, delete_portfolio_entry
from src.invest import get_invest_data
from src.login_register import get_user_register, get_user_login, bcrypt
from src.home import get_home_data
from functools import wraps
from src.forms import LoginForm, RegistrationForm
from dotenv import find_dotenv, load_dotenv
from authlib.integrations.flask_client import OAuth
from os import environ as env
from authlib.integrations.flask_oauth2 import ResourceProtector
import ssl 
ssl._create_default_https_context = ssl._create_unverified_context

app = Flask(__name__, static_url_path='/static')
app.config.from_object('config.Config')
db.init_app(app) 
bcrypt.init_app(app)

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app.secret_key = env.get("APP_SECRET_KEY")

oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    audidance=env.get("AUTH0_AUDIANCE"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)

# Create the tables
with app.app_context():
    db.create_all()


#decorator to check if user logged in and returns user if successful
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        user = User.query.get(user_id) if user_id else None
        if user is None:
            return redirect(url_for('login'))
        return f(user, *args, **kwargs)
    return decorated_function

#decorator to check if user logged in and returns user if successful
def login_required_for_new_way(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = oauth.auth0.authorize_access_token()
        values = token['userinfo']
        print(values)
        emailValue = values['name'].strip()
        user = User.query.filter_by(email=emailValue).first() if emailValue else None
        print(user)
        if user is None:
            print("no user info present")
            return redirect(url_for('login'))
        return f(user, *args, **kwargs)
    return decorated_function

#login route returns to login template
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        return oauth.auth0.authorize_redirect(redirect_uri=url_for("home", _external=True))
        # form = LoginForm()
        # if form.validate_on_submit():
        #     return get_user_login(form)
        # return render_template('login.html', form=form)
    except Exception as e:
        print(f"Error trying to login: {e}")
        return None


@app.route('/register', methods=['GET', 'POST'])
def register():
    try:
        form = RegistrationForm()
        if form.validate_on_submit():
            return get_user_register(form)
        return render_template('register.html', form=form)
    except Exception as e:
        print(f"Error trying to register: {e}")
        return None
    
#returns to invest template to record investments 
@app.route('/invest', methods=['GET', 'POST'])
@login_required
def invest(user):
    try:
        return get_invest_data(user)
    except Exception as e:
        print(f"Error trying to redirecting to invest page: {e}")
        return None
    
#returns to home template
@app.route('/home', methods=['GET'])
@login_required_for_new_way
def home(user):
    try:
        return get_home_data(user)
    except Exception as e:
        print(f"Error trying to redirecting to home page: {e}")
        return None
    
#returns dashboard template
@app.route('/dashboard')
@login_required
def dashboard(user):
    try:
        # Retrieve the portfolio data for the current user
        return get_portfolio_data(user)
    except Exception as e:
        print(f"Error trying to redirecting to dashboard: {e}")
        return None
    
@app.route('/edit_entry/<int:entry_id>', methods=['POST'])
@login_required
def edit_entry(user, entry_id):
    return handle_entry_action(user, edit_portfolio_entry, entry_id)

@app.route('/delete_entry/<int:entry_id>', methods=['POST'])
@login_required
def delete_entry(user, entry_id):
    return handle_entry_action(user, delete_portfolio_entry, entry_id)

def handle_entry_action(user, action_function, entry_id):
    try:
        action_function(user, entry_id)
        return redirect(url_for('invest'))  # Redirect to the dashboard
    except Exception as e:
        print(f"Error trying to perform action on entry: {e}")
        return "Error", 500  # Return an error message


#returns to login template once logout succesful
@app.route('/logout')
def logout():
    try:
        session.clear()
        return redirect(
        "https://"
        + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("login", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )
        session.pop('user_id', None)  # Remove the user ID from the session
        return redirect(url_for('login')) 
    except Exception as e:
        print(f"Error trying to logout: {e}")
        return None


if __name__ == '__main__':
    app.run(debug=True)
