from flask_sqlalchemy import SQLAlchemy
from flask import Flask, jsonify, request, url_for, redirect, session
import requests
from uuid import uuid4
from requests_oauthlib import OAuth2Session
import jwt
from jwt import PyJWKClient
from jwt.exceptions import DecodeError
from werkzeug.exceptions import InternalServerError, Unauthorized
import logging
from logging_loki import LokiHandler
import time
from prometheus_client import Counter, generate_latest

app = Flask(__name__)
managment_metric = Counter('managment', 'Managment view')
house_metric = Counter('house', 'House view')
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://xaslace:SIV01YGjiQkC@ep-jolly-hat-46905879.us-east-2.aws.neon.tech/managment?sslmode=require'
app.config["SECRET_KEY"] = str(uuid4())
db = SQLAlchemy(app)
logger = logging.getLogger("my_logger")
logger.setLevel(logging.INFO)

handler = logging.FileHandler('/managment/info/infolog.log')
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

IDP_CONFIG = {
  "well_known_url": "http://keycloak.auth:8080/realms/master/.well-known/openid-configuration",
  "client_id": "flask",
  "client_secret": "qcbRSbJH0Qz1oLtO2rtcAxv7LhlkL47h",
  "scope": ["profile", "email", "openid"]
}

def get_well_known_metadata():
    response = requests.get(IDP_CONFIG["well_known_url"])
    response.raise_for_status()
    return response.json()

def get_oauth2_session(**kwargs):
    oauth2_session = OAuth2Session(IDP_CONFIG["client_id"],
                                   scope=IDP_CONFIG["scope"],
                                   redirect_uri=url_for(".callback", _external=True),
                                   **kwargs)
    return oauth2_session

@app.before_request
def verify_and_decode_token():
    if request.endpoint not in {"login", "callback"}:
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split()[1]
        elif "id_token" in session:
            token = session["id_token"]
        else:
            return Unauthorized("Missing authorization token")

        try:
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            header_data = jwt.get_unverified_header(token)
            decoded_token = jwt.decode(token,
                                       signing_key.key,
                                       algorithms=[header_data['alg']],
                                       audience=IDP_CONFIG["client_id"])
            user_role = decoded_token.get("role")
            if "myrole" not in user_role:
                return Unauthorized("Access denied: insufficient privileges")
            request.user_data = decoded_token
        except DecodeError:
            return Unauthorized("Authorization token is invalid")
        except Exception as e:
            return InternalServerError("Error authenticating client")

@app.route("/login")
def login():
    well_known_metadata = get_well_known_metadata()
    oauth2_session = get_oauth2_session()
    authorization_url, state = oauth2_session.authorization_url(well_known_metadata["authorization_endpoint"])
    session["oauth_state"] = state
    return redirect(authorization_url.replace("keycloak.auth", "localhost"))

@app.route("/user/id")
def get_user_id():
    return request.user_data

@app.route("/callback")
def callback():
    well_known_metadata = get_well_known_metadata()
    oauth2_session = get_oauth2_session(state=session["oauth_state"])
    tok = oauth2_session.fetch_token(well_known_metadata["token_endpoint"],
                                                        client_secret=IDP_CONFIG["client_secret"],
                                                        code=request.args["code"])
    session["id_token"] = tok["id_token"]
    return "ok"

def get_jwks_client():
    well_known_metadata = get_well_known_metadata()
    jwks_client = PyJWKClient(well_known_metadata["jwks_uri"])
    return jwks_client

jwks_client = get_jwks_client()

class House(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(80), unique=True, nullable=False)
    management_id = db.Column(db.Integer, db.ForeignKey('management.id'), nullable=False)

class Management(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    contact_info = db.Column(db.String(120))
    ratings = db.relationship('Rating', backref='management', lazy=True)

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    score = db.Column(db.Integer, nullable=False)
    management_id = db.Column(db.Integer, db.ForeignKey('management.id'), nullable=False)

@app.route('/house/<int:house_id>')
def get_management(house_id):
    house = House.query.get_or_404(house_id)
    management = Management.query.get_or_404(house.management_id)
    average_rating = None
    if management.ratings:
        average_rating = sum(rating.score for rating in management.ratings) / len(management.ratings)
    logger.info('House info received')
    house_metric.inc()
    return jsonify({
        'management_name': management.name,
        'contact_info': management.contact_info,
        'average_rating': average_rating
    })

@app.route('/rate_management/<int:management_id>', methods=['POST'])
def rate_management(management_id):
    score = request.json.get('score')
    if not score or not (1 <= score <= 5):
        return jsonify({'error': 'Invalid score'}), 400
    rating = Rating(score=score, management_id=management_id)
    db.session.add(rating)
    db.session.commit()
    managment_metric.inc()
    logger.info('House rated')
    return jsonify({'message': 'Rating added successfully'}), 201

if __name__ == '__main__':
    with app.app_context():
        db.drop_all()
        db.create_all()
        if not Management.query.first():
            management1 = Management(name="Management Company 1", contact_info="contact1@example.com")
            db.session.add(management1)
            db.session.commit()

            house1 = House(address="Street 1, House 1", management_id=management1.id)
            db.session.add(house1)
            db.session.commit()
    app.run(host='0.0.0.0', port=5001, debug=True)
