from flask import Flask, jsonify, request, url_for, redirect, session
import requests
from flask_sqlalchemy import SQLAlchemy
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
appeals_metric = Counter('appeals', 'Appeals view')
appeals_create_metric = Counter('my_appeals_created', 'Appeals created view')
appeal_deleted = Counter('appeal_deleted', 'Appeal deleted view')
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://contestormi:RkQc0vo1DmYw@ep-young-haze-43228957.us-east-2.aws.neon.tech/appeals?sslmode=require'
app.config["SECRET_KEY"] = str(uuid4())
db = SQLAlchemy(app)
logger = logging.getLogger("my_logger")
logger.setLevel(logging.INFO)

loki_handler = LokiHandler(
    url="http://loki:3100/loki/api/v1/push",
    tags={"application": "my-web-service"},
    version="1"
)

handler = logging.FileHandler('/appeals/info/infolog.log')
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
    if request.endpoint not in {"login", "callback", "metrics"}:
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

class Appeal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(255), nullable=False)
    house_id = db.Column(db.Integer, nullable=False)
    management_info = db.Column(db.String(255))

@app.route('/metrics')
def metrics():
    return generate_latest()

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

@app.route('/appeal', methods=['POST'])
def create_appeal():
    data = request.json
    house_id = data.get('house_id')
    description = data.get('description')

    response = requests.get(f'http://house_service:5001/house/{house_id}')
    if response.status_code != 200:
        return jsonify({'error': 'House not found'}), 404

    management_info = response.json()
    new_appeal = Appeal(description=description, house_id=house_id, management_info=str(management_info))
    db.session.add(new_appeal)
    db.session.commit()
    success_message = f'Appeal created successfully with appeal_id: {new_appeal.id}'
    logger.info(success_message)
    appeals_create_metric.inc()
    return jsonify({'message': success_message, 'appeal_id': new_appeal.id}), 201

@app.route('/appeals', methods=['GET'])
def get_appeals():
    appeals = Appeal.query.all()
    appeals_data = [{
        'id': appeal.id,
        'description': appeal.description,
        'house_id': appeal.house_id,
        'management_info': appeal.management_info
    } for appeal in appeals]
    logger.info("Appeals received")
    appeals_metric.inc()
    return jsonify(appeals_data), 200

@app.route('/appeal/<int:appeal_id>', methods=['DELETE'])
def delete_appeal(appeal_id):
    appeal_to_delete = Appeal.query.get_or_404(appeal_id)
    db.session.delete(appeal_to_delete)
    db.session.commit()
    success_message = f'Appeal deleted successfully with appeal_id: {appeal_id}'
    logger.info(success_message)
    appeal_deleted.inc()
    return jsonify({'message': 'Appeal deleted successfully'}), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5002, debug=True)
