import requests
import json

from typing import Any

from six.moves.urllib.request import urlopen

from jose import jwt
from authlib.integrations.flask_client import OAuth
from google.cloud import datastore

from flask import Flask, request, jsonify

CLIENT_ID = 'X'
CLIENT_SECRET = 'X'
DOMAIN = 'X'

app = Flask(__name__)

client = datastore.Client()

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url=f'https://{DOMAIN}',
    acess_token_url=f'https://{DOMAIN}/oauth/token',
    authorize_url=f'https://{DOMAIN}/authorize',
    client_kwargs={
        'scope': 'openid profile email'
    }
)

# Required Fields
USER_FIELDS = ["Username", "Password"]


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def _handle_auth_error(ex):
    """ Handle the AuthError by returning a JSON response to the client. """
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


def _verify_request(body: dict[str, Any], fields: list) -> bool:
    """ Verify that an incoming request contains the required fields """
    if not body or len(body) < len(fields):
        return False

    for field in fields:
        if field not in body:
            return False

    return True


def get_token(request):
    """ Retrieve the JWT from the authorization header. """
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError(
            {
                "code": "no_auth_header",
                "description": "Authorization header is missing"},
            401
        )

    return token


def verify_signature(token):
    """ Verify that the client contains an RS256 signed JWT. """
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError(
            {
                "code": "invalid_header",
                "description": "Invalid header. Use an RS256 signed JWT Access Token"},
            401
        )

    if unverified_header["alg"] == "HS256":
        raise AuthError(
            {
                "code": "invalid_header",
                "description": "Invalid header. Use an RS256 signed JWT Access Token"},
            401
        )

    return unverified_header


def build_rsa_key(unverified_header):
    """ Retrieve the RSA key from the JWKS endpoint. """
    jsonurl = urlopen(
        "https://" + DOMAIN + "/.well-known/jwks.json"
    )
    jwks = json.loads(jsonurl.read())

    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }

    return rsa_key


def verify_rsa_key(rsa_key, token):
    """ Verify that the RSA Key is valid. """
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms="RSA256",
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError(
                {
                    "code": "token_expired",
                    "description": "Token is expired"
                },
                401
            )
        except jwt.JWTClaimsError:
            raise AuthError(
                {
                    "code": "invalid_claims",
                    "description": "Incorrect claims, please check the audience and issuer"
                },
                401
            )
        except Exception:
            raise AuthError(
                {
                    "code": "invalid_header",
                    "description": "Unable to parse authentication token."},
                401
            )
        return payload

    raise AuthError(
        {
            "code": "no_rsa_key",
            "description": "No RSA key in JWKS"},
        401
    )


def _verify_jwt():
    """ Verify that the client has a valid JWT. """
    token = get_token(request)
    unverified_header = verify_signature(token)
    rsa_key = build_rsa_key(unverified_header)
    return verify_rsa_key(rsa_key, token)


@app.route('/')
def index():
    return "Please provide a resource path to use the API."


@app.route('/users/login', methods=['POST'])
def user_login():
    """ Generate a JWT for a single user """
    pass


@app.route('/users', methods=['GET'])
def get_all_users():
    """ Return summary information for all users """
    pass


@app.route('/users/<int:id>', methods=['GET'])
def get_user(id):
    """ Return detailed information for a single user """
    pass


@app.route('/users/<int:id>/avatar', methods=['POST', 'GET', 'DELETE'])
def avatar(id):
    """ Upload or return an avatar for a single user based on the request type """
    if request.method == 'GET':
        _get_avatar(id)

    if request.method == 'POST':
        _upload_avatar(id)

    if request.method == 'DELETE':
        _delete_avatar(id)


def _get_avatar(id):
    """ Upload an avatar for a single user """
    pass


def _upload_avatar(id):
    """ Return the avatar for a single user """
    pass


def _delete_avatar(id):
    """ Delete the avatar for a single user """
    pass


@app.route('/courses', methods=['POST', 'GET'])
def course():
    """ Create a course or return all courses depending on the request type """
    pass


def _get_all_courses():
    """ Return all courses """
    pass


def _create_course():
    """ Create a single course """
    pass


@app.route('/courses/<int:id>', methods=['GET', 'PUT', 'DELETE'])
def course_by_id(id):
    """ Return or update a single course depending on the request type """
    if request.method == 'GET':
        _get_course(id)

    if request.method == 'PUT':
        _update_course(id)

    if request.method == 'DELETE':
        _delete_course(id)


def _get_course(id):
    """ Return a single course """
    pass


def _update_course(id):
    """ Update a single course """
    pass


def _delete_course(id):
    """ Delete a single course """
    pass


@app.route('/courses/<int:id>/students', methods=['PUT', 'GET'])
def course_students(id):
    """
    Update the enrollment of student or return all students for a single course
    depending on the request type
    """
    if request.method == 'PUT':
        _update_enrollment(id)

    if request.method ==['GET']:
        _get_all_students(id)


def _update_enrollment(id):
    """ Update students' enrollment in a single course """
    pass


def _get_all_students(id):
    """ Return all students enrolled in a single course """
    pass


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
