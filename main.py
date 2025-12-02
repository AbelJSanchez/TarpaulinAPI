import requests
import json
import os
import io

from typing import Any
from dotenv import load_dotenv

from six.moves.urllib.request import urlopen

from jose import jwt
from authlib.integrations.flask_client import OAuth
from google.cloud import datastore, storage
from google.cloud.datastore import Entity

from flask import Flask, request, jsonify, send_file

load_dotenv()
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
DOMAIN = os.getenv("DOMAIN")
BUCKET = os.getenv("BUCKET")

app = Flask(__name__)

client = datastore.Client()

oauth = OAuth(app)

GURL = "https://assignment-6-tarpaulin-479819.wl.r.appspot.com"

auth0 = oauth.register(
    "auth0",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url=f"https://{DOMAIN}",
    access_token_url=f"https://{DOMAIN}/oauth/token",
    authorize_url=f"https://{DOMAIN}/authorize",
    client_kwargs={"scope": "openid profile email"},
)

# Required Fields
USER_FIELDS = ["username", "password"]
COURSE_FIELDS = ["subject", "number", "title", "term", "instructor_id"]


class AuthError(Exception):
    def __init__(self, error: dict[str, Any], status_code: int) -> None:
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    """Handle the AuthError by returning a JSON response to the client."""
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


def get_token_from_auth_header(request) -> str:
    """Retrieve the JWT from the authorization header."""
    if "Authorization" in request.headers:
        auth_header = request.headers["Authorization"].split()
        token = auth_header[1]
    else:
        raise AuthError(
            {
                "code": "no_auth_header",
                "description": "Authorization header is missing",
            },
            401,
        )

    return token


def verify_token_signature(token: str) -> dict[str, Any]:
    """Verify that the client contains an RS256 signed JWT."""
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError(
            {
                "code": "invalid_header",
                "description": "Invalid header. Use an RS256 signed JWT Access Token",
            },
            401,
        )

    if unverified_header["alg"] == "HS256":
        raise AuthError(
            {
                "code": "invalid_header",
                "description": "Invalid header. Use an RS256 signed JWT Access Token",
            },
            401,
        )

    return unverified_header


def build_rsa_key(unverified_header: dict[str, Any]) -> dict[str, Any]:
    """Retrieve the RSA key from the JWKS endpoint."""
    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())

    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"],
            }

    return rsa_key


def verify_rsa_key(rsa_key: dict[str, Any], token: str) -> dict[str, Any]:
    """Verify that the RSA Key is valid."""
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms="RS256",
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/",
            )
        except jwt.ExpiredSignatureError:
            raise AuthError(
                {"code": "token_expired", "description": "Token is expired"}, 401
            )
        except jwt.JWTClaimsError:
            raise AuthError(
                {
                    "code": "invalid_claims",
                    "description": "Incorrect claims, please check the audience and issuer",
                },
                401,
            )
        except Exception:
            raise AuthError(
                {
                    "code": "invalid_header",
                    "description": "Unable to parse authentication token.",
                },
                401,
            )
        return payload

    raise AuthError({"code": "no_rsa_key", "description": "No RSA key in JWKS"}, 401)


def verify_jwt() -> dict[str, Any]:
    """Verify that the client has a valid JWT."""
    token = get_token_from_auth_header(request)
    unverified_header = verify_token_signature(token)
    rsa_key = build_rsa_key(unverified_header)
    return verify_rsa_key(rsa_key, token)


def get_user_jwt(content: dict[str, Any]) -> requests.Response:
    """Return the user's JWT from Auth0."""
    body = {
        "grant_type": "password",
        "username": content.get("username", ""),
        "password": content.get("password", ""),
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }
    headers = {"content-type": "application/json"}
    url = "https://" + DOMAIN + "/oauth/token"
    response = requests.post(url, json=body, headers=headers)

    return response


def verify_request_body(body: dict[str, Any], fields: list[str]) -> bool:
    """Verify that an incoming request contains the required fields"""
    if not body or len(body) < len(fields):
        return False

    for field in fields:
        if field not in body:
            return False

    return True


def verify_user_role(payload: dict[str, Any], role: str) -> bool:
    """Verify the users role prior to granting access to resources."""
    user = fetch_user_by_sub(payload.get("sub", ""))

    if user and user.get("role", "") == role:
        return True
    else:
        return False


def fetch_user(id: int) -> Entity:
    """Retrieve a user using their user ID."""
    user_key = client.key("users", id)
    user = client.get(key=user_key)
    return user


def fetch_user_by_sub(sub: str) -> Entity:
    """Retrieve a user using their sub."""
    query = client.query(kind="users")
    query.add_filter("sub", "=", sub)
    user = next(query.fetch(), None)
    return user


@app.route("/")
def index():
    return "Please provide a resource path to use the API."


@app.route("/users/login", methods=["POST"])
def user_login() -> tuple[dict[str, Any], int]:
    """Get a JWT for a single user"""
    content = request.get_json()
    valid_request = verify_request_body(content, USER_FIELDS)

    if not valid_request:
        return {"Error": "The request body is invalid"}, 400

    response = get_user_jwt(content).json()

    if "error" in response:
        return {"Error": "Unauthorized"}, 401

    token = response.get("id_token")

    return {"token": token}, 200


@app.route("/users", methods=["GET"])
def get_all_users() -> tuple[dict[str, Any], int] | tuple[list[Any], int]:
    """
    Return summary information for all users:
        1. User ID
        2. User Role
        3. User Sub
    """
    try:
        payload = verify_jwt()
    except AuthError:
        return {"Error": "Unauthorized"}, 401

    is_admin = verify_user_role(payload, "admin")

    # Only return information if the user is an admin
    if is_admin:
        query = client.query(kind="users")
        results = list(query.fetch())

        for r in results:
            r["id"] = r.key.id
            r.pop("avatar_url", None)
            r.pop("file_name", None)

        return results, 200

    return {"Error": "You don't have permission on this resource"}, 403


@app.route("/users/<int:id>", methods=["GET"])
def get_user(id: int) -> tuple[dict[str, Any], int] | tuple[list[Any], int]:
    """Return detailed information for a single user."""
    try:
        payload = verify_jwt()
    except AuthError:
        return {"Error": "Unauthorized"}, 401

    user = fetch_user(id)
    user["id"] = user.key.id

    if not user:
        return {"Error": "You don't have permission on this resource"}, 403

    is_admin = verify_user_role(payload, "admin")

    # If the user is an admin, simply return summary information
    if is_admin:
        return user, 200

    # If the user is not an admin, they can only access their own information
    if payload.get("sub", "") != user.get("sub", ""):
        return {"Error": "You don't have permission on this resource"}, 403

    user_role = user.get("role", "")

    # If the user is a student, return a list of courses they are enrolled in
    if user_role == "student":
        kind = "course_students"
        filter_id = "student_id"

    # If the user is an instructor, return a list of courses they are teaching
    if user_role == "instructor":
        kind = "courses"
        filter_id = "instructor_id"

    user["courses"] = build_course_list(kind, filter_id, id)
    user.pop("file_name", None)

    return user, 200


def build_course_list(kind: str, filter_id: str, user_id: int) -> list[str]:
    """Build a list of course URLs to be sent to the client."""
    query = client.query(kind=kind)
    query.add_filter(filter_id, "=", user_id)

    courses = list(query.fetch())
    return [f"{GURL}/courses/{course.get('id', '')}" for course in courses]


@app.route("/users/<int:id>/avatar", methods=["POST", "GET", "DELETE"])
def avatar(id: int):
    """Upload or return an avatar for a single user based on the request type."""
    if request.method == "GET":
        get_avatar(id)

    if request.method == "POST":
        upload_avatar(id)

    if request.method == "DELETE":
        delete_avatar(id)


def get_avatar(id: int):
    """Return an avatar for a single user."""
    try:
        payload = verify_jwt()
    except AuthError:
        return {"Error": "Unauthorized"}, 401

    user = fetch_user(id)

    if not user:
        return {"Error": "You don't have permission on this resource"}, 403

    # User can only access their own information
    if payload.get("sub", "") != user.get("sub", ""):
        return {"Error": "You don't have permission on this resource"}, 403

    # If the user does not have an avatar
    if user.pop("avatar_url", None) is None:
        return {"Error": "Not found"}, 404

    file = get_avatar_from_bucket(user.get("file_name", ""))

    return file, 200


def get_avatar_from_bucket(file_name: str):
    """Helper function to get file from Google cloud bucket."""
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(BUCKET)

    blob = bucket.blob(file_name)
    file_obj = io.BytesIO()
    blob.download_to_file(file_obj)

    file_obj.seek(0)

    return send_file(file_obj, mimetype="image/x-png", download_name=file_name)


def upload_avatar(id: int) -> tuple[dict[str, str], int]:
    """Upload an avatar for a single user."""
    if "file" not in request.files["file"]:
        return {"Error": "The request body is invalid"}, 400

    try:
        payload = verify_jwt()
    except AuthError:
        return {"Error": "Unauthorized"}, 401

    user = fetch_user(id)

    if not user:
        return {"Error": "You don't have permission on this resource"}, 403

    # User can only access their own information
    if payload.get("sub", "") != user.get("sub", ""):
        return {"Error": "You don't have permission on this resource"}, 403

    return_url = upload_avatar_to_bucket(request, user)

    return {"avatar_url": return_url}, 200


def upload_avatar_to_bucket(request, entity: Entity) -> str:
    """Helper function to upload file to Google cloud bucket."""
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(BUCKET)

    file_obj = request.files["file"]
    blob = bucket.blob(file_obj.filename)
    file_obj.seek(0)
    blob.upload_from_file(file_obj)

    avatar_url = f"{GURL}/users/{id}/avatar"

    entity.update({"avatar_url": avatar_url, "file_name": file_obj.file_name})
    client.put(entity)

    return avatar_url


def delete_avatar(id: int) -> tuple[dict[str, str], int] | tuple[str, int]:
    """Delete the avatar for a single user"""
    try:
        payload = verify_jwt()
    except AuthError:
        return {"Error": "Unauthorized"}, 401

    user = fetch_user(id)

    if not user:
        return {"Error": "You don't have permission on this resource"}, 403

    # User can only delete their own information
    if payload.get("sub", "") != user.get("sub", ""):
        return {"Error": "You don't have permission on this resource"}, 403

    # If the user does not have an avatar
    if user.pop("avatar_url", None) is None:
        return {"Error": "Not found"}, 404

    delete_avatar_from_bucket(user.get("file_name", ""))

    return "", 204


def delete_avatar_from_bucket(file_name: str) -> None:
    """Helper function to delete a file from Google cloud bucket."""
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(BUCKET)
    blob = bucket.blob(file_name)
    blob.delete()


@app.route("/courses", methods=["POST", "GET"])
def courses():
    """Create a course or return all courses depending on the request type."""
    if request.method == "POST":
        create_course()

    if request.method == "GET":
        get_all_courses()


def get_all_courses():
    """Return all courses using pagination."""
    pass


def create_course() -> tuple[dict[str, Any], int]:
    """Create a single course."""
    try:
        payload = verify_jwt()
    except AuthError:
        return {"Error": "Unauthorized"}, 401

    is_admin = verify_user_role(payload, "admin")

    # Only admin can create courses
    if not is_admin:
        return {"Error": "You don't have permission on this resource"}, 403

    content = request.get_json()

    valid_request = verify_request_body(content, USER_FIELDS)
    if not valid_request:
        return {"Error": "The request body is invalid"}, 400

    # If the user tries to assign the course to an instructor that does not exist
    user = fetch_user(content.get("instructor_id"))
    if not user:
        return {"Error": "You don't have permission on this resource"}, 400

    course = create_course_in_datastore(content)

    return course, 201


def create_course_in_datastore(content: dict[str, Any]) -> dict[str, Any]:
    """Helper function to create a course Entity in Datastore."""
    new_key = client.key("courses")
    new_course = datastore.Entity(key=new_key)

    new_course.update(
        {
            "instructor_id": content["instructor_id"],
            "number": content["number"],
            "subject": content["subject"],
            "term": content["term"],
            "title": content["title"],
        }
    )

    client.put(new_course)
    new_course["id"] = new_course.key.id
    new_course["self"] = f"{GURL}/courses/{new_course['id']}"

    return new_course


@app.route("/courses/<int:id>", methods=["GET", "PUT", "DELETE"])
def course_by_id(id):
    """Return or update a single course depending on the request type"""
    if request.method == "GET":
        get_course(id)

    if request.method == "PUT":
        update_course(id)

    if request.method == "DELETE":
        delete_course(id)


def get_course(id):
    """Return a single course"""
    pass


def update_course(id):
    """Update a single course"""
    pass


def delete_course(id):
    """Delete a single course"""
    pass


@app.route("/courses/<int:id>/students", methods=["PUT", "GET"])
def course_students(id):
    """
    Update the enrollment of student or return all students for a single course
    depending on the request type
    """
    if request.method == "PUT":
        update_enrollment(id)

    if request.method == "GET":
        get_all_students(id)


def update_enrollment(id):
    """Update students' enrollment in a single course"""
    pass


def get_all_students(id):
    """Return all students enrolled in a single course"""
    pass


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)
