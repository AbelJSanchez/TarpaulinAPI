from __future__ import annotations

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

# Environment variables
load_dotenv()
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
DOMAIN = os.getenv("DOMAIN")
BUCKET = os.getenv("BUCKET")

# Required Fields
USER_FIELDS = ["username", "password"]
COURSE_FIELDS = ["subject", "number", "title", "term", "instructor_id"]

app = Flask(__name__)

client = datastore.Client()

oauth = OAuth(app)

GURL = "http://127.0.0.1:8080"

auth0 = oauth.register(
    "auth0",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url=f"https://{DOMAIN}",
    access_token_url=f"https://{DOMAIN}/oauth/token",
    authorize_url=f"https://{DOMAIN}/authorize",
    client_kwargs={"scope": "openid profile email"},
)


# ----------------------------------------------------------------------------
# JWT/AUTHENTICATION FUNCTIONS
# ----------------------------------------------------------------------------


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


# ----------------------------------------------------------------------------
# ROOT ENDPOINT
# ----------------------------------------------------------------------------


@app.route("/")
def index():
    return "Please provide a resource path to use the API."


# ----------------------------------------------------------------------------
# USER ENDPOINTS
# ----------------------------------------------------------------------------


@app.route("/users/login", methods=["POST"])
def user_login() -> tuple[dict, int]:
    """Return a JWT for a single user."""
    content = request.get_json()

    # If the request is missing any required fields
    valid_request = verify_request_body(content, USER_FIELDS)
    if not valid_request:
        return {"Error": "The request body is invalid"}, 400

    # If there is an error fetching the token
    response = get_user_jwt(content).json()
    if "error" in response:
        return {"Error": "Unauthorized"}, 401

    token = response.get("id_token")
    return {"token": token}, 200


@app.route("/users", methods=["GET"])
def get_all_users() -> tuple[dict, int] | tuple[list, int]:
    """Return summary information for all users."""
    try:
        payload = verify_jwt()
    except AuthError:
        return {"Error": "Unauthorized"}, 401

    # Only return information if the user is an admin
    is_admin = verify_user_role(payload, "admin")
    if not is_admin:
        return {"Error": "You don't have permission on this resource"}, 403

    return fetch_users(), 200


def fetch_users() -> list[dict]:
    """Return a list of all users in the database."""
    query = client.query(kind="users")
    results = list(query.fetch())

    for r in results:
        r["id"] = r.key.id
        r.pop("avatar_url", None)
        r.pop("file_name", None)

    return results


@app.route("/users/<int:user_id>", methods=["GET"])
def get_user(user_id: int) -> tuple[dict, int] | tuple[list, int]:
    """Return detailed information for a single user."""
    try:
        payload = verify_jwt()
    except AuthError:
        return {"Error": "Unauthorized"}, 401

    # If the id does not exist in the database
    user = fetch_user_by_id(user_id)
    if not user:
        return {"Error": "You don't have permission on this resource"}, 403

    # If the user is an admin, simply return summary information
    is_admin = verify_user_role(payload, "admin")
    user["id"] = user.key.id
    if is_admin:
        return user, 200

    # If the user is not an admin, they can only access their own information
    if payload.get("sub", "") != user.get("sub", ""):
        return {"Error": "You don't have permission on this resource"}, 403

    # If the user is a student, return a list of courses they are enrolled in
    # If the user is an instructor, return a list of courses they teach
    kind, filter_id = get_kind_and_filter_id(user.get("role", ""))
    user["courses"] = build_course_list(kind, filter_id, user_id)
    user.pop("file_name", None)

    return user, 200


def get_kind_and_filter_id(user_role: str) -> tuple[str, str]:
    """Return the kind and filter ID based on the user's role."""
    if user_role == "student":
        kind = "course_students"
        filter_id = "student_id"
    else:
        kind = "courses"
        filter_id = "instructor_id"

    return kind, filter_id


# ----------------------------------------------------------------------------
# AVATAR ENDPOINTS
# ----------------------------------------------------------------------------


@app.route("/users/<int:user_id>/avatar", methods=["POST", "GET", "DELETE"])
def avatar(
    user_id: int,
) -> tuple[dict, int] | tuple[str, int] | tuple[requests.Response, int] | None:
    """Upload or return an avatar for a single user based on the request type."""
    # Verify the JWT
    try:
        payload = verify_jwt()
    except AuthError:
        return {"Error": "Unauthorized"}, 401

    # If the user does not exist
    user = fetch_user_by_id(user_id)
    if not user:
        return {"Error": "You don't have permission on this resource"}, 403

    # User can only delete/access their own information
    if payload.get("sub", "") != user.get("sub", ""):
        return {"Error": "You don't have permission on this resource"}, 403

    if request.method == "GET":
        return get_avatar(user)

    if request.method == "POST":
        return upload_avatar(user_id, user)

    if request.method == "DELETE":
        return delete_avatar(user)

    return None


def get_avatar(
    user: dict[str, Any],
) -> tuple[dict, int] | tuple[requests.Response, int]:
    """Return an avatar for a single user."""
    if user.get("avatar_url", None) is None:
        return {"Error": "Not found"}, 404
    file = get_avatar_from_bucket(user.get("file_name", ""))
    return file, 200


def get_avatar_from_bucket(file_name: str):
    """Get a file from Google cloud bucket."""
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(BUCKET)

    blob = bucket.blob(file_name)
    file_obj = io.BytesIO()
    blob.download_to_file(file_obj)

    file_obj.seek(0)

    return send_file(file_obj, mimetype="image/png")


def upload_avatar(user_id: int, user: Entity) -> tuple[dict, int]:
    """Upload an avatar for a single user."""
    storage_client = storage.Client(project="assignment-6-tarpaulin-479819")
    bucket = storage_client.get_bucket(BUCKET)

    # If no file was provided
    file_obj = request.files.get("file", None)
    if file_obj is None:
        return {"Error": "The request body is invalid"}, 400

    blob = bucket.blob(file_obj.filename)
    file_obj.seek(0)
    blob.upload_from_file(file_obj)

    avatar_url = f"{GURL}/users/{str(user_id)}/avatar"

    user.update({"avatar_url": avatar_url, "file_name": file_obj.filename})
    client.put(user)

    return {"avatar_url": avatar_url}, 200


def delete_avatar(user: Entity) -> tuple[dict, int] | tuple[str, int]:
    """Delete the avatar for a single user"""
    if user.get("avatar_url", None) is None:
        return {"Error": "Not found"}, 404
    delete_avatar_from_bucket(user.get("file_name", ""))
    remove_avatar_url(user)
    return "", 204


def delete_avatar_from_bucket(file_name: str) -> None:
    """Helper function to delete a file from Google cloud bucket."""
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(BUCKET)
    blob = bucket.blob(file_name)
    blob.delete()


def remove_avatar_url(user: Entity) -> None:
    """Helper function to delete avatar_url property"""
    del user["avatar_url"]
    client.put(user)


# ----------------------------------------------------------------------------
# COURSE ENDPOINTS
# ----------------------------------------------------------------------------


@app.route("/courses", methods=["POST", "GET"])
def courses() -> tuple[dict, int] | None:
    """Create a course or return all courses depending on the request type."""
    if request.method == "GET":
        return get_all_courses()

    # Verify the JWT
    try:
        payload = verify_jwt()
    except AuthError:
        return {"Error": "Unauthorized"}, 401

    # Only admin can create courses
    is_admin = verify_user_role(payload, "admin")
    if not is_admin:
        return {"Error": "You don't have permission on this resource"}, 403

    if request.method == "POST":
        return create_course(request)

    return None


def get_all_courses() -> tuple[dict, int]:
    """Return all courses using pagination."""
    offset = int(request.args.get("offset", 0))
    limit = int(request.args.get("limit", 3))

    # Get the requested page of data
    query = client.query(kind="courses")
    query.order = ["subject"]
    l_iterator = query.fetch(limit=limit, offset=offset)
    pages = l_iterator.pages
    results = list(next(pages))

    # Create and return the response
    course_list = create_course_list(results)
    return {"courses": course_list, "next": f"{GURL}/courses?limit=3&offset=3"}, 200


def create_course_list(courses: list[Entity]) -> list[dict]:
    """"""
    course_list = []
    for course in courses:
        course["id"] = (course.key.id,)
        course["self"] = f"{GURL}/courses/{str(course.key.id)}"
        course_list.append(course)
    return course_list


def create_course(request) -> tuple[dict, int]:
    """Create a single course."""
    # Ensure all required fields were provided
    content = request.get_json()
    valid_request = verify_request_body(content, COURSE_FIELDS)
    if not valid_request:
        return {"Error": "The request body is invalid"}, 400

    # If the user tries to assign the course to an instructor that does not exist
    user = fetch_user_by_id(content.get("instructor_id"))
    if not user:
        return {"Error": "The request body is invalid"}, 400

    # If the user tries to assign the course to a user that is not an instructor
    if user.get("role", "") != "instructor":
        return {"Error": "The request body is invalid"}, 400

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


@app.route("/courses/<int:course_id>", methods=["GET", "PATCH", "DELETE"])
def course_by_id(course_id: int) -> tuple[dict, int] | tuple[str, int] | None:
    """Return or update a single course depending on the request type"""
    if request.method == "GET":
        return get_course(course_id)

    # Verify the JWT
    try:
        payload = verify_jwt()
    except AuthError:
        return {"Error": "Unauthorized"}, 401

    # If the course does not exist
    if not fetch_course(course_id):
        return {"Error": "You don't have permission on this resource"}, 403

    # Only admins can update/delete courses
    is_admin = verify_user_role(payload, "admin")
    if not is_admin:
        return {"Error": "You don't have permission on this resource"}, 403

    if request.method == "PATCH":
        return update_course(course_id)

    if request.method == "DELETE":
        return delete_course(course_id)

    return None


def get_course(course_id: int) -> tuple[dict, int]:
    """Return a single course"""
    course = fetch_course(course_id)
    if not course:
        return {"Error": "Not found"}, 404
    course["id"] = course.key.id
    course["self"] = f"{GURL}/courses/{course['id']}"
    return course, 200


def update_course(course_id: int) -> tuple[dict, int]:
    """Update a single course"""
    content = request.get_json()

    # If the user tries to update a course with an instructor that does not exist
    if "instructor_id" in content:
        instructor = fetch_user_by_id(content.get("instructor_id", ""))

        # If the user tries to update a course with a user that is not an instructor
        if instructor.get("role", "") != "instructor":
            return {"Error": "You don't have permission on this resource"}, 400

    course = update_course_in_datastore(course_id, content)

    return course, 200


def update_course_in_datastore(
    course_id: int, content: dict[str, Any]
) -> dict[str, Any]:
    """Update the course in Datastore."""
    course = fetch_course(course_id)
    for key, value in content.items():
        course[key] = value
    client.put(course)
    course["id"] = course.key.id
    course["self"] = f"{GURL}/courses/{course['id']}"
    return course


def delete_course(course_id: int) -> tuple[str, int]:
    """Delete a single course."""
    # Delete enrollment for students in course
    delete_student_enrollment(course_id)
    course = fetch_course(course_id)
    client.delete(course.key)
    return "", 204


def delete_student_enrollment(course_id: int) -> None:
    students = query_students(course_id)
    for student in students:
        query = client.query(kind="course_students")
        query.add_filter("student_id", "=", student.key.id)
        query.add_filer("course_id", "=", course_id)
        results = list(query.fetch())
        for r in results:
            client.delete(r.key)


# ----------------------------------------------------------------------------
# ENROLLMENT ENDPOINTS
# ----------------------------------------------------------------------------


@app.route("/courses/<int:course_id>/students", methods=["PUT", "GET"])
def course_students(course_id) -> None | tuple[dict[str, str], int] | tuple[list, int]:
    """
    Update the enrollment of student(s) or return all students for a single course
    depending on the request type.
    """
    # Verify the JWT
    try:
        payload = verify_jwt()
    except AuthError:
        return {"Error": "Unauthorized"}, 401

    # If the course does not exist
    course = fetch_course(course_id)
    if not course:
        return {"Error": "You don't have permission on this resource"}, 403

    # Only an admin or the instructor of the course can see student enrollment
    if not is_admin_or_instructor(payload, course.get("instructor_id", "")):
        return {"Error": "You don't have permission on this resource"}, 403

    if request.method == "PUT":
        return update_enrollment(request, course_id)

    if request.method == "GET":
        return get_all_students(course_id)

    return None


def is_admin_or_instructor(payload: dict[str, Any], user_id: str) -> bool:
    """Return true if the user is either an admin or the course instructor."""
    is_admin = verify_user_role(payload, "admin")
    instructor = fetch_user_by_sub(payload.get("sub", ""))
    is_instructor = True if int(instructor.key.id) == int(user_id) else False
    return True if is_instructor or is_admin else False


def update_enrollment(request, course_id: int):
    """Update students' enrollment in a single course."""
    content = request.get_json()
    students_to_add = content.get("add", [])
    students_to_remove = content.get("remove", [])

    # If there is a student(s) that are in both lists
    overlap = set(students_to_add) & set(students_to_remove)
    if overlap:
        return {"Error": "Enrollment data is invalid"}, 409

    # Create a set of all students in the enrolled in the course
    results = query_students(course_id)
    enrolled_students = {entity["student_id"] for entity in results}

    # Check if both lists are valid
    add_list_valid = is_valid_list(students_to_add)
    remove_list_valid = is_valid_list(students_to_remove)

    if add_list_valid and remove_list_valid:
        enroll_students(students_to_add, course_id, enrolled_students)
        remove_students(students_to_remove, course_id, enrolled_students)
        return "", 200

    return {"Error": "Enrollment data is invalid"}, 409


def is_valid_list(student_list: list[int]):
    for student in student_list:
        # If the user they are trying to add is not a student
        user = fetch_user_by_id(student)
        if user.get("role", "") != "student":
            return False
    return True


def enroll_students(
    students_to_add: list,
    course_id: int,
    enrolled: set[Entity],
) -> None:
    """Enroll all students in the list"""
    for student in students_to_add:
        # If the student is already enrolled, skip them
        if student in enrolled:
            continue

        new_key = client.key("course_students")
        new_student = datastore.Entity(key=new_key)
        new_student.update(
            {
                "student_id": student,
                "course_id": course_id,
            }
        )
        client.put(new_student)


def remove_students(
    students_to_remove: list, course_id: int, enrolled: set[Entity]
) -> None:
    """Remove all students in the list."""
    for student in students_to_remove:
        # If the student is not enrolled in the course, skip them
        if student not in enrolled:
            continue

        query = client.query(kind="course_students")
        query.add_filter("student_id", "=", student)
        query.add_filer("course_id", "=", course_id)
        results = list(query.fetch())
        for r in results:
            client.delete(r.key)


def get_all_students(course_id: int) -> tuple[list, int]:
    """Return all students enrolled in a single course"""
    results = query_students(course_id)
    student_list = create_student_list(results)
    return student_list, 200


def create_student_list(students: list[dict]) -> list[int]:
    """Return a list of student IDs for all students enrolled in the course."""
    student_list = []
    for student in students:
        student_list.append(student.get("student_id", ""))
    return student_list


def query_students(course_id: int) -> list[Entity]:
    """Return a list of students enrolled in the course"""
    query = client.query(kind="course_students")
    query.add_filter("course_id", "=", course_id)
    results = list(query.fetch())
    return results


# ----------------------------------------------------------------------------
# HELPER FUNCTIONS
# ----------------------------------------------------------------------------


def verify_request_body(body: dict[str, Any], fields: list[str]) -> bool:
    """Verify that an incoming request contains the required fields."""
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


def fetch_user_by_id(user_id: int) -> Entity | None:
    """Retrieve a user using their user ID."""
    user_key = client.key("users", user_id)
    user = client.get(key=user_key)
    user["id"] = user.key.id
    if not user:
        return None
    return user


def fetch_user_by_sub(sub: str) -> Entity | None:
    """Retrieve a user using their sub."""
    query = client.query(kind="users")
    query.add_filter("sub", "=", sub)
    user = next(query.fetch(), None)
    user["id"] = user.key.id
    if not user:
        return None
    return user


def build_course_list(kind: str, filter_id: str, user_id: int) -> list[str]:
    """Build a list of course URLs to be sent to the client."""
    query = client.query(kind=kind)
    query.add_filter(filter_id, "=", user_id)

    courses = list(query.fetch())
    return [f"{GURL}/courses/{course.get('id', '')}" for course in courses]


def fetch_course(course_id: int) -> Entity | None:
    """Retrieve a course by its ID."""
    course_key = client.key("courses", course_id)
    course = client.get(key=course_key)
    if not course:
        return None
    return course


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)
