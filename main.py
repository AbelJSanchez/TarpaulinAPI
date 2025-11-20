import requests
import json

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


def _valid_request():
    pass


def _handle_auth_error():
    pass


def _verify_jwt():
    pass


@app.route('/')
def index():
    pass


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
