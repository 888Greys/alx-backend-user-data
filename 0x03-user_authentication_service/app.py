#!/usr/bin/env python3
"""
This module contains the implementation of a user authentication
service using Flask.

The service provides endpoints for user registration, login,
logout,
profile retrieval,
password reset token generation, and password update.

Endpoints:
- GET /: Returns a welcome message.
- POST /users: Registers a new user.
- POST /sessions: Logs in a user and creates a session.
- DELETE /sessions: Logs out a user and destroys the session.
- GET /profile: Retrieves the user's profile.
- POST /reset_password: Generates a password reset token for
a user.
- PUT /reset_password: Updates the user's password using a reset
token.

"""

from flask import Flask, jsonify, request, abort, redirect
from auth import Auth

AUTH = Auth()

app = Flask(__name__)


@app.route('/', methods=['GET'])
def index() -> str:
    """
    Returns a welcome message.

    Returns:
        str: Welcome message.
    """
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'])
def users() -> str:
    """
    Registers a new user.

    Returns:
        str: JSON response with the user's email and a success
        message.
    """
    email = request.form.get('email')
    password = request.form.get('password')

    # regsiter user if user does not exist
    try:
        user = AUTH.register_user(email, password)
        return jsonify({"email": user.email, "message": "user created"})
    except Exception:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'])
def login() -> str:
    """
    Logs in a user and creates a session.

    Returns:
        str: JSON response with the user's email and a success message.
    """
    email = request.form.get('email')
    password = request.form.get('password')

    if not (AUTH.valid_login(email, password)):
        abort(401)
    else:
        # create a new session
        session_id = AUTH.create_session(email)
        response = jsonify({"email": email, "message": "logged in"})
        response.set_cookie('session_id', session_id)

    return response


@app.route('/sessions', methods=['DELETE'])
def logout() -> str:
    """
    Logs out a user and destroys the session.

    Returns:
        str: Redirects to the home page.
    """
    session_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)
    if not user:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect('/')


@app.route('/profile', methods=['GET'])
def profile() -> str:
    """
    Retrieves the user's profile.

    Returns:
        str: JSON response with the user's email.
    """
    session_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)
    if user:
        return jsonify({"email": user.email}), 200
    else:
        abort(403)


@app.route('/reset_password', methods=['POST'])
def get_reset_password_token() -> str:
    """
    Generates a password reset token for a user.

    Returns:
        str: JSON response with the user's email and the reset token.
    """
    email = request.form.get('email')
    try:
        reset_token = AUTH.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": reset_token}), 200
    except Exception:
        abort(403)


@app.route('/reset_password', methods=['PUT'])
def update_password() -> str:
    """
    Updates the user's password using a reset token.

    Returns:
        str: JSON response with the user's email and a success message.
    """
    email = request.form.get('email')
    reset_token = request.form.get('reset_token')
    new_password = request.form.get('new_password')
    try:
        AUTH.update_password(reset_token, new_password)
        return jsonify({"email": email, "message": "Password updated"}), 200
    except Exception:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
