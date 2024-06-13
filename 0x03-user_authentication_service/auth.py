#!/usr/bin/env python3
"""
This module contains the Auth class and related functions for
user authentication.

It provides functionality to register users, validate login
credentials, create sessions,
retrieve user information from session IDs, destroy sessions,
generate reset password tokens,
and update passwords.

Classes:
- Auth

Functions:
- _hash_password
- _generate_uuid
"""

import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4

from typing import Union


def _hash_password(password: str) -> str:
    """Hashes the given password using bcrypt.

    Args:
        password (str): The password to be hashed.

    Returns:
        str: The hashed password.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def _generate_uuid() -> str:
    """Generates a UUID (Universally Unique Identifier).

    Returns:
        str: The generated UUID.
    """
    id = uuid4()
    return str(id)


class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        """Initializes an instance of the Auth class."""
        self._db = DB()

    def register_user(self, email: str, password: str) -> Union[None, User]:
        """Registers a new user with the given email and password.

        Args:
            email (str): The email of the user.
            password (str): The password of the user.

        Returns:
            Union[None, User]: The registered User object if successful,
            None otherwise.
        
        Raises:
            ValueError: If the user with the given email already exists.
        """
        try:
            # find the user with the given email
            self._db.find_user_by(email=email)
        except NoResultFound:
            # add user to database
            return self._db.add_user(email, _hash_password(password))

        else:
            # if user already exists, throw error
            raise ValueError('User {} already exists'.format(email))

    def valid_login(self, email: str, password: str) -> bool:
        """Validates the login credentials of a user.

        Args:
            email (str): The email of the user.
            password (str): The password of the user.

        Returns:
            bool: True if the login credentials are valid, False otherwise.
        """
        try:
            # find the user with the given email
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False
        # check validity of password
        return bcrypt.checkpw(password.encode('utf-8'), user.hashed_password)

    def create_session(self, email: str) -> str:
        """Creates a session for the user with the given email.

        Args:
            email (str): The email of the user.

        Returns:
            str: The session ID if successful, None otherwise.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        else:
            user.session_id = _generate_uuid()
            return user.session_id

    def get_user_from_session_id(self, session_id: str) -> User:
        """Retrieves the user information from the given session ID.

        Args:
            session_id (str): The session ID of the user.

        Returns:
            User: The User object if the session ID is valid, None otherwise.
        """
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        else:
            return user

    def destroy_session(self, user_id: str) -> None:
        """Destroys the session of the user with the given ID.

        Args:
            user_id (str): The ID of the user.
        """
        try:
            user = self._db.find_user_by(id=user_id)
        except NoResultFound:
            return None
        else:
            user.session_id = None
            return None

    def get_reset_password_token(self, email: str) -> str:
        """Generates a reset password token for the user with the given email.

        Args:
            email (str): The email of the user.

        Returns:
            str: The reset password token if successful.

        Raises:
            ValueError: If the user with the given email does not exist.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError
        else:
            user.reset_token = _generate_uuid()
            return user.reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates the password of the user with the given reset password token.

        Args:
            reset_token (str): The reset password token.
            password (str): The new password.
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError
        else:
            user.hashed_password = _hash_password(password)
            user.reset_token = None
            return None
