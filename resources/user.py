from flask.views import MethodView
from flask_smorest import Blueprint, abort
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    get_jwt,
    jwt_required,
)
from passlib.hash import pbkdf2_sha256

from db import db
from models import UserModel
from schemas import UserSchema
from blocklist import BLOCKLIST


blp = Blueprint("Users", "users", description="Operations on users")


@blp.route("/register")
class UserRegister(MethodView):
    @blp.arguments(UserSchema)
    def post(self, user_data):
        """
        Register a new user
        ---
        tags:
          - Users
        parameters:
          - in: body
            name: body
            schema:
              id: User
              required:
                - username
                - password
              properties:
                username:
                  type: string
                  description: The username of the new user
                password:
                  type: string
                  description: The password for the new user
        responses:
          201:
            description: User created successfully
          409:
            description: A user with that username already exists
        """
        if UserModel.query.filter(UserModel.username == user_data["username"]).first():
            abort(409, message="A user with that username already exists.")

        user = UserModel(
            username=user_data["username"],
            password=pbkdf2_sha256.hash(user_data["password"]),
        )
        db.session.add(user)
        db.session.commit()

        return {"message": "User created successfully."}, 201


@blp.route("/login")
class UserLogin(MethodView):
    @blp.arguments(UserSchema)
    def post(self, user_data):
        """
        User Login
        ---
        tags:
          - Users
        parameters:
          - in: body
            name: body
            schema:
              id: UserLogin
              required:
                - username
                - password
              properties:
                username:
                  type: string
                  description: The username of the user
                password:
                  type: string
                  description: The password of the user
        responses:
          200:
            description: Login successful
            schema:
              properties:
                access_token:
                  type: string
                  description: JWT access token
                refresh_token:
                  type: string
                  description: JWT refresh token
          401:
            description: Invalid credentials
        """
        user = UserModel.query.filter(
            UserModel.username == user_data["username"]
        ).first()

        if user and pbkdf2_sha256.verify(user_data["password"], user.password):
            access_token = create_access_token(identity=user.id, fresh=True)
            refresh_token = create_refresh_token(user.id)
            return {"access_token": access_token, "refresh_token": refresh_token}, 200

        abort(401, message="Invalid credentials.")


@blp.route("/logout")
class UserLogout(MethodView):
    @jwt_required()
    def post(self):
        """
        User Logout
        ---
        tags:
          - Users
        consumes:
          - application/json
        parameters:
          - in: header
            name: Authorization
            required: true
            description: JWT Authorization header using the Bearer scheme. "
            type: string
        security:
          - bearerAuth: []
        responses:
          200:
            description: Successfully logged out
            schema:
              properties:
                message:
                  type: string
                  description: Logout success message
          401:
            description: Missing or invalid token
        """
        jti = get_jwt()["jti"]
        BLOCKLIST.add(jti)
        return {"message": "Successfully logged out"}, 200


@blp.route("/user/<int:user_id>")
class User(MethodView):
    """
    This resource can be useful when testing our Flask app.
    We may not want to expose it to public users, but for the
    sake of demonstration in this course, it can be useful
    when we are manipulating data regarding the users.
    """

    @blp.response(200, UserSchema)
    def get(self, user_id):
        """
        Get User by ID
        ---
        tags:
          - Users
        parameters:
          - in: path
            name: user_id
            required: true
            description: ID of the user to retrieve
            type: integer
        responses:
          200:
            description: User retrieved successfully
            schema:
              id: User
              properties:
                id:
                  type: integer
                  description: The user ID
                username:
                  type: string
                  description: The username of the user
          404:
            description: User not found
          500:
            description: Server error
        """
        user = UserModel.query.get_or_404(user_id)
        return user

    def delete(self, user_id):
        """
        Delete User by ID
        ---
        tags:
          - Users
        parameters:
          - in: path
            name: user_id
            required: true
            description: ID of the user to delete
            type: integer
        responses:
          200:
            description: User deleted successfully
            schema:
              properties:
                message:
                  type: string
                  description: Deletion success message
          404:
            description: User not found
          500:
            description: Server error
        """
        user = UserModel.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        return {"message": "User deleted."}, 200


@blp.route("/refresh")
class TokenRefresh(MethodView):
    @jwt_required(refresh=True)
    def post(self):
        """
        User Refresh
        ---
        tags:
          - Users
        consumes:
          - application/json
        parameters:
          - in: header
            name: Authorization
            required: true
            description: JWT Authorization header using the Bearer scheme. "
            type: string
        security:
          - bearerAuth: []
        responses:
          200:
            description: Successfully logged out
            schema:
              properties:
                message:
                  type: string
                  description: Logout success message
          401:
            description: Missing or invalid token
        """
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user, fresh=False)
        # Make it clear that when to add the refresh token to the blocklist will depend on the app design
        jti = get_jwt()["jti"]
        BLOCKLIST.add(jti)
        return {"access_token": new_token}, 200