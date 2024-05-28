#!/usr/bin/python3
""" handle all default RestFul API actions for Users """
from models import storage
from models.user import User
from api.v1.views import app_views
from flask import jsonify, abort, request, make_response
from bcrypt import gensalt, hashpw, checkpw

@app_views.route("/users", methods=["GET"], strict_slashes=False)
def get_all_users():
    """get all users in the database"""
    all_users = storage.all(User).values()
    users_list = []
    for user in all_users:
        users_list.append(user.to_dict())
    return jsonify(users_list)


@app_views.route("/users/<user_id>", methods=["GET"], strict_slashes=False)
def get_user(user_id):
    """ get user by its id """
    user = storage.get(User, user_id)
    if not user:
        abort(404)

    return jsonify(user.to_dict())


@app_views.route("/users/<user_id>", methods=["DELETE"], strict_slashes=False)
def delete_user(user_id):
    """ delete user by its id """
    user = storage.get(User, user_id)
    if not user:
        abort(404)

    storage.delete(user)
    storage.save()
    return make_response(jsonify({"msg": "user deleted successfully"}), 200)


@app_views.route("/signup", methods=["POST"], strict_slashes=False)
def create_user():
    """ create a new user """
    data = request.get_json()
    
    if not request.get_json():
        abort(400, "Not a JSON")

    # handle missing fields
    required = ["username", "email", "password"]
    for key in required:
        if key not in data:
            msg = f"Missing {key}"
            abort(400, description= msg)
    # handle unique values
    if storage.get(User, {"email": data["email"]}):
        abort(400, description="email already registered")
    
    if storage.get(User, {"username": data["username"]}):
        abort(400, description="username already registered")

    # handel empty values 
    if len(data["username"]) < 4:
        abort(400, description= "username must be at least 4 chars")
    if len(data["email"]) < 15:
        abort(400, description= "email must be at least 15, chars")
    if len(data["password"]) < 8:
        abort(400, description= "password must be at least 8, chars")

    # encrypt the password
    salt = gensalt()
    password = data["password"]
    hashed_password = hashpw(password.encode("utf-8"), salt)
    data["password"] = hashed_password

    # create new user
    new_user = User(**data)
    storage.new(new_user)
    storage.save()
    return make_response(jsonify(new_user.to_dict()), 201)


@app_views.route("/signin", methods=["POST"], strict_slashes=False)
def loggin_user():
    """
    (log the user in) by receiving the email or username and password
    and check the database for the existing user with this data
    and then compare the plain text password with the stored hashed password
    """
    data = request.get_json()

    if not data:
        abort(400, "Not a JSON")

    if "email" not in data:
        abort(400, "Missin username or email")
    if "password" not in data:
        abort(400, "Missing password")
    # get user from database 
    user = storage.get(User, {"email": data["email"]})
    if not user:    
        user = storage.get(User, {"username": data["email"]})
        if not user:
            abort(400, "Invalid email or username")

    # compare the password
    hashed_password = user.password
    password = data["password"].encode("utf-8")
    if checkpw(password, hashed_password):
        user.is_loggin = True
        storage.save()
    else:
        abort(400, "Incorrect Password")

    return make_response(jsonify(user.to_dict()), 200)


@app_views.route("/signout/<user_id>", methods=["GET"], strict_slashes=False)
def loggout_user(user_id):
    "log the user out "
    user = storage.get(User, user_id)
    if not user:
        abort(404)
    user.is_loggin = False
    storage.save()

    return make_response(jsonify({"msg": "logged out successfully"}), 200)

@app_views.route("/users/<user_id>", methods=["PATCH"], strict_slashes=False)
def update_user(user_id):
    """ update user by its id """
    user = storage.get(User, user_id)
    if not user:
        abort(404)
    if not request.get_json():
        abort(400, "not a json")
    
    data = request.get_json()
    ignor = ["id", "created_at", "updated_at"]
    allowed_fields = ['username', 'email', 'password']

    for key , value in data.items():
        if key in allowed_fields:
            # handle empty username or unique username
            if key == "username":
                if len(data[key]) < 4:
                    abort(400, description= "username must be at least 4 chars")
                elif storage.get(User, {"username": data[key]}):
                    abort(400, description="username already registered")
                else:
                    setattr(user, key, value)
            # handle empty email or unique email
            if key == "email":
                if len(data[key]) < 15:
                    abort(400, description= "email must be at least 15 chars")
                elif storage.get(User, {"email": data[key]}):
                    abort(400, description="email already registered")
                else:
                    setattr(user, key, value)
            # handle empty password and encrypt the password
            if key == "password":
                if len(key) < 8:
                    abort(400, description= "password must be at least 8 chars")
                salt = gensalt()
                password = data[key]
                hashed_password = hashpw(password.encode("utf-8"), salt)
                value = hashed_password
                setattr(user, key, value)

        elif key in ignor:
            abort(400, "Key Not allowed")
        else:
            abort(400, "Invalid Key")
    storage.save()
    return make_response(jsonify(user.to_dict()), 200)
