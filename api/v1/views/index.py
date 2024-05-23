#!/usr/bin/python3
""" status of my API """
from models.user import User
from models.task import Task
from models import storage
from api.v1.views import app_views
from flask import jsonify



@app_views.route("/status", methods=["GET"], strict_slashes=False)
def status():
    """ Status of API """
    return jsonify({"status": "OK"})


@app_views.route("/stats", methods=["GET"], strict_slashes=False)
def number_objects():
    """ Retrieves the number of each objects by type """
    classes = [User, Task]
    names = ["users", "tasks"]

    num_objs = {}
    for i in range(len(classes)):
        num_objs[names[i]] = storage.count(classes[i])

    return jsonify(num_objs)
