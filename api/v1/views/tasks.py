#!/usr/bin/python3
""" handle all default RestFul API actions for Users """
from models import storage
from models.user import User
from models.task import Task, TaskCategory, TaskPriority, TaskStatus
from api.v1.views import app_views
from flask import jsonify, abort, request, make_response


@app_views.route("/tasks", methods=["GET"], strict_slashes=False)
def get_all_tasks():
    """get all tasks in the database"""
    all_tasks = storage.all(Task).values()
    tasks_list = []
    for task in all_tasks:
        tasks_list.append(task.to_dict())
    return jsonify(tasks_list)


@app_views.route("/tasks/<task_id>", methods=["GET"], strict_slashes=False)
def get_task(task_id):
    """ get task by its id """
    task = storage.get(Task, task_id)
    if not task:
        abort(404)

    return jsonify(task.to_dict())


@app_views.route("/users/<user_id>/tasks", methods=["GET"], strict_slashes=False)
def get_tasks_for_user(user_id):
    """ get all tasks for certain user by its id """
    user = storage.get(User, user_id)
    if not user:
        abort(404)
    user_tasks = user.created_tasks
    tasks_list = []
    for task in user_tasks:
        tasks_list.append(task.to_dict())
    return jsonify(tasks_list)


@app_views.route("/tasks/<task_id>", methods=["DELETE"], strict_slashes=False)
def delete_task(task_id):
    """ delete task by its id """
    task = storage.get(Task, task_id)
    if not task:
        abort(404)

    storage.delete(task)
    storage.save()
    return make_response(jsonify({"msg": "task deleted successfully"}), 200)


@app_views.route("/users/<user_id>/tasks", methods=["POST"], strict_slashes=False)
def create_task(user_id):
    """ create a new task for user """
    user = storage.get(User, user_id)
    if not user:
        abort(404)
    if not request.get_json():
        abort(400, description="Not a JSON")
    if 'title' not in request.get_json():
        abort(400, description="Missing title")
    if 'status' not in request.get_json():
        abort(400, description="Missing status")
    if 'category' not in request.get_json():
        abort(400, description="Missing category")
    if 'priority' not in request.get_json():
        abort(400, description="Missing priority")

    data = request.get_json()
    data['status'] = TaskStatus[data['status'].upper()]
    data['priority'] = TaskPriority[data['priority'].upper()]
    data['category'] = TaskCategory[data['category'].upper()]

    new_task = Task(**data)
    new_task.creator_id = user.id
    storage.new(new_task)
    storage.save()
    return make_response(jsonify(new_task.to_dict()), 201)


@app_views.route("/tasks/<task_id>", methods=["PATCH"], strict_slashes=False)
def update_task(task_id):
    """ update task by its id """
    task = storage.get(Task, task_id)
    if not task:
        abort(404)
    if not request.get_json():
        abort(400, "not a json")
    
    data = request.get_json()
    ignor = ["id", "creator_id", "created_at", "updated_at"]
    allowed_fields = ['title', 'description', 'status', "category", "priority"]

    for key , value in data.items():
        if key in allowed_fields:
            try:
                if key == "status":
                    value = TaskStatus[value.upper()]
                if key == "category":
                    value = TaskCategory[value.upper()]
                if key == "priority":
                    value = TaskPriority[value.upper()]
            except KeyError:
                abort(400, f"Invalid enum value for{KeyError.args[0]}")
            setattr(task, key, value)
        elif key in ignor:
            abort(400, "Key Not allowed")
        else:
            abort(400, "Invalid Key")
    storage.save()
    return make_response(jsonify(task.to_dict()), 200)


@app_views.route("/users/<user_id>/tasks/<task_id>", methods=["PATCH"], strict_slashes=False)
def update_task_for_user(user_id,task_id):
    """ update task by its id for certain user """
    user = storage.get(User, user_id)
    task = storage.get(Task, task_id)

    if not user:
        abort(404)
    if not task:
        abort(404)
    if task.creator_id != user.id:
        abort(404)
    
    if not request.get_json():
        abort(400, "not a json")
    
    data = request.get_json()
    ignor = ["id", "creator_id", "created_at", "updated_at"]
    allowed_fields = ['title', 'description', 'status', "category", "priority"]

    for key , value in data.items():
        if key in allowed_fields:
            try:
                if key == "status":
                    value = TaskStatus[value.upper()]
                if key == "category":
                    value = TaskCategory[value.upper()]
                if key == "priority":
                    value = TaskPriority[value.upper()]
            except KeyError:
                abort(400, f"Invalid enum value for{KeyError.args[0]}")
            setattr(task, key, value)
        elif key in ignor:
            abort(400, "Key Not allowed")
        else:
            abort(400, "Invalid Key")
    storage.save()
    return make_response(jsonify(task.to_dict()), 200)
