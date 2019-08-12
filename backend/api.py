#!/usr/bin/env python3

import jwt
import datetime

from config import Configuration
from wrappers import is_admin, requires_admin, not_admin

from copy import deepcopy
from flask import render_template, request, redirect, flash, url_for, Blueprint, send_from_directory
from functools import wraps
from flask_login import login_required, current_user

key_template = {
    "user": "",
    "date_generated": "",
    "key_id": 0,
    "name": ""
}

api_api = Blueprint('api_api', __name__)


# Decorator that determines if a user is allowd to use the API
def allowed_api(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        crt_user = current_user.get_id()
        user_entry = Configuration.users.find_one({"username": crt_user})  # TODO make a try except. Check for none

        # Check if user is authorised to use an API
        try:
            if user_entry["allow_api"] is not True:
                flash("Forbidden!")
                Configuration.logger.warning("User '%s' tried accessing %s without being API allowed" %
                                             (crt_user, request.base_url))
                return redirect(url_for('api_api.main_api'))
        except KeyError:
            Configuration.logger.error("User entry does not contain 'allow_api' key: %s" % user_entry)
            flash("Server error!")
            return redirect(url_for('api_api.main_api'))

        kwargs["user_entry"] = user_entry
        return f(*args, **kwargs)
    return decorated_function


# Decorator that checks the validity of a API key sent
def require_key(f):
    @wraps(f)
    def require_key_decorator(*args, **kwargs):
        api_key = request.form.get("apikey", None)

        if api_key is None:
            return {"success": False, "reason": "Api key missing!"}

        try:
            decoded_api_key = jwt_decode(api_key, Configuration.api_secret_key)
        except jwt.exceptions.InvalidSignatureError:
            return {"success": False, "reason": "Invalid API key!"}

        user_entry = Configuration.users.find_one({"username": decoded_api_key["user"]})  # TODO make a try except. Check for none

        try:
            if api_key not in user_entry["api_keys"] or user_entry["allow_api"] is not True:
                return {"success": False, "reason": "Forbidden, invalid or expired API key!"}
        except KeyError:
            Configuration.logger.warning("User entry does not contain 'api_keys' or 'allow_api' key: %s" % user_entry)

        kwargs["user_entry"] = user_entry
        return f(*args, **kwargs)
    return require_key_decorator


# Helper funtion that returns a dictionary from a utf-8 encoded jwt
def jwt_decode(token, api_key):
    return jwt.decode(token.encode("utf-8"), api_key)


# Helper funtion that create a jwt token from a dictionary then encodes it in utf8
def jwt_encode(dic, api_key):
    return jwt.encode(dic, api_key, algorithm='HS512').decode("utf-8")


@api_api.route('/api/', methods=['GET'])
@login_required
@not_admin
def main_api():
    user_entry = Configuration.users.find_one({"username": current_user.get_id()})  # TODO make a try except. Check for none

    api_keys = []
    try:
        for key in user_entry["api_keys"]:
            entry = dict()

            entry["key"] = key

            # The jwt comes from the database, no need to check for validity
            values = jwt_decode(entry["key"], Configuration.api_secret_key)
            entry["name"] = values["name"]
            entry["date_generated"] = datetime.datetime.strptime(values["date_generated"], '%Y-%m-%dT%H:%M:%S.%f')\
                .strftime('%H:%M - %d.%m.%Y')

            api_keys.append(entry)
    except KeyError:
        Configuration.logger.warning("User entry does not contain 'api_keys' key: %s" % user_entry)

    return render_template('api.html', logged_in=True, api_keys=api_keys)


@api_api.route('/api/autoupload.py', methods=['GET'])
@login_required
@not_admin
def send_autoupload():
    return send_from_directory(api_api.static_folder, "autoupload.py")


@api_api.route('/api/generate-key/', methods=['POST'])
@login_required
@not_admin
@allowed_api
def generate_key(_, **kwargs):
    api_key = deepcopy(key_template)

    try:
        user_entry = kwargs["user_entry"]
        crt_user = user_entry["username"]
    except KeyError:
        flash("Server error!")
        Configuration.logger.error("Expected attribute 'user_entry' missing from decorator. Got: %s" % kwargs)
        return redirect(url_for('api_api.main_api'))

    try:
        new_id = str(1000 + len(user_entry["api_keys"]))
    except KeyError:
        Configuration.logger.error("User entry does not contain 'api_keys' key: %s" % user_entry)
        flash("Server error!")
        return redirect(url_for('api_api.main_api'))

    # Generate key from user + date_generated + key id + name
    api_key["user"] = crt_user
    api_key["date_generated"] = datetime.datetime.now().isoformat()
    api_key["key_id"] = new_id
    api_key["name"] = request.form.get("keyname", "unnamed")

    user_entry["api_keys"].append(jwt_encode(api_key, Configuration.api_secret_key))

    # TODO make a try except
    Configuration.users.update_one({"username": crt_user}, {"$set": user_entry})
    flash("API key generated successfully!", category='success')

    return redirect(url_for('api_api.main_api'))


@api_api.route('/api/v1/getwork', methods=['POST'])
@require_key
def getwork_v1(_, **kwargs):
    return {"success": True}


@api_api.route('/api/v1/pausework', methods=['POST'])
@require_key
def pausework_v1(_, **kwargs):
    return {"success": True}


@api_api.route('/api/v1/stopwork', methods=['POST'])
@require_key
def stopwork_v1(_, **kwargs):
    return {"success": True}


@api_api.route('/api/v1/sendeta', methods=['POST'])
@require_key
def sendeta_v1(_, **kwargs):
    return {"success": True}


@api_api.route('/api/v1/sendresult', methods=['POST'])
@require_key
def sendresult_v1(_, **kwargs):
    return {"success": True}
