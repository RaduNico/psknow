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


def allowed_api(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # user =
        # result = Configuration.users.find({})
        #
        # if not is_admin(current_user):
        #     return f(*args, **kwargs)

        flash("Not permitted for admin account!")
        return redirect(url_for("home"))

    return decorated_function


def jwt_decode(token, api_key):
    return jwt.decode(token.encode("utf-8"), api_key)


def jwt_encode(dic, api_key):
    return jwt.encode(dic, api_key, algorithm='HS512').decode("utf-8")


@api_api.route('/api/', methods=['GET'])
@login_required
@not_admin
def main_api():
    # TODO make a try except
    Configuration.logger.warning(current_user.get_id())

    user_entry = Configuration.users.find_one({"username": current_user.get_id()})

    try:
        allow_api = True if user_entry["allow_api"] is True else False
    except KeyError:
        allow_api = False
        Configuration.logger.warning("User entry does not contain 'allow_api' key: %s" % user_entry)

    api_keys = []
    try:
        for key in user_entry["api_keys"]:
            if len(key) > 1:
                Configuration.logger.error("More than one entry in API dictionary: %s" % key)
                continue

            entry = dict()

            entry["key"] = list(key.values())[0]

            values = jwt_decode(entry["key"], Configuration.api_secret_key)
            entry["name"] = values["name"]
            Configuration.logger.warning(values["date_generated"])   # 2019-08-12T01:35:15.431092
            entry["date_generated"] = datetime.datetime.strptime(values["date_generated"], '%Y-%m-%dT%H:%M:%S.%f')\
                .strftime('%H:%M - %d.%m.%Y')

            api_keys.append(entry)
    except KeyError:
        Configuration.logger.warning("User entry does not contain 'api_keys' key: %s" % user_entry)

    return render_template('api.html', logged_in=True, allow_api=allow_api, api_keys=api_keys)


@api_api.route('/api/autoupload.py', methods=['GET'])
@login_required
@not_admin
def send_autoupload():
    return send_from_directory("autoupload.py")


@api_api.route('/api/generate-key/', methods=['POST'])
@login_required
@not_admin
def generate_key():
    api_key = deepcopy(key_template)

    # TODO make a try except
    crt_user = current_user.get_id()
    user_entry = Configuration.users.find_one({"username": crt_user})

    # Check if user is authorised to use an API
    try:
        if user_entry["allow_api"] is not True:
            flash("Forbidden!")
            return redirect(url_for('api_api.main_api'))
    except KeyError:
        Configuration.logger.error("User entry does not contain 'allow_api' key: %s" % user_entry)
        flash("Server error!")
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

    user_entry["api_keys"].append({new_id: jwt_encode(api_key, Configuration.api_secret_key)})

    # TODO make a try except
    Configuration.users.update_one({"username": crt_user}, {"$set": user_entry})
    flash("API key generated successfully!", category='success')

    return redirect(url_for('api_api.main_api'))


@api_api.route('/api/v1/getwork', methods=['GET'])
@login_required
@not_admin
@allowed_api
def getwork_v1():
    return render_template('api.html')

