#!/usr/bin/env python3

import jwt
import datetime

from copy import deepcopy

from werkzeug.exceptions import abort

from .config import Configuration
from flask import Flask, render_template, request, redirect, flash, url_for
from functools import wraps
from werkzeug.utils import secure_filename
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from backend import application, not_admin

key_template = {
    "user": "",
    "date_generated": "",
    "key_id": 0,
    "name": ""
}


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


@application.route('/api/', methods=['GET'])
@login_required
@not_admin
def main_api():
    # TODO Render page differently if user is allowed to access API or not
    return render_template('api.html')


@application.route('/api/autoupload.py', methods=['GET'])
@login_required
@not_admin
def send_autoupload():
    return application.send_static_file("autoupload.py")


@application.route('/api/generate-key', methods=['GET'])
@login_required
@not_admin
def generate_key():
    api_key = deepcopy(key_template)

    # TODO make a try except
    user_entry = Configuration.users.find_one({"username": current_user})

    # Check if user is authorised to use an API
    try:
        if user_entry["allow_api"] is not True:
            flash("Forbidden!")
            return redirect(url_for('main_api'))
    except KeyError:
        Configuration.logger.error("User entry does not contain 'allow_api' key: %s" % user_entry)
        flash("Server error!")
        return redirect(url_for('main_api'))

    try:
        new_id = 1000 + len(user_entry["api_keys"])
    except KeyError:
        Configuration.logger.error("User entry does not contain 'api_keys' key: %s" % user_entry)
        flash("Server error!")
        return redirect(url_for('main_api'))

    # Generate key from user + date_generated + key id + name
    api_key["user"] = current_user
    api_key["date_generated"] = datetime.datetime.now()
    api_key["key_id"] = new_id
    api_key["name"] = "muiepula"  # Todo get from user
    enc_api_key = jwt.encode(api_key, application.api_secret_key, algorithm='HS512')

    # TODO make a try except
    user_entry["api_keys"].append({new_id: enc_api_key})
    flash("API key generated successfully!", category='success')

    return redirect(url_for('main_api'))


@application.route('/api/v1/getwork', methods=['GET'])
@login_required
@not_admin
@allowed_api
def getwork_v1():
    return render_template('api.html')

