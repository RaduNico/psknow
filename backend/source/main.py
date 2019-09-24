#!/usr/bin/env python3

import logging

from .config import Configuration
from .backend import blob_api
from .api import api_api
from .upload import upload_api
from .user import User

from flask import Flask, request, flash, redirect, url_for, send_from_directory
from flask_login import LoginManager

application = Flask("psknow_backend", static_folder='static')
Configuration.application = application
application.register_blueprint(blob_api)
application.register_blueprint(api_api)
application.register_blueprint(upload_api)

login_manager = LoginManager()
login_manager.init_app(application)
login_manager.login_view = 'blob_api.login'


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


@application.route('/css/navbar.css', methods=["GET"])
def send_navbar():
    return send_from_directory(application.static_folder, "navbar.css")


@application.route('/css/log_reg.css', methods=["GET"])
def send_logreg():
    return send_from_directory(application.static_folder, "log_reg.css")


@application.route('/css/table.css', methods=["GET"])
def send_table():
    return send_from_directory(application.static_folder, "table.css")


@application.route('/dict', methods=["GET"])
def send_dict():
    dict_name = request.args.get("dict")
    if dict_name is None or dict_name == "" or dict_name not in Configuration.dictionary_names:
        flash("Bad dictionary request!")
        Configuration.logger.warning("Bad dictionary request at link %s" % request.args.get("dict"))
        return redirect(url_for("statuses"))

    return send_from_directory(application.static_folder, dict_name)


if __name__ == "__main__":
    # Manually initialize app
    application.secret_key = Configuration.get_key_from_file("keys/secret_key")
    application.api_secret_key = Configuration.get_key_from_file("keys/api_secret_key")

    application.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

    Configuration.initialize()
    Configuration.logger = application.logger
    application.run(host='127.0.0.1', port='9645')
else:
    gunicorn_logger = logging.getLogger('gunicorn.error')
    application.logger.handlers = gunicorn_logger.handlers
    application.logger.setLevel(gunicorn_logger.level)
    Configuration.logger = application.logger
