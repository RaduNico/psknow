#!/usr/bin/env python3

import os
import logging
import random
import string
import datetime
import tempfile
import inspect
import sys

from copy import deepcopy

from werkzeug.exceptions import abort

from config import Configuration
from process import Process
from user import User

from flask import Flask, render_template, request, redirect, flash, url_for
from functools import wraps
from werkzeug.utils import secure_filename
from flask_login import LoginManager, login_user, logout_user, login_required, current_user


application = Flask(__name__)


login_manager = LoginManager()
login_manager.init_app(application)
login_manager.login_view = 'login'


def die(condition, message):
    if condition:
        Configuration.logger.critical("line %s in function %s, error %s" %
                                      (inspect.currentframe().f_back.f_lineno, inspect.stack()[1][3], message))
        sys.exit(-1)


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


def is_admin(user):
    return user is not None and user.is_authenticated and user.get_id() == Configuration.admin_account


def requires_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if is_admin(current_user):
            return f(*args, **kwargs)
        return redirect(url_for("home"))

    return decorated_function


def not_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_admin(current_user):
            return f(*args, **kwargs)

        flash("Not permitted for admin account!")
        return redirect(url_for("home"))

    return decorated_function


def get_cracked_tuple(handshake, document):
    ssid = handshake["SSID"]
    mac = handshake["MAC"]
    hs_type = handshake["handshake_type"]
    date_added = document["date_added"].strftime('%H:%M - %d.%m.%Y')
    crack_level = handshake["crack_level"]

    password = handshake["password"]
    date = handshake["date_cracked"].strftime('%H:%M - %d.%m.%Y')
    raw_date = handshake["date_cracked"]

    return ssid, mac, hs_type, date_added, crack_level, password, date, raw_date


def get_uncracked_tuple(handshake, document):
    ssid = handshake["SSID"]
    mac = handshake["MAC"]
    hs_type = handshake["handshake_type"]
    date_added = document["date_added"].strftime('%H:%M - %d.%m.%Y')
    if handshake["active"]:
        next_rule = Configuration.get_next_rule(handshake["crack_level"])
        crack_level = "%d -> %d" % \
                      (handshake["crack_level"], next_rule["priority"])
        eta = handshake["eta"]
    else:
        crack_level = handshake["crack_level"]
        eta = ""

    return ssid, mac, hs_type, date_added, crack_level, eta


@application.route('/admin/', methods=['GET', 'POST'])
@requires_admin
def admin_panel():
    if request.method == 'GET':
        if check_db_conn() is None:
            flash("DATABASE IS DOWN!")
            return render_template('admin.html')

        admin_table, error = Configuration.get_admin_table()
        if admin_table is None:
            flash(error)
            return render_template('admin.html')

        workload = int(admin_table["workload"])

        if workload < 1 or workload > 4:
            workload = 2
            flash("Workload returned by database is not within bounds! Corrected to value 2.")
            Configuration.logger.error("Workload returned by database is not within bounds! Corrected to value 2.")

        return render_template('admin.html', workload=workload)

    elif request.method == 'POST':
        workload = int(request.form.get("workload", None))
        force = False if request.form.get("force_checkbox", None) is None else True

        update = {"workload": workload, "force": force}

        flash("Workload = '%s', force = '%s'" % (workload, force), category='success')

        Configuration.set_admin_table(update)

        return render_template('admin.html', workload=workload)
    else:
        Configuration.logger.error("Unsupported method!")
        abort(404)


@application.route('/', methods=['GET'])
def home():
    if is_admin(current_user):
        if check_db_conn() is None:
            flash("DATABASE IS DOWN")
            return render_template('admin_home.html')

        # Dictionary with key=<user>, value=[<handshake>]
        user_handshakes = {}

        try:
            all_files = Configuration.wifis.find({}).sort([("date_added", 1)])
            Configuration.logger.info("Retrieved all user data for admin display.")
        except Exception as e:
            Configuration.logger.error("Database error at retrieving all user data %s" % e)
            flash("Database error at retrieving all user data %s" % e)
            return render_template('admin_home.html')

        for file_structure in all_files:
            crt_user = file_structure["user"]
            if crt_user not in user_handshakes:
                user_handshakes[crt_user] = [[], []]

            for handshake in sorted(file_structure["handshakes"], key=lambda k: k['SSID']):
                if handshake["password"] == "":
                    user_handshakes[crt_user][0].append(get_uncracked_tuple(handshake, file_structure))
                else:
                    user_handshakes[crt_user][1].append(get_cracked_tuple(handshake, file_structure))

        # Sort based on crack date and remove trailing raw date
        for entry in user_handshakes.values():
            entry[1] = sorted(entry[1], key=lambda k: k[7])

        # Transform dict to list and sort by username
        user_handshakes = sorted(user_handshakes.items(), key=lambda k: k[0])

        return render_template('admin_home.html', user_handshakes=user_handshakes)

    logged_in = current_user.is_authenticated
    if logged_in and check_db_conn() is None:
        flash("Database error!")
        return render_template('home.html', logged_in=True)

    uncracked = []
    cracked = []
    if logged_in:
        # Sort in mongo by the time the handshake was added
        for file_structure in Configuration.wifis.find({"user": current_user.get_id()}).sort([("date_added", 1)]):
            # Sort in python by the SSID
            for handshake in sorted(file_structure["handshakes"], key=lambda k: k['SSID']):
                if handshake["password"] == "":
                    uncracked.append(get_uncracked_tuple(handshake, file_structure))
                else:
                    cracked.append(get_cracked_tuple(handshake, file_structure))

    # Sort based on crack date and remove trailing raw date
    cracked = sorted(cracked, key=lambda k: k[7])

    return render_template('home.html', uncracked=uncracked, cracked=cracked, logged_in=logged_in)


def get_rule_tuple(rule):
    try:
        priority = rule["priority"]
        name = rule["name"]
    except KeyError:
        Configuration.logger.error("Error! Malformed rule %s" % rule)
        return None

    examples = ""
    desc = ""
    link = ""
    try:
        desc = rule["desc"]
        link = rule["link"]
        for example in rule["examples"]:
            examples += example + " "

        if len(examples) > 0:
            examples = examples[:-1]
    except KeyError:
        pass

    return priority, name, desc, examples, link


@application.route('/statuses/', methods=['GET'])
@login_required
def statuses():
    status_list = []

    for rule in Configuration.get_active_rules():
        status_list.append(get_rule_tuple(rule))

    return render_template('statuses.html', statuses=status_list)


@application.route('/login/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash("User is already authenticated!")
        return redirect(url_for("home"))

    if request.method == 'GET':
        return render_template('login.html')

    if request.method == 'POST':
        username = request.form.get("username", None)
        password = request.form.get("password", None)

        if username is None or len(username) == 0:
            flash("No username introduced!")
            return redirect(request.url)

        if password is None or len(password) == 0:
            flash("No password introduced!")
            return redirect(request.url)

        Configuration.logger.info("Login attempt from username = '%s'" % username)

        if not User.check_credentials(username, password):
            flash("Incorrect username/password!")
            return redirect(request.url)

        login_user(User(username))

        return redirect(url_for("home"))


@application.route("/register/", methods=["GET", "POST"])
def register():
    if request.method == 'GET':
        if current_user.is_authenticated:
            flash("You are already have an account")
            return redirect(url_for("home"))
        return render_template('register.html')

    if request.method == "POST":
        username = request.form.get("username", None)
        password = request.form.get("password", None)

        if username is None or len(username) == 0:
            flash("No username introduced!")
            return redirect(request.url)

        if password is None or len(password) == 0:
            flash("No password introduced!")
            return redirect(request.url)

        if len(password) < 6:
            flash("C'mon... use at least 6 characters... pretty please?")
            return redirect(request.url)

        if Configuration.username_regex.search(username) is None:
            flash("Username should start with a letter and only contain alphanumeric or '-._' characters!")
            return redirect(request.url)

        if len(username) > 150 or len(password) > 150:
            flash("Either the username or the password is waaaaay too long. Please dont.")
            return redirect(request.url)

        retval = User.create_user(username, password)

        if retval is None:
            return redirect(url_for("home"))

        flash(retval)
        return redirect(request.url)


@application.route('/logout/', methods=["GET"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


@application.route('/css/navbar.css', methods=["GET"])
def send_navbar():
    return application.send_static_file("navbar.css")


@application.route('/css/log_reg.css', methods=["GET"])
def send_logreg():
    return application.send_static_file("log_reg.css")


@application.route('/dict', methods=["GET"])
def send_dict():
    dict_name = request.args.get("dict")
    if dict_name is None or dict_name == "" or dict_name not in Configuration.dictionary_names:
        flash("Bad dictionary request!")
        Configuration.logger.warning("Bad dictionary request at link %s" % request.args.get("dict"))
        return redirect(url_for("statuses"))

    return application.send_static_file(dict_name)


def check_db_conn():
    try:
        info = Configuration.check_db_conn()
    except Exception as e:
        Configuration.logger.critical("Database is down with reason %s!" % e)
        return None

    return info


def get_random_string(length):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))


def valid_filename(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Configuration.accepted_extensions


def append_number_beforeext(filename, number):
    position = filename.rfind('.')
    return filename[:position] + str(number) + filename[position:]


def get_unique_id():
    unique_id = get_random_string(Configuration.id_length)
    while len(list(Configuration.wifis.find({"id": unique_id}))) > 0:
        unique_id = get_random_string(25)
    return unique_id


def get_unique_filename_path(raw_filename):
    orig_fname = secure_filename(raw_filename)

    full_path = os.path.join(Configuration.save_file_location, orig_fname)
    number = 0
    position = orig_fname.rfind('.')
    new_filename = orig_fname
    while True:
        try:
            os.close(os.open(full_path, os.O_EXCL | os.O_CREAT, 0o644))
            break
        except FileExistsError:
            number = number + 1
            new_filename = orig_fname[:position] + "_" + str(number).rjust(4, '0') + orig_fname[position:]
            full_path = os.path.join(Configuration.save_file_location, new_filename)

    return new_filename, full_path


def get_hccapx_file(attack_type, filepath):
    _, temp_filename = tempfile.mkstemp(prefix="psknow_backend")

    # Memorize name so we can later delete it
    flag = ""
    if attack_type == "PMKID":
        flag = "-z"
    elif attack_type == "WPA":
        flag = "-o"
    else:
        die(True, "Unsupported attack type %s" % attack_type)

    # Conversion to hccapx
    die(not os.path.isfile(filepath), "File %s does not exist!" % filepath)
    stdout = Process(["hcxpcaptool", flag, temp_filename, filepath], crit=True).stdout()

    if "written to" not in stdout:
        os.remove(temp_filename)
        return None

    return temp_filename


def duplicate_lookup(mac, ssid):
    try:
        duplicates = Configuration.wifis.find({"handshakes.SSID": ssid, "handshakes.MAC": mac})
        Configuration.logger.info("Duplication lookup for '%s-%s'" % (ssid, mac))
    except Exception as e:
        Configuration.logger.error(
            "Database error at retrieving duplication for '%s-%s' %s" % (ssid, mac, e))
        flash("Server error at duplication data.")
        return None, True

    # TODO allow PMKID if only a handshake exists
    if len(list(duplicates)) > 0:
        flash("A PMKID/handshake for pair MAC-SSID: '%s-%s' already exists!" % (mac, ssid), category='warning')
        return True, False

    return False, False


# TODO change this to proper file type check - use file or directly detect magic numbers
def check_handshake(file_path, filename):
    entry_values = dict()
    entry_values["handshakes"] = []

    duplicate_pair = set()
    duplicate_flag = False

    # We add: file_type, handshake[SSID, MAC, open, handshake_type]
    # We will add later: handshake[crack_level, password, date_cracked]
    if filename.endswith(".16800"):
        entry_values["file_type"] = "16800"

        with open(file_path, "r") as file_handler:
            lines = file_handler.readlines()

        if len(lines) < 0:
            flash("Error! File '%s' is empty!" % filename)
            return False, None

        with open(file_path, "w") as file_handler:
            for line in lines:
                matchobj = Configuration.pmkid_regex.match(line)
                if matchobj is None:
                    continue

                file_handler.write(line)
                handshake = deepcopy(Configuration.default_handshake)
                handshake["MAC"] = ":".join(a + b for a, b in zip(matchobj.group(1)[::2], matchobj.group(1)[1::2]))
                handshake["SSID"] = bytearray.fromhex(matchobj.group(2)).decode()
                handshake["handshake_type"] = "PMKID"

                is_duplicate, error = duplicate_lookup(handshake["MAC"], handshake["SSID"])
                if error:
                    return False, None
                if is_duplicate:
                    duplicate_flag = True
                    continue

                entry_values["handshakes"].append(handshake)

    if filename.endswith((".cap", ".pcap", ".pcapng")):
        # We count how many already cracked files we got
        entry_values["file_type"] = filename[filename.rfind('.') + 1:]
        hs_types = ["PMKID", "WPA"]

        # Try for both PMKID and WPA
        for hs_type in hs_types:
            temp_filename = get_hccapx_file(hs_type, file_path)

            if temp_filename is None:
                continue

            crack_type = "-m 16800" if hs_type == "PMKID" else "-m 2500"
            show_command = "hashcat --potfile-path=%s --left %s %s" % \
                           (Configuration.empty_pot_path, crack_type, temp_filename)

            # Test with hashcat if files contain valid data
            to_crack = list(filter(None, Process(show_command, crit=True).stdout().split('\n')))

            for cracked_target in to_crack:
                cracker_obj = Configuration.hashcat_left_regex.match(cracked_target)

                if cracker_obj is None:
                    Configuration.logger.error("REGEX error! Could not match the left line: %s" % cracked_target)
                    continue

                mac = ":".join(a + b for a, b in zip(cracker_obj.group(1)[::2], cracker_obj.group(1)[1::2]))

                # Remove duplicate entries in the same file - filter by MAC
                flag = False
                for hs in entry_values["handshakes"]:
                    if hs["MAC"] == mac:
                        flag = True
                        break
                if flag:
                    continue

                handshake = deepcopy(Configuration.default_handshake)
                handshake["MAC"] = mac
                if hs_type == "PMKID":
                    handshake["SSID"] = bytearray.fromhex(cracker_obj.group(2)).decode()
                    if handshake["SSID"].startswith("$HEX[") and handshake["SSID"].endswith("]"):
                        handshake["SSID"] = handshake["SSID"][5:-1].decode("hex")
                else:
                    handshake["SSID"] = cracker_obj.group(2)
                handshake["handshake_type"] = hs_type

                # Avoid duplicate 'duplicate message' for files with both PMKID and handshakes
                if (handshake["MAC"], handshake["SSID"]) in duplicate_pair:
                    continue

                is_duplicate, error = duplicate_lookup(handshake["MAC"], handshake["SSID"])
                if error:
                    return False, None
                if is_duplicate:
                    duplicate_pair.add((handshake["MAC"], handshake["SSID"]))
                    duplicate_flag = True
                    continue

                entry_values["handshakes"].append(handshake)

            os.remove(temp_filename)

    if len(entry_values["handshakes"]) == 0:
        if not duplicate_flag:
            flash("Error! File '%s' does not contain a valid handshake" % filename)
            return False, None, False
        
        return False, None, True

    return True, entry_values, False


@application.route('/upload/', methods=['GET', 'POST'])
@login_required
@not_admin
def upload_file():
    if request.method == 'GET':
        return render_template('upload.html')

    if request.method == 'POST':
        # Check if database is not down
        if check_db_conn() is None:
            flash("Error 500. Service unavailable!")
            return render_template('upload.html')

        # Check existence of file field
        if 'file' not in request.files:
            Configuration.logger.info("No file uploaded.")
            flash("No file uploaded.")
            return redirect(request.url)

        files = request.files.getlist('file')
        Configuration.logger.info(files)
        # Check for empty filename
        if len(files) == 0:
            Configuration.logger.info("No selected file.")
            flash("No selected file.")
            return redirect(request.url)

        for file in files:
            # Check for valid extension
            filename = file.filename
            if not valid_filename(filename):
                Configuration.logger.info("Invalid file type %s uploaded" % filename[filename.rfind('.'):])
                flash("Invalid file type %s uploaded" % filename[filename.rfind('.'):])
                continue

            # Create tmpfile with unique name
            _, tmp_path = tempfile.mkstemp()
            file.save(tmp_path)

            # Validate handshake and get file type and handshake type
            valid_handshake, extra_info, duplicate_flag = check_handshake(tmp_path, file.filename)

            if duplicate_flag:
                continue

            if not valid_handshake:
                Configuration.logger.info("No valid handshake found in file '%s'" % filename)
                flash("No valid handshake found in file '%s'" % filename)
                continue

            # Generate unique ID for our document
            rando = get_unique_id()

            # Generate a unique filename to permanently save file
            new_filename, file_path = get_unique_filename_path(file.filename)

            new_entry = deepcopy(Configuration.default_wifi)

            new_entry["id"] = rando
            new_entry["date_added"] = datetime.datetime.now()

            # new_entry["location"]["keyword"] = #TODO POST keyword
            # new_entry["location"]["coordinates"] = #TODO POST coordinates

            new_entry["path"] = new_filename
            new_entry["handshakes"] = extra_info["handshakes"]
            new_entry["file_type"] = extra_info["file_type"]
            new_entry["user"] = current_user.get_id()
            new_entry["priority"] = 0

            # Save received file
            try:
                os.rename(tmp_path, file_path)
                Configuration.logger.info("Saved file with id %s at %s" % (rando, file_path))
            except Exception as e:
                Configuration.logger.error("Exception at saving received file at path = %s : %s" % (file_path, e))
                flash("Error saving file '%s'" % filename)
                return redirect(request.url)

            # Insert document in database with all information
            try:
                obj = Configuration.wifis.insert_one(new_entry)
                Configuration.logger.info("Inserted object _id = %s with id = %s" % (obj.inserted_id, rando))
            except Exception as e:
                Configuration.logger.error("Exception at inserting file = %s: %s" % (file_path, e))
                flash("Database error at saving filename %s" % filename)
                return redirect(request.url)

            flash("File '%s' uploaded successfully!" % filename, category='success')
        return redirect(request.url)


if __name__ == "__main__":
    # Manually initialize app
    # TODO check key/file existence and generate one from /dev/random of it does not exist
    with open("secret_key", "r") as sc_fd:
        application.secret_key = "".join(sc_fd.readlines())
    application.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

    Configuration.initialize()
    Configuration.logger = application.logger
    application.run(host='127.0.0.1', port='9645')
else:
    gunicorn_logger = logging.getLogger('gunicorn.error')
    application.logger.handlers = gunicorn_logger.handlers
    application.logger.setLevel(gunicorn_logger.level)
    Configuration.logger = application.logger
