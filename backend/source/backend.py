import os
import random
import string
import subprocess

from werkzeug.exceptions import abort
import json

from werkzeug.utils import secure_filename

from .config import Configuration
from .user import User, enc_bcrypt
from .wrappers import is_admin, requires_admin, check_db_conn, ajax_requires_admin

from flask import render_template, request, redirect, flash, url_for, Blueprint, jsonify, current_app
from flask_login import login_user, logout_user, login_required, current_user

from .database_helper import update_hs_id, lookup_by_id

from .upload import retire_handshake

from flask_mail import Mail, Message

blob_api = Blueprint('blob_api', __name__)


def get_cracked_tuple(document):
    handshake = document["handshake"]
    result = dict()

    result["id"] = document["id"]
    result["ssid"] = handshake["SSID"]
    result["mac"] = handshake["MAC"]
    result["hs_type"] = handshake["handshake_type"]
    result["date_added"] = document["date_added"].strftime('%H:%M - %d.%m.%Y')
    result["cracked_by"] = handshake["cracked_rule"]

    result["password"] = handshake["password"]
    result["date"] = handshake["date_cracked"].strftime('%H:%M - %d.%m.%Y')
    result["raw_date"] = handshake["date_cracked"]

    return result


def get_uncracked_tuple(document):
    handshake = document["handshake"]
    result = dict()

    result["id"] = document["id"]
    result["ssid"] = handshake["SSID"]
    result["mac"] = handshake["MAC"]
    result["hs_type"] = handshake["handshake_type"]
    result["date_added"] = document["date_added"].strftime('%H:%M - %d.%m.%Y')

    if handshake["active"]:
        result["tried_rules"] = "Trying rule %s" % document["reserved"]["tried_rule"]
        result["eta"] = handshake["eta"]
        return result

    try:
        with open('rules') as json_data:
            rules = json.load(json_data)
    except Exception as e:
        Configuration.log_fatal("Error trying to load rules data: %s" % e)

    valid_rules = 0
    for rule in rules:
        valid = False
        for rule_language in rule["languages"]:
            if rule_language == 'none':
                valid_rules = valid_rules + 1
                break
            for hs_language in document["languages"]:
                if hs_language == rule_language:
                    valid_rules = valid_rules + 1
                    valid = True
                    break
            if valid:
                break

    result["tried_rules"] = "%s/%s" % (len(handshake["tried_dicts"]), int(valid_rules))
    result["eta"] = ""

    return result


@blob_api.route('/admin/', methods=['GET', 'POST'])
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


# @blob_api.route('/delete_rule/<name>', methods=['GET'])
# @ajax_requires_admin
# def delete_rule(name):
#     rules = []
#
#     for rule in Configuration.get_active_rules():
#         if rule["name"] == name:
#             Configuration.rule_dict.pop(name, 'No Key found')
#         else:
#             rules.append(rule)
#
#     with open('rules', 'w') as filehandle:
#         json.dump(rules, filehandle, indent=4)
#
#     return render_template('rules.html', rules=rules)


@blob_api.route('/rules/', methods=['GET'])
@requires_admin
def handle_rules():
    return render_template('rules.html', rules=Configuration.get_active_rules())


@blob_api.route('/delete_rule/', methods=['POST'])
@requires_admin
def delete_rule():
    rule_to_delete = request.form.get("rule_to_delete")

    if rule_to_delete in Configuration.rule_dict:
        del Configuration.rule_dict[rule_to_delete]
    else:
        Configuration.logger.info("No key found")

    with open('rules', 'w') as filehandle:
        json.dump(Configuration.get_active_rules(), filehandle, indent=4)

    return redirect(url_for("blob_api.handle_rules"))


@blob_api.route('/edit_rule/<name>', methods=['GET', 'POST'])
@requires_admin
def edit_rule(name):
    rule_to_edit = Configuration.rule_dict[name]
    priorities = []
    names = []

    for rule in Configuration.get_active_rules():
        priorities.append(rule["priority"])
        names.append(rule["name"])

    if request.method == 'GET':
        if check_db_conn() is None:
            flash("DATABASE IS DOWN!")
            return render_template('rules.html', rules=Configuration.get_active_rules())

        if rule_to_edit == {}:
            return render_template('rules.html', rules=Configuration.get_active_rules())
        else:
            return render_template('edit_rule.html', priorities=priorities, names=names, rule=rule_to_edit)
    elif request.method == 'POST':
        new_rule = {"name": request.form.get("name", None), "type": request.form.get("type", None),
                    "priority": int(request.form.get("priority", None)), "path": request.form.get("path", None)}

        if new_rule["type"] == "wordlist" or new_rule["type"] == "filemask_hashcat":
            new_rule["wordsize"] = int(request.form.get("wordsize", None))
        elif new_rule["type"] == "john":
            new_rule["rule"] = request.form.get("rule", None)
            new_rule["wordsize"] = int(request.form.get("wordsize", None))
        elif new_rule["type"] == "generated":
            new_rule["command"] = request.form.get("command", None)
            new_rule["wordsize"] = int(request.form.get("wordsize", None))
        elif new_rule["type"] == "mask_hashcat":
            new_rule["mask_hashcat"] = request.form.get("pattern", None)
            new_rule["wordsize"] = int(request.form.get("wordsize", None))
        elif new_rule["type"] == "scrambler":
            new_rule["wordsize"] = 0
            new_rule["path"] = ""

        # Languages - all languages/no language selected = none
        new_rule["languages"] = request.form.getlist("languages", None)
        if len(new_rule["languages"]) == 0 or len(new_rule["languages"]) == Configuration.nr_languages:
            new_rule["languages"] = "none"

        # Description of the rule
        new_rule["desc"] = request.form.get("description", None)

        # Examples from dictionary
        str_examples = request.form.get("examples", None)
        examples = list(str_examples.split(","))
        examples.pop()
        new_rule["examples"] = examples

        # Initialise reqs
        new_rule["reqs"] = request.form.getlist("reqs", None)

        # Link
        new_rule["link"] = request.form.get("link", None)

        # Save the dictionary and process it for the path and wordsize
        # available for the types "wordlist", "john", "generated", "filemask_hashcat"
        if 'file' in request.files:
            dictionary = request.files.get("file")
            filename = secure_filename(dictionary.filename)

            if filename != '':
                # Save dictionary
                dictionary.save(os.path.join("static/crack", filename))
                os.system("cp " + "static/crack/" + filename + " ../cracker/dict")

                # Compute wordsize and path
                p1 = subprocess.Popen(["wc", "-l", "static/crack/" + filename], stdout=subprocess.PIPE)
                p2 = subprocess.Popen(["awk", '{print $1}'], stdin=p1.stdout, stdout=subprocess.PIPE, universal_newlines=True)
                if new_rule["type"] != "generated":
                    new_rule["wordsize"] = p2.stdout.read()[:-1]
                new_rule["path"] = filename
            else:
                if new_rule["path"] == "":
                    flash("You forgot to upload the file, didn't you? Try again!")
                    return render_template('edit_rule.html', priorities=priorities, names=names, rule=rule_to_edit)

        # Requirements for cracking
        if new_rule["type"] == "scrambler":
            new_rule["reqs"] = ["john", "hashcat"]
        elif new_rule["type"] == "john":
            new_rule["reqs"] = ["hashcat", "john", new_rule["path"], "john-local.conf"]
        elif new_rule["type"] == "mask_hashcat":
            new_rule["reqs"] = ["hashcat"]
        else:
            new_rule["reqs"] = ["hashcat", new_rule["path"]]

        # Modify rule configuration if changes were made
        rules = []

        if new_rule["name"] not in Configuration.rule_dict:
            # The name changed => add a new rule
            Configuration.rule_dict[new_rule["name"]] = new_rule
            rules = Configuration.get_active_rules()
        else:
            # Rule name is the same => edit the actual rule (if necessary)
            shared_items = {k: rule_to_edit[k] for k in rule_to_edit if k in new_rule and rule_to_edit[k] == new_rule[k]}
            if len(shared_items) == len(rule_to_edit.keys()):
                # No changes were made
                return render_template('rules.html', rules=Configuration.get_active_rules())
            else:
                # Changes were made
                Configuration.rule_dict[new_rule["name"]] = new_rule
                for rule in Configuration.get_active_rules():
                    if rule["name"] == new_rule["name"]:
                        rules.append(new_rule)
                    else:
                        rules.append(rule)

        # Write the changes in the rules file
        with open('rules', 'w') as filehandle:
            json.dump(rules, filehandle, indent=4)

        return redirect(url_for("blob_api.handle_rules"))
        # return render_template('rules.html', rules=rules)

    else:
        Configuration.logger.error("Unsupported method!")
        abort(404)


@blob_api.route('/add_rule/', methods=['GET', 'POST'])
@requires_admin
def add_rule():
    if request.method == 'GET':
        if check_db_conn() is None:
            flash("DATABASE IS DOWN!")
            return render_template('rules.html', rules=Configuration.get_active_rules())

        priorities = []
        names = []
        for rule in Configuration.get_active_rules():
            priorities.append(rule["priority"])
            names.append(rule["name"])
        return render_template('add_rule.html', priorities=priorities, names=names)

    elif request.method == 'POST':
        new_rule = {"name": request.form.get("name", None), "type": request.form.get("type", None),
                    "priority": int(request.form.get("priority", None)), "path": ""}

        if new_rule["type"] == "wordlist" or new_rule["type"] == "filemask_hashcat":
            new_rule["wordsize"] = 0
        elif new_rule["type"] == "john":
            new_rule["rule"] = request.form.get("rule", None)
            new_rule["wordsize"] = 0
        elif new_rule["type"] == "generated":
            new_rule["command"] = request.form.get("command", None)
            new_rule["wordsize"] = 0  # modify
        elif new_rule["type"] == "mask_hashcat":
            new_rule["mask_hashcat"] = request.form.get("pattern", None)
            new_rule["wordsize"] = 0  # modify
        elif new_rule["type"] == "scrambler":
            new_rule["wordsize"] = 0

        # Languages - all languages/no language selected = none
        new_rule["languages"] = request.form.getlist("languages", None)
        if len(new_rule["languages"]) == 0 or len(new_rule["languages"]) == Configuration.nr_languages:
            new_rule["languages"] = "none"

        # Description of the rule
        new_rule["desc"] = request.form.get("description", None)

        # Examples from dictionary
        new_rule["examples"] = request.form.getlist("examples", None)

        # Initialise reqs
        new_rule["reqs"] = []

        # Link
        new_rule["link"] = request.form.get("link", None)

        # Save the dictionary and get the path + wordsize
        if new_rule["type"] in ["wordlist", "john", "generated", "filemask_hashcat"]:
            if 'file' not in request.files:
                Configuration.logger.info("No file uploaded.")
                flash("No file uploaded.")
                return redirect(request.url)

            # Save dictionary
            dictionary = request.files.get("file")
            filename = secure_filename(dictionary.filename)
            dictionary.save(os.path.join("static/crack", filename))
            os.system("cp " + "static/crack/" + filename + " ../cracker/dict")

            # Compute path and wordsize
            p1 = subprocess.Popen(["wc", "-l", "static/crack/" + filename], stdout=subprocess.PIPE)
            p2 = subprocess.Popen(["awk", '{print $1}'], stdin=p1.stdout, stdout=subprocess.PIPE, universal_newlines=True)
            new_rule["path"] = filename
            if new_rule["type"] != "generated":
                new_rule["wordsize"] = p2.stdout.read()[:-1]

        # Requirements for cracking
        if new_rule["type"] == "scrambler":
            new_rule["reqs"] = ["john", "hashcat"]
        elif new_rule["type"] == "john":
            new_rule["reqs"] = ["hashcat", "john", new_rule["path"], "john-local.conf"]
        elif new_rule["type"] == "mask_hashcat":
            new_rule["reqs"] = ["hashcat"]
        else:
            new_rule["reqs"] = ["hashcat", new_rule["path"]]

        # Save rule in the configuration
        Configuration.rule_dict[new_rule["name"]] = new_rule
        rules = Configuration.get_active_rules()
        rules.append(new_rule)

        # Add the new rule to rules file
        with open('rules', 'w') as filehandle:
            json.dump(rules, filehandle, indent=4)

        # return render_template('rules.html', rules=rules)
        return redirect(url_for("blob_api.handle_rules"))
    else:
        Configuration.logger.error("Unsupported method!")
        abort(404)


@blob_api.route('/', methods=['GET'])
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
            # First user is the original uploader
            crt_user = file_structure["users"][0]

            if crt_user not in user_handshakes:
                user_handshakes[crt_user] = {"cracked": [], "uncracked": []}

            if file_structure["handshake"]["password"] == "":
                user_handshakes[crt_user]["uncracked"].append(get_uncracked_tuple(file_structure))
            else:
                user_handshakes[crt_user]["cracked"].append(get_cracked_tuple(file_structure))

        users_list = list(Configuration.users.find())
        no_users = len(users_list)
        for i in range(no_users):
            crt_user = users_list[i]["username"]
            if crt_user not in user_handshakes and crt_user != Configuration.admin_account:
                user_handshakes[crt_user] = {"cracked": [], "uncracked": []}

        # Sort based on crack date using raw date field
        for entry in user_handshakes.values():
            entry["cracked"] = sorted(entry["cracked"], key=lambda k: k["raw_date"])

        # Transform dict to list and sort by username
        user_handshakes = sorted(user_handshakes.items(), key=lambda k: k[0])

        #  Dictionary with key=<user>, value=[<allow_api_value>]
        entries = Configuration.users.find({})
        allow_api_dict = {}
        for entry in entries:
            allow_api_dict[entry['username']] = entry['allow_api']

        return render_template('admin_home.html', user_handshakes=user_handshakes, permissions=allow_api_dict)

    logged_in = current_user.is_authenticated
    if logged_in and check_db_conn() is None:
        flash("Database error!")
        return render_template('home.html', logged_in=True)

    uncracked = []
    cracked = []
    if logged_in:
        # Sort in mongo by the time the handshake was added
        for file_structure in Configuration.wifis.find({"users": current_user.get_id()}).sort([("date_added", 1)]):
            # Sort in python by the SSID
            handshake = file_structure["handshake"]
            if handshake["password"] == "":
                uncracked.append(get_uncracked_tuple(file_structure))
            else:
                cracked.append(get_cracked_tuple(file_structure))

    # Sort based on crack date using raw date field
    cracked = sorted(cracked, key=lambda k: k["raw_date"])

    return render_template('home.html', uncracked=uncracked, cracked=cracked, logged_in=logged_in)


@blob_api.route('/change_permissions/<name>')
@ajax_requires_admin
def change_permissions(name):
    change = False
    if Configuration.users.find_one({'username': name})['allow_api']:
        Configuration.users.update_one({'username': name}, {"$set": {'allow_api': False}})
    else:
        Configuration.users.update_one({'username': name}, {"$set": {'allow_api': True}})
        change = True

    return jsonify({"success": True, "data": change})


@blob_api.route('/delete_wifi/', methods=['POST'])
@login_required
def delete_wifi():
    wifi_id = request.form.get("id")
    document = lookup_by_id(wifi_id)
    if document is None:
        flash("Id does not exist!")
        return redirect(url_for("home"))

    if document is False:
        flash("Internal error occured")
        return redirect(url_for("blob_api.home"))

    new_users = document["users"]
    new_users.remove(current_user.get_id())
    if len(new_users) < 1:
        retire_handshake(wifi_id, document)
    else:
        update_hs_id(wifi_id, {"users": new_users})

    return redirect(url_for("blob_api.home"))


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


@blob_api.route('/statuses/', methods=['GET'])
@login_required
def statuses():
    status_list = []

    for rule in Configuration.get_active_rules():
        status_list.append(get_rule_tuple(rule))

    return render_template('statuses.html', statuses=status_list)


@blob_api.route('/login/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash("User is already authenticated!")
        return redirect(url_for("blob_api.home"))

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

        if not User.check_credentials(username, password):
            if not User.check_recovery_credentials(username, password):
                Configuration.logger.warning("Failed login attempt from username = '%s' with password = '%s'" %
                                             (username, password))
                flash("Incorrect username/password!")
                return redirect(request.url)

        login_user(User(username))

        return redirect(url_for("blob_api.home"))


@blob_api.route("/register/", methods=["GET", "POST"])
def register():
    if request.method == 'GET':
        if current_user.is_authenticated:
            flash("You already have an account")
            return redirect(url_for("blob_api.home"))
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
            return redirect(url_for("blob_api.home"))

        flash(retval)
        return redirect(request.url)


@blob_api.route('/logout/', methods=["GET"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("blob_api.home"))


@blob_api.route('/profile/', methods=['GET', 'POST'])
@login_required
def profile():
    user_entry = Configuration.users.find_one({"username": current_user.get_id()})

    fst_name = ""
    last_name = ""
    email = ""
    password = ""
    confirm = ""

    if request.method == "POST":
        fst_name = request.form.get("first_name", None)
        last_name = request.form.get("last_name", None)
        email = request.form.get("email", None)
        password = request.form.get("password", None)
        confirm = request.form.get("confirm", None)

    if len(fst_name) > 0:
        try:
            if user_entry["first_name"] != fst_name:
                Configuration.users.update({"username": current_user.get_id()}, {"$set": {"first_name": fst_name}})
        except KeyError:
            Configuration.users.update({"username": current_user.get_id()}, {"$set": {"first_name": fst_name}})
    else:
        try:
            fst_name = user_entry["first_name"]
        except KeyError:
            fst_name = "Enter first name"

    if len(last_name) > 0:
        try:
            if user_entry["last_name"] != last_name:
                Configuration.users.update({"username": current_user.get_id()}, {"$set": {"last_name": last_name}})
        except KeyError:
            Configuration.users.update({"username": current_user.get_id()}, {"$set": {"last_name": last_name}})
    else:
        try:
            last_name = user_entry["last_name"]
        except KeyError:
            last_name = "Enter last name"

    if len(email) > 0:
        try:
            if user_entry["email"] != email:
                Configuration.users.update({"username": current_user.get_id()}, {"$set": {"email": email}})
        except KeyError:
            Configuration.users.update({"username": current_user.get_id()}, {"$set": {"email": email}})
    else:
        try:
            email = user_entry["email"]
        except KeyError:
            email = "Enter email"

    # password resetting
    if len(password) == 0 and len(confirm) > 0:
        flash("Invalid password!")

    if len(password) > 0:
        if len(password) < 6:
            flash("C'mon... use at least 6 characters... pretty please?")
            return redirect(request.url)

        if len(password) > 150:
            flash("The password is waaaaay too long. Please don't.")
            return redirect(request.url)

        if password != confirm:
            flash("The password confirmation does not match.")
            return redirect(request.url)

        if enc_bcrypt(password) != user_entry["password"]:
            Configuration.users.update({"username": current_user.get_id()}, {"$set": {"password": enc_bcrypt(password)}})
            Configuration.users.update({"username": current_user.get_id()}, {"$set": {"recovery_password": ""}})

    return render_template('profile.html', username=current_user.get_id(), first_name=fst_name,
                           last_name=last_name, email=email)


@blob_api.route('/reset_password/', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        # send email when the form is submitted
        email = request.form.get("email", None)
        if Configuration.users.find_one({"email": email}) is None:
            flash("Incorrect email")
            return redirect(request.url)

        current_app.config['MAIL_SERVER'] = 'smtp.gmail.com'
        current_app.config['MAIL_PORT'] = 465
        current_app.config['MAIL_USERNAME'] = 'psknow.pandora@gmail.com'
        current_app.config['MAIL_PASSWORD'] = 'Pandora1!'
        current_app.config['MAIL_USE_TLS'] = False
        current_app.config['MAIL_USE_SSL'] = True
        mail = Mail(current_app)
        msg = Message(
            "Password reset",
            sender=("PSKnow", "psknow.pandora@gmail.com"),
            recipients=[email]
        )

        random_string = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase +
                                                             string.digits) for _ in range(10))
        msg.body = "Please use the code " + random_string + " to reset your password. "
        msg.body = msg.body + "If you did not request your password to be reset, ignore this message."
        mail.send(msg)
        Configuration.users.update({"email": email}, {"$set": {"recovery_password": enc_bcrypt(random_string)}})
        flash("Successfully sent! Please check your email account for a message with a confirmation code "
              "you can use to reset your password.", 'success')
        return redirect(url_for("blob_api.login"))

    # show the form, it wasn't submitted
    return render_template('reset_password.html')
