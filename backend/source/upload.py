import datetime
import tempfile
import os
import string
import random

from .process import Process
from .config import Configuration
from .wrappers import die, not_admin, check_db_conn

from werkzeug.utils import secure_filename
from flask import flash, redirect, Blueprint, request, render_template
from flask_login import login_required, current_user
from copy import deepcopy

upload_api = Blueprint('upload_api', __name__)


def get_random_string(length):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))


def valid_filename(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Configuration.accepted_extensions


def append_number_beforeext(filename, number):
    position = filename.rfind('.')
    return filename[:position] + str(number) + filename[position:]


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


def get_unique_id():
    unique_id = get_random_string(Configuration.id_length)
    while len(list(Configuration.wifis.find({"id": unique_id}))) > 0:
        unique_id = get_random_string(25)
    return unique_id


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


@upload_api.route('/upload/', methods=['GET', 'POST'])
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
