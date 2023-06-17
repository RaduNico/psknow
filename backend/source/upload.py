import datetime
import os
import string
import random
import shutil
from .process import Process
from .config import Configuration
from .wrappers import die, not_admin, check_db_conn
from .database_helper import add_user_to_entry_id, generic_find, lookup_by_id

from tempfile import NamedTemporaryFile
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
    while True:
        try:
            os.close(os.open(full_path, os.O_EXCL | os.O_CREAT, 0o644))
            break
        except FileExistsError:
            number = number + 1
            new_filename = orig_fname[:position] + "_" + str(number).rjust(4, '0') + orig_fname[position:]
            full_path = os.path.join(Configuration.save_file_location, new_filename)

    return full_path


def get_unique_id():
    unique_id = get_random_string(Configuration.id_length)
    while len(list(Configuration.wifis.find({"id": unique_id}))) > 0:
        unique_id = get_random_string(25)
    return unique_id


def get_22000_file(filepath, is_16800=False):
    # Sanity check - file must exist
    die(not os.path.isfile(filepath), "File %s does not exist!" % filepath)

    # Memorize name so we can later delete it
    tmp_file = NamedTemporaryFile(prefix="psknow_backend_get_22000_file",
                                  delete=False, dir=Configuration.tempfile_dir)
    temp_filename = tmp_file.name

    # Conversion to .22000
    if is_16800:
        input_parameter = "--pmkidin=%s" % filepath
        output_parameter = "--pmkideapolout=%s" % temp_filename
        command = ["hcxmactool", input_parameter, output_parameter]
    else:
        command = ["hcxpcapngtool", "-o", temp_filename, filepath]

    Process(command, crit=True).wait()

    if os.stat(temp_filename).st_size == 0:
        os.remove(temp_filename)
        return None

    return temp_filename


# Return True if error occured or False otherwise
def retire_handshake(internal_id, document=None):
    if document is None:
        document = lookup_by_id(internal_id)

    if document is None:
        flash("Id does not exist!")
        return False
    if document is False:
        flash("Error occured")
        return True

    del document["_id"]
    document["retired_on"] = datetime.datetime.now()

    try:
        result = Configuration.retired.insert_one(document)
        Configuration.logger.info("Retired document with id '%s'. New _id: %s" %
                                  (internal_id, result.inserted_id))
    except Exception as e:
        Configuration.logger.error(
            "Database error at inserting document '%s': %s" % (document, e))
        flash("Server error at duplication data.")
        return True

    try:
        Configuration.wifis.delete_one({"id": internal_id})
        Configuration.logger.info("Delete retired document with internal id '%s'" % internal_id)
    except Exception as e:
        Configuration.logger.error(
            "Database error at deleting document with internal id '%s': %s" % (internal_id, e))
        flash("Server error at duplication data.")
        return True

    return False


# TODO if appending WPA/PMKID from another user use the current upload time
# TODO replace if PMKID (done) or if M3 is present
def treat_duplicate(wifi_entry):
    ssid = wifi_entry["handshake"]["SSID"]
    mac = wifi_entry["handshake"]["MAC"]
    user = wifi_entry["users"][0]
    hs_type = wifi_entry["handshake"]["handshake_type"]
    duplicate_flag = False
    added_flag = False

    duplicates, error = generic_find(Configuration.wifis, {"handshake.SSID": ssid, "handshake.MAC": mac})

    if error:
        return None, True

    duplicates = list(duplicates)

    # There are multiple entries with the same SSID-MAC pair
    if len(duplicates) > 1:
        Configuration.logger.warning("Multiple entries with SSID-MAC '%s-%s' exist. Will not attempt PMKID substitution"
                                     % (ssid, mac))
        duplicate_flag = True

        # Attempt to add the current user to the users list for that entry, if it's not already there
        for duplicate in duplicates:
            if user not in duplicate["users"]:
                add_user_to_entry_id(user, duplicate["id"])
                added_flag = True

    elif len(duplicates) == 1:
        duplicate_flag = True
        duplicate = duplicates[0]

        # If only one other entry exists, it is a WPA type and the duplicate is a PMKID substitute it
        if duplicate["handshake"]["handshake_type"] == "WPA" and hs_type == "PMKID":
            if duplicate["handshake"]["active"]:
                # TODO this should be fixed automatically in the back and not bother the user
                flash("A PMKID was found inside the file '%s' for SSID-MAC '%s-%s', which could replace an existing "
                      "WPA handshake, however that handshake is currently being attacked and could not be retired."
                      "Try again later!" % (wifi_entry["path"], ssid, mac))
                if user not in duplicate["users"]:
                    if not add_user_to_entry_id(user, duplicate["id"]):
                        flash("Attached existing WPA for SSID-MAC '%s-%s' to your account" % (ssid, mac),
                              category="success")
                return duplicates, True

            if retire_handshake(duplicate["id"]):
                return duplicates, True

            # Modify new entry so it matches data from old handshake
            wifi_entry["handshake"]["tried_dicts"] = duplicate["handshake"]["tried_dicts"]
            wifi_entry["handshake"]["cracked_rule"] = duplicate["handshake"]["cracked_rule"]
            wifi_entry["handshake"]["date_cracked"] = duplicate["handshake"]["date_cracked"]
            wifi_entry["handshake"]["password"] = duplicate["handshake"]["password"]

            wifi_entry["date_added"] = duplicate["date_added"]
            wifi_entry["location"] = deepcopy(duplicate["location"])
            wifi_entry["priority"] = duplicate["priority"]

            wifi_entry["users"] = duplicate["users"]
            if user not in duplicate["users"]:
                wifi_entry["users"].append(user)

            flash("A WPA handshake was found for SSID-MAC '%s-%s'. Replacing with provided PMKID" % (ssid, mac),
                  category='success')
            duplicate_flag = False

        # Attempt to add the current user to the users list for that entry, if it's not already there
        elif user not in duplicate["users"]:
            if add_user_to_entry_id(user, duplicate["id"]):
                return None, True
            else:
                Configuration.logger.info("Successfully added user %s in handshake '%s-%s'" % (user, ssid, mac))
                added_flag = True

    if duplicate_flag:
        message = "A PMKID/WPA for pair MAC-SSID: '%s-%s' already exists!" % (mac, ssid)
        category = "warning"

        # Change the message if the duplicate was attached to the current user accout
        if added_flag:
            message += " Attached existing PMKID/WPA to your account."
            category = "success"

        flash(message, category=category)

    return duplicate_flag, False


def check_handshake(file_path, filename, wifi_entry):
    """
        Function that checks if a file located at the path file_path contains any valid handshakes
        :returns is_valid_handshake, wifi_entries
    """
    entries = []
    temp_filename = None
    must_delete_temp_file = True

    duplicate_pair = set()
    duplicate_flag = False

    # Sanity check (file should always exist)
    die(not os.path.isfile(file_path), "File %s does not exist!" % file_path)

    # TODO change this to proper file type check - use file or directly detect magic numbers
    # We add to wifi_entry: file_type, handshake[SSID, MAC, open, handshake_type]
    if not filename.endswith((".cap", ".pcap", ".pcapng", ".16800", ".22000")):
        Configuration.logger.info("Cannot process file type for the file '%s'" % filename)
        flash("Invalid filetype for file '%s'" % filename)
        return False, None

    wifi_entry["file_type"] = filename[filename.rfind('.') + 1:]

    if wifi_entry["file_type"] == "22000":
        temp_filename = file_path
        must_delete_temp_file = False
    elif wifi_entry["file_type"] == "16800":
        temp_filename = get_22000_file(file_path, is_16800=True)
    elif wifi_entry["file_type"] in ["cap", "pcap", "pcapng"]:
        temp_filename = get_22000_file(file_path)
    else:
        die(True, "Filetype '%s' not properly covered by if conditions" % wifi_entry["file_type"])

    if temp_filename is None:
        # if temp_filename variable is None the file does not exist
        return False, None

    try:
        show_command = "hashcat --potfile-path=%s --left -m 22000 %s" % (Configuration.empty_pot_path, temp_filename)

        # Test with hashcat if files contain valid data
        mac_ssid_list = []

        output = Process(show_command, crit=True).stdout()
        if output is None or len(output) <= 0:
            return False, None

        for cracked_target in output.split():
            regex_matches = Configuration.regex_22000.match(cracked_target)

            if regex_matches is None:
                Configuration.logger.error("REGEX error! Could not match the left line: %s" % cracked_target)
                continue

            handshake_type = "PMKID" if regex_matches.group(1) == "1" else "WPA"
            mac = ":".join(a + b for a, b in zip(regex_matches.group(2)[::2], regex_matches.group(2)[1::2]))

            # TODO what do if ssid is not printable? This might erorr out.
            ssid = bytearray.fromhex(regex_matches.group(3)).decode()

            mac_ssid_list.append((mac, ssid, handshake_type))

        for mac, ssid, hs_type in mac_ssid_list:
            # Remove duplicate entries in the same file - filter by MAC
            flag = False
            for hs in entries:
                if hs["handshake"]["MAC"] == mac:
                    flag = True
                    break
            if flag:
                continue

            new_handshake = deepcopy(Configuration.default_handshake)
            new_handshake["MAC"] = mac
            new_handshake["SSID"] = ssid
            new_handshake["handshake_type"] = hs_type

            # Avoid duplicate 'duplicate message' for files with both PMKID and handshakes
            if (new_handshake["MAC"], new_handshake["SSID"]) in duplicate_pair:
                continue

            new_wifi_entry = deepcopy(wifi_entry)

            # Generate unique ID for our document
            new_wifi_entry["id"] = get_unique_id()
            new_wifi_entry["handshake"] = new_handshake

            is_duplicate, error = treat_duplicate(new_wifi_entry)

            if error:
                return False, None

            if is_duplicate:
                duplicate_pair.add((new_handshake["MAC"], new_handshake["SSID"]))
                duplicate_flag = True
                continue

            entries.append(new_wifi_entry)

        if len(entries) == 0:
            # If the duplicate_flag is True it means at least a hash has been found (even if useless)
            if not duplicate_flag:
                Configuration.logger.info("No valid handshake found in file '%s'" % filename)
                flash("No valid handshake found in file '%s'" % filename)
            return False, None
    finally:
        if must_delete_temp_file:
            os.remove(temp_filename)

    return True, entries


@upload_api.route('/upload/', methods=['GET', 'POST'])
@login_required
@not_admin
def upload_file():
    if request.method == 'GET':
        return render_template('upload.html')

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
        temp_file = NamedTemporaryFile(prefix="psknow_backend_upload_file",
                                      delete=False, dir=Configuration.tempfile_dir)
        tmp_path = temp_file.name
        file.save(tmp_path)

        new_entry = deepcopy(Configuration.default_wifi)

        # new_entry["location"]["keyword"] = #TODO POST keyword
        # new_entry["location"]["coordinates"] = #TODO POST coordinates
        new_entry["date_added"] = datetime.datetime.now()
        new_entry["users"] = [current_user.get_id()]
        new_entry["priority"] = 0

        # Validate handshake and get file type and handshake type
        is_valid_handshake, wifi_entries = check_handshake(tmp_path, file.filename, new_entry)

        if not is_valid_handshake:
            os.remove(tmp_path)
            continue

        # Generate a unique filename to permanently save file
        file_path = get_unique_filename_path(file.filename)

        for wifi_entry in wifi_entries:
            wifi_entry["path"] = file_path

        # Save received file
        try:
            shutil.move(tmp_path, file_path)
            Configuration.logger.info("Saved file at %s" % file_path)
        except Exception as e:
            Configuration.logger.error("Exception at saving received file at path = %s : %s" % (file_path, e))
            flash("Error saving file '%s'" % filename)
            return redirect(request.url)

        # Insert document in database with all information
        try:
            objs = Configuration.wifis.insert_many(wifi_entries)
            if len(objs.inserted_ids) != len(wifi_entries):
                flash("Database error at saving filename %s" % filename)
                Configuration.logger.error("Inserted object number (%d) does not match intended (%d)!"
                                           "Inserted ids - '%s', intended wifis - '%s'" %
                                           (len(objs.inserted_ids), len(wifi_entries), objs.inserted_ids, wifi_entries))
            for idx, obj in enumerate(objs.inserted_ids):
                Configuration.logger.info("Inserted object _id = %s with id = %s" %
                                          (obj, wifi_entries[idx]))
        except Exception as e:
            Configuration.logger.error("Exception at inserting file = %s: %s" % (file_path, e))
            flash("Database error at saving filename %s" % filename)
            return redirect(request.url)

        flash("File '%s' uploaded successfully!" % filename, category='success')
    return redirect(request.url)
