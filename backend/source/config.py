import sys
import re
import os
import json
import hashlib

from time import sleep
from pymongo import MongoClient
from copy import deepcopy
from secrets import token_urlsafe
from threading import Lock


class Configuration(object):
    static_folder = "static"

    # Database Variables
    database_location = '127.0.0.1:27017'
    admin_account = "pandora"
    database_name = "psknow"

    # TODO move this in a private file
    db_username = 'psknow'
    db_password = 'xY6R0YPFBpjebMwFHBYXQTokZ25nI1G8eZfjWqQrUtUeajcucgKpNxncVBCW'

    conn = None
    db = None
    wifis = None
    users = None
    admin = None
    retired = None

    admin_table_name = "MainControlTable"
    default_admin_table = {"id": "MainControlTable", "workload": 2, "force": False}

    # Length of document/file public identification number
    id_length = 25
    default_wifi = {"id": None,
                    "date_added": None,
                    "location": {"address": "",
                                 "city": "",
                                 "coordinates": [0.0, 0.0],
                                 "keyword": ""},

                    "path": None,
                    "handshake": None,
                    "file_type": "",

                    "users": [],
                    "priority": 0,
                    "details": ""}

    default_handshake = {  # Metadata
        "tried_dicts": [],
        "cracked_rule": "",
        "active": False,
        "handshake_type": None,

        # Identification information
        "SSID": "",
        "MAC": "",
        "open": False,

        # Crack information
        "date_cracked": None,
        "password": ""}

    # Handshake save folder
    save_file_location = 'handshakes'

    # Handshake verification
    pmkid_regex = re.compile("^[0-9a-f]{32}\\*([0-9a-f]{12})\\*[0-9a-f]{12}\\*([0-9a-f]*)[\n]?$")
    username_regex = re.compile("^[a-zA-Z][-_.0-9a-zA-Z]*$")
    hashcat_left_regex = re.compile("[0-9a-f]{32}[:*]([0-9a-f]{12})[:*][0-9a-f]{12}[:*](.*)[\n]?$")
    # aircrack_regex = re.compile("^ {0,3}[0-9]{0,3} {2}([0-9A-Fa-f:]{17}) {2}(.*) {2}"
    #                             "(None \\([0-9]*\\.[0-9]*\\.[0-9]*\\.[0-9]*\\)|"
    #                             "No data - WEP or WPA|"
    #                             "WEP \\([0-9]* IVs\\)|"
    #                             "WPA \\([0-9*] handshake.*\\)|"
    #                             "Unknown)[\n]?$")

    empty_pot_path = 'config_files/empty_potfile'

    # Accepted uplaod extensions
    accepted_extensions = {"cap", "pcap", "16800", "pcapng"}

    # Dictionaries allowed for download
    dictionary_names = ["wordlist-top4800-probable.txt", "dic_lc_rom.txt", "dic_lc_eng.txt", "nume_bac2018.txt",
                        "top_2500_engl.txt", "nume_comune_bac2018.txt"]

    # Logging variables
    logger = None

    # Secret keys
    api_secret_key = None

    # Cracker side data
    max_rules = 0
    number_rules = 0
    rule_priorities = {}
    wifis_lock = Lock()
    rule_dict = {}
    programs = ["hashcat", "john"]

    cap_template_name = "config_files/capabilities_template"
    cap_generate_name = "config_files/capabilities_generated"

    cap_dict = None

    allowed_eta_regex = re.compile("^[a-zA-Z0-9,() .]+$")

    @staticmethod
    def get_key_from_file(filename):
        try:
            with open(filename, "r") as sc_fd:
                key = "".join(sc_fd.readlines())
        except FileNotFoundError:
            key = token_urlsafe(150)
            with open(filename, "w") as sc_fd:
                sc_fd.write(key)

        return key

    # TODO Maybe attempt restoration. Change value returned by get_admin_table() if restoration succeeds
    @staticmethod
    def __sanity_check_admin_table(admin_table):
        if admin_table is None:
            Configuration.logger.error("Admin table missing!")
            return "Admin table missing!"

        if not isinstance(admin_table, dict):
            Configuration.logger.error("Admin table is not a dictionary!")
            return "Admin table is not a dictionary!"

        if "workload" not in admin_table:
            Configuration.logger.error("Admin table found but does not contain critical workload data!")
            return "Admin table found but does not contain critical workload data!"

        if admin_table["workload"] < 1 or admin_table["workload"] > 4:
            Configuration.logger.error("Workload returned by database is not within bounds!")
            return "Workload returned by database is not within bounds!"

        return None

    @staticmethod
    def get_admin_table():
        if Configuration.admin is None:
            return None, "Admin collection is None!"

        try:
            table = Configuration.admin.find_one({"id": Configuration.admin_table_name})
            Configuration.logger.debug("Retrieving admin table")
        except Exception as e:
            Configuration.logger.error("Exception at retrieving admin tabl: %s" % e)
            return None, "Error retrieving admin table from database"

        error = None
        if table is None:
            Configuration.logger.warning("No admin table found, trying to create one.")
            try:
                Configuration.admin.insert_one(Configuration.default_admin_table)
                table = deepcopy(Configuration.default_admin_table)
            except Exception as e:
                Configuration.logger.error("Error at creating admin table: %s" % e)
                error = "Admin table not found, attemted to create one, but failed with %s" % e
        else:
            error = Configuration.__sanity_check_admin_table(table)

        # Only return table if it is in a sane state
        if error is not None:
            table = None

        return table, error

    @staticmethod
    def set_admin_table(table):
        error = Configuration.__sanity_check_admin_table(table)

        if error is not None:
            return False

        try:
            update_code = Configuration.admin.update_one({"id": Configuration.admin_table_name}, {"$set": table})
        except Exception as e:
            Configuration.logger.error("Failed to update admin table with data: %s. Exception: %s" % (table, e))
            return False

        if update_code.matched_count != 1:
            Configuration.logger.error("Failed to update admin table with data: %s" % table)
            return False

        return True

    @staticmethod
    def get_active_rules():
        return list(Configuration.rule_dict.values())

    @staticmethod
    def log_fatal(message):
        Configuration.logger.critical(message)
        sleep(10)
        sys.exit(-1)

    @staticmethod
    def database_conection():
        try:
            conn_loc = "mongodb://%s:%s@%s/%s" %\
                       (Configuration.db_username, Configuration.db_password,
                        Configuration.database_location, Configuration.database_name)
            Configuration.logger.debug("Connecting at %s" % conn_loc)

            Configuration.conn = MongoClient(conn_loc, serverSelectionTimeoutMS=10, connectTimeoutMS=20)
            Configuration.db = Configuration.conn[Configuration.database_name]
            Configuration.wifis = Configuration.db["wifis"]
            Configuration.users = Configuration.db["users"]
            Configuration.admin = Configuration.db["admin"]
            Configuration.retired = Configuration.db["retired"]
            Configuration.check_db_conn()
        except Exception as e:
            Configuration.log_fatal("Could not establish initial connection with error %s" % e)

    @staticmethod
    def read_rules():
        rules = []

        # TODO if you ever do this dinamically you need to make sure no work is being sent while rules are updating
        try:
            with open('rules') as json_data:
                rules = json.load(json_data)
        except Exception as e:
            Configuration.log_fatal("Error trying to load rules data: %s" % e)

        for rule in rules:
            # Check for duplicate rules
            if rule["name"] in Configuration.rule_dict:
                Configuration.log_fatal("Duplicate rule %s" % rule["name"])

            Configuration.rule_dict[rule["name"]] = rule
            Configuration.rule_priorities[rule["name"]] = int(rule["priority"])

            if rule["priority"] > Configuration.max_rules:
                Configuration.max_rules = rule["priority"]

        Configuration.number_rules = len(Configuration.rule_dict)

    @staticmethod
    def sha1file(filepath):
        with open(filepath, 'rb') as f:
            return hashlib.sha1(f.read()).hexdigest()

    @staticmethod
    def get_mtime_for_cap_file(path):
        path = os.path.join(Configuration.static_folder, "crack", path.split("/")[-1])

        if not os.path.exists(path):
            return None, path

        return os.stat(path).st_mtime, path

    @staticmethod
    def set_cap_dict_data(name, base_cap_dict, final_dict):
        new_cap_dict = deepcopy(base_cap_dict)

        last_mod, path = Configuration.get_mtime_for_cap_file(base_cap_dict["path"])

        # File does not currently exist create empty
        if last_mod is None:
            final_dict[name] = new_cap_dict
            new_cap_dict["sha1"] = ""
            new_cap_dict["last_change"] = None
            return

        if base_cap_dict["last_change"] is None or\
                (base_cap_dict["last_change"] is not None and last_mod > base_cap_dict["last_change"]):
            new_cap_dict["last_change"] = last_mod
            new_cap_dict["sha1"] = Configuration.sha1file(path)

        if new_cap_dict["sha1"] == "":
            Configuration.log_fatal("sha1 hash for '%s-%s' is empty" % (name, new_cap_dict))

        final_dict[name] = new_cap_dict

    @staticmethod
    def read_caps():
        def load_data(file):
            json_data = None
            try:
                with open(file) as fd:
                    json_data = json.load(fd)
            except Exception as e:
                Configuration.log_fatal("Error trying to load %s data: %s" % (file, e))
            return json_data

        cap_dict = load_data(Configuration.cap_template_name)
        final_dict = dict()

        # Check if the generated file exists
        if not os.path.exists(Configuration.cap_generate_name):
            Configuration.logger.info("No capabability files was generated, creating one.")
            for name, data in cap_dict.items():
                Configuration.set_cap_dict_data(name, data, final_dict)

        # Check if the template changed
        elif os.stat(Configuration.cap_template_name).st_mtime > os.stat(Configuration.cap_generate_name).st_mtime:
            Configuration.logger.info("Template was updated. Generating new capabilities file.")
            for name, data in cap_dict.items():
                Configuration.set_cap_dict_data(name, data, final_dict)

        # Generated file exists, try to load data from it
        else:
            old_cap_dict = load_data(Configuration.cap_generate_name)

            for name, data in cap_dict.items():
                # Check if data is already written in generated file
                if name in old_cap_dict:
                    # Try and load it from generated file
                    old_mtime = old_cap_dict[name].get("last_change")
                    new_mtime, _ = Configuration.get_mtime_for_cap_file(data["path"])

                    # last_change does not exist in generated file or a change occured
                    if new_mtime is None or old_mtime is None or old_mtime < new_mtime:
                        Configuration.logger.info("File '%s' was updated, reloading data" % name)
                        Configuration.set_cap_dict_data(name, data, final_dict)
                    else:
                        Configuration.logger.debug("Loaded data for '%s' from generated file." % name)
                        final_dict[name] = deepcopy(old_cap_dict[name])
                # Data for this entry is not present in generated file
                else:
                    Configuration.set_cap_dict_data(name, data, final_dict)

        with open(Configuration.cap_generate_name, "w") as fp:
            json.dump(final_dict, fp, indent=4)

        Configuration.cap_dict = final_dict

    @staticmethod
    def initialize():
        # Establish database connection
        Configuration.database_conection()

    @staticmethod
    def preinitialize(server):
        Configuration.logger = server.log

        # Read rule data
        Configuration.read_rules()

        # Read capabilities data
        Configuration.read_caps()

        # Check if handshake folder exists
        if not os.path.isdir(Configuration.save_file_location):
            Configuration.logger.debug("Creating handshake folder hierarchy '%s'" % Configuration.save_file_location)
            os.makedirs(Configuration.save_file_location)

        # Make sure the pot_path is empty
        with open(Configuration.empty_pot_path, "w") as _:
            pass

    @staticmethod
    def check_db_conn():
        return Configuration.conn.server_info()


if __name__ == '__main__':
    print("Run main!")
    sys.exit(-1)
