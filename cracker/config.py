import sys
import logbook
import json
import re
import os
from copy import deepcopy
from pymongo import MongoClient


class Configuration(object):
    # Database variables
    database_location = 'mongodb://127.0.0.1:27017/'
    database_name = "psknow"

    conn = None
    db = None
    wifis = None
    admin = None

    admin_table_name = "MainControlTable"
    default_hashcat_dict = {"progress": -1, "eta": "", "speed": ""}

    # Handshake related variables
    backend_local = False
    backend_ip = "127.0.0.1"
    backend_remote_handshake_path = "/home/pandora/PycharmProjects/psknow/backend/handshakes"
    backend_handshake_path = '../backend/handshakes'
    handshake_path = 'handshakes'

    # Cracking paths
    john_path = "/home/pandora/PycharmProjects/psknow/helpers/sources/john/run/john"
    attack_path = 'crack'
    hashcat_potfile_path = os.path.join(attack_path, 'hashcat.pot')  # TODO create file if it does not exist!
    escapes_path = 'escapes'

    # Cracking regexes
    hashcat_left_regex = re.compile("[0-9a-f]{32}[:*]([0-9a-f]{12})[:*][0-9a-f]{12}[:*](.*)[\n]?$")
    hashcat_show_regex = re.compile("[0-9a-f]{32}[:*]([0-9a-f]{12})[:*][0-9a-f]{12}[:*].*[:*](.*)[\n]?$")
    atoi_regex = re.compile(" *[-]?[0-9]*")

    hashcat_progress_re = re.compile("^Progress[.]{9}: ([0-9]*)$")
    hashcat_eta_re = re.compile("^Time[.]Estimated[.]{3}: [A-Za-z0-9: ]* ([(].*[)])$")
    hashcat_speed_re = re.compile("^Speed[.]#1[.]{9}:[ ]+([0-9]* ?.?H/s)")

    # Cracking variables
    hot_words = ["parola", "password", "wifi"]
    max_rules = -1
    rules = None

    # Accepted uplaod extensions
    accepted_extensions = {"cap", "pcap", "16800", "pcapng"}

    # Logging variables
    log_filename = 'logs/cracker.log'
    logLevel = "DEBUG"
    # :logLevel = "INFO"
    myLogger = None

    @staticmethod
    def database_conection():
        Configuration.conn = MongoClient(Configuration.database_location,
                                         serverSelectionTimeoutMS=10,
                                         connectTimeoutMS=20)
        Configuration.db = Configuration.conn[Configuration.database_name]
        Configuration.wifis = Configuration.db["wifis"]
        Configuration.admin = Configuration.db["admin"]

    @staticmethod
    def setup_logging():
        Configuration.myLogger = logbook.Logger("")
        Configuration.myLogger.handlers.append(logbook.FileHandler(Configuration.log_filename,
                                                                   level=Configuration.logLevel))
        Configuration.myLogger.info("Logging activated!")

    @staticmethod
    def read_rules():
        try:
            with open('rules') as json_data:
                Configuration.rules = json.load(json_data)
        except Exception as e:
            Configuration.log_fatal("Error trying to load rules data: %s" % e)

        rule_names = set()

        for rule in Configuration.rules:
            # Check for duplicate rules
            if rule["name"] in rule_names:
                Configuration.log_fatal("Duplicate rule %s" % rule["name"])
            rule_names.add(rule["name"])

            if rule["priority"] > Configuration.max_rules:
                Configuration.max_rules = rule["priority"]

        if "rules" in Configuration.db.list_collection_names():
            Configuration.db["rules"].drop()

        rules_db = Configuration.db["rules"]
        rules_db.insert_many(Configuration.rules)

    @staticmethod
    def initialize():
        Configuration.setup_logging()
        Configuration.database_conection()
        Configuration.read_rules()

        if not Configuration.backend_local and Configuration.backend_ip == "":
            Configuration.log_fatal("Backend is not local but location is not specified")

    @staticmethod
    def get_admin_table():
        if Configuration.admin is None:
            Configuration.log_fatal("Trying to get admin table before it is initialised!")

        ret_val = Configuration.admin.find_one({"id": Configuration.admin_table_name})
        if ret_val is None or "workload" not in ret_val:
            Configuration.log_fatal("Database failure. Admin table could not be retrieved or 'workload' is not set")

        Configuration.admin.update_one({"id": Configuration.admin_table_name}, {"$set": {"force": False}})

        return ret_val

    @staticmethod
    def log_fatal(message):
        Configuration.myLogger.critical(message)
        sys.exit(-1)

    # TODO make multiple base dictionaries available
    @staticmethod
    def get_next_rules_data(rule_number):
        next_rule_number = Configuration.max_rules + 1
        next_rule = None
        for rule in Configuration.rules:
            if next_rule_number > rule["priority"] > rule_number:
                next_rule_number = rule["priority"]
                next_rule = rule

        if next_rule is None:
            return None

        return deepcopy(next_rule)


if __name__ == '__main__':
    print("Run main!", file=sys.stderr)
    sys.exit(-1)
