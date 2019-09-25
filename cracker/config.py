import sys
import logbook
import re
import os
import hashlib
from shutil import which


class Configuration(object):
    apikey = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJ1c2VyIjoicmFkdSIsImRhdGVfZ2VuZXJhdGVkIjoiMjAxOS0wOS0wOFQxOTo" \
             "0Mzo1My4yNTExNDQiLCJrZXlfaWQiOiIxMDAwIiwibmFtZSI6Im11aWUifQ.opggNbRjlkv2S3GzzyK145CDKmZrzuoR9xxKZkFr" \
             "HjnSpIfwaTO5G-wvu5AENUknItPePFrRTKd_ZIzaOq5MeQ"
    john_path = "/home/pandora/sec/psknow/dependencies/sources/john/run/john"

    # Remote location info
    # remote_server = "https://pandorak.go.ro/"
    remote_server = "http://192.168.14.103:9645/api/v1/"
    capabilities = []
    capab_dirs = ["dict", "dict/generators", "dict/maskfiles"]
    programs = ["hashcat", "john"]

    # Logging variables
    log_filename = 'logs/cracker.log'
    logLevel = "DEBUG"
    # :logLevel = "INFO"
    logger = None

    @staticmethod
    def dual_print(log, message):
        log(message)
        print(message)

    @staticmethod
    def gather_capabilities():
        Configuration.capabilities = {}

        if os.path.isfile("john-local.conf"):
            Configuration.capabilities["john-local.conf"] = Configuration.sha1file("john-local.conf")

        for directory in Configuration.capab_dirs:
            if not os.path.isdir(directory):
                continue

            all_files = os.listdir(directory)

            for file in all_files:
                path = os.path.join(directory, file)
                if os.path.isfile(path) and not file.startswith("."):
                    Configuration.capabilities[file] = Configuration.sha1file(path)

        for program in Configuration.programs:
            # John path needs to be hardcoded it seems
            if program == "john" and Configuration.john_path != "john" and os.path.exists(Configuration.john_path):
                Configuration.capabilities[program] = None

            if which(program) is not None:
                Configuration.capabilities[program] = None

    @staticmethod
    def setup_logging():
        Configuration.logger = logbook.Logger("")
        Configuration.logger.handlers.append(logbook.FileHandler(Configuration.log_filename,
                                                                 level=Configuration.logLevel))
        Configuration.logger.info("Logging activated!")

    @staticmethod
    def sha1file(filepath):
        with open(filepath, 'rb') as f:
            return hashlib.sha1(f.read()).hexdigest()

    @staticmethod
    def initialize():
        Configuration.setup_logging()
        Configuration.gather_capabilities()

    default_hashcat_dict = {"progress": -1, "eta": "", "speed": ""}

    # Cracking paths
    attack_path = 'crack'
    hashcat_potfile_path = os.path.join(attack_path, 'hashcat.pot')

    # Cracking regexes
    hashcat_left_regex = re.compile("[0-9a-f]*[:*][0-9a-f]*[:*](.*)[:*](.*)[\n]?$")
    atoi_regex = re.compile(" *[-]?[0-9]*")

    hashcat_progress_re = re.compile("^Progress[.]{9}: ([0-9]*)$")
    hashcat_eta_re = re.compile("^Time[.]Estimated[.]{3}: [A-Za-z0-9: ]* ([(].*[)])$")
    hashcat_speed_re = re.compile("^Speed[.]#1[.]{9}:[ ]+([0-9]* ?.?H/s)")

    # Cracking variables
    hot_words = ["parola", "password", "wifi"]  # TODO get those from server

    @staticmethod
    def log_fatal(message):
        Configuration.dual_print(Configuration.logger.critical, message)
        sys.exit(-1)


if __name__ == '__main__':
    print("Run main!", file=sys.stderr)
    sys.exit(-1)
