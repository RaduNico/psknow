import sys
import logbook
import re
import os
import hashlib
import json
from shutil import which


class Configuration(object):
    apikey = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJ1c2VyIjoicmFkdSIsImRhdGVfZ2VuZXJhdGVkIjoiMjAxOS0wOS0wOFQxOTo" \
             "0Mzo1My4yNTExNDQiLCJrZXlfaWQiOiIxMDAwIiwibmFtZSI6Im11aWUifQ.opggNbRjlkv2S3GzzyK145CDKmZrzuoR9xxKZkFr" \
             "HjnSpIfwaTO5G-wvu5AENUknItPePFrRTKd_ZIzaOq5MeQ"
    john_path = "/home/pandora/sec/psknow/dependencies/sources/john/run/john"

    # Remote location info
    # remote_server = "https://pandorak.go.ro/api/v1/"
    remote_server = "http://127.0.0.1:9645/api/v1/"
    capabilities = []
    capab_dirs = ["dict", "dict/generators", "dict/maskfiles"]
    programs = ["hashcat", "john"]

    # Logging variables
    log_filename = 'logs/cracker.log'
    logLevel = "DEBUG"
    # :logLevel = "INFO"
    logger = None

    old_sha1s = None
    sha1s_filename = "crack/sha1s.txt"
    save_result_filename = "crack/saveresult.txt"

    default_hashcat_dict = {"progress": -1, "eta": "", "speed": ""}

    # Cracking paths
    attack_path = 'crack'
    hashcat_potfile_path = os.path.join(attack_path, 'hashcat.pot')

    # Cracking regexes
    hashcat_show_regex = re.compile("[0-9a-f]*[:*][0-9a-f]{12}[:*][0-9a-f]{12}[:*].*[:*](.*)[\n]?$")
    atoi_regex = re.compile(" *[-]?[0-9]*")

    hashcat_progress_re = re.compile("^Progress[.]{9}: ([0-9]*)$")
    hashcat_eta_re = re.compile("^Time[.]Estimated[.]{3}: [A-Za-z0-9: ]* ([(].*[)])$")
    hashcat_speed_re = re.compile("^Speed[.]#1[.]{9}:[ ]+([0-9]* ?.?H/s)")

    # Cracking variables
    hot_words = ["parola", "password", "wifi"]  # TODO get those from server

    # Requester messages
    no_work_message = "No work to be done at the moment."
    no_job_message = "No running job on this API key."
    cap_updated = "Capabilities updated!"

    @staticmethod
    def dual_print(log, message):
        log(message)
        print(message)

    @staticmethod
    def check_file(path, file):
        flag = False
        new_mtime = os.stat(path).st_mtime

        # If sha1 was calculated before and the file was not changed use last modification
        if file in Configuration.old_sha1s and Configuration.old_sha1s[file]["last_change"] == new_mtime:
            Configuration.capabilities[file] = Configuration.old_sha1s[file]["sha1"]
        else:
            print("calculating sha1 for %s" % file)
            flag = True
            sha1 = Configuration.sha1file(path)
            Configuration.capabilities[file] = sha1
            Configuration.old_sha1s[file] = {"last_change": new_mtime, "sha1": sha1}

        return flag

    @staticmethod
    def gather_capabilities():
        Configuration.capabilities = {}
        sha1_file_changed = False

        if os.path.isfile("john-local.conf") and Configuration.check_file("john-local.conf", "john-local.conf"):
            sha1_file_changed = True

        for directory in Configuration.capab_dirs:
            if not os.path.isdir(directory):
                continue

            all_files = os.listdir(directory)

            for file in all_files:
                path = os.path.join(directory, file)
                if os.path.isfile(path) and not file.startswith("."):
                    if Configuration.check_file(path, file):
                        sha1_file_changed = True

        if sha1_file_changed:
            try:
                with open(Configuration.sha1s_filename, "w+") as fd:
                    json.dump(Configuration.old_sha1s, fd, indent=4)
            except Exception as e:
                Configuration.log_fatal("Error trying to dump data in %s: %s" % (Configuration.sha1s_filename, e))

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
    def load_sha1s():
        Configuration.old_sha1s = {}
        if not os.path.exists(Configuration.sha1s_filename):
            with open(Configuration.sha1s_filename, "w+") as _:
                return

        try:
            with open(Configuration.sha1s_filename) as fd:
                Configuration.old_sha1s = json.load(fd)
        except json.decoder.JSONDecodeError:
            return
        except Exception as e:
            Configuration.log_fatal("Error trying to load %s data: %s" % (Configuration.sha1s_filename, e))

    @staticmethod
    def sha1file(filepath):
        with open(filepath, "rb") as f:
            hash_sha1 = hashlib.sha1()
            for chunk in iter(lambda: f.read(2 ** 20), b""):
                hash_sha1.update(chunk)

        return hash_sha1.hexdigest()

    @staticmethod
    def initialize():
        Configuration.setup_logging()
        Configuration.load_sha1s()
        Configuration.gather_capabilities()

    @staticmethod
    def log_fatal(message):
        Configuration.dual_print(Configuration.logger.critical, message)
        sys.exit(-1)


if __name__ == '__main__':
    print("Run main!", file=sys.stderr)
    sys.exit(-1)
