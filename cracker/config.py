import sys
import re
import os
import hashlib
import json

from tempfile import mkstemp
from shutil import which
from comunicator import Comunicator
from process import SingleProcess


class Configuration(object):
    apikey = None
    john_path = None

    config_file = "cracker.conf"
    empty_config = {
        "john_path": "",
	    "apikey": "" }

    # Remote location info
    remote_server = None

    capabilities = dict()
    capab_dirs = ["dict", "dict/generators", "dict/maskfiles"]
    programs = ["hashcat", "john"]

    old_sha1s = None
    sha1s_filename = "crack/sha1s.txt"
    save_result_filename = "crack/saveresult.txt"

    # Cracking paths
    attack_path = 'crack'
    hashcat_potfile_path = os.path.join(attack_path, 'hashcat.pot')

    # Cracking regexes
    hashcat_show_regex = re.compile("[0-9a-f]*[:*][0-9a-f]{12}[:*].*[:*](.*)[\n]?$")
    atoi_regex = re.compile(" *[-]?[0-9]*")

    # Cracking variables
    hot_words = ["parola", "password", "wifi"]  # TODO get those from server
    hashcat_workload = 4

    # Requester messages
    no_work_message = "No work to be done at the moment."
    no_job_message = "No running job on this API key."
    cap_updated = "Capabilities updated!"

    @staticmethod
    def check_file(path, file):
        """
        :param path: The relative path to the file
        :param file: The filename needed for indexing in the capabilities file/dictionary
        :return:
            True If the file has changed since last calculation
            False Otherwise
        """
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
    def test_john():
        """
            Function that tests if john the ripper properly works
            Tests if john can be run and if the setting for running local config files is active

        :return:
            True if john the ripper properly works
            "<ERROR>" otherwise
        """
        # Test if regular john the ripper works
        _, passwd_file = mkstemp(prefix="psknow_crack")

        try:
            with open(passwd_file, "w") as fd:
                fd.write("password\n")

            test_john_runs = "%s --wordlist=%s --stdout --rules=None" % (Configuration.john_path, passwd_file)
            p = SingleProcess(test_john_runs, crit=False)

            p.generate_output()
            retcode = p.poll()
            if retcode != 0:
                return "process '%s' crashed with return code '%d'\nStdout: %s\nStderr: %s" %\
                       (test_john_runs, retcode, p.stdout(), p.stderr())

            test_john_runs = "%s --wordlist=%s --stdout --rules=TestRulePSKnow" % (Configuration.john_path, passwd_file)
            p = SingleProcess(test_john_runs, crit=False)

            p.generate_output()
            retcode = p.poll()
            if 'No "TestRulePSKnow" mode rules found in' in p.stderr():
                return "john-local.conf was not loaded by john. Check the configuration file '%s.conf' and uncomment" \
                       "the line `#.include './john-local.conf'`" % Configuration.john_path

            if retcode != 0:
                return "process '%s' crashed with return code '%d'\nStdout: %s\nStderr: %s" % \
                       (test_john_runs, retcode, p.stdout(), p.stderr())
        except Exception as e:
            raise e
        finally:
            os.remove(passwd_file)

        return True

    @staticmethod
    def test_capabilities():
        """
            Test cracking capabilities and run dummy programs to check for errors
            Removes capabilities from 'capabilities' if the test fails
        :return:
            None
        """
        if "john" in Configuration.capabilities:
            res = Configuration.test_john()
            if res is not True:
                del Configuration.capabilities["john"]
                Comunicator.dual_printer(Comunicator.logger.warn, "John is currently not available:\n%s" % res)

        # if "hashcat" in Configuration.capabilities:
        #     res = Configuration.test_hashcat()
        #     if res is not True:
        #         del Configuration.capabilities["hashcat"]
        #         Comunicator.dual_printer(Comunicator.logger.warn, "Hashcat is not currently available: '%s'" % res)


    @staticmethod
    def gather_capabilities():
        """
            Returns a dictionary of the client capabilities.
            The list has two types of items:
                1) Installed programs in the form of 'program': True
                2) Files in the form of 'filename': sha1hash(file)
            The hashes are used server side to check if the files changed in any way

            This function also calls Configuration.check_file() to check if files changed
            in any way
            :return:
                Dictionary as described above
        """
        sha1_file_changed = False

        # Check if local john configuration exists
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
                Comunicator.fatal_debug_printer("Error trying to dump data in %s: %s" % (Configuration.sha1s_filename, e))

        one_program = False
        for program in Configuration.programs:
            # John path needs to be hardcoded it seems
            # Only the key is relevant for hashcat/john - we mark them with True
            if program == "john":
                if Configuration.john_path is not None:
                    if not os.path.exists(Configuration.john_path):
                        Comunicator.fatal_debug_printer("Supplied john path '%s' is invalid. Check config file!" %
                                                        Configuration.john_path)
                    Configuration.capabilities[program] = True
                    one_program = True
                else:
                    Comunicator.printer("John the ripper not installed, some rules will not run until it is installed and "
                                        "path supplied in config file '%s'" % Configuration.config_file)
                continue

            if which(program) is not None:
                Configuration.capabilities[program] = True
                one_program = True
            else:
                Comunicator.printer("'%s' not installed, some rules will not run until it is installed" % program)

        if not one_program:
            Comunicator.fatal_regular_message("None of the cracking programs are installed, cracking not possible!")

    @staticmethod
    def load_config():
        """
            Loads api key from file defined in variable Configuration.apikey_path.
            Ignores lines prefixed by '#', any leading ' ' and trailing '\n'
            The key is stored in Configuration.apikey
        :return:
            None
        """
        error_string = ""
        try:
            with open(Configuration.config_file) as file:
                config = json.load(file)
                def load_key(lkey):
                    try:
                        return config[lkey], ""
                    except KeyError:
                        return None, "Missing vital information '%s' from config file\n" % lkey

                Configuration.apikey, err = load_key("apikey")
                error_string += err
                Configuration.john_path, err = load_key("john_path")
                error_string += err
                Configuration.remote_server, err = load_key("server_location")
                error_string += err
                Configuration.hashcat_workload, err = load_key("hashcat_workload")
                error_string += err
        except json.decoder.JSONDecodeError as e:
            Comunicator.fatal_regular_message("Configuration file '%s' is not a valid json with error '%s'. Fix"
                                      "file or completely remove to restore to default state." %
                                      (Configuration.config_file, e))
        except FileNotFoundError:
            with open(Configuration.config_file, "w") as fd:
                json.dump(Configuration.empty_config, fd)
            Comunicator.fatal_regular_message("Configuration file '%s' did not exist. Empty file was generated, please"
                                      "fill in data for the cracker to properly work." % Configuration.config_file)
        if len(error_string) > 0:
            if error_string.endswith("\n"):
                error_string = error_string[:-1]
            Comunicator.fatal_regular_message(error_string)

        # Check remote server location
        if Configuration.remote_server is None or len(Configuration.remote_server) < 1:
            Comunicator.fatal_regular_message("Invalid or missing remote server location. Please write server location"
                                              "in configuration file Ex. '\"server_location\": \"http://127.0.0.1:9645/\"'")
        if not (Configuration.remote_server.startswith("https://") or Configuration.remote_server.startswith("http://")):
            Comunicator.fatal_regular_message("Server location should start with either 'https://' or 'http://'")

        if not Configuration.remote_server.endswith("/"):
            Configuration.remote_server += "/"
        Configuration.remote_server += "api/v1/"

        Comunicator.printer("Using remote server '%s'" % Configuration.remote_server)

        # Check hashcat workload
        if type(Configuration.hashcat_workload) is not int:
            Comunicator.fatal_regular_message("Key 'hashcat_workload' from configuration file '%s' has invalid type %s"
                                              " instead of int" % (Configuration.config_file,
                                                                   type(Configuration.hashcat_workload)))
        if Configuration.hashcat_workload < 1 or Configuration.hashcat_workload > 4:
            Comunicator.dual_printer(Comunicator.logger.warn, "Hashcat workload should be 1-4. Value found is %d."
                                                              "Using default 4")
            Configuration.hashcat_workload = 4

        # Check API key
        if Configuration.apikey is None or len(Configuration.apikey) < 10:
            Comunicator.fatal_regular_message("Invalid or missing api key in config file '%s'. Please generate key "
                                      "and write it on the configuration file." % Configuration.config_file)

        # Check john path
        if len(Configuration.john_path) == 0:
            Configuration.john_path = None
        elif not os.path.exists(Configuration.john_path):
            Comunicator.fatal_regular_message("Supplied path for john the ripper '%s' is not valid" % Configuration.john_path)

    @staticmethod
    def load_sha1s():
        """
            To reduce startup time sha1's are stored in the file Configuration.sha1s_filename
            and only recalculated if the file has changed after the hash was calculated.
            This function loads the sha1 hashes along with the time when the hash was calculated into
            the variable Configuration.old_sha1s
        :return:
            None
        """
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
            Comunicator.fatal_debug_printer("Error trying to load %s data: %s" % (Configuration.sha1s_filename, e))

    @staticmethod
    def sha1file(filepath):
        """
            This function calculates the sha1 hexdigest for a given file
        :param filepath: The file for which we calculated the sha1
        :return:
            sha1_hexdigest for given file
        """
        with open(filepath, "rb") as f:
            hash_sha1 = hashlib.sha1()
            for chunk in iter(lambda: f.read(2 ** 20), b""):
                hash_sha1.update(chunk)

        return hash_sha1.hexdigest()

    @staticmethod
    def initialize():
        Configuration.load_config()
        Configuration.load_sha1s()
        Configuration.gather_capabilities()


if __name__ == '__main__':
    print("Run main!", file=sys.stderr)
    sys.exit(-1)
