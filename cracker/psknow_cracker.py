#!/usr/bin/python3

import os
import sys
import inspect
import signal
import stat

from time import sleep
from tempfile import mkstemp
from base64 import b64decode

from config import Configuration
from process import SingleProcess, DoubleProcess
from scrambler import Scrambler
from requester import Requester


def die(condition, message):
    if condition:
        Configuration.logger.critical("line %s in function %s, error %s" %
                                      (inspect.currentframe().f_back.f_lineno, inspect.stack()[1][3], message))
        sys.exit(-1)


slow_stop_flag = False


def slow_stop(signum, _):
    global slow_stop_flag

    Configuration.logger.info("Received %s signal. Slow stopping!" % signum)
    slow_stop_flag = True


def fast_stop():
    if Cracker.crt_process is not None:
        Configuration.logger.info("Killing running process %s" % Cracker.crt_process.get_command())
        # Kill currently running process
        Cracker.crt_process.terminate()

        # Clean current varibles so all tempfiles are deleted
        Cracker.clean_variables()

    Requester.stopwork()


def signal_handler(signum, _):
    if signum == signal.SIGINT or signum == signal.SIGTERM:
        Configuration.logger.info("Received signal %d. Exitting!" % signum)
        fast_stop()

        sys.exit(0)
    else:
        Configuration.logger.info("Received %s signal" % signum)


class Cracker:
    crt_process = None

    attack_command = None
    scrambler = None
    eta_dict = None
    crt_rule = None

    old_eta = ""
    path_temp_file = None
    crt_workload = None  # TODO make adjustable at start

    @staticmethod
    def get_attack_command(rule, attack_type, filename, ssid):
        generator = ""
        attack_command = "hashcat -w %d --potfile-path=%s" % \
                         (Cracker.crt_workload, Configuration.hashcat_potfile_path)
        scrambler = None

        # Append hash identification based on attack type
        if attack_type == "PMKID":
            attack_command += " -m 16800"
        elif attack_type == "WPA":
            attack_command += " -m 2500"
        else:
            die(True, "Unsupported attack type %s" % attack_type)

        # Translate rule type to command
        if rule["type"] == "generated":
            generator = rule["aux_data"]

        elif rule["type"] == "john":
            generator = "%s --min-length=8 --wordlist=%s --rules=%s --stdout" %\
                        (Configuration.john_path, rule["aux_data"]["baselist"], rule["aux_data"]["rule"])

        elif rule["type"] == "scrambler":
            scrambler = Scrambler(ssid)
            generator = "%s --min-length=8 --wordlist=%s --rules=Jumbo --stdout" %\
                        (Configuration.john_path, scrambler.get_high_value_tempfile())

        elif rule["type"] == "wordlist" or rule["type"] == "mask_hashcat" or rule["type"] == "filemask_hashcat":
            pass

        else:
            die(True, "Rules error! Unknows rule type %s" % rule["type"])

        attack_command += " " + filename

        # Append the wordlist after the cracked file
        if rule["type"] == "wordlist":
            attack_command += " " + rule["aux_data"]
            generator = ""

        if rule["type"] == "mask_hashcat" or rule["type"] == "filemask_hashcat":
            attack_command += " -a 3 " + rule["aux_data"]

        else:
            attack_command += " -a 0"

        return generator, attack_command, scrambler

    @staticmethod
    def clean_variables():
        Cracker.crt_process = None

        if Cracker.path_temp_file is not None:
            os.remove(Cracker.path_temp_file)
        Cracker.path_temp_file = None

        Cracker.attack_command = None
        Cracker.scrambler = None  # Deletes the tempfile
        Cracker.eta_dict = None
        Cracker.crt_rule = None

    @staticmethod
    def seconds_to_time(seconds):
        if seconds < 0:
            return "(0 secs)"
        m, s = divmod(int(seconds), 60)
        h, m = divmod(m, 60)
        d, h = divmod(h, 24)

        if d != 0:
            return "(%d days, %d hrs)" % (d, h)
        if h != 0:
            return "(%d hrs, %d mins)" % (h, m)
        if m != 0:
            return "(%d mins, %d secs)" % (m, s)
        return "(%d secs)" % s

    @staticmethod
    def update_eta():
        new_eta_dict = Cracker.crt_process.get_dict()

        if Cracker.eta_dict is None:
            is_changed = True
        else:
            is_changed = False
            for key, value in new_eta_dict.items():
                if value != Cracker.eta_dict[key]:
                    is_changed = True
                    break

        # If no changes were made no updates are necessary
        if not is_changed:
            return

        Cracker.eta_dict = new_eta_dict
        # TODO This message is wrongly displayed right around when a hashcat process stops
        eta = "Error calculating ETA"

        # TODO maksfile eta is not properly calculated because hashcat outputs eta for current queue
        # TODO each mask has it's own queue
        # TODO implement rule 5 with hashcat only
        if Cracker.crt_rule["type"] == "filemask_hashcat" or Cracker.crt_rule["wordsize"] <= 0:
            eta = "No ETA available"
        elif Cracker.eta_dict["progress"] == -1 and Cracker.eta_dict["eta"] == "":
            eta = "Calculating ETA"
        elif Cracker.eta_dict["eta"] != "" and Cracker.eta_dict["eta"] != "(0 secs)":
            eta = Cracker.eta_dict["eta"]
        elif Cracker.eta_dict["speed"] != "" and Cracker.eta_dict["progress"] != -1:
            # For rules generated at runtime with variable base dictionary length we cannot calculate ETA
            # TODO speed could be in kH - adjust for that
            speed = int(Configuration.atoi_regex.match(Cracker.eta_dict["speed"]).group())
            if speed != 0:
                if Cracker.crt_rule["wordsize"] < Cracker.eta_dict["progress"]:
                    Configuration.logger.error("Dict size (%d) seems less than current attacked (%d)" %
                                               (Cracker.crt_rule["wordsize"], Cracker.eta_dict["progress"]))

                eta_seconds = (Cracker.crt_rule["wordsize"] - Cracker.eta_dict["progress"]) / speed
                eta = Cracker.seconds_to_time(eta_seconds)
            else:
                eta = "Generating dict..."

        # Check if the eta already has the desired value in order to avoid an update
        # Usually happens when 'Cracker.crt_rule["wordsize"] <= 0'
        if Cracker.old_eta == eta:
            return

        Cracker.old_eta = eta

        Requester.sendeta(eta)

    @staticmethod
    def crack_existing_handshakes():
        # Something just finished!
        if Cracker.crt_process is not None and Cracker.crt_process.isdead():
            # Check if process exited cleanly
            Cracker.crt_process.check_clean_exit()
            show_stdout = list(filter(None, SingleProcess(Cracker.attack_command +
                                                          " --show").split_stdout()))

            # Check if we cracked something!
            if len(show_stdout) != 0:
                cracked_obj = Configuration.hashcat_show_regex.match(show_stdout)
                die(cracked_obj is None, "REGEX error! could not match the --show line:%s" % show_stdout)

                Requester.sendresult(cracked_obj.group(1))
            else:
                Requester.sendresult("")

            Cracker.clean_variables()

        # Process is still running - update eta
        if Cracker.crt_process is not None:
            Cracker.update_eta()
            return

        if slow_stop_flag:
            Configuration.logger.info("Slow shutdown signal received - shutting down!")
            sys.exit(0)

        # Before getting more work make sure we are up to date
        Cracker.complete_missing()

        # Nothing is running - getting more work
        work = Requester.getwork()

        die(work is True, "An error occured while getting work!")

        # No work to be done right now
        if work is None:
            return

        # Redundant check
        if work is False:
            Configuration.dual_print(Configuration.logger.warning, "Capabilities out of date!")
            return

        _, Cracker.path_temp_file = mkstemp(prefix="psknow_crack")

        if work["handshake"]["file_type"] == "16800":
            with open(Cracker.path_temp_file, "w") as fd:
                fd.write(work["handshake"]["data"])
        else:
            with open(Cracker.path_temp_file, "wb") as fd:
                fd.write(b64decode(work["handshake"]["data"].encode("utf8")))

        # Memorize attack type - we need it to decode the output
        attack_type = work["handshake"]["handshake_type"]
        Cracker.crt_rule = work["rule"]

        attacked_file = Cracker.path_temp_file

        # Get commands needed to run hashcat
        generator_command, Cracker.attack_command, Cracker.scrambler =\
            Cracker.get_attack_command(Cracker.crt_rule, attack_type, attacked_file, work["handshake"]["ssid"])

        Configuration.logger.info("Trying rule %s on '%s-%s'" %
                                  (Cracker.crt_rule["name"], work["handshake"]["mac"], work["handshake"]["ssid"]))
        if generator_command == "":
            Cracker.crt_process = SingleProcess(Cracker.attack_command)
        else:
            Cracker.crt_process = DoubleProcess(generator_command, Cracker.attack_command)

    @staticmethod
    def complete_missing():
        gather_flag = False
        missings = Requester.getmissing()

        if missings is None:
            return

        for missing in missings:
            if missing["type"] == "program":
                Configuration.dual_print(Configuration.logger.info, "Please install program '%s'" % missing["name"])
            elif missing["type"] in ["dict", "maskfile", "generator", "john-local.conf"]:
                Configuration.dual_print(Configuration.logger.info, "Downloading '%s'..." % missing["path"])

                gather_flag = True

                if "/" in missing["path"]:
                    directory, filename = missing["path"].rsplit('/', 1)

                    # Create directory if they do not exist
                    os.makedirs(directory, exist_ok=True)
                else:
                    filename = missing["path"]
                    print(filename)

                if Requester.checkfile(filename) is not None and \
                        Requester.getfile(filename, missing["path"]) is not None:
                    Configuration.dual_print(Configuration.logger.info, "Downloaded '%s'" % missing["path"])
                    if missing["type"] == "generator":
                        os.chmod(missing["path"], stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            else:
                Configuration.dual_print(Configuration.logger.warning, "Unknown missing type '%s'" % missing)

        if gather_flag:
            Configuration.gather_capabilities()

    @staticmethod
    def resume_work():
        Requester.stopwork()
        return

    @staticmethod
    def run():
        Configuration.initialize()
        Cracker.crt_workload = 4  # TODO get value from parameters, adjust from keyboard

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Cracker.resume_work()

        while True:
            Cracker.crack_existing_handshakes()
            sleep(10)


if __name__ == "__main__":
    Cracker().run()
