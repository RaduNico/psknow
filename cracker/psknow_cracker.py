#!/usr/bin/python3

import os
import sys
import inspect
import signal
import stat
import traceback

from time import sleep
from tempfile import mkstemp
from datetime import datetime

from config import Configuration
from process import SingleProcess, DoubleProcess
from scrambler import Scrambler
from requester import Requester
from comunicator import Comunicator


def die(condition, message):
    if condition:
        msg = "File '%s', line %s, in %s: '%s'" %\
              (inspect.getmodule(inspect.stack()[1][0]).__file__, inspect.currentframe().f_back.f_lineno,
               inspect.stack()[1][3], message)
        Comunicator.dual_printer(Comunicator.logger.critical, msg)
        sys.exit(-1)


slow_stop_flag = False


def slow_stop(signum, _):
    global slow_stop_flag

    Comunicator.info_logger("Received %s signal. Slow stopping!" % signum)
    slow_stop_flag = True


def fast_stop():
    if Cracker.crt_process is not None:
        Comunicator.info_logger("Killing running process %s" % Cracker.crt_process.get_command())
        # Kill currently running process
        Cracker.crt_process.terminate()

    # Clean current varibles so all tempfiles are deleted
    Cracker.clean_variables()

    try:
        if Cracker.req is not None:
            Cracker.req.stopwork()
    except Cracker.req.ServerDown:
        pass
    Comunicator.stop()

    sys.exit(0)


def signal_handler(signum, _):
    if signum == signal.SIGINT or signum == signal.SIGTERM:
        Comunicator.info_logger("Received signal %d. Exitting!" % signum)
        fast_stop()
    else:
        Comunicator.info_logger("Received %s signal" % signum)


class Cracker:
    crt_process = None

    attack_command = None

    scrambler = None
    eta_dict = None
    crt_rule = None
    mac_ssid_job = ""

    old_eta = ""
    path_temp_file = None
    crt_workload = None

    capabilities_tested = False

    req = None

    @staticmethod
    def get_attack_command(rule, attack_type, filename, ssid):
        generator = ""
        attack_command = "hashcat -w %d --potfile-path=%s -m 22000" % \
                         (Cracker.crt_workload, Configuration.hashcat_potfile_path)
        scrambler = None

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
            die(True, "Rule error, unknown rule type '%s'" % rule["type"])

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
        Cracker.mac_ssid_job = ""

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
            eta = "Cracking process starting"
        elif Cracker.eta_dict["eta"] != "" and Cracker.eta_dict["eta"] != "(0 secs)":
            eta = Cracker.eta_dict["eta"]
        elif Cracker.eta_dict["speed"] != -1 and Cracker.eta_dict["progress"] != -1:
            # For rules generated at runtime with variable base dictionary length we cannot calculate ETA
            speed = Cracker.eta_dict["speed"]
            if speed != 0:
                if Cracker.crt_rule["wordsize"] < Cracker.eta_dict["progress"]:
                    Comunicator.error_logger("Dict size (%d) seems less than current attacked (%d)" %
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

        try:
            Cracker.req.sendeta(eta)
        except Cracker.req.ServerDown:
            pass

    @staticmethod
    def safe_send_result(password):
        written_flag = False
        while True:
            try:
                res = Cracker.req.sendresult(password)
                die(res is True, "Sending result '%s' for job '%s' produced an error" %
                    (password, Cracker.mac_ssid_job))

                if os.path.exists(Configuration.save_result_filename):
                    os.remove(Configuration.save_result_filename)

                if res is False:
                    Comunicator.warning_logger("Server cancelled last job. Requesting stopwork.")
                    Cracker.req.stopwork()

                break
            except Cracker.req.ServerDown:
                if not written_flag:
                    msg = "Trying to send result '%s' for last job but the server is unreachable" % password
                    Comunicator.dual_printer(Comunicator.logger.warning, msg)
                    written_flag = True
                    with open(Configuration.save_result_filename, "w") as fp:
                        fp.write(password)
                sleep(10)

    @staticmethod
    def process_result():
        # Disable communicator until we start another job
        Comunicator.disable()

        # Check if process exited cleanly
        if Cracker.crt_process is not None:
            Cracker.crt_process.check_clean_exit()
        show_stdout = list(filter(None, SingleProcess(Cracker.attack_command +
                                                      " --show").split_stdout()))
        password = ""

        # Check if we cracked something!
        if len(show_stdout) != 0:
            for line in show_stdout:
                cracked_obj = Configuration.hashcat_show_regex.match(line)
                die(cracked_obj is None, "REGEX error! could not match the --show line:%s" % show_stdout)
                password = cracked_obj.group(1)

        msg = "[FAIL] Password for '%s' is not contained in rule '%s'\n" %\
              (Cracker.mac_ssid_job, Cracker.crt_rule["name"])
        if len(password) > 7:
            msg = "[SUCCESS] The password for '%s' is '%s'\n" % (Cracker.mac_ssid_job, password)

        Comunicator.printer(msg)
        Cracker.safe_send_result(password)

        Cracker.clean_variables()

    @staticmethod
    def is_already_cracked(command):
        show_stdout = list(filter(None, SingleProcess(command + " --show").split_stdout()))

        if len(show_stdout) > 0:
            return True
        return False

    @staticmethod
    def start_cracking(work):
        Cracker.mac_ssid_job = "%s-%s" % (work["handshake"]["mac"], work["handshake"]["ssid"])
        msg = "Running '%s' with rule '%s'" % (Cracker.mac_ssid_job, work["rule"]["name"])
        Comunicator.enable(interactive=False)
        Comunicator.dual_printer(Comunicator.logger.info, msg)

        _, Cracker.path_temp_file = mkstemp(prefix="psknow_crack")

        with open(Cracker.path_temp_file, "w") as fd:
            fd.write(work["handshake"]["data"])

        # Memorize attack type - we need it to decode the output
        attack_type = work["handshake"]["handshake_type"]
        Cracker.crt_rule = work["rule"]

        attacked_file = Cracker.path_temp_file

        # Get commands needed to run hashcat
        generator_command, Cracker.attack_command, Cracker.scrambler =\
            Cracker.get_attack_command(Cracker.crt_rule, attack_type, attacked_file, work["handshake"]["ssid"])

        Comunicator.info_logger("Trying rule %s on '%s-%s'" %
                                (Cracker.crt_rule["name"], work["handshake"]["mac"], work["handshake"]["ssid"]))

        if Cracker.is_already_cracked(Cracker.attack_command):
            Comunicator.warning_logger("'%s' has already been cracked. Attempting to send result." %
                                       Cracker.mac_ssid_job)
            Cracker.process_result()
            return

        if generator_command == "":
            Cracker.crt_process = SingleProcess(Cracker.attack_command)
        else:
            Cracker.crt_process = DoubleProcess(generator_command, Cracker.attack_command)

    @staticmethod
    def do_work():
        # Something just finished!
        if Cracker.crt_process is not None and Cracker.crt_process.isdead():
            Cracker.process_result()

        # Process is still running - update eta
        if Cracker.crt_process is not None:
            Cracker.update_eta()
            return

        if slow_stop_flag:
            Comunicator.info_logger("Slow shutdown signal received - shutting down!")
            sys.exit(0)

        # Before getting more work make sure we are up to date
        Cracker.complete_missing()

        # Test capabilities once
        if not Cracker.capabilities_tested:
            Configuration.test_capabilities()
            Cracker.capabilities_tested = True

        # Nothing is running - getting more work
        try:
            work = Cracker.req.getwork()
        except Cracker.req.ServerDown:
            Comunicator.printer(Comunicator.printer(Requester.DownMessage))
            return

        die(work is True, "A server side error occured while getting work!")

        # No work to be done right now
        if work is None:
            Comunicator.printer("No work to be done, checking in 10 seconds again.")
            return

        # Redundant check
        if work is False:
            Comunicator.warning_logger("Capabilities out of date!")
            return

        # Make status seem a bit more responsive
        Cracker.old_eta = "Cracking process starting"

        Cracker.start_cracking(work)

    @staticmethod
    def complete_missing():
        gather_flag = False
        try:
            missings = Cracker.req.getmissing()
        except Cracker.req.ServerDown:
            return

        die(missings is True, "Server side error occurred.")

        if missings is None:
            return

        for missing in missings:
            if missing["type"] == "program":
                Comunicator.info_logger("Please install program '%s'" % missing["name"])
            elif missing["type"] in ["dict", "maskfile", "generator", "john-local.conf"]:
                Comunicator.dual_printer(Comunicator.logger.info, "Downloading '%s'..." % missing["path"])
                gather_flag = True

                if "/" in missing["path"]:
                    directory, filename = missing["path"].rsplit('/', 1)

                    # Create directory if they do not exist
                    os.makedirs(directory, exist_ok=True)
                else:
                    filename = missing["path"]

                try:
                    if Cracker.req.checkfile(filename) is None and \
                            Cracker.req.getfile(filename, missing["path"]) is None:
                        Comunicator.dual_printer(Comunicator.logger.info, "Downloaded '%s'" % missing["path"])
                        if missing["type"] == "generator":
                            os.chmod(missing["path"], stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
                except Cracker.req.ServerDown:
                    return
            else:
                Comunicator.warning_logger("Unknown missing type '%s'" % missing)

        if gather_flag:
            Configuration.gather_capabilities()

    @staticmethod
    def resume_work():
        if os.path.exists(Configuration.save_result_filename):
            with open(Configuration.save_result_filename) as fp:
                password = fp.read()

            Cracker.safe_send_result(password)
            return

        while True:
            try:
                Cracker.req.stopwork(suppress_stdout=True)
                break
            except Cracker.req.ServerDown:
                Comunicator.printer(Requester.DownMessage)
                sleep(10)
        return

    @staticmethod
    def print_status():
        def pad(msg):
            width = 13
            return msg.ljust(width, '.') + ": "

        def human_format(num):
            magnitude = 0
            while abs(num) >= 1000:
                magnitude += 1
                num /= 1000.0
            # add more suffixes if you need them
            return '%.1f%sH/s' % (num, ['', 'K', 'M', 'G', 'T', 'P'][magnitude])

        def space_format(num):
            return f'{num:,}'

        hashcat_status = Cracker.crt_process.get_dict()
        output = pad("Current rule") + "%s\n" % Cracker.crt_rule["name"]

        output += pad("Eta") + "%s\n" % Cracker.old_eta

        if hashcat_status["speed"] > 0:
            if len(hashcat_status["devices"]) > 2:
                total_speed = -1
                for idx, speed in enumerate(sorted(hashcat_status["devices"].keys())):
                    if total_speed == -1:
                        total_speed = speed
                        continue
                    output += pad("Speed #%d" % idx) + "%s\n" % human_format(speed)
                if total_speed != -1:
                    output += pad("Total Speed") + "%s\n" % human_format(total_speed)
            else:
                output += pad("Total Speed") + "%s\n" % human_format(hashcat_status["speed"])

        if hashcat_status["progress"] > 0:
            progress_len = len(space_format(Cracker.crt_rule["wordsize"]))
            output += pad("Progress") + "%s/%s\n" % (space_format(hashcat_status["progress"]).rjust(progress_len, ' '),
                                                     space_format(Cracker.crt_rule["wordsize"]))

        if output.endswith("\n"):
            output = output[:-1]

        Comunicator.printer(output)

    @staticmethod
    def parse_command(cmd):
        global slow_stop_flag

        if cmd == 's':
            Cracker.print_status()
        elif cmd == 'q':
            Comunicator.printer("Stopping...", reprint=False)
            fast_stop()
        elif cmd == 'f':
            slow_stop_flag = True
            Comunicator.finished = True
            Comunicator.printer("Will finnish current job and stop. Press 'd' to cancel.")
        elif cmd == 'd':
            if Comunicator.finished:
                slow_stop_flag = False
                Comunicator.finished = False
                Comunicator.printer("Finish command cancelled. Will continue working.")
        elif Comunicator.interactive:
            if cmd == 'p':
                # TODO if finished pause might not work...
                Comunicator.paused = True
                Comunicator.printer("Pause command sent to hashcat")
                # TODO send pause command
            elif cmd == 'r':
                # TODO if process stops resume might not work
                Comunicator.paused = False
                Comunicator.printer("Resume command sent to hashcat")
                # TODO send resume command
            elif cmd == 'c':
                # TODO implement checkpoint command
                pass  # checkpoint

    @staticmethod
    def run():
        Comunicator.initialize()

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        Configuration.initialize()
        Cracker.crt_workload = Configuration.hashcat_workload  # TODO maybe adjust from keyboard

        Cracker.req = Requester(Configuration.apikey, Comunicator.error_logger)

        Cracker.resume_work()

        Comunicator.printer("Cracker initialized", reprint=False)

        try:
            # Disable terminal echo
            os.system("stty -echo")

            last_time = None
            while True:
                now_time = datetime.now()
                if last_time is None or (now_time - last_time).total_seconds() > 10:
                    last_time = now_time
                    Cracker.do_work()

                cmd = Comunicator.get_command()
                if cmd is not None:
                    Cracker.parse_command(cmd)
                sleep(0.1)
        except Exception as e:
            Cracker.clean_variables()
            Comunicator.fatal_debug_printer("Caught unexpected exception: '%s' '%s'" % (e, traceback.format_exc()))
        finally:
            # Reenable terminal echo
            os.system("stty echo")
            pass


if __name__ == "__main__":
    Cracker().run()
