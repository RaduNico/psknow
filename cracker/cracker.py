#!/usr/bin/python3

import os
import sys
import inspect
import signal
from datetime import datetime
from os import path
from config import Configuration
from tempfile import mkstemp
from process import SingleProcess, DoubleProcess
from time import sleep
from scrambler import Scrambler


def append_number_beforeext(filename, number):
    position = filename.rfind('.')
    return filename[:position] + str(number) + filename[position:]


def die(condition, message):
    if condition:
        Configuration.myLogger.critical("line %s in function %s, error %s" %
                                        (inspect.currentframe().f_back.f_lineno, inspect.stack()[1][3], message))
        sys.exit(-1)


slow_stop_flag = False


def slow_stop(signum, _):
    global slow_stop_flag

    Configuration.myLogger.info("Received %s signal. Slow stopping!" % signum)
    slow_stop_flag = True


def fast_stop():
    # Set all database entries to active : false
    cursor = Configuration.wifis.find({"handshakes.active": True})
    entries = cursor[:]

    # TODO do this as a sanity check at start
    for entry in entries:
        for handshake in entry["handshakes"]:
            if handshake["active"]:
                Configuration.myLogger.info("Setting (%s, %s) to inactive" % (handshake["SSID"], handshake["MAC"]))
                handshake["active"] = False
        Cracker.update_handshake(entry["id"], entry["handshakes"])

    if Cracker.crt_process is not None:
        Configuration.myLogger.info("Killing running process %s" % Cracker.crt_process.get_command())
        # Kill currently running process
        Cracker.crt_process.terminate()

        # Clean current varibles so cracking does not advance
        Cracker.clean_variables()


def signal_handler(signum, _):
    if signum == signal.SIGINT or signum == signal.SIGTERM:
        Configuration.myLogger.info("Received signal %d. Exitting!" % signum)
        fast_stop()

        sys.exit(0)
    else:
        Configuration.myLogger.info("Received %s signal" % signum)


class Cracker:
    crt_capture = None
    crt_process = None
    crt_workload = None
    path_temp_file = None
    to_crack = None
    attack_command = None
    scrambler = None
    eta_dict = None
    crt_rule = None

    @staticmethod
    def update_handshake(handshake_id, handshakes):
        # TODO make sanity check stricter
        die(type(handshakes) is not list or "password" not in handshakes[0],
            "The varialbe %s does not seem to be handshake list" % handshakes)
        Configuration.myLogger.debug("Updating document id='%s' with data handshakes='%s'" % (handshake_id, handshakes))

        upd = Configuration.wifis.update({"id": handshake_id}, {"$set": {"handshakes": handshakes}})
        die(not upd["updatedExisting"], "Failed to update document handshake = '%s' with ID = '%s' with message '%s'"
            % (handshakes, handshake_id, upd))
        die(upd["nModified"] > 1, "Database error! Multiple IDs %s present!" % handshake_id)

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
            die(True, "Database error! Unsupported attack type %s" % attack_type)

        # Translate rule type to command
        if rule["type"] == "generated":
            generator = rule["command"]

        elif rule["type"] == "john":
            generator = "%s --min-length=8 --wordlist=%s --rules=%s --stdout"\
                % (Configuration.john_path, rule["baselist"], rule["rule"])

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
            attack_command += " " + rule["wordlist"]
            generator = ""

        if rule["type"] == "mask_hashcat":
            attack_command += " -a 3 " + rule["mask_hashcat"]
        elif rule["type"] == "filemask_hashcat":
            attack_command += " -a 3 " + rule["filemask_path"]
        else:
            attack_command += " -a 0"

        return generator, attack_command, scrambler

    @staticmethod
    def get_mac_password(line):
        cracked_obj = Configuration.hashcat_show_regex.match(line)
        die(cracked_obj is None, "REGEX error! could not match the --show line:%s" % line)

        return cracked_obj.group(1), cracked_obj.group(2)

    @staticmethod
    def get_hccapx_file(attack_type, filepath, filter_mac=None):
        _, temp_filename = mkstemp(prefix="psknow_crack")
        extract_file = filepath
        intermediary_file = None

        # Filter packets based on bssid so we attack only one wifi in a file with multiple captures
        if filter_mac is not None:
            _, intermediary_file = mkstemp(prefix="psknow_crack")

            filter_cmd = "tshark -r %s -Y wlan.bssid==%s -w %s -F pcap" % (filepath, filter_mac, intermediary_file)

            x = SingleProcess(filter_cmd)
            x.generate_output()
            extract_file = intermediary_file

        # Memorize name so we can later delete it
        flag = ""
        if attack_type == "PMKID":
            flag = "-z"
        elif attack_type == "WPA":
            flag = "-o"
        else:
            die(True, "Unsupported attack type %s" % attack_type)

        # Conversion to hccapx
        die(not os.path.isfile(extract_file), "File %s does not exist!" % extract_file)
        stdout = SingleProcess(["hcxpcaptool", flag, temp_filename, extract_file]).stdout()

        if intermediary_file is not None:
            os.remove(intermediary_file)

        if "written to" not in stdout:
            os.remove(temp_filename)
            return None

        return temp_filename

    # Test a document against the hashcat.pot file
    # TODO Add a handshakes field in the database and store pointers to those handshakes in wifis. Should help with
    # TODO duplicating (so for example we do not attack the same bssid two times)
    # TODO only check a type if a handshake is present
    @staticmethod
    def already_cracked(document):
        if document["file_type"] not in Configuration.accepted_extensions:
            return 0

        # We count how many already cracked files we got
        counter = 0

        if document["file_type"] == "16800":
            show_command = "hashcat --potfile-path=%s --show -m 16800 %s" % \
                           (Configuration.hashcat_potfile_path, document["path"])
            cracked_targets = list(filter(None, SingleProcess(show_command).split_stdout()))
            for cracked_target in cracked_targets:
                cracked_mac, cracked_pass = Cracker.get_mac_password(cracked_target)

                for target in document["handshakes"]:
                    if target["MAC"].replace(":", "") == cracked_mac and target["password"] == "":
                        Configuration.myLogger.info("Already cracked pmkid '%s' - '%s': '%s' - id_orig '%s'" %
                                                    (target["SSID"], target["MAC"], cracked_pass, document["id"]))
                        counter += 1
                        target["password"] = cracked_pass
                        target["date_cracked"] = datetime.now()

            if counter != 0:
                Cracker.update_handshake(document["id"], document["handshakes"])

        else:
            hs_types = ["PMKID", "WPA"]

            # Try for both PMKID and WPA
            # TODO this check should be performed on type
            for hs_type in hs_types:
                temp_filename = Cracker.get_hccapx_file(hs_type, document["path"])

                Configuration.myLogger.debug("Got temp_filename='%s'" % temp_filename)

                if temp_filename is None:
                    continue

                crack_type = "-m 16800" if hs_type == "PMKID" else "-m 2500"
                show_command = "hashcat --potfile-path=%s --show %s %s" %\
                               (Configuration.hashcat_potfile_path, crack_type, temp_filename)

                # Test with hashcat if we already cracked the files
                cracked_targets = list(filter(None, SingleProcess(show_command).split_stdout()))
                for cracked_target in cracked_targets:
                    cracked_mac, cracked_pass = Cracker.get_mac_password(cracked_target)

                    for target in document["handshakes"]:
                        if target["MAC"].replace(":", "") == cracked_mac and target["password"] == "":
                            Configuration.myLogger.info("Already cracked handshake '%s' - '%s': '%s' - id_orig '%s'" %
                                                        (target["SSID"], target["MAC"], cracked_pass, document["id"]))
                            counter += 1
                            target["password"] = cracked_pass
                            target["date_cracked"] = datetime.now()

                os.remove(temp_filename)
                if counter != 0:
                    Cracker.update_handshake(document["id"], document["handshakes"])

        return counter

    @staticmethod
    def clean_variables():
        Cracker.crt_capture = None
        Cracker.crt_process = None

        # TODO create a tmp file directory so we can delete all tempfiles properly in case of crash
        if Cracker.path_temp_file is not None:
            os.remove(Cracker.path_temp_file)
        Cracker.path_temp_file = None
        Cracker.to_crack = None
        Cracker.attack_command = None
        Cracker.scrambler = None
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
        eta = "Error calculating ETA"

        # TODO maksfile eta is not properly calculated because hashcat outputs eta for current queue
        # TODO each mask has it's own queue
        if Cracker.crt_rule["type"] == "filemansk_hashcat":
            eta = "No ETA available"
        elif Cracker.eta_dict["progress"] == -1 and Cracker.eta_dict["eta"] == "":
            eta = "Calculating ETA"
        elif Cracker.eta_dict["eta"] != "" and Cracker.eta_dict["eta"] != "(0 secs)":
            eta = Cracker.eta_dict["eta"]
        elif Cracker.eta_dict["speed"] != "" and Cracker.eta_dict["progress"] != -1:
            # For rules generated at runtime with variable base dictionary length we cannot calculate ETA
            # TODO implement rule 5 with hashcat only
            if Cracker.crt_rule["wordsize"] <= 0:
                eta = "No ETA available"
            else:
                # TODO speed could be in kH - adjust for that
                speed = int(Configuration.atoi_regex.match(Cracker.eta_dict["speed"]).group())
                if speed != 0:
                    if Cracker.crt_rule["wordsize"] < Cracker.eta_dict["progress"]:
                        Configuration.myLogger.error("Dict size (%d) seems less than current attacked (%d)" %
                                                     (Cracker.crt_rule["wordsize"], Cracker.eta_dict["progress"]))

                    eta_seconds = (Cracker.crt_rule["wordsize"] - Cracker.eta_dict["progress"]) / speed
                    eta = Cracker.seconds_to_time(eta_seconds)
                else:
                    eta = "Generating dict..."

        for target in Cracker.crt_capture["handshakes"]:
            if target["active"] is True:
                # Check if the eta already has the desired value in order to avoid an update
                # Usually happens when 'Cracker.crt_rule["wordsize"] <= 0'
                if target["eta"] == eta:
                    return
                target["eta"] = eta

        Cracker.update_handshake(Cracker.crt_capture["id"], Cracker.crt_capture["handshakes"])

    @staticmethod
    def crack_existing_handshakes():
        # Something just finished!
        if Cracker.crt_process is not None and Cracker.crt_process.isdead():
            # Check if process exited cleanly
            Cracker.crt_process.check_clean_exit()
            show_stdout = list(filter(None, SingleProcess(Cracker.attack_command +
                                                          " --show").split_stdout()))
            left_stdout = list(filter(None, SingleProcess(Cracker.attack_command +
                                                          " --left").split_stdout()))

            # Check if we cracked something!
            if len(left_stdout) != len(Cracker.to_crack):
                initial_macs = []
                for initial_uncracked in Cracker.to_crack:
                    initial_macs.append(Configuration.hashcat_left_regex.match(initial_uncracked).group(1))

                for cracked_target in show_stdout:
                    cracked_mac, cracked_pass = Cracker.get_mac_password(cracked_target)

                    # Check if this cracked MAC is freshly aquired
                    if cracked_mac in initial_macs:

                        # Iterate through capture
                        for target in Cracker.crt_capture["handshakes"]:
                            if target["MAC"].replace(":", "") == cracked_mac:
                                Configuration.myLogger.info("Cracked handshake '%s' - '%s': '%s'" %
                                                            (target["SSID"], target["MAC"], cracked_pass))
                                target["password"] = cracked_pass
                                target["date_cracked"] = datetime.now()
                                target["crack_level"] = Cracker.crt_rule["priority"]
                                target["active"] = False

            # Iterate all targets and make them inactive
            for target in Cracker.crt_capture["handshakes"]:
                if target["active"] is True:
                    target["crack_level"] =Cracker.crt_rule["priority"]
                target["active"] = False

            Cracker.update_handshake(Cracker.crt_capture["id"], Cracker.crt_capture["handshakes"])

            Cracker.clean_variables()

        # If a process is still running don't try to schedule a new one
        # Update eta for current process
        if Cracker.crt_process is not None:
            Cracker.update_eta()
            return

        if slow_stop_flag:
            Configuration.myLogger.info("Slow shutdown signal received - shutting down!")
            sys.exit(0)

        # Nothing is running now....let's fix that!
        # TODO make a Scheduler class and move this code in a schedule function

        # TODO There is a bug that only happens when multiple handshakes are present in a file:
        # TODO The first element returned by the capture cursor will be the one with the lowest crack_level
        # TODO but it can be one with an already cracked password
        capture_cursor = Configuration.wifis.find(
            {"handshakes": {"$elemMatch": {"$and": [{"crack_level": {"$lt": Configuration.max_rules, "$gt": -1}},
                                                    {"open": False}, {"password": ""}]}}}).\
            sort([("priority", 1), ("handshakes.crack_level", 1)])

        Cracker.crt_capture = next(capture_cursor, None)
        if Cracker.crt_capture is None:
            return

        # See if the current found document has any already cracked files
        if Cracker.already_cracked(Cracker.crt_capture) != 0:
            return

        # Filter out open and cracked handshakes from handshake list
        available_handshakes =\
            [x for x in Cracker.crt_capture["handshakes"] if x["password"] == "" and
             x["open"] is False and
             x["crack_level"] < Configuration.max_rules]

        # Sort the target list so we get the lowest crack_level (easiest to crack)
        target_handshake = sorted(available_handshakes, key=lambda elem: elem["crack_level"])[0]

        # Memorize attack type - we need it to decode the output
        attack_type = target_handshake["handshake_type"]
        Cracker.crt_rule = Configuration.get_next_rules_data(target_handshake["crack_level"])

        # Sanity check
        die(Cracker.crt_rule is None, "No next rule found - target is curretly at maximum level!")

        # Set attacked file base on file type - if it is a (p)cap we need to convert it
        if Cracker.crt_capture["file_type"] == "16800":
            attacked_file = Cracker.crt_capture["path"]
        else:
            # Create a file in which we put the hccapx converted file
            Cracker.path_temp_file = Cracker.get_hccapx_file(attack_type, Cracker.crt_capture["path"],
                                                             filter_mac=target_handshake["MAC"])

            # Sanity check. Should never happen because we filter all entries at upload
            die(Cracker.path_temp_file is None, "Invalid handshake in file %s. Could not convert to hccapx" %
                Cracker.crt_capture["path"])

            attacked_file = Cracker.path_temp_file

        # Get commands needed to run hashcat
        generator_command, Cracker.attack_command, Cracker.scrambler =\
            Cracker.get_attack_command(Cracker.crt_rule, attack_type, attacked_file, target_handshake["SSID"])

        Cracker.to_crack = list(filter(None, SingleProcess(Cracker.attack_command +
                                                           " --left").split_stdout()))

        # Sanity check. Should never happen because we filter all entries at upload
        die(len(Cracker.to_crack) == 0, "There are no networks to be attacked in document id='%s'!" %
            Cracker.crt_capture["id"])

        display_targets = []
        for target_left in Cracker.to_crack:
            group_obj = Configuration.hashcat_left_regex.match(target_left)
            die(group_obj is None, "REGEX error! could not match the --left line:%s" % target_left)

            essid = group_obj.group(2)
            if attack_type == "PMKID":
                essid = bytearray.fromhex(group_obj.group(2)).decode()

            mac = ""
            for target in Cracker.crt_capture["handshakes"]:
                # Attack only targets we detect as being uncracked
                if group_obj.group(1) == target["MAC"].replace(":", ""):
                    mac = target["MAC"]
                    target["active"] = True
                    target["eta"] = "Getting ETA..."

            # TODO duplicates will be present if a capture file has multiple handshakes
            display_targets.append("(" + mac + ", " + essid + ")")

        Cracker.update_handshake(Cracker.crt_capture["id"], Cracker.crt_capture["handshakes"])

        Configuration.myLogger.info("Trying rule %d on %s" % (Cracker.crt_rule["priority"], ', '.join(display_targets)))
        if generator_command == "":
            Cracker.crt_process = SingleProcess(Cracker.attack_command)
        else:
            Cracker.crt_process = DoubleProcess(generator_command, Cracker.attack_command)

    @staticmethod
    def get_new_handshakes():
        # TODO Check for identical duplicates!
        filenames = [f for f in os.listdir(Configuration.backend_handshake_path) if
                     path.isfile(path.join(Configuration.backend_handshake_path, f))]

        # Relocate all files from webservice to final location
        for file in filenames:
            # Log in mongo!
            document = Configuration.wifis.find_one({'path': file})

            if document is None:
                Configuration.myLogger.warning("Found file '%s' "
                                               "which is not in database! Moving to escapes" % file)
                os.rename(path.join(Configuration.backend_handshake_path, file),
                          os.path.join(Configuration.escapes_path, file))
                continue

            filename = file
            number = 0
            position = filename.rfind('.')
            while True:
                newpath = path.join(Configuration.handshake_path, filename)
                if not path.isfile(newpath):
                    # Change path
                    document["path"] = newpath
                    for handshake in document["handshakes"]:
                        handshake["crack_level"] = 0

                    # document["location"]["address"] = #TODO get city/address based on coordinates

                    Configuration.myLogger.info("New handshake! Path is '%s'" % newpath)
                    os.rename(path.join(Configuration.backend_handshake_path, file), newpath)
                    break
                number = number + 1
                filename = file[:position] + str(number).rjust(3, '0') + file[position:]

            upd = Configuration.wifis.update({"id": document["id"]}, document)

            die(not upd["updatedExisting"], "Failed to update moving document = '%s' with ID = '%s' with message '%s'" %
                (document, document["id"], upd))
            die(upd["nModified"] > 1, "Database error! Multiple IDs %s present!" % document["id"])

            Cracker.already_cracked(document)

    @staticmethod
    def update_admin_table():
        admin_table = Configuration.get_admin_table()

        Cracker.crt_workload = int(admin_table["workload"])
        if admin_table["force"]:
            Configuration.myLogger.info("Force restarting current cracking process!")
            fast_stop()

    @staticmethod
    def run():
        Configuration.initialize()

        admin_table = Configuration.get_admin_table()
        Cracker.crt_workload = int(admin_table["workload"])

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        while True:
            Cracker.get_new_handshakes()
            Cracker.crack_existing_handshakes()
            Cracker.update_admin_table()
            sleep(3)


if __name__ == "__main__":
    Cracker().run()
