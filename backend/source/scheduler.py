import os
import datetime

from .process import Process
from .database_helper import generic_find, update_hs_id
from .config import Configuration

from tempfile import mkstemp
from base64 import b64encode
from copy import deepcopy


class Scheduler:
    default_task = {
        "handshake": {
            "data": "",
            "ssid": "",
            "mac": "",
        },
        "rule": {
            "name": "",
            "type": "",
            "aux_data": "",
            "wordsize": -1
        }
    }

    @staticmethod
    def _reserve_handshake(handshake_id, apikey, rule):
        reserved = dict()
        reserved["date_reserved"] = datetime.datetime.now()
        reserved["apikey"] = apikey
        reserved["status"] = "running"
        reserved["tried_rule"] = rule

        return update_hs_id(handshake_id, {"reserved": reserved, "handshake.active": True,
                                           "handshake.eta": "Not available"})

    @staticmethod
    def release_handshake(handshake_id):
        return update_hs_id(handshake_id, {"reserved": None, "handshake.active": False})

    @staticmethod
    def get_reserved(apikey):
        data, error = generic_find(Configuration.wifis, {"reserved.apikey": apikey}, api_query=True)
        if error:
            return None, "Database error"

        return data, ""

    @staticmethod
    def has_reserved(apikey):
        data, error = Scheduler.get_reserved(apikey)

        result = False if next(data, None) is None else True

        return result, error

    @staticmethod
    def _get_pmkid_mac(file, mac_addr):
        with open(file) as fd:
            for line in fd:
                if line.endswith("\n"):
                    line = line[:-1]
                matchobj = Configuration.pmkid_regex.match(line)
                if matchobj is None:
                    continue
                match_mac = ":".join(a + b for a, b in zip(matchobj.group(1)[::2], matchobj.group(1)[1::2]))
                if mac_addr == match_mac:
                    return line
            return None

    @staticmethod
    def _get_hccapx_data(crt_capture):
        if not os.path.isfile(crt_capture["path"]):
            Configuration.logger.error("File '%s' from id '%s' does not exist." %
                                       (crt_capture['path'], crt_capture["id"]))
            return None

        if crt_capture["file_type"] == "16800":
            return Scheduler._get_pmkid_mac(crt_capture["path"], crt_capture["handshake"]["MAC"])

        _, temp_filename = mkstemp(prefix="psknow_backend")

        if crt_capture["handshake"]["handshake_type"] == "PMKID":
            flag = "-z"
        elif crt_capture["handshake"]["handshake_type"] == "WPA":
            flag = "-o"
        else:
            Configuration.logger.error("Unknown type of attack '%s' in entry '%s'" %
                                       (crt_capture["handshake"]["handshake_type"], crt_capture))
            return None

        mac_addr = crt_capture["handshake"]["MAC"].replace(":", "")

        # Filter packets based on bssid so we attack only one wifi in a file with multiple captures
        hcx_cmd = "hcxpcaptool %s %s %s --filtermac=%s" %\
                  (flag, temp_filename, crt_capture["path"], mac_addr)

        stdout = Process(hcx_cmd, crit=True).stdout()

        if "written to" not in stdout:
            os.remove(temp_filename)
            return None

        with open(temp_filename, "rb") as fd:
            return b64encode(fd.read()).decode("utf8")

    @staticmethod
    def get_next_handshake(apikey):
        error = ""
        task = deepcopy(Scheduler.default_task)

        query = {"handshake.crack_level": {"$lt": Configuration.max_rules, "$gt": -1},
                 "handshake.open": False, "reserved_by": None, "handshake.password": ""}

        with Configuration.wifis_lock:
            entry = next(Configuration.wifis.find(query).sort([("priority", 1), ("handshake.crack_level", 1),
                                                               ("date_added", 1)]), None)

            # min(lst, key=lambda val: a[val])
            if entry is None:
                return task, "No work to be done at the moment."

            query = {"priority": {"$gt": entry["handshake"]["crack_level"], "$lt": Configuration.max_rules}}
            next_rule = next(Configuration.rules.find(query).sort([("priority", 1)]), None)

            if next_rule is None:
                Configuration.logger.error("Next rule was None in query '%s'" % query)
                return task, "Internal server error 101"

            Scheduler._reserve_handshake(entry["id"], apikey, next_rule["name"])

        task["rule"]["wordsize"] = next_rule["wordsize"]
        task["rule"]["type"] = next_rule["type"]
        task["rule"]["name"] = next_rule["name"]

        mapper = {"wordlist": next_rule.get("wordlist", None),
                  "john": next_rule.get("rule", None),
                  "generated": next_rule.get("command", None),
                  "mask_hashcat": next_rule.get("mask_hashcat", None),
                  "filemask_hashcat": next_rule.get("filemask_path", None)}

        task["rule"]["aux_data"] = mapper[next_rule["type"]]

        task["handshake"]["data"] = Scheduler._get_hccapx_data(entry)
        task["handshake"]["ssid"] = entry["handshake"]["SSID"]
        task["handshake"]["mac"] = entry["handshake"]["MAC"]
        task["handshake"]["file_type"] = entry["file_type"]
        task["handshake"]["handshake_type"] = entry["handshake"]["handshake_type"]

        if task["handshake"]["data"] is None:
            error = "Error getting handshake data from file."
            Scheduler.release_handshake(entry["id"])

        return task, error

    @staticmethod
    def get_specific_handshake():

        # Cracker.crt_capture = next(capture_cursor, None)
        # if Cracker.crt_capture is None:
        #     return

        return False
