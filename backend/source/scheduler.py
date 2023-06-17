import os
import datetime

from .process import Process
from .database_helper import generic_find, update_hs_id
from .config import Configuration

from tempfile import NamedTemporaryFile
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
    def _filter_22000hash_filter_mac(hashes, mac_addr):
        for line in hashes:
            if line.endswith("\n"):
                line = line[:-1]

            # Match based on the 22000 format regex
            matchobj = Configuration.regex_22000.match(line)
            if matchobj is None:
                continue

            # Group 2 is the position where the AP MAC is stored
            match_mac = ":".join(a + b for a, b in zip(matchobj.group(2)[::2], matchobj.group(2)[1::2]))
            if mac_addr == match_mac:
                return line
        return None

    @staticmethod
    def _get_22000hash_from_16800_filter_mac(file, mac_addr):
        """ return 22000 hash from a .16800 file that matches the given MAC """

        tmp_file = NamedTemporaryFile(prefix="psknow_backend_get22000_from16800",
                                      delete = False, dir = Configuration.tempfile_dir)

        temp_22000_filename = tmp_file.name

        try:
            cmd = "hcxmactool --pmkidin=%s --pmkideapolout=%s" % (file, temp_22000_filename)
            process = Process(cmd, crit=True)

            process.wait()

            with open(temp_22000_filename) as fd:
                return Scheduler._filter_22000hash_filter_mac(fd.readlines(), mac_addr)
        finally:
            os.unlink(temp_22000_filename)


    @staticmethod
    def _get_22000hash_from_capture_filter_mac(file, mac_addr):
        """ return 22000 hash from a capture file that matches the given MAC """

        tmp_file = NamedTemporaryFile(prefix="psknow_backend_get22000_from_capture",
                                      delete = False, dir = Configuration.tempfile_dir)
        temp_22000_filename = tmp_file.name

        try:
            cmd = "hcxpcapngtool -o %s %s" % (temp_22000_filename, file)
            process = Process(cmd, crit=True)

            process.wait()

            with open(temp_22000_filename) as fd:
                return Scheduler._filter_22000hash_filter_mac(fd.readlines(), mac_addr)
        finally:
            os.unlink(temp_22000_filename)


    @staticmethod
    def generate_22000_from_wifi_db_entry(capture):
        """
            This function returns the hash associated with the wifi present in the capture parameter
        :param capture: A wifi capture entry from the database.
        :return: False in case no hashes could be written, The hash in case of success
        """
        if not (capture["handshake"]["handshake_type"] == "PMKID" or capture["handshake"]["handshake_type"] == "WPA"):
            Configuration.logger.error("Unknown type of attack '%s' in entry '%s'" %
                                       (capture["handshake"]["handshake_type"], capture))
            return None

        if not os.path.isfile(capture["path"]):
            Configuration.logger.error("File '%s' from id '%s' does not exist." %
                                       (capture['path'], capture["id"]))
            return None

        if capture["file_type"] == "16800":
            return Scheduler._get_22000hash_from_16800_filter_mac(capture["path"], capture["handshake"]["MAC"])

        if capture["file_type"] == "22000":
            with open(capture["path"]) as fd:
                lines = fd.readlines()
                return Scheduler._filter_22000hash_filter_mac(lines, capture["handshake"]["MAC"])

        return Scheduler._get_22000hash_from_capture_filter_mac(capture["path"], capture["handshake"]["MAC"])


    @staticmethod
    def get_all_possible_rules(client_capabilities):
        result = {}

        for rule_name in Configuration.rule_priorities.keys():
            not_good = False
            rule = Configuration.rule_dict[rule_name]

            for requirement in rule["reqs"]:
                if requirement not in client_capabilities:
                    not_good = True
                    break

            if not_good:
                continue

            result[rule_name] = rule["priority"]
        return result

    @staticmethod
    def get_next_handshake(apikey, client_capabilities):
        task = deepcopy(Scheduler.default_task)

        # Avoid sending error if the wifis collection was not created yet.
        # This can happen if no handshakes have ever been uploaded
        if "wifis" not in Configuration.db.list_collection_names():
            return task, "No work to be done at the moment."

        pipeline_branches = []
        possible_rules = Scheduler.get_all_possible_rules(client_capabilities)
        for rule_name in possible_rules:
            pipeline_branches.append({"case" : {"$eq": ["$$value", rule_name]}, "then": possible_rules[rule_name]})

        pipeline_min_prio_min_rule = [
            {"$match": {
                "handshake.open": False,
                "reserved": None,
                "handshake.password": "",
                "handshake.tried_dicts.%s" % (Configuration.number_rules - 1): {"$exists": False}
            }},

            # Only keep documents with lowest priority
            { "$group": {
                "_id": "$priority",
                "docs": {"$push": "$$ROOT"}
            }},
            { "$sort": { "_id": 1 } },
            { "$limit": 1 },
            { "$unwind": "$docs"},
            { "$replaceRoot": {"newRoot": "$docs"}},

            # Find document with lowest allowed rule that has not been tried
            {
                "$addFields":  {
                    "lowestNotTried": {
                        "$min": {
                            "$map": {
                                "input": {"$setDifference" : [list(Scheduler.get_all_possible_rules(client_capabilities).keys()),
                                                "$handshake.tried_dicts"]},
                                "as": "value",
                                "in": {
                                    "$switch": {
                                        "branches": pipeline_branches,
                                        "default": "$$value"
            }}}}}}},
            { "$sort": {"lowestNotTried" : 1}},
            { "$limit": 1}]

        # Lock this in order to ensure that multiple threads do not reserve the same handshake
        with Configuration.wifis_lock:
            try:
                response = Configuration.wifis.aggregate(pipeline_min_prio_min_rule)
            except Exception as e:
                Configuration.logger.error("Error occured while doing the aggregation pipeline: %s" % e)
                return None, "Internal server error 101"

            response = list(response)

            if len(response) == 0:
                # NOTE this message is checked in requester
                return task, "No work to be done at the moment."

            best_handshake = response[0]
            next_rule_name = None

            for rule_name, rule_prio in possible_rules.items():
                if rule_prio == best_handshake["lowestNotTried"]:
                    next_rule_name = rule_name

            if next_rule_name is None:
                Configuration.logger.error("Error occured mapping the lowest rule priority not tried back to rule name.")
                return None, "Internal server error 102"

            Scheduler._reserve_handshake(best_handshake["id"], apikey, next_rule_name)

        task["handshake"]["data"] = Scheduler.generate_22000_from_wifi_db_entry(best_handshake)

        if task["handshake"]["data"] is None:
            Scheduler.release_handshake(best_handshake["id"])
            return None, "Error getting handshake data from file."

        task["handshake"]["ssid"] = best_handshake["handshake"]["SSID"]
        task["handshake"]["mac"] = best_handshake["handshake"]["MAC"]
        task["handshake"]["file_type"] = best_handshake["file_type"]

        next_rule = Configuration.rule_dict[next_rule_name]
        task["rule"]["wordsize"] = next_rule["wordsize"]
        task["rule"]["type"] = next_rule["type"]
        task["rule"]["name"] = next_rule["name"]

        aux_data = None

        if next_rule["type"] == "john":
            aux_data = {"rule": next_rule.get("rule", None),
                    "baselist": Configuration.cap_dict[next_rule["path"]]["path"]}
        elif next_rule["type"] == "mask_hashcat":
            aux_data = next_rule['mask_hashcat']
        elif next_rule["path"] != "":
            aux_data = Configuration.cap_dict[next_rule["path"]]["path"]

        task["rule"]["aux_data"] = aux_data

        return task, ""
