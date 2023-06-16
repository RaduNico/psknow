import os
import datetime
import tempfile

from .process import Process
from .database_helper import generic_find, update_hs_id
from .config import Configuration

from bson.code import Code
from tempfile import mkstemp
from copy import deepcopy


class Scheduler:
    # prios = [{rule_name: rule_prio}] - priorities only for possible rules
    # crt = [{tried_rule_name: 1}] - all tried rules for current hs
    mapper_template = "function() {" \
                      " var prios = %s;" \
                      " var result_name = '';" \
                      " var result_prio = 900000;" \
                      " var crt = {};" \
                      " for (var iter in this['handshake']['tried_dicts']) {" \
                      " 	crt[this['handshake']['tried_dicts'][iter]] = 1;" \
                      " }" \
                      " for (var name in prios) {" \
                      " 	if ( crt[name] !== 1 && prios[name] < result_prio) {" \
                      " 		result_name = name;" \
                      " 		result_prio = prios[name];" \
                      " 	}" \
                      " }" \
                      " var result = {};" \
                      " result['date_added'] = this['date_added'];" \
                      " result['priority'] = this['priority'];" \
                      " result['id'] = this['id'];" \
                      " result['path'] = this['path'];" \
                      " result['file_type'] = this['file_type'];" \
                      " result['id'] = this['id'];" \
                      " result['mac'] = this['handshake']['MAC'];" \
                      " result['ssid'] = this['handshake']['SSID'];" \
                      " result['next_rule'] = result_name;" \
                      " result['rule_prio'] = result_prio;" \
                      " result['handshake_type'] = this['handshake']['handshake_type'];" \
                      " emit(0, result)" \
                      "}"

    reducerf = Code("function (rule_prio, documents) {"
                    "	var good_document = documents[0];"
                    "	var best_user_prio = documents[0]['priority'];"
                    "	var best_date = documents[0]['date_added'];"
                    "	var best_rule_prio = documents[0]['rule_prio'];"
                    "	"
                    "	for (var i = 1; i < documents.length; i++) {"
                    "		if (documents[i]['priority'] < best_user_prio) {"
                    "			good_document = documents[i];"
                    "			"
                    "			best_user_prio = documents[i]['priority'];"
                    "			best_rule_prio = documents[i]['rule_prio'];"
                    "			best_date = documents[i]['date_added'];"
                    "		} else if (documents[i]['priority'] === best_user_prio &&"
                    "					documents[i]['rule_prio'] < best_rule_prio) {"
                    "			good_document = documents[i];"
                    "			"
                    "			best_rule_prio = documents[i]['rule_prio'];"
                    "			best_date = documents[i]['date_added'];"
                    "		} else if (documents[i]['priority'] === best_user_prio &&"
                    "					documents[i]['rule_prio'] === best_rule_prio &&"
                    "					documents[i]['date_added'] < best_date) {"
                    "			good_document = documents[i];"
                    "			best_date = documents[i]['date_added'];"
                    "		}"
                    "	}"
                    "	return good_document;"
                    "}")

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

        _, temp_22000_filename = mkstemp(prefix="psknow_backend")

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
        _, temp_22000_filename = mkstemp(prefix="psknow_backend")

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
            query = {"handshake.open": False, "reserved": None, "handshake.password": "",
                     "handshake.tried_dicts.%s" % (Configuration.number_rules - 1): {"$exists": False}}
            mapper = Code(Scheduler.mapper_template % Scheduler.get_all_possible_rules(client_capabilities))
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
        task["handshake"]["handshake_type"] = best_handshake["handshake"]["handshake_type"]

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
