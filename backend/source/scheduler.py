import os
import datetime

from .process import Process
from .database_helper import generic_find, update_hs_id
from .config import Configuration

from bson.code import Code
from tempfile import mkstemp
from copy import deepcopy


class Scheduler:
    # attributes = [{rule_name: rule_prio, rule_language}] - priorities only for possible rules
    # crt = [{tried_rule_name: 1}] - all tried rules for current hs
    mapper_template = "function() {" \
                      " var attributes = %s;" \
                      " var result_name = '';" \
                      " var result_prio = 900000;" \
                      " var crt = {};" \
                      " for (var name in attributes) { " \
                      "     var valid_rule = false;" \
                      "     for (var rule_language in attributes[name][1]) {" \
                      "         if (attributes[name][1][rule_language] === 'none') { " \
                      "             valid_rule = true;" \
                      "             break;" \
                      "         }" \
                      "         for (var hs_language in this['languages']) { " \
                      "             if (attributes[name][1][rule_language] === this['languages'][hs_language]) { " \
                      "                 valid_rule = true;" \
                      "                 break;" \
                      "             }" \
                      "         }" \
                      "         if (valid_rule === true) {" \
                      "             break;" \
                      "         }" \
                      "     }" \
                      "     if (valid_rule === false) {" \
                      "         delete attributes[name];" \
                      "     }" \
                      " }" \
                      " for (var iter in this['handshake']['tried_dicts']) {" \
                      " 	crt[this['handshake']['tried_dicts'][iter]] = 1;" \
                      " }" \
                      " for (var name in attributes) {" \
                      " 	if (crt[name] !== 1 && attributes[name][0] < result_prio) {" \
                      " 		result_name = name;" \
                      " 		result_prio = attributes[name][0];" \
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
    def _get_pmkid_from16800_mac(file, mac_addr):
        """ return PMKID from a .16800 file that matches the given MAC """
        with open(file) as fd:
            for line in fd:
                if line.endswith("\n"):
                    line = line[:-1]
                matchobj = Configuration.pmkid_16800_regex.match(line)
                if matchobj is None:
                    continue
                match_mac = ":".join(a + b for a, b in zip(matchobj.group(1)[::2], matchobj.group(1)[1::2]))
                if mac_addr == match_mac:
                    return line
            return None

    @staticmethod
    def _get_capture_from22000_mac(file, mac_addr):
        """ return PMKID/handshake from a .22000 file that matches the given MAC """
        with open(file) as fd:
            for line in fd:
                if line.endswith("\n"):
                    line = line[:-1]
                matchobj = Configuration.regex_pmkid.match(line)
                if matchobj is None:
                    matchobj = Configuration.regex_handshake.match(line)
                    if matchobj is None:
                        continue
                match_mac = ":".join(a + b for a, b in zip(matchobj.group(1)[::2], matchobj.group(1)[1::2]))
                if mac_addr == match_mac:
                    return line
            return None

    @staticmethod
    def _get_22000_data(crt_capture):
        """
            This function should never be called from outside of this file because
            the parameter it takes does not coincide with the database format.
            :param crt_capture: Capture information as formatted by the mapreduce 'Scheduler.mapper_template'
            :return: 22000 format file for provided parameter
        """
        if not os.path.isfile(crt_capture["path"]):
            Configuration.logger.error("File '%s' from id '%s' does not exist." %
                                       (crt_capture['path'], crt_capture["id"]))
            return None

        if crt_capture["file_type"] == "16800":
            return Scheduler._get_pmkid_from16800_mac(crt_capture["path"], crt_capture["mac"])

        if crt_capture["file_type"] == "22000":
            return Scheduler._get_capture_from22000_mac(crt_capture["path"], crt_capture["mac"])

        if not (crt_capture["handshake_type"] == "PMKID" or crt_capture["handshake_type"] == "WPA"):
            Configuration.logger.error("Unknown type of attack '%s' in entry '%s'" %
                                       (crt_capture["handshake_type"], crt_capture))
            return None

        f, temp_filename = mkstemp(prefix="psknow_backend")

        cmd = "hcxpcapngtool -o %s %s" % (temp_filename, crt_capture["path"])
        stdout = Process(cmd, crit=True).stdout()

        if "written to" not in stdout:
            os.remove(temp_filename)
            return None

        capture = Scheduler._get_capture_from22000_mac(temp_filename, crt_capture["mac"])
        os.remove(temp_filename)
        return capture

    @staticmethod
    def get_22000_data(crt_capture):
        """
            This is a temporary fix needed until a better result checking
            method is implemented. This should be removed as soon as po ssible.
            Do not use this method.
        :param crt_capture:
        :return:
        """
        intermediary = dict()
        intermediary['date_added'] = crt_capture['date_added']
        intermediary['priority'] = crt_capture['priority']
        intermediary['languages'] = crt_capture['languages']
        intermediary['id'] = crt_capture['id']
        intermediary['path'] = crt_capture['path']
        intermediary['file_type'] = crt_capture['file_type']
        intermediary['id'] = crt_capture['id']
        intermediary["mac"] = crt_capture["handshake"]["MAC"]
        intermediary['ssid'] = crt_capture['handshake']['SSID']
        intermediary['next_rule'] = ""
        intermediary['rule_prio'] = -1
        intermediary["handshake_type"] = crt_capture["handshake"]["handshake_type"]

        return Scheduler._get_22000_data(intermediary)

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

            result[rule_name] = [rule["priority"], rule["languages"]]
        return result

    @staticmethod
    def get_next_handshake(apikey, client_capabilities):
        task = deepcopy(Scheduler.default_task)

        query = {"handshake.open": False, "reserved": None, "handshake.password": "",
                 "handshake.tried_dicts.%s" % (Configuration.number_rules - 1): {"$exists": False}}

        # Avoid sending error if the wifis collection was not created yet.
        # This can happen if no handshakes have ever been uploaded
        if "wifis" not in Configuration.db.list_collection_names():
            return task, "No work to be done at the moment."

        # Lock this in order to ensure that multiple threads do not reserve the same handshake
        with Configuration.wifis_lock:
            mapper = Code(Scheduler.mapper_template % Scheduler.get_all_possible_rules(client_capabilities))

            try:
                response = Configuration.wifis.map_reduce(mapper, Scheduler.reducerf, {"inline": 1}, query=query)
            except Exception as e:
                Configuration.logger.error("Error occured while doing the mapreduce: %s" % e)
                return None, "Internal server error 101"

            if len(response["results"]) == 0:
                # NOTE this message is checked in requester
                return task, "No work to be done at the moment."

            best_handshake = response["results"][0]["value"]

            Scheduler._reserve_handshake(best_handshake["id"], apikey, best_handshake["next_rule"])

        task["handshake"]["data"] = Scheduler._get_22000_data(best_handshake)

        if task["handshake"]["data"] is None:
            Scheduler.release_handshake(best_handshake["id"])
            return None, "Error getting handshake data from file."

        task["handshake"]["ssid"] = best_handshake["ssid"]
        task["handshake"]["mac"] = best_handshake["mac"]
        task["handshake"]["file_type"] = best_handshake["file_type"]
        task["handshake"]["handshake_type"] = best_handshake["handshake_type"]

        next_rule = Configuration.rule_dict[best_handshake["next_rule"]]
        task["rule"]["wordsize"] = next_rule["wordsize"]
        task["rule"]["type"] = next_rule["type"]
        task["rule"]["name"] = next_rule["name"]

        data = None

        if next_rule["type"] == "john":
            data = {"rule": next_rule.get("rule", None),
                    "baselist": Configuration.cap_dict[next_rule["path"]]["path"]}
        elif next_rule["type"] == "mask_hashcat":
            data = next_rule['mask_hashcat']
        elif next_rule["path"] != "":
            data = Configuration.cap_dict[next_rule["path"]]["path"]

        task["rule"]["aux_data"] = data

        return task, ""
