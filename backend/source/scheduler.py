import os
import datetime

from .process import Process
from .database_helper import generic_find, update_hs_id
from .config import Configuration

from bson.code import Code
from tempfile import mkstemp
from base64 import b64encode
from copy import deepcopy


class Scheduler:
    mapper_template = "function() {" \
                      " var prios = %s;" \
                      " var result_name = '';" \
                      " var result_prio = 900000;" \
                      " var crt = {};" \
                      " for (var iter in this['handshake']['tried_dicts']) {" \
                      " 	crt[this['handshake']['tried_dicts'][iter]] = 1;" \
                      " }" \
                      " for (var key in prios) {" \
                      " 	if ( crt[key] !== 1 && prios[key] < result_prio) {" \
                      " 		result_name = key;" \
                      " 		result_prio = prios[key];" \
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
                      " result['handshake_type'] = this['handshake']['handshake_type'];" \
                      " emit(result_prio, result)" \
                      "}"

    reducer = Code("function (rule_prio, documents) {"
                   "	var good_document = documents[0];"
                   "	var best_user_prio = documents[0]['priority'];"
                   "	var best_date = documents[0]['date_added'];"
                   "	for (var i = 1; i < documents.length; i++) {"
                   "		if (documents[i]['priority'] < best_user_prio) {"
                   "			best_user_prio = documents[i]['priority'];"
                   "			"
                   "			good_document = documents[i];"
                   "			best_date = documents[i]['date_added'];"
                   "		} else if (documents[i]['priority'] === "
                   "best_user_prio && documents[i]['date_added'] < best_date) {"
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
            return Scheduler._get_pmkid_mac(crt_capture["path"], crt_capture["mac"])

        _, temp_filename = mkstemp(prefix="psknow_backend")

        if crt_capture["handshake_type"] == "PMKID":
            flag = "-z"
        elif crt_capture["handshake_type"] == "WPA":
            flag = "-o"
        else:
            Configuration.logger.error("Unknown type of attack '%s' in entry '%s'" %
                                       (crt_capture["handshake_type"], crt_capture))
            return None

        mac_addr = crt_capture["mac"].replace(":", "")

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
    def _extract_rule_with_parameters(entries, capabilities):
        result = None
        best_prio = 900000
        best_rule_prio = 900000
        for full_entry in entries:
            entry = full_entry["value"]
            not_good = False

            # Check if the client can run this rule based on capabilities
            rule = Configuration.rule_dict[entry["next_rule"]]
            Configuration.logger.fatal("")
            Configuration.logger.fatal("capabilities %s, rule_reqs %s" % (capabilities, rule["reqs"]))
            for requirement in rule["reqs"]:
                if requirement not in capabilities:
                    Configuration.logger.fatal("lacks '%s' capability" % requirement)
                    not_good = True
                    break
            if not_good:
                continue

            # We have two parameters - the handshake priority which takes precedence and the rule priority
            if best_prio > entry["priority"]:
                result = entry
                best_rule_prio = 900000
                best_prio = entry["priority"]
            elif best_prio == entry["priority"] and best_rule_prio > rule["priority"]:
                best_rule_prio = rule["priority"]
                result = entry
        return result

    @staticmethod
    def get_next_handshake(apikey, capabilities):
        task = deepcopy(Scheduler.default_task)

        query = {"handshake.open": False, "reserved_by": None, "handshake.password": "",
                 "handshake.tried_dicts.%s" % (Configuration.number_rules - 1): {"$exists": False}}

        # Lock this in order to ensure that multiple threads do not reserve the same handshake
        with Configuration.wifis_lock:
            mapper = Code(Scheduler.mapper_template % Configuration.rule_priorities)
            try:
                response = Configuration.wifis.map_reduce(mapper, Scheduler.reducer, {"inline": 1}, query=query)
            except Exception as e:
                Configuration.logger.error("Error occured while doing the mapreduce: %s" % e)
                return None, "Internal server error 101"

            entries = response["results"]

            if len(entries) == 0:
                return task, "No work to be done at the moment."

            best_handshake = Scheduler._extract_rule_with_parameters(entries, capabilities)

            if best_handshake is None:
                return task, "No work can be done with current capabilities"

            Scheduler._reserve_handshake(best_handshake["id"], apikey, best_handshake["next_rule"])

        task["handshake"]["data"] = Scheduler._get_hccapx_data(best_handshake)

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

        mapper = {"wordlist": next_rule.get("wordlist", None),
                  "john": next_rule.get("rule", None),
                  "generated": next_rule.get("command", None),
                  "mask_hashcat": next_rule.get("mask_hashcat", None),
                  "filemask_hashcat": next_rule.get("filemask_path", None)}

        task["rule"]["aux_data"] = mapper[next_rule["type"]]

        return task, ""
