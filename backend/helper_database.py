import random
import string
import sys
import json

from pymongo import MongoClient
from copy import deepcopy


db_username = "psknow"
db_password = "xY6R0YPFBpjebMwFHBYXQTokZ25nI1G8eZfjWqQrUtUeajcucgKpNxncVBCW"
database_location = "127.0.0.1"
database_name = "psknow"

conn_loc = "mongodb://%s:%s@%s/%s" %\
           (db_username, db_password,
            database_location, database_name)

conn = MongoClient(conn_loc, serverSelectionTimeoutMS=10, connectTimeoutMS=20)
db = conn[database_name]
wifis = db["wifis"]
rules = db["rules"]

def get_random_string(length):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))


def get_unique_id():
    unique_id = get_random_string(25)
    while len(list(wifis.find({"id": unique_id}))) > 0:
        unique_id = get_random_string(25)
    return unique_id


if len(sys.argv) > 1 and sys.argv[1] == "cristi":
    iterator = wifis.find({"users": "Cristi", "handshake.password": {"$ne": ""}})

    lst = []
    for entry in iterator:
        jso = dict()
        jso["SSID"] = entry["handshake"]["SSID"]
        jso["MAC"] = entry["handshake"]["MAC"]
        jso["password"] = entry["handshake"]["password"]
        lst.append(jso)

    with open("dump_cristi.json", "w") as fd:
        json.dump(lst, fd, indent=4)

    print("muie")
    sys.exit(0)

# Treat simple fields
all_entries = wifis.find({})
for entry in all_entries:
    clean_entry = deepcopy(entry)

    if "reserved" not in clean_entry:
        clean_entry["reserved"] = None

    if "user" in clean_entry:
        del clean_entry["user"]
        clean_entry["users"] = [entry["user"]]

    try:
        wifis.update({"id": entry["id"]}, clean_entry)
    except Exception as e:
        print("Exception at updating %s: %s" % (clean_entry, e))
        sys.exit(-1)


# Treat handshakes field and the potential splits
all_entries = wifis.find({})
for entry in all_entries:
    clean_entry = deepcopy(entry)
    if "handshakes" in clean_entry:
        del clean_entry["handshakes"]

        for handshake in entry["handshakes"]:
            clean_entry["handshake"] = handshake
            if len(entry["handshakes"]) > 1:
                del clean_entry["_id"]
                clean_entry["id"] = get_unique_id()
                try:
                    wifis.insert(clean_entry)
                except Exception as e:
                    print("Exception at inserting %s: %s" % (clean_entry, e))
                    sys.exit(-1)
                try:
                    wifis.delete_one({"_id": entry["_id"]})
                except Exception as e:
                    print("Exception at deleting %s: %s" % (entry, e))
                    sys.exit(-1)

            else:
                try:
                    wifis.update({"id": entry["id"]}, clean_entry)
                except Exception as e:
                    print(entry["id"])
                    print("Exception at updating %s: %s" % (clean_entry, e))
                    sys.exit(-1)

all_entries = wifis.find({})
all_rules = rules.find({})

# construct names list based on potential crack_levels
tried_dict = {"130": ""}
rule_names = {"130": "manual"}
list_tries = []
for rule in all_rules:
    rule_names[str(rule["priority"])] = rule["name"]
    list_tries.append(rule["name"])
    tried_dict[str(rule["priority"])] = deepcopy(list_tries)

for entry in all_entries:
    if "handshake" not in entry:
        print("Error 'handshake' not in entry! Did you modify old 'handshakes'?")
        continue

    if "crack_level" not in entry["handshake"]:
        continue

    old_crack_level = str(entry["handshake"]["crack_level"])

    del entry["handshake"]["crack_level"]
    entry["handshake"]["tried_dicts"] = tried_dict[old_crack_level]
    if entry["handshake"]["password"] != "":
        entry["handshake"]["cracked_rule"] = rule_names[old_crack_level]

    try:
        wifis.update({"id": entry["id"]}, entry)
    except Exception as e:
        print(entry["id"])
        print("Exception at updating %s: %s" % (entry, e))
        sys.exit(-1)
