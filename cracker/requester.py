import requests
import traceback

from config import Configuration


class Requester:
    @staticmethod
    def _decode_json(response):
        try:
            data = response.json()
        except Exception as e:
            return None, "%s\n%s" % (e, traceback.format_exc())

        if data["success"] is False:
            return None, data["reason"]

        return data.get("data"), ""

    # Send a request for work
    # Returns:
    # None if no work can be done
    # True if an error occured
    # False if a capability is out of date
    # work dictionary if successful
    @staticmethod
    def getwork():
        url = Configuration.remote_server + "getwork"
        Configuration.logger.info("Requesting work from '%s'" % url)
        try:
            response = requests.post(url, json={"apikey": Configuration.apikey,
                                                "capabilities": Configuration.capabilities})
        except requests.exceptions.ConnectionError:
            Configuration.dual_print(Configuration.logger.error, "Server is down!")
            return None

        data, err = Requester._decode_json(response)
        if err != "":
            if err == "Capabilities updated!":
                return False

            if err == "No work can be done with current capabilities":
                return None

            Configuration.dual_print(Configuration.logger.error, "Error retrieving data from server '%s'" % err)
            return True

        return data

    @staticmethod
    def stopwork():
        url = Configuration.remote_server + "stopwork"
        Configuration.logger.info("Stopping work from '%s'" % url)
        try:
            response = requests.post(url, data={"apikey": Configuration.apikey})
        except requests.exceptions.ConnectionError:
            Configuration.dual_print(Configuration.logger.error, "Server is down!")
            return None

        _, err = Requester._decode_json(response)
        if err != "":
            Configuration.dual_print(Configuration.logger.error, "Error stopping work '%s'" % err)
            return None

        return True

    @staticmethod
    def pausework():
        url = Configuration.remote_server + "pausework"
        Configuration.logger.info("Pausing work from '%s'" % url)
        try:
            response = requests.post(url, data={"apikey": Configuration.apikey})
        except requests.exceptions.ConnectionError:
            Configuration.dual_print(Configuration.logger.error, "Server is down!")
            return None

        _, err = Requester._decode_json(response)
        if err != "":
            Configuration.dual_print(Configuration.logger.error, "Error pausing work '%s'" % err)
            return None

        return True

    @staticmethod
    def sendeta(eta):
        url = Configuration.remote_server + "sendeta"
        Configuration.logger.info("Sending eta to '%s': '%s'" % (url, eta))
        try:
            response = requests.post(url, data={"apikey": Configuration.apikey, "eta": eta})
        except requests.exceptions.ConnectionError:
            Configuration.dual_print(Configuration.logger.error, "Server is down!")
            return None

        _, err = Requester._decode_json(response)
        if err != "":
            Configuration.dual_print(Configuration.logger.error, "Error sending eta '%s'" % err)
            return None

        return True

    @staticmethod
    def checkfile(filename):
        url = Configuration.remote_server + "checkfile"
        Configuration.logger.info("Checking if file '%s' exists at '%s'" % (filename, url))

        try:
            response = requests.post(url, data={"apikey": Configuration.apikey, "file": filename})
        except requests.exceptions.ConnectionError:
            Configuration.dual_print(Configuration.logger.error, "Server is down!")
            return None

        _, err = Requester._decode_json(response)
        if err != "":
            Configuration.dual_print(Configuration.logger.error, "Error downloading '%s': '%s'" % (filename, err))
            return None

        return True

    @staticmethod
    def getfile(filename, path):
        url = Configuration.remote_server + "getfile"
        Configuration.logger.info("Getting file '%s' from '%s'" % (filename, url))

        try:
            with requests.post(url, data={"apikey": Configuration.apikey, "file": filename}, stream=True) as req:
                req.raise_for_status()
                with open(path, "wb+") as fd:
                    for chunk in req.iter_content(chunk_size=8192):
                        if chunk:
                            fd.write(chunk)
        except requests.exceptions.ConnectionError:
            Configuration.dual_print(Configuration.logger.error, "Server is down!")
            return None

        return True

    @staticmethod
    def getmissing():
        url = Configuration.remote_server + "getmissing"
        Configuration.logger.info("Getting missing capabilites at '%s'" % url)

        try:
            response = requests.post(url, json={"apikey": Configuration.apikey,
                                                "capabilities": Configuration.capabilities})
        except requests.exceptions.ConnectionError:
            Configuration.dual_print(Configuration.logger.error, "Server is down!")
            return None

        data, err = Requester._decode_json(response)
        if err != "":
            Configuration.dual_print(Configuration.logger.error,
                                     "Error while retrieving missing capabilites '%s'" % err)

        return data

    @staticmethod
    def sendresult(password):
        url = Configuration.remote_server + "sendresult"
        Configuration.logger.info("Sending result at '%s'" % url)
        try:
            response = requests.post(url, data={"apikey": Configuration.apikey, "password": password})
        except requests.exceptions.ConnectionError:
            Configuration.dual_print(Configuration.logger.error, "Server is down!")
            return None

        _, err = Requester._decode_json(response)
        if err != "":
            Configuration.dual_print(Configuration.logger.error, "Error while sending result '%s'" % err)
            return None

        return True
