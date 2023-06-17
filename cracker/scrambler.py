import re
import os
from tempfile import NamedTemporaryFile
from config import Configuration


class Scrambler:
    def __init__(self, ssid: str):
        self.ssid = ssid
        self.temp_filename = ""
        self.temp_file = None

    def __del__(self):
        if self.temp_file is not None:
            os.remove(self.temp_filename)

    @staticmethod
    def _break_apart(word):
        result = set()

        for i in range(1, len(word) - 2):
            result = result.union({word[:-i]})
            result = result.union({word[i:]})

        return result

    @staticmethod
    def _scramble_string(hvstring):
        # The plain ssid
        result = {hvstring}

        more_words = len(hvstring.split()) > 1

        if more_words:
            # The ssid without spaces
            result = result.union({hvstring.replace(" ", "")})

        for word in hvstring.split():
            if more_words:
                result = result.union({word})
            result = result.union(Scrambler._break_apart(word))

        return result

    def _ssid_to_passwords(self):
        result = Scrambler._scramble_string(self.ssid)

        # Keep only letters and spaces
        aux = "".join(re.findall(r"[a-zA-Z ]+", self.ssid))

        if aux != self.ssid:
            result = result.union(Scrambler._scramble_string(" ".join(aux.split())))

        # Keep only numbers
        aux = "".join(re.findall(r"[0-9]+", self.ssid))

        if aux != self.ssid:
            for number in aux:
                if len(number) > 3:
                    result = result.union(Scrambler._scramble_string(number))

        for word in re.findall(r"[a-zA-Z]+", self.ssid):
            if len(word) > 2:
                result = result.union(Scrambler._scramble_string(word))

        return result

    def get_high_value_temp_filename(self):
        self.temp_file = NamedTemporaryFile(delete=False, prefix="psknow_crack_get_high_value_tempfile",
                                            dir=Configuration.tempfile_dir)

        self.temp_filename = self.temp_file.name
        handler = open(self.temp_filename, "w")

        for entry in self._ssid_to_passwords():
            handler.write("%s\n" % entry)

        for entry in Configuration.hot_words:
            handler.write("%s\n" % entry)

        handler.close()

        return self.temp_filename
