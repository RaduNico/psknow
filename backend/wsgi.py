from backend import application
from config import Configuration
from secrets import token_urlsafe


def get_key_from_file(filename):
    try:
        with open(filename, "r") as sc_fd:
            key = "".join(sc_fd.readlines())
    except FileNotFoundError:
        key = token_urlsafe(150)
        with open(filename, "w") as sc_fd:
            sc_fd.write(application.secret_key)

    return key


application.secret_key = get_key_from_file("keys/secret_key")
application.api_secret_key = get_key_from_file("keys/api_secret_key")

application.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024
Configuration.initialize()
