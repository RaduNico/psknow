from backend import application
from config import Configuration

# TODO check key/file existence and generate one from /dev/random of it does not exist
with open("secret_key", "r") as sc_fd:
    application.secret_key = "".join(sc_fd.readlines())
application.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
Configuration.initialize()
