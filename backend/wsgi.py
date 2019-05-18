from backend import application
from config import Configuration
from secrets import token_urlsafe

# TODO check key/file existence and generate one from /dev/random of it does not exist
try:
    with open("secret_key", "r") as sc_fd:
        application.secret_key = "".join(sc_fd.readlines())
except FileNotFoundError:
    application.secret_key = token_urlsafe(90)
    with open("secret_key", "w") as sc_fd:
        sc_fd.write(application.secret_key)
application.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
Configuration.initialize()
