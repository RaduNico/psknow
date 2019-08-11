from main import application
from config import Configuration

application.secret_key = Configuration.get_key_from_file("keys/secret_key")
Configuration.api_secret_key = Configuration.get_key_from_file("keys/api_secret_key")

application.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024
Configuration.initialize()
