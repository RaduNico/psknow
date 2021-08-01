import bcrypt
import base64
import hashlib

from .config import Configuration

from flask_login import UserMixin
from copy import deepcopy


user_template = {
    "username": "",
    "password": "",
    "allow_api": False,
    "api_keys": [],
    "email": "Enter email"
}


def preprocess_password(password):
    return base64.b64encode(hashlib.sha256(password.encode('ascii')).digest())


def enc_bcrypt(password):
    return base64.b64encode(bcrypt.hashpw(preprocess_password(password), bcrypt.gensalt(14))).decode('ascii')


def check_bcrypt(hashed, password):
    return bcrypt.checkpw(preprocess_password(password), base64.b64decode(hashed.encode('ascii')))


class User(UserMixin):
    def __init__(self, uid):
        self.id = uid

    def get_id(self):
        return self.id

    @staticmethod
    def check_credentials(username, password):
        document = list(Configuration.users.find({"username": username}, {"password": 1, "_id": 0}))

        if len(document) > 1:
            Configuration.logger.crititcal("Database integrity error. Multiple users '%s' exist!" % username)

        return len(document) != 0 and check_bcrypt(document[0]["password"], password)

    # @staticmethod
    # def check_recovery_credentials(username, password):
    #     document = list(Configuration.users.find({"username": username}, {"recovery_password": 1, "_id": 0}))
    #
    #     if len(document) > 1:
    #         Configuration.logger.crititcal("Database integrity error. Multiple users '%s' exist!" % username)
    #
    #     try:
    #         return len(document) != 0 and check_bcrypt(document[0]["recovery_password"], password)
    #     except KeyError:
    #         return False
    #     except ValueError:
    #         return False

    @staticmethod
    def create_user(username, password):
        user = list(Configuration.users.find({"username": username}))

        if len(user) == 0:
            new_user = deepcopy(user_template)
            new_user["username"] = username
            new_user["password"] = enc_bcrypt(password)

            try:
                obj = Configuration.users.insert_one(new_user)
                Configuration.logger.info("Created user '%s' with _id = %s" % (username, obj.inserted_id))
            except Exception as e:
                Configuration.logger.error("Exception at creating user = '%s': %s" % (username, e))
                return "Error 503. Retry"
            return None

        else:
            return "Username '%s' already exists!" % username
