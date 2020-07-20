import sys
import inspect

from .config import Configuration

from functools import wraps
from flask_login import current_user
from flask import flash, redirect, request


def check_db_conn():
    try:
        info = Configuration.check_db_conn()
    except Exception as e:
        Configuration.logger.critical("Database is down with reason %s!" % e)
        return None
    return info


def die(condition, message):
    if condition:
        Configuration.logger.critical("line %s in function %s, error %s" %
                                      (inspect.currentframe().f_back.f_lineno, inspect.stack()[1][3], message))
        sys.exit(-1)


def is_admin(user):
    return user is not None and user.is_authenticated and user.get_id() == Configuration.admin_account


def requires_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if is_admin(current_user):
            return f(*args, **kwargs)

        flash("Not permitted!")
        return redirect("/")

    return decorated_function


def ajax_requires_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        request_xhr_key = request.headers.get('X-Requested-With')
        if is_admin(current_user) and request_xhr_key and request_xhr_key == 'XMLHttpRequest':
            return f(*args, **kwargs)
        flash("Not permitted!")
        return redirect("/")

    return decorated_function


def not_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_admin(current_user):
            return f(*args, **kwargs)

        flash("Not permitted for admin account!")
        return redirect("/")

    return decorated_function