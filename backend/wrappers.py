from config import Configuration

from functools import wraps
from flask_login import current_user
from flask import flash, redirect


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


def not_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_admin(current_user):
            return f(*args, **kwargs)

        flash("Not permitted for admin account!")
        return redirect("/")

    return decorated_function
