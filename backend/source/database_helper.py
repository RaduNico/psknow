import traceback

from .config import Configuration
from flask import flash


# Returns True if error occured, False otherwise
def add_user_to_entry_id(user, entry_id):
    err = False
    try:
        Configuration.wifis.update_one({"id": entry_id}, {"$push": {"users": user}})
        Configuration.logger.info("db.wifis: Appended user '%s' to document id '%s'" % (user, entry_id))
    except Exception as e:
        Configuration.logger.error("db.wifis: Error at appending user '%s' to document id '%s': %s" %
                                   (user, entry_id, e))
        flash("An entry already exists in the database but could not be added to your account.")
        err = True

    return err


# Returns True if error occured, False otherwise
def update_hs_id(handshake_id, set_query):
    error = False
    try:
        upd = Configuration.wifis.update_one({"id": handshake_id}, {"$set": set_query})
        if not upd.matched_count > 0:
            Configuration.logger.error("db.wifis: Failed to update document with id = '%s'" %
                                       handshake_id)
            error = True
        Configuration.logger.info("db.wifis: Updated handshake id '%s', with $set data %s" % (handshake_id, set_query))
    except Exception as e:
        Configuration.logger.error("db.wifis: Failed to update document with id = '%s' with error '%s'\n%s" %
                                   (handshake_id, e, traceback.format_exc()))
        error = True
    return error


# Returns the result of the query and True if error occured, False otherwise
def generic_find(col, query, api_query=False):
    values = None
    err = False

    try:
        values = col.find(query)
        Configuration.logger.info("db.%s: Successfully ran query '%s'" % (col.name, query))
    except Exception as e:
        Configuration.logger.error("db.%s: Database error at running find query '%s': %s" % (col.name, query, e))
        err = True
        if not api_query:
            flash("Server error at duplication data.")

    return values, err


def lookup_by_id(internal_id):
    try:
        document = Configuration.wifis.find_one({"id": internal_id})
        Configuration.logger.info("Lookup for id '%s'" % internal_id)
        return document
    except Exception as e:
        Configuration.logger.error(
            "Database error at retrieving document with internal id '%s': %s" % (internal_id, e))
        return False
