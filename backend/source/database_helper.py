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


# Returns the result of the query and True if error occured, False otherwise
def generic_find(col, query, api_query=False):
    values = None
    err = False

    try:
        values = col.find(query)
        Configuration.logger.info("db.%s: Error for query:'%s'" % (col.name, query))
    except Exception as e:
        Configuration.logger.error("db.%s: Database error at running find query '%s': %s" % (col.name, query, e))
        err = True
        if not api_query:
            flash("Server error at duplication data.")

    return values, err
