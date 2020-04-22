import sys
import tty
import termios
import logbook
import inspect

from _thread import start_new_thread
from collections import deque
from threading import Lock


def reader_thread():
    if not Comunicator.reader_alive:
        return

    try:
        tty.setcbreak(sys.stdin.fileno())
        while Comunicator.reader_alive:
            key = sys.stdin.read(1)

            with Comunicator.cmd_lock:
                if Comunicator.enabled:
                    Comunicator.cmd_deque.append(key)
    except Exception as e:
        print("Unexpected exception in reader thread %s" % e)
        sys.exit(-1)

class Comunicator:
    # Logging variables
    log_filename = 'logs/cracker.log'
    logLevel = "DEBUG"
    # :logLevel = "INFO"
    logger = None

    interactive_cmds = "[s]tatus, [q]uit, [f]inish, [c]heckpoint, [p]ause"
    interactive_cmds_p = "[s]tatus, [q]uit, [f]inish, [c]heckpoint, [r]esume"
    interactive_cmds_f = "[s]tatus, [q]uit, [d]ont_finish, [c]heckpoint, [p]ause"
    interactive_cmds_fp = "[s]tatus, [q]uit, [d]ont_finish, [c]heckpoint, [r]esume"
    non_interactive_cmds = "[s]tatus, [q]uit, [f]inish"
    non_interactive_cmds_f = "[s]tatus, [q]uit, [d]ont_finish"

    paused = False
    finished = False
    interactive = False
    enabled = False
    space_needed = False
    reader_alive = False
    old_settings = None

    pressed_key = set()
    cmd_lock = Lock()
    cmd_deque = deque()

    @staticmethod
    def setup_logging():
        Comunicator.logger = logbook.Logger("")
        Comunicator.logger.handlers.append(logbook.FileHandler(Comunicator.log_filename,
                                                               level=Comunicator.logLevel))
        Comunicator.logger.info("Logging activated!")

    @staticmethod
    def print_commands(space=True):
        if space:
            print("")

        if Comunicator.interactive:
            if Comunicator.finished:
                msg = Comunicator.interactive_cmds_f
                if Comunicator.paused:
                    msg = Comunicator.interactive_cmds_fp
            else:
                msg = Comunicator.interactive_cmds
                if Comunicator.paused:
                    msg = Comunicator.interactive_cmds_p
        else:
            msg = Comunicator.non_interactive_cmds
            if Comunicator.finished:
                msg = Comunicator.non_interactive_cmds_f

        sys.stdout.write(msg)
        sys.stdout.flush()
        Comunicator.space_needed = True

    @staticmethod
    def get_command():
        with Comunicator.cmd_lock:
            try:
                return Comunicator.cmd_deque.popleft()
            except IndexError:
                return None

    @staticmethod
    def initialize():
        Comunicator.old_settings = termios.tcgetattr(sys.stdin.fileno())
        Comunicator.setup_logging()
        Comunicator.reader_alive = True
        start_new_thread(reader_thread, ())

    @staticmethod
    def stop():
        Comunicator.reader_alive = False

        if Comunicator.old_settings is not None:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, Comunicator.old_settings)

    @staticmethod
    def enable(interactive=False):
        Comunicator.interactive = interactive
        Comunicator.enabled = True

    @staticmethod
    def disable():
        Comunicator.enabled = False
        with Comunicator.cmd_lock:
            Comunicator.cmd_deque.clear()

    @staticmethod
    def printer(msg, reprint=True):
        if Comunicator.space_needed is True:
            print("")
            Comunicator.space_needed = False

        print(msg)
        if reprint and Comunicator.enabled:
            Comunicator.print_commands()

    @staticmethod
    def dual_printer(logger, msg, reprint=True):
        logger(msg)

        if Comunicator.space_needed is True:
            print("")
            Comunicator.space_needed = False

        print(msg)
        if reprint and Comunicator.enabled:
            Comunicator.print_commands()

    @staticmethod
    def fatal_regular_message(message):
        Comunicator.dual_printer(Comunicator.logger.critical, message, reprint=False)
        Comunicator.stop()
        sys.exit(-1)

    @staticmethod
    def fatal_debug_printer(message):
        fmt_message = "File '%s', line %s, in %s: %s" % \
                      (inspect.getmodule(inspect.stack()[1][0]).__file__, inspect.currentframe().f_back.f_lineno,
                       inspect.stack()[1][3], message)
        Comunicator.fatal_regular_message(fmt_message)

    @staticmethod
    def error_logger(msg):
        Comunicator.logger.error(msg)

    @staticmethod
    def debug_logger(msg):
        Comunicator.logger.debug(msg)

    @staticmethod
    def info_logger(msg):
        Comunicator.logger.info(msg)

    @staticmethod
    def warning_logger(msg):
        Comunicator.logger.warning(msg)
