import sys
import tty
import termios

from _thread import start_new_thread
from collections import deque
from threading import Lock
from config import Configuration


def reader_thread():
    tty.setcbreak(sys.stdin.fileno())

    while Comunicator.reader_alive:
        key = sys.stdin.read(1)

        with Comunicator.cmd_lock:
            if Comunicator.enabled:
                Comunicator.cmd_deque.append(key)


class Comunicator:
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
        Comunicator.reader_alive = True
        start_new_thread(reader_thread, ())
        # Comunicator.listener.start()

    @staticmethod
    def stop():
        Comunicator.reader_alive = False

        if Comunicator.old_settings is not None:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, Comunicator.old_settings)
        # Comunicator.listener.stop()

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
        if reprint:
            Comunicator.print_commands()

    @staticmethod
    def dual_printer(msg, logger, reprint=True):
        logger(msg)

        if Comunicator.space_needed is True:
            print("")
            Comunicator.space_needed = False

        print(msg)
        if reprint:
            Comunicator.print_commands()

    @staticmethod
    def error_printer(msg):
        Comunicator.dual_printer(msg, Configuration.logger.error, reprint=False)
