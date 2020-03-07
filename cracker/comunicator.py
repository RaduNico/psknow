from pynput.keyboard import Listener
from collections import deque
from threading import Lock
from config import Configuration


def on_press(key):
    try:
        char = key.char
    except AttributeError:
        return

    if key in Comunicator.pressed_key:
        return

    Comunicator.pressed_key.add(key)

    with Comunicator.cmd_lock:
        if Comunicator.enabled:
            Comunicator.cmd_deque.append(char)


def on_release(key):
    Comunicator.pressed_key.discard(key)


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

    pressed_key = set()
    cmd_lock = Lock()
    cmd_deque = deque()
    listener = Listener(on_press=on_press, on_release=on_release)

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

        print(msg)

    @staticmethod
    def get_command():
        with Comunicator.cmd_lock:
            try:
                return Comunicator.cmd_deque.popleft()
            except IndexError:
                return None

    @staticmethod
    def initialize():
        Comunicator.listener.start()

    @staticmethod
    def stop():
        Comunicator.listener.stop()

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
        print(msg)
        if reprint:
            Comunicator.print_commands()

    @staticmethod
    def dual_printer(msg, logger, reprint=True):
        logger(msg)
        print(msg)
        if reprint:
            Comunicator.print_commands()

    @staticmethod
    def error_printer(msg):
        Comunicator.dual_printer(msg, Configuration.logger.error, reprint=False)
