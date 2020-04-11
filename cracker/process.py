#!/usr/bin/env python
# -- coding: utf-8 --

import time
import signal
import os
import sys
import traceback
from config import Configuration
from copy import deepcopy
from threading import Thread
from subprocess import Popen


class NoProcess:
    @staticmethod
    def get_devnull_w():
        return open('/dev/null', 'w')

    @staticmethod
    def get_devnull_r():
        return open('/dev/null', 'r')

    @staticmethod
    def get_pipe_wrapper():
        r, w = os.pipe()
        return os.fdopen(r, "r"), os.fdopen(w, "w")

    @staticmethod
    def command_is_hashcat(command):
        return (isinstance(command, str) and command.split(' ')[0] == "hashcat") or \
               (isinstance(command, list) and command[0] == "hashcat")

    @staticmethod
    def _close_helper(file):
        if file is not None:
            file.close()
        return [None]

    @staticmethod
    def _join_helper(thread):
        if thread is not None:
            thread.join()
        return [None]

    # TODO Taken project, rewrite this
    @staticmethod
    def interrupt(process, cmd, wait_time=2.0):
        try:
            pid = process.pid
            if type(cmd) is list:
                cmd = ' '.join(cmd)

            Configuration.logger.info('sending interrupt to PID %d (%s)' % (pid, cmd))

            if wait_time == 0.0:
                os.kill(pid, signal.SIGTERM)
                process.terminate()
                return

            os.kill(pid, signal.SIGINT)

            start_time = time.time()  # Time since Interrupt was sent
            while process.poll() is None:
                # Process is still running
                time.sleep(0.1)
                if time.time() - start_time > wait_time:
                    # We waited too long for process to die, terminate it.
                    Configuration.logger.info('Waited > %0.2f seconds for process to die, killing it' % wait_time)
                    os.kill(pid, signal.SIGTERM)
                    process.terminate()
                    break

        except OSError as e:
            if 'No such process' in str(e):
                return
            raise e  # process cannot be killed

    @staticmethod
    def _all_reader_thread(read_pipe, error_list):
        # Read error pipe and close reading stream
        error_list += read_pipe.readlines()
        read_pipe.close()

    @staticmethod
    def _hashcat_out_thread(read_pipe, output_list, hashcat_progress):
        for line in read_pipe:
            match = Configuration.hashcat_progress_re.match(line)
            if match is not None:
                hashcat_progress["progress"] = int(match.group(1))

            match = Configuration.hashcat_eta_re.match(line)
            if match is not None:
                hashcat_progress["eta"] = match.group(1)

            match = Configuration.hashcat_speed_re.match(line)
            if match is not None:
                hashcat_progress["speed"] = match.group(1)

            output_list.append(line)
        read_pipe.close()

    @staticmethod
    def __func_name():
        return traceback.extract_stack(None, 2)[0][2]

    def __init__(self):
        self.hashcat_progress = deepcopy(Configuration.default_hashcat_dict)

    def get_dict(self):
        raise ValueError("%s method not implemented!" % NoProcess.__func_name())

    def isdead(self):
        raise ValueError("%s method not implemented!" % NoProcess.__func_name())

    def poll(self):
        raise ValueError("%s method not implemented!" % NoProcess.__func_name())

    def get_command(self):
        raise ValueError("%s method not implemented!" % NoProcess.__func_name())

    def generate_output(self):
        raise ValueError("%s method not implemented!" % NoProcess.__func_name())

    def terminate(self):
        self._force_cleanup()

    def _force_cleanup(self):
        raise ValueError("%s internal method not implemented!" % NoProcess.__func_name())

    def check_clean_exit(self):
        self.isdead()


class DoubleProcess(NoProcess):
    def __init__(self, fst_cmd, snd_cmd, crit=True):
        super(DoubleProcess, self).__init__()
        if len(fst_cmd) == 0 or len(snd_cmd) == 0:
            Configuration.log_fatal("One empty command in chained processes '%s' | '%s'" %
                                    (fst_cmd, snd_cmd))

        self.critical = crit
        self.ended = False

        # Logging data
        self.command = fst_cmd + ' | ' + snd_cmd
        self.fst_cmd = fst_cmd
        self.snd_cmd = snd_cmd

        disp1 = fst_cmd if type(fst_cmd) is str else " ".join(fst_cmd)
        disp2 = snd_cmd if type(snd_cmd) is str else " ".join(snd_cmd)

        Configuration.logger.debug("Executing chained commands: '%s | %s'" % (disp1, disp2))

        # Output variables need to be mutable in order to modify them
        # from generic thread
        self.snd_out = []
        self.snd_err = []
        self.fst_err = []

        self.comm_r, self.comm_w = DoubleProcess.get_pipe_wrapper()
        self.snd_out_r, self.snd_out_w = DoubleProcess.get_pipe_wrapper()
        self.fst_err_r, self.fst_err_w = DoubleProcess.get_pipe_wrapper()
        self.snd_err_r, self.snd_err_w = DoubleProcess.get_pipe_wrapper()

        self.fst_reaped = False
        self.snd_reaped = False

        # Why an entire thread just to read from pipes?
        # Because if a pipe is full the program writing to the pipe will
        # get stuck until data is read from the pipe. If we simply call
        # wait for the process without reading data it will get stuck.
        # If we call readlines before we wait we might get stuck because
        # the writing end of the pipe is never closed... despite the program
        # not running anymore.
        self.fst_err_reader_thread = Thread(target=self._all_reader_thread, args=(self.fst_err_r, self.fst_err))
        self.snd_err_reader_thread = Thread(target=self._all_reader_thread, args=(self.snd_err_r, self.snd_err))

        if DoubleProcess.command_is_hashcat(self.snd_cmd):
            self.snd_out_reader_thread = Thread(target=self._hashcat_out_thread,
                                                args=(self.snd_out_r, self.snd_out, self.hashcat_progress))
        else:
            self.snd_out_reader_thread = Thread(target=self._all_reader_thread, args=(self.snd_out_r, self.snd_out))

        if type(snd_cmd) is str:
            snd_cmd = snd_cmd.split(' ')
        try:
            self.snd_proc = Popen(snd_cmd, stdin=self.comm_r, stdout=self.snd_out_w, stderr=self.snd_err_w)
        except Exception as e:
            Configuration.log_fatal("Error while trying to run command '%s':\n%s" % (snd_cmd, e))

        if type(fst_cmd) is str:
            fst_cmd = fst_cmd.split(' ')
        try:
            self.fst_proc = Popen(fst_cmd, stdin=DoubleProcess.get_devnull_r(),
                                  stdout=self.comm_w, stderr=self.fst_err_w)
        except Exception as e:
            Configuration.log_fatal("Error while trying to run command '%s':\n%s" % (fst_cmd, e))

        self.fst_err_reader_thread.start()
        self.snd_err_reader_thread.start()
        self.snd_out_reader_thread.start()

    def __del__(self):
        self._force_cleanup()

    def get_dict(self):
        if DoubleProcess.command_is_hashcat(self.snd_cmd):
            return deepcopy(self.hashcat_progress)
        else:
            raise ValueError

    def isdead(self):
        self._reap_fst()
        self._reap_snd()

        return self.snd_proc.poll() is not None

    #  Returns exit code if process is dead, otherwise 'None'
    def poll(self):
        return self.snd_proc.poll()

    def get_command(self):
        return self.command

    def _force_cleanup(self):
        try:
            if self.fst_proc and self.fst_proc.poll() is None:
                self.interrupt(self.fst_proc, self.fst_cmd)

            if self.snd_proc and self.snd_proc.poll() is None:
                self.interrupt(self.snd_proc, self.snd_cmd)

            # Close both processes writing pipe if they are still open
            self.fst_err_w = DoubleProcess._close_helper(self.fst_err_w)[0]  # Stops fst_err_reader_thread
            self.snd_err_w = DoubleProcess._close_helper(self.snd_err_w)[0]  # Stops snd_err_reader_thread
            self.snd_out_w = DoubleProcess._close_helper(self.snd_out_w)[0]  # Stops snd_out_reader_thread

            # Close interprocess pipe if it not killed yet
            self.comm_r = DoubleProcess._close_helper(self.comm_r)[0]
            self.comm_w = DoubleProcess._close_helper(self.comm_w)[0]

            # Join threads if they are still running. Stopping the threads also closes the respective pipes
            self.fst_err_reader_thread = DoubleProcess._join_helper(self.fst_err_reader_thread)[0]
            self.snd_err_reader_thread = DoubleProcess._join_helper(self.snd_err_reader_thread)[0]
            self.snd_out_reader_thread = DoubleProcess._join_helper(self.snd_out_reader_thread)[0]

            # The reading ends of the pipes were closed by the threads
            self.snd_err_r = self.snd_out_r = self.fst_err_r = None

        except AttributeError as e:
            Configuration.logger.error("Attribute error raised %s" % e)
            pass

    # Check if the first process is ready to be stopped
    # If the now value is specified it waits for the process to stop
    # Returns True if the process is not running anymore else False
    def _reap_fst(self, now=False):
        if self.fst_reaped:
            return True

        if now and self.fst_proc.poll() is None:
            # Wait for the first process to stop executing
            self.fst_proc.wait()

        if self.fst_proc.poll() is not None:
            # The first process stopped executing, close it's write pipes
            self.fst_err_w.close()
            self.fst_err_w = None

            self.comm_w.close()
            self.comm_w = None

            # After we closed the writing end of the err pipe _all_reader_thread should stop
            self.fst_err_reader_thread.join()
            self.fst_err_reader_thread = None

            # Convert error from list to string
            self.fst_err = "".join(self.fst_err)

            # Mark the first process as completely stopped
            self.fst_reaped = True

            # TODO this can be generic. If this becomes static the poll needs to be checked against None
            if self.critical and self.fst_proc.poll() != 0:
                Configuration.logger.debug("First process %s exited with status %d. Stderr:\n%s" %
                                           (self.fst_cmd, self.fst_proc.poll(), None))
                self._force_cleanup()
                sys.exit(self.fst_proc.poll())

            return True
        return False

    # Check if the second process is ready to be stopped
    # If the now value is specified it waits for the process to stop
    # Returns True if the process is not running anymore else False
    def _reap_snd(self, now=False):
        if self.snd_reaped:
            return True

        if now and self.snd_proc.poll() is None:
            self.snd_proc.wait()
            # self.snd_out, _ = self.snd_proc.get_output()

        if self.snd_proc.poll() is not None:
            # Process stopped so close the writing end of the pipes
            self.snd_err_w.close()
            self.snd_err_w = None

            self.snd_out_w.close()
            self.snd_out_w = None

            # Cleanup the reading pipe
            self.comm_r.close()
            self.comm_r = None

            # After we closed the writing end of the pipe _all_reader_thread should stop
            self.snd_err_reader_thread.join()
            self.snd_err_reader_thread = None

            self.snd_out_reader_thread.join()
            self.snd_out_reader_thread = None

            # Convert error from list to string
            self.snd_err = "".join(self.snd_err)

            # Mark the second process as completely stopped
            self.snd_reaped = True

            if self.critical and self.snd_proc.poll() != 0:
                # Second process could be hashcat which sometimes returns 1 but no error
                if DoubleProcess.command_is_hashcat(self.snd_cmd) and self.snd_proc.poll() != 1:
                    Configuration.logger.debug("Second process %s exited with status %d. Stderr:\n%s" %
                                               (self.snd_cmd, self.snd_proc.poll(), self.snd_err))
                    self._force_cleanup()
                    sys.exit(self.snd_proc.poll())

            return True

        return False

    def stdout(self):
        self.generate_output()
        return "".join(self.snd_out)

    def split_stdout(self):
        self.generate_output()
        return self.snd_out

    def fst_stderr(self):
        self.generate_output()
        return self.fst_err

    def snd_stderr(self):
        self.generate_output()
        return self.snd_err

    def generate_output(self):
        if not self.ended:
            self._reap_fst(now=True)
            self._reap_snd(now=True)
            self.ended = True


class SingleProcess(NoProcess):
    def ___hashcat_writer_thread(self, write_pipe):
        old_time = time.time()

        while not self.stop_in_thread:
            if time.time() - old_time > 30:
                old_time = time.time()
                if write_pipe:
                    write_pipe.write("s")
                    write_pipe.flush()
            else:
                time.sleep(1)

        write_pipe.close()

    def __init__(self, cmd, crit=True, nolog=False):
        super(SingleProcess, self).__init__()
        if len(cmd) == 0:
            Configuration.log_fatal("Empty command '%s' send to SingleProcess" % cmd)

        self.critical = crit

        # Logging data
        self.cmd = cmd

        if not nolog:
            if type(cmd) is str:
                Configuration.logger.debug("Executing command: '%s'" % self.cmd)
            else:
                Configuration.logger.debug("Executing command: '%s'" % " ".join(self.cmd))

        # Output variables need to be mutable in order to modify them
        # from generic thread
        self.out = []
        self.err = []

        self.out_r, self.out_w = SingleProcess.get_pipe_wrapper()
        self.err_r, self.err_w = SingleProcess.get_pipe_wrapper()
        self.in_r, self.in_w = None, None
        self.in_writer_thread = None

        self.reaped = False
        self.stop_in_thread = False
        self.ended = False

        # Why an entire thread just to read from pipes?
        # Because if a pipe is full the program writing to the pipe will
        # get stuck until data is read from the pipe. If we simply call
        # wait for the process without reading data it will get stuck.
        # If we call readlines before we wait we might get stuck because
        # the writing end of the pipe is never closed... despite the program
        # not running anymore.
        self.err_reader_thread = Thread(target=self._all_reader_thread, args=(self.err_r, self.err))

        if SingleProcess.command_is_hashcat(self.cmd):
            self.in_r, self.in_w = SingleProcess.get_pipe_wrapper()
            self.in_w.write("s")
            self.in_writer_thread = Thread(target=self.___hashcat_writer_thread, args=(self.in_w,))
            self.out_reader_thread = Thread(target=self._hashcat_out_thread,
                                            args=(self.out_r, self.out, self.hashcat_progress))
        else:
            self.out_reader_thread = Thread(target=self._all_reader_thread, args=(self.out_r, self.out))

        if type(cmd) is str:
            cmd = cmd.split(' ')
        try:
            self.proc = Popen(cmd, stdin=self.in_r, stdout=self.out_w, stderr=self.err_w)
        except Exception as e:
            Configuration.log_fatal("Error while trying to run command '%s':\n%s" % (cmd, e))

        if self.in_writer_thread is not None:
            self.in_writer_thread.start()
        self.err_reader_thread.start()
        self.out_reader_thread.start()

    def __del__(self):
        self._force_cleanup()

    def get_dict(self):
        if SingleProcess.command_is_hashcat(self.cmd):
            return deepcopy(self.hashcat_progress)
        else:
            raise ValueError

    def isdead(self):
        self._reap()

        return self.proc.poll() is not None

    #  Returns exit code if process is dead, otherwise 'None'
    def poll(self):
        return self.proc.poll()

    def get_command(self):
        return self.cmd

    def _force_cleanup(self):
        try:
            if self.proc and self.proc.poll() is None:
                self.interrupt(self.proc, self.cmd)

            # Stop ___hashcat_writer_thread as soon as possible (takes a bit because of the sleep(1))
            self.stop_in_thread = True

            # Close both processes writing pipe if they are still open
            self.err_w = SingleProcess._close_helper(self.err_w)[0]  # Stops err_reader_thread
            self.out_w = SingleProcess._close_helper(self.out_w)[0]  # Stops out_reader_thread

            # Join threads if they are still running. Stopping the threads also closes the respective pipes
            self.in_writer_thread = SingleProcess._join_helper(self.in_writer_thread)[0]
            self.err_reader_thread = SingleProcess._join_helper(self.err_reader_thread)[0]
            self.out_reader_thread = SingleProcess._join_helper(self.out_reader_thread)[0]

            # The reading/writing ends of the pipes were closed by the threads
            self.err_r = self.out_r = self.in_w = None

            # Close the reading end of the stdin pipe
            self.in_r = SingleProcess._close_helper(self.in_r)[0]

        except AttributeError as e:
            Configuration.logger.error("Attribute error raised %s" % e)
            pass

    # Check if the process is ready to be stopped
    # If the now value is specified it waits for the process to stop
    # Returns True if the process is not running anymore else False
    def _reap(self, now=False):
        if self.reaped:
            return True

        if now and self.proc.poll() is None:
            # Wait for the first process to stop executing
            self.proc.wait()

        if self.proc.poll() is not None:
            # Stop ___hashcat_writer_thread as soon as possible (takes a bit because of the sleep(1))
            self.stop_in_thread = True  # This stops the ___hashcat_writer_thread

            # The process stopped executing, close it's write pipes
            self.err_w = SingleProcess._close_helper(self.err_w)[0]  # Stops err_reader_thread
            self.out_w = SingleProcess._close_helper(self.out_w)[0]  # Stops out_reader_thread

            # After we closed the writing end of the pipe _all_reader_thread should stop
            self.err_reader_thread = SingleProcess._join_helper(self.err_reader_thread)[0]
            self.out_reader_thread = SingleProcess._join_helper(self.out_reader_thread)[0]

            # This process might take a bit to shutdown because it has a sleep(1)
            # Mark stop_in_thread as true ASAP in order to give the thread time to stop
            self.in_writer_thread = SingleProcess._join_helper(self.in_writer_thread)[0]

            # Convert error from list to string
            self.err = "".join(self.err)

            # Mark the second process as completely stopped
            self.reaped = True

            if self.critical and self.proc.poll() != 0:
                # Second process could be hashcat which sometimes returns 1 but no error
                if SingleProcess.command_is_hashcat(self.cmd) and self.proc.poll() != 1:
                    Configuration.logger.debug("Process %s exited with status %d. Stderr:\n%s" %
                                                 (self.cmd, self.proc.poll(), self.err))
                    self._force_cleanup()
                    sys.exit(self.proc.poll())

            return True
        return False

    def stdout(self):
        self.generate_output()
        return "".join(self.out)

    def split_stdout(self):
        self.generate_output()
        return self.out

    def stderr(self):
        self.generate_output()
        return self.err

    def generate_output(self):
        if not self.ended:
            self._reap(now=True)
            self.ended = True
