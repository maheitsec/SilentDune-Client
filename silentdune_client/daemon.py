#
# Authors: Robert Abram <robert.abram@entpack.com>
#
# Original author is Sander Marechal <s.marechal@jejik.com>
# http://www.jejik.com/articles/2007/02/a_simple_unix_linux_daemon_in_python/
#
# Copyright (C) 2015 EntPack
# see file 'LICENSE' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

# Changes: Robert Abram
#
# Added code to demote daemon process to specified uid and gid
# Added debug logging
# Re-coded for python 3.x


import sys
import os
import time
import atexit
import grp
import pwd
import logging
from signal import SIGTERM


class Daemon:
    """
    A generic daemon class.

    Usage: subclass the Daemon class and override the run() method
    """

    def __init__(self, procbase, dirmask, pidfile, uid='nobody', gid='nobody', stdin='/dev/null', stdout='/dev/null',
                 stderr='/dev/null'):
        self.procbase = procbase
        self.dirmask = dirmask
        self.pidfile = os.path.join(procbase, pidfile)
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.uid = uid
        self.gid = gid

        self.__logger = logging.getLogger()

    def daemonize(self):
        """
        do the UNIX double-fork magic, see Stevens' "Advanced
        Programming in the UNIX Environment" for details (ISBN 0201563177)
        http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
        """

        # Lookup group and user id
        if self.uid != 'nobody':
            try:
                groupinfo = grp.getgrnam(self.gid)
                self.__logger.debug('our group info. n: {0}, i:{1}'.format(groupinfo.gr_name, groupinfo.gr_gid))

            except KeyError:
                self.__logger.critical('get daemon group id failed')
                sys.exit(1)

            try:
                userinfo = pwd.getpwnam(self.uid)
                self.__logger.debug('our user info n: {0}, i:{1}'.format(userinfo.pw_name, userinfo.pw_uid))
            except KeyError:
                self.__logger.critical('get daemon user id failed')
                sys.exit(1)

        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except os.error as err:
            self.__logger.critical('fork #1 of double fork failed. ({0}): {1}'.format(err.errno, err.strerror))
            sys.exit(1)

        # decouple from parent environment
        os.chdir("/")
        os.setsid()
        os.umask(0)

        # do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # exit from second parent
                sys.exit(0)
        except os.error as err:
            self.__logger.critical('fork #2 of double fork failed. ({0}): {1}'.format(err.errno, err.strerror))
            sys.exit(1)

        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = open(self.stdin, 'rb')
        so = open(self.stdout, 'a+b')
        se = open(self.stderr, 'a+b')
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

        # Setup proc base directory and mask
        os.makedirs(self.procbase, int(self.dirmask, 8), exist_ok=True)

        # write pidfile
        atexit.register(self.delpid)
        pid = str(os.getpid())
        open(self.pidfile, 'w+').write("%s\n" % pid)
        os.chmod(self.pidfile, 0o444)

        # If uid != nobody try to demote the process
        if self.uid != 'nobody':
            # Assume that we can only demote the process if we are running as root
            if os.getuid() == 0:
                # Make the procbase directory and pid file are owned by our process user
                os.chown(self.procbase, userinfo.pw_uid, groupinfo.gr_gid)
                os.chown(self.pidfile, userinfo.pw_uid, groupinfo.gr_gid)
                # demote process to 'pki' user and 'secure' group
                os.setgid(groupinfo.gr_gid)
                os.setuid(userinfo.pw_uid)
            else:
                self.__logger.warning('not running as root, unable to demote process')

    def delpid(self):
        os.remove(self.pidfile)

    def start(self, parm):
        """
        Start the daemon
        """
        # check to see if the log path exists
        # path = os.path.dirname(parm['Default']['logfile'])
        # os.makedirs(path, exist_ok=True)

        # Check for a pidfile to see if the daemon already runs

        pid = None

        if os.path.isfile(self.pidfile):
            try:
                pf = open(self.pidfile, 'r')
                pid = int(pf.read().strip())
                pf.close()
            except os.error:
                pid = None

        if pid:
            self.__logger.warning('pidfile {0} already exists. daemon already running?'.format(self.pidfile))
            sys.exit(1)

        # Start the daemon
        self.daemonize()
        self.run(parm)

    def stop(self):
        """
        Stop the daemon
        """
        # Get the pid from the pidfile
        try:
            pf = open(self.pidfile, 'r')
            pid = int(pf.read().strip())
            pf.close()
        except os.error as err:
            self.__logger.debug('unknown error when attempting to get pid from pid file. ({0}): {1}'
                                .format(err.errno, err.strerror))
            pid = None

        if not pid:
            self.__logger.warning('pidfile {0} does not exist. daemon not running?'.format(self.pidfile))
            return  # not an error in a restart

        # Try killing the daemon process
        try:
            while 1:
                os.kill(pid, SIGTERM)
                time.sleep(0.2)
        except os.error as err:
            if err.errno == 3:  # No such process
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                self.__logger.error('unknown error when attempting to kill process. ({0}): {1}'
                                    .format(err.errno, err.strerror))
                sys.exit(1)

        try:
            os.rmdir(self.procbase)
        except OSError:
            pass

    def restart(self, parm):
        """
        Restart the daemon
        """
        self.stop()
        self.start(parm)

    def run(self, parm):
        """
        You should override this method when you subclass Daemon. It will be called after the process has been
        daemonized by start() or restart().
        """
