#
# Authors: Robert Abram <robert.abram@entpack.com>
#
# Copyright (C) 2015-2016 EntPack
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

import argparse
import gettext
import logging
import multiprocessing
import os
import signal
import sys
import time

from multiprocessing import Manager

from silentdune_client import modules
from silentdune_client.utils.log import setup_logging
from silentdune_client.utils.misc import node_info_dump

from silentdune_client.utils.configuration import ClientConfiguration
from silentdune_client.utils.daemon import Daemon

_logger = logging.getLogger('sd-client')


def run():

    class SDCDaemon(Daemon):

        # Node configuration information
        _args = None
        _config = None
        stopProcessing = False
        reload = False

        t_start = time.time()
        t_mod_check = 0

        def __init__(self, *args, **kwargs):

            self._args = kwargs.pop('args', None)

            super(SDCDaemon, self).__init__(*args, **kwargs)

        def startup_modules(self):

            # Get the path where this file is located.
            app_path = os.path.split(os.path.realpath(__file__))[0]
            # Get our package path and package name
            base_path, package_name = os.path.split(app_path)

            # Get loadable module list
            mods = modules.__load_modules__(base_path=base_path)

            # Have each module do their startup work now.
            for mod in mods:
                mod.set_config(self._config)  # Set the configuration information in the module.
                result = mod.service_startup()
                if result is not None and result is False:
                    _logger.critical('Module ({0}) failed during startup.'.format(mod.get_name))
                    sys.exit(1)

            pmanager = Manager()
            mqueue = pmanager.Queue()

            # Keep the created child processes.
            cprocs = dict()   # Dictionary of module process handlers.
            cqueues = dict()  # Dictionary of module Queue objects.
            mlist = list()    # List of module names.

            # Get list of module names
            for mod in mods:
                mlist.append(mod.get_name())

            # Setup thread for modules wanting a processing thread.
            for mod in mods:
                name = mod.get_name()

                cprocs[name] = None  # Add a place holder for the module process

                if mod.wants_processing_thread:
                    _logger.debug('Initializing thread for {0}.'.format(name))

                    cqueues[name] = multiprocessing.Queue()
                    cprocs[name] = multiprocessing.Process(
                        target=mod.process_handler, args=(cqueues[name], mqueue, mlist))
                    cprocs[name].start()

            return mods, pmanager, mqueue, cprocs, cqueues, mlist

        def check_module_state(self, mods, cprocs, force=False):
            """
            Check each module that has a thread and make sure it is still alive.
            :param mods:
            :return: False if all threads are running fine, True if failed module.
            """

            # We only want to do a check once a minute.
            time_t = int((time.time() - self.t_start))

            if (time_t > self.t_mod_check and time_t % 60.0 == 0.0) or force:
                self.t_mod_check = int((time.time() - self.t_start))

                # Check to see that module process threads are still running.
                _logger.debug('Checking module threads.')
                for mod in mods:
                    if mod.get_name() in cprocs and cprocs[mod.get_name()]:
                        if not cprocs[mod.get_name()].is_alive():
                            # TODO: Maybe restart the module?
                            _logger.critical('{0} module has unexpectedly stopped.'.format(mod.get_name()))
                            return True

            return False

        def terminate_modules(self, mods, cprocs, cqueues):
            """
            Shutdown modules.
            """
            for mod in mods:

                name = mod.get_name()

                if cprocs[name] and cprocs[name].is_alive():
                    _logger.debug('Signalling {0} module to stop processing.'.format(name))
                    cqueues[name].put(modules.QueueTask(modules.TASK_STOP_PROCESSING))
                    cqueues[name].close()
                    cqueues[name].join_thread()
                    cprocs[name].join()

        def run(self):

            _logger.debug('Setting signal handlers.')
            # Set SIGTERM signal Handler
            signal.signal(signal.SIGTERM, signal_term_handler)
            signal.signal(signal.SIGHUP, signal_hup_handler)

            _logger.info('Starting firewall service.')

            # This loop allows for restarting and reloading the configuration after a SIGHUP signal has been received.
            while True:

                # Reset loop controllers
                self.stopProcessing = False
                self.reload = False

                # Read the local configuration file.
                self._config = ClientConfiguration(self._args.config).read_config()

                mods, pmanager, mqueue, cprocs, cqueues, mlist = self.startup_modules()

                # RUn main loop until we get an external signal.
                _logger.debug('Starting main processing loop.')
                while not self.stopProcessing:

                    if self.check_module_state(mods, cprocs):
                        self.stopProcessing = True
                        break

                    # Check manage queue for any QueueTask object.
                    try:
                        task = mqueue.get_nowait()
                        _logger.debug('Forwarding task ({0}) from {1} to {2}'.format(
                            task.get_task_id(), task.get_sender(), task.get_dest_name()))

                        if task:
                            # Find the destination module and send task to it.
                            if not task.get_dest_name() or not cqueues[task.get_dest_name()]:
                                _logger.error('Task from {0} has unknown destination.'.format(task.get_sender()))

                            cqueues[task.get_dest_name()].put(task)
                    except:
                        pass

                    # Sleep.
                    time.sleep(0.25)

                # Stop all module processing threads
                _logger.debug('Shutting firewall service down.')

                self.terminate_modules(mods, cprocs, cqueues)

                # If we are not reloading, just shutdown.
                if not self.reload:
                    break

                _logger.debug('Reloading firewall.')

            _logger.info('Firewall shutdown complete.')

            # exit process
            sys.exit(0)

    def signal_term_handler(signal, frame):

        if not _daemon.stopProcessing:
            _logger.debug('Received SIGTERM signal.')
        _daemon.stopProcessing = True

    def signal_hup_handler(signal, frame):

        if not _daemon.reload:
            _logger.debug('Received SIGHUP signal.')
        _daemon.reload = True
        _daemon.stopProcessing = True

    _logger.addHandler(setup_logging('--debug' in sys.argv))

    # Setup i18n - Good for 2.x and 3.x python.
    kwargs = {}
    if sys.version_info[0] < 3:
        kwargs['unicode'] = True
    gettext.install('sdc_service', **kwargs)

    # Setup program arguments.
    parser = argparse.ArgumentParser(prog='sdc-firewall')
    parser.add_argument('-c', '--config', help=_('Use config file'), default=None, type=str)  # noqa
    parser.add_argument('--debug', help=_('Enable debug output'), default=False, action='store_true')  # noqa
    parser.add_argument('--nodaemon', help=_('Do not daemonize process'), default=False, action='store_true')  # noqa
    parser.add_argument('action', choices=('start', 'stop', 'restart'), default='')

    args = parser.parse_args()

    if os.getuid() != 0:
        print('sdc-firewall: error: must be run as root')
        sys.exit(4)

    # --nodaemon only valid with start action
    if args.nodaemon and args.action != 'start':
        print('sdc-firewall: error: --nodaemon option not valid with stop or restart action')
        sys.exit(1)

    # Read the local configuration file.
    config = ClientConfiguration(args.config).read_config()

    # Dump debug information
    if args.debug:
        node_info_dump(args)

    if not config:
        _logger.error('Invalid configuration file information, aborting.')
        sys.exit(1)

    # Do not fork the daemon process, run in foreground. For systemd service or debugging.
    if args.nodaemon:
        _daemon = SDCDaemon(args=args)
        _daemon.run()
    else:
        # Setup daemon object
        _daemon = SDCDaemon(
            os.path.split(config.get('settings', 'pidfile'))[0],
            '0o700',
            os.path.split(config.get('settings', 'pidfile'))[1],
            config.get('settings', 'user'),
            config.get('settings', 'group'),
            '/dev/null',
            config.get('settings', 'logfile'),
            '/dev/null',
            args=args
        )

        if args.action == 'start':
            _logger.debug('Starting daemon.')
            _daemon.start()
        elif args.action == 'stop':
            _logger.debug('Stopping daemon.')
            _daemon.stop()
        elif args.action == 'restart':
            _logger.debug('Restarting daemon.')
            _daemon.restart()

    return 0


# --- Main Program Call ---
if __name__ == '__main__':
    sys.exit(run())
