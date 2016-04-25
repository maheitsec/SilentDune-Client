#
# Authors: Robert Abram <robert.abram@entpack.com>
#
# Copyright (C) 2015 EntPack
# see file 'COPYING' for use and warranty information
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

        def __init__(self, *args, **kwargs):

            self._args = kwargs.pop('args', None)

            super(SDCDaemon, self).__init__(*args, **kwargs)

        # def process_tasks(self, qu):
        #
        #     _logger.debug('Processing queue thread started.')
        #
        #     while True:
        #
        #         try:
        #             task = qu.get(1.0)
        #         except multiprocessing.TimeoutError:
        #             continue
        #
        #         if task:
        #
        #             time.sleep(0.1)
        #
        #         else:
        #             _logger.debug('Got signal that we are done processing, closing processing queue thread.')
        #             break
        #
        #     _logger.debug('Processing queue thread closed cleanly.')

        def run(self):

            _logger.debug('Setting signal handlers.')
            # Set SIGTERM signal Handler
            signal.signal(signal.SIGTERM, signal_term_handler)
            signal.signal(signal.SIGHUP, signal_hup_handler)

            _logger.info('Beginning firewall startup.')

            # Get the path where this file is located.
            app_path = os.path.split(os.path.realpath(__file__))[0]
            # Get our package path and package name
            base_path, package_name = os.path.split(app_path)

            while True:

                # Reset loop controllers
                self.stopProcessing = False
                self.reload = False

                # Read the local configuration file.
                self._config = ClientConfiguration(self._args.config).read_config()

                # Get loadable module list
                mods = modules.__load_modules__(base_path=base_path)

                # Have each module do their startup work now.
                for mod in mods:
                    result = mod.service_startup()
                    if result is not None and result is False:
                        _logger.critical('Module ({0}) failed during startup.'.format(mod.get_name))
                        sys.exit(1)

                pmanager = Manager()
                mqueue = pmanager.Queue()

                # Keep the created child processes.
                cprocs = dict()
                cqueues = dict()

                # Setup thread for modules wanting a processing thread.
                for mod in mods:
                    name = mod.get_name()

                    cprocs[name] = None  # Add a place holder for the module process

                    if mod.wants_processing_thread:
                        _logger.debug('Initializing thread for {0}.'.format(name))

                        cqueues[name] = multiprocessing.Queue()
                        cprocs[name] = multiprocessing.Process(
                            target=mod.process_handler, args=(cqueues[name], mqueue, ))
                        cprocs[name].start()

                counter = 50

                # loop until we get an external signal
                _logger.debug('Starting main processing loop.')
                while not self.stopProcessing:

                    # Check management queue for any QueueTask task
                    try:
                        task = mqueue.get_nowait()
                        _logger.debug('Main process: task from {0} found.'.format(task.get_src_name()))
                        _logger.debug('Sending task to {0}'.format(task.get_dest_name()))

                        if task:
                            # Find the destination module and send task to it.
                            if not cqueues[task.get_dest_name()]:
                                _logger.error('QueueTask object has unknown destination module.')

                            cqueues[task.get_dest_name()].put(task)
                    except:
                        pass

                    time.sleep(0.01)

                    counter -= 1

                    if not counter:
                        _logger.info('Run loop.')
                        counter = 50

                    # Check to see that module processes are still running.
                    for mod in mods:
                        if mod.get_name() in cprocs and cprocs[mod.get_name()]:
                            if not cprocs[mod.get_name()].is_alive():
                                # TODO: Maybe restart the module?
                                _logger.critical('{0} module has unexpectedly stopped.'.format(mod.get_name()))
                                self.stopProcessing = True
                                break

                # Stop all module processing threads
                _logger.debug('Ending main processing loop.')

                for mod in mods:
                    name = mod.get_name()
                    _logger.debug('Stopping {0} thread.'.format(name))

                    if cprocs[name] and cprocs[name].is_alive():
                        _logger.debug('Signalling {0} module to stop processing.'.format(name))
                        cqueues[name].put(modules.QueueTask(modules.TASK_STOP_PROCESSING))
                        cqueues[name].close()
                        cqueues[name].join_thread()
                        cprocs[name].join()

                # If we are not reloading, just shutdown.
                if not self.reload:
                    break

            _logger.info('Firewall shutdown complete.')

            # exit process
            sys.exit(0)

    def signal_term_handler(signal, frame):

        if not _daemon.stopProcessing:
            _logger.warning("Firewall: Got SIGTERM, quitting.")
        _daemon.stopProcessing = True

    def signal_hup_handler(signal, frame):

        if not _daemon.reload:
            _logger.warning("Firewall: Got SIGHUP, reloading.")
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
