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

        def process_tasks(self, qu):

            _logger.debug('Processing queue thread started.')

            while True:

                try:
                    task = qu.get(1.0)
                except multiprocessing.TimeoutError:
                    continue

                if task:

                    time.sleep(0.1)

                else:
                    _logger.debug('Got signal that we are done processing, closing processing queue thread.')
                    break

            _logger.debug('Processing queue thread closed cleanly.')

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

                # Read the local configuration file.
                self._config = ClientConfiguration(self._args.config).read_config()

                # TODO: Load client modules here.

                _logger.debug('Initializing processing queue child.')
                qu = multiprocessing.Queue()
                child = multiprocessing.Process(target=self.process_tasks, args=(qu,))
                child.start()

                # loop until we get a signal
                _logger.debug('Starting main processing loop.')
                while not self.stopProcessing and child.is_alive():

                    time.sleep(2)
                    _logger.info('Run loop.')

                if child.is_alive():
                    _logger.debug('Waiting for processing queue child process to finish.')
                    qu.put(None)

                qu.close()
                qu.join_thread()
                child.join()

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

    # setup_logging(args.debug, config.get('settings', 'logfile'))

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
