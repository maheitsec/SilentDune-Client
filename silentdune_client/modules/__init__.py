#
# Authors: Robert Abram <robert.abram@entpack.com>,
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

import logging
import multiprocessing
import os
import time


from silentdune_client.utils.console import ConsoleBase
from silentdune_client.utils.module_loading import import_by_str
from silentdune_client.utils.exceptions import ModuleLoadError

_logger = logging.getLogger('sd-client')

# Parent to Child task queue IDs
TASK_STOP_PROCESSING = 0

# Child to Parent task queue IDs
TASK_IS_MODULE_AVAIL = 100  # As the parent process if another module is available.
TASK_SEND_TASK_TO_MODULE = 110  # Send a QueueTask object to another module


class QueueTask(object):
    """
    The QueueTask object is an object to be passed between the parent processing thread
    and the module processing threads.  Allows for back and forth communication along with
    passing tasks between module processing threads.
    """

    _task_id = None  # One of the TASK id value from above.
    _src_name = None  # Source module name
    _dest_name = None  # Destination module name
    _data = None  # Data for this task.

    def __init__(self, task_id, src_name=None, dest_name=None, data=None):
        self._task_id = task_id
        self._src_name = src_name
        self._dest_name = dest_name
        self._data = data

    def get_task_id(self):
        return self._task_id

    def get_src_name(self):
        return self._src_name

    def get_dest_name(self):
        return self._dest_name

    def get_data(self):
        return self._data


class BaseModule(ConsoleBase):
    """
    This is the Virtual module object every module should inherit from.
    Each property and method are virtual and can be overridden as needed.
    """

    # The name of the module and version.
    # _name = 'UnknownModule'
    _arg_name = 'unknown'  # This is the argparser name for this module
    _config_section = 'unknown'  # This is the configuration file section name
    _version = '0.0.1'
    _config = None
    _enabled = True

    # Multi thread processing properties
    wants_processing_thread = False  # Set this to true if your module will use a child processing thread.

    # Parent process management queue.  This is only valid if we are using a processing thread.
    _mqueue = None

    # Delay to wait for a message from the parent.  After timeout has expired, process_loop is called.
    _queue_timeout = 1.0  # Min = 0.01, Max = 2.0.

    # Process counter, this value is incremented by one each time the process_loop method is called.
    # The _queue_timeout value and the _process_counter can be used together to determine roughly how
    # much time has passed. See self.get_ticks()
    #
    #    Number of times process_loop is called per second = ticks = ((10.0 / _queue_timeout) / 10.0)
    #    Total seconds = time = (ticks * _process_counter)
    #    Do something every 20 seconds: time % 20
    #
    _process_counter = 0

    """
    Installer Virtual Methods
    """

    def get_name(self):
        """
        :return: module name
        """
        # return self._name
        return type(self).__name__

    def get_version(self):
        """
        :return: module version
        """
        return self._version

    def get_ticks(self):
        """
        Return the number of times per second the process_loop will be called.
        """
        return (10.0 / self._queue_timeout) / 10.0

    def get_counter(self):
        """
        Return the self._process_counter value.
        """
        return self._process_counter

    def add_installer_arguments(self, parser):
        pass

    def get_config(self):
        """
        :return: configuration
        """
        return self._config

    def disable_module(self):
        self._enabled = False

    def module_enabled(self):
        return self._enabled

    def validate_arguments(self, args):
        """
        Validate command line arguments and save values to our configuration object.
        :param args: An argparse object.
        :return: True if command line arguments are valid, otherwise False.
        """
        pass

    def validate_config(self, config):
        """
        Validate configuration file arguments and save values to our config object.
        :param config: A ConfigParser object.
        :return: True if configuration file values are valid, otherwise False.
        """
        pass

    def prepare_config(self, config):
        """
        Add the module configuration items that need to be saved to the configuration file.
        :param config: A ClientConfiguration object.
        :return: True if configuration file values were prepared correctly, otherwise False.
        """
        pass

    def pre_install(self, node_info):
        """
        Called by the installer before the formal install process starts.
        :param installer: The Installer object.
        :return: True if successful, otherwise False.
        """
        pass

    def install_module(self, node_info):
        """
        Called by the installer during the formal install process.
        :param installer: The Installer object.
        :return: True if successful, otherwise False.
        """
        pass

    def post_install(self, node_info):
        """
        Called by the installer after the formal install process has completed.
        :param installer: The Installer object.
        :return: True if successful, otherwise False.
        """
        pass

    def uninstall_module(self, node_info):
        """
        Called by the installer during an uninstall process.
        :param installer: The Installer object.
        :return: True if successful, otherwise False.
        """
        pass

    """
    Service Daemon Virtual Methods
    """

    def service_startup(self):
        """
        Called by the service daemon during service start or reload.
        :return: True if successful, otherwise False.
        """
        pass

    def service_shutdown(self):
        """
        Called by the service daemon during service stop.
        :return: True if successful, otherwise False.
        """
        pass

    def process_task(self, task):
        """
        Process a QueueTask object and do something. Called by the process_handler method
        when there is a QueueTask object sent by the parent process.
        :param task:
        :return:
        """
        pass

    def process_loop(self):
        """
        This is called during after each idle timeout period has expired in process_handler.
        This method should do some work if needed and then return to the process_handler.
        Do not set a long term loop in this method. Doing so will break the parent processing.
        :return:
        """
        pass

    def process_handler(self, queue, mqueue):
        """
        !!! Please do not override this method, override the process_loop method !!!
        Called during the service loop.
        :param queue: Multiprocessing queue object.
        """
        _logger.debug('{0} processing thread started.'.format(self.get_name()))

        self._mqueue = mqueue

        if self._queue_timeout < 0.01:
            self._queue_timeout = 0.01
        if self._queue_timeout > 2.0:
            self._queue_timeout = 2.0

        while True:

            try:
                self._process_counter += 1
                task = queue.get(timeout=self._queue_timeout)  # Wait while looking for a QueueTask object.
            except:
                self.process_loop(self)  # Call the processing loop for module idle processing.
                continue

            # Check to see that task is a QueueTask object
            if isinstance(task, QueueTask):

                _logger.debug('{0} task id: {1}.'.format(self.get_name(), task.get_task_id()))

                if task.get_task_id() == TASK_STOP_PROCESSING:
                    _logger.debug('({0}) received stop signal, ending process handler.'.format(self.get_name()))
                    break

                # Process task.
                self.process_task(task)

            else:
                _logger.debug('({0}) Received bad task object, discarding.'.format(self.get_name()))

        _logger.debug('({0}) Module processing thread closed cleanly.'.format(self.get_name()))

    def send_parent_task(self, qtask):
        """
        Send a QueueTask object to the parent process.
        :param qtask: QueueTask object
        :return:
        """
        self._mqueue.put(qtask)


def __load_modules__(base_path=None, module_path='silentdune_client/modules'):
    """
    Search for modules to load.  Modules must reside under the modules directory and
    have a "module_list" dict defined in the __init__.py file. Each entry in the
    "module_list" must list a Class that subclasses BaseModule.
    """

    module_list = list()

    # Loop through the directories looking for modules to import.
    for root, dirs, files in os.walk(os.path.join(base_path, module_path), topdown=True):
        # Skip our directory.
        if root == '.':
            continue

        # Look only at __init__.py files.
        for name in files:
            if name == '__init__.py':

                # Remove base_path and convert to dotted path.
                mp = root.replace(base_path + '/', '').replace('./', '').replace('/', '.')

                # Attempt to import 'module_list' from __init__.py file.
                try:
                    ml = import_by_str(mp + '.module_list')

                # If we get an Exception check to see if the python module loaded but there was no
                # client module definition found, otherwise just reraise the last Exception for debugging.
                except ModuleLoadError:
                    # Looks like a clean import error. IE: __init__.py is not a real module.
                    continue
                except:
                    # Found a module to load, but it threw an Exception. Just pass the Exception up.
                    raise

                for mname, mdict in ml.items():
                    _logger.debug('Found module definition "{0}" in path {1}'.format(mname, mp))
                    for key, name in mdict.items():

                        if key == 'module':
                            tpath = mp + '.' + name
                            try:
                                mod = import_by_str(tpath)
                                module_list.append(mod())
                                _logger.debug('Adding "{0}" module ({1}).'.format(mname, tpath))
                            except ImportError:
                                _logger.error('Adding "{0}" module failed. ({1}).'.format(mname, tpath))
                                pass

    return module_list












