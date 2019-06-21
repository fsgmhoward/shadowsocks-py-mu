#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2015 mengskysama
# Copyright 2016 Howard Liu
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import traceback
import manager
import sys
import os
import logging
import time
from dbtransfer import DbTransfer
from sys import platform
# Check whether the config is correctly renamed
try:
    import config
except ImportError:
    print('[ERROR] Please rename `config_example.py` to `config.py` first!')
    sys.exit('config not found')
# For those system do not have thread (or _thread in Python 3)
try:
    import thread
except ImportError:
    import _thread as thread

if config.LOG_ENABLE:
    logger = logging.getLogger()
    logger.setLevel(config.LOG_LEVEL)

    if config.LOG_STDOUT:
        consoleHandler = logging.StreamHandler(stream=sys.stdout)
        consoleHandler.setFormatter(
            logging.Formatter(
                config.LOG_FORMAT,
                datefmt=config.LOG_DATE_FORMAT))
        consoleHandler.setLevel(config.LOG_LEVEL)
        if platform == 'linux' or platform == 'linux2':
            # Check whether the instance is running in Docker
            with open('/proc/1/cgroup', 'rt') as ifh:
                if 'docker' in ifh.read():
                    print('[INFO] Running inside a docker.')
                    print(
                        '[INFO] Config of log file path will be ignored & log will not be printed to stdout.')
                    config.LOG_FILE = 'shadowsocks.log'
                else:
                    logger.addHandler(consoleHandler)
        else:
            logger.addHandler(consoleHandler)

    if config.LOG_FILE:
        # If enabled logging to file, add a fileHandler as well
        if sys.version_info >= (2, 6) and platform != 'win32':
            # If python version is >= 2.6 and it is not running on Windows, use
            # WatchedFileHandler
            import logging.handlers
            fileHandler = logging.handlers.WatchedFileHandler(config.LOG_FILE)
        else:
            fileHandler = logging.FileHandler(config.LOG_FILE)
        fileHandler.setFormatter(
            logging.Formatter(
                config.LOG_FORMAT,
                datefmt=config.LOG_DATE_FORMAT))
        fileHandler.setLevel(config.LOG_LEVEL)
        logger.addHandler(fileHandler)


# Check whether the versions of config files match
try:
    import config_example
    if not hasattr(
            config,
            'CONFIG_VERSION') or config.CONFIG_VERSION != config_example.CONFIG_VERSION:
        logging.error(
            'Your config file is outdated. Please update `config.py` according to `config_example.py`.')
        sys.exit('config out-dated')
except ImportError:
    logging.error(
        'DO NOT delete the example configuration! Please re-upload it or use `git reset` to recover the file!')
    sys.exit('example config file missing')

if os.path.isdir('../.git') and not os.path.exists('../.nogit'):
    import subprocess
    if "check_output" not in dir(subprocess):
        # Compatible with Python < 2.7
        VERSION = subprocess.Popen(["git",
                                    "describe",
                                    "--tags",
                                    "--always"],
                                   stdout=subprocess.PIPE).communicate()[0]
    else:
        VERSION = subprocess.check_output(
            ["git", "describe", "--tags", "--always"])
    # Remove EOL characters in git's output
    VERSION = VERSION.rstrip()
else:
    VERSION = '3.4.0-dev'


def subprocess_callback(stack, exception):
    logging.info('Exception thrown in %s: %s' % (stack, exception))
    if config.SS_VERBOSE:
        traceback.print_exc()


def main():
    if config.SS_FIREWALL_ENABLED:
        if config.SS_FIREWALL_MODE == 'blacklist':
            firewall_ports = config.SS_BAN_PORTS
        else:
            firewall_ports = config.SS_ALLOW_PORTS
    else:
        firewall_ports = None

    config_passed = {
        'server': config.SS_BIND_IP,
        'local_port': 1081,
        'port_password': {},
        'method': config.SS_METHOD,
        'manager_address': '%s:%s' % (config.MANAGER_BIND_IP, config.MANAGER_PORT),
        'timeout': config.SS_TIMEOUT,
        'fast_open': config.SS_FASTOPEN,
        'verbose': config.SS_VERBOSE,
        'forbidden_ip': config.SS_FORBIDDEN_IP,
        'firewall_mode': config.SS_FIREWALL_MODE,
        'firewall_trusted': config.SS_FIREWALL_TRUSTED,
        'firewall_ports': firewall_ports,
        'aead_enforcement': config.SS_ENFORCE_AEAD
    }
    logging.info('-----------------------------------------')
    logging.info('Multi-User Shadowsocks Server Starting...')
    logging.info('Current Server Version: %s' % VERSION)
    if config.API_ENABLED:
        logging.info('Now using MultiUser API as the user interface')
    else:
        logging.info('Now using MySQL Database as the user interface')
    logging.info('Now starting manager thread...')
    thread.start_new_thread(manager.run, (config_passed, subprocess_callback,))
    time.sleep(5)
    logging.info('Now starting user pulling thread...')
    thread.start_new_thread(DbTransfer.thread_pull, ())
    time.sleep(5)
    logging.info('Now starting user pushing thread...')
    thread.start_new_thread(DbTransfer.thread_push, ())

    while True:
        time.sleep(100)


if __name__ == '__main__':
    main()
