# -*- coding: utf-8 -*-

# Copyright (C) 2014 Avencall
#
# This program is free software: you can redistribute it and/or modify
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
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import logging
import sys

DEFAULT_LOG_FORMAT = '%(asctime)s [%(process)d] (%(levelname)s) (%(name)s): %(message)s'


class _LogLevelFilter(logging.Filter):
    def __init__(self, level_filter):
        self._level_filter = level_filter

    def filter(self, record):
        return self._level_filter(record.levelno)


def setup_logging(log_file, foreground=False, debug=False, loglevel=logging.INFO, log_format=DEFAULT_LOG_FORMAT):
    root_logger = logging.getLogger()

    formatter = logging.Formatter(log_format)

    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)
    root_logger.addHandler(handler)

    if foreground:
        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_handler.addFilter(_LogLevelFilter(lambda level: level <= logging.WARNING))
        stdout_handler.setFormatter(formatter)
        root_logger.addHandler(stdout_handler)

        stderr_handler = logging.StreamHandler(sys.stderr)
        stderr_handler.addFilter(_LogLevelFilter(lambda level: level > logging.WARNING))
        stderr_handler.setFormatter(formatter)
        root_logger.addHandler(stderr_handler)

    if debug:
        root_logger.setLevel(logging.DEBUG)
    else:
        root_logger.setLevel(loglevel)


def get_log_level_by_name(loglevel_name):
    levels = {
        'CRITICAL': logging.CRITICAL,
        'ERROR': logging.ERROR,
        'WARNING': logging.WARNING,
        'WARN': logging.WARN,
        'INFO': logging.INFO,
        'DEBUG': logging.DEBUG,
    }
    loglevel_name = loglevel_name.upper()
    if loglevel_name in levels:
        return levels[loglevel_name]
    else:
        raise ValueError("Unknown log level %r" % loglevel_name)
