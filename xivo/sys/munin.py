# -*- coding: utf-8 -*-

# Copyright (C) 2010-2013 Avencall
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

import logging, subprocess

logger = logging.getLogger('xivo.sys.munin')

class Munin(object):
    def __init__(self):
        self.cmd1 = ['/usr/sbin/xivo-monitoring-update']
        self.cmd2 = ['/usr/bin/munin-cron', '--force-root']

    def update(self):
        try:
            p = subprocess.Popen(self.cmd1, close_fds=True)
            ret = p.wait()
        except Exception:
            logger.debug("can't execute '%s'" % self.cmd1)
            raise ("can't execute '%s'" % self.cmd1)
        if ret != 0:
            raise ("'%s' process return error %d" % (self.cmd1, ret))

        try:
            p = subprocess.Popen(self.cmd2, close_fds=True)
        except Exception:
            logger.debug("can't execute '%s'" % self.cmd2)
            raise ("can't execute '%s'" % self.cmd2[0])

        return True
