# -*- coding: utf-8 -*-

# Copyright (C) 2011-2013 Avencall
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

import subprocess

DHCPD_UDPATE_COMMAND = ['dhcpd-update', '-dr']

class Dhcpd(object):

    def update(self):
        """Download the latest ISC dhcp server configuration files and
        regenerate the affected configuration files via the dhcpd-update
        command.
        """
        try:
            returncode = subprocess.call(DHCPD_UDPATE_COMMAND, close_fds=True)
        except OSError, e:
            raise ("error while executing dhcpd-update command", e)
        else:
            if returncode:
                raise ("dhcpd-update command returned %s" % returncode)
            else:
                return True
