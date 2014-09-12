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

import logging
import os
import subprocess
import json

from flask.helpers import make_response
from ..sysconfd_server import app

logger = logging.getLogger('xivo_sysconf.modules.services')
SERVICE_DIR = '/etc/init.d'


class InvalidActionException(ValueError):
    def __init__(self, service_name, action):
        super(InvalidActionException, self).__init__(self)
        self.service_name = service_name
        self.action = action


class InvalidServiceException(ValueError):
    def __init__(self, service_name):
        super(InvalidServiceException, self).__init__(self)
        self.service_name = service_name


class Services(object):

    def action(self, service, action):
        """
        GET /services

        >>> services('networking', 'restart')
        """
        output = self._run_action_for_service(service, action)

        return output


    def _run_action_for_service(self, service, action):
        output = ''
        try:
            self._validate_action(service, action)
            self._validate_service(service)
            output = self._run_action_for_service_validated(service, action)
        except InvalidActionException as e:
            logger.error("action %s not authorized on %s service", e.action, e.service_name)
        except InvalidServiceException as e:
            logger.error("service %s is not valid", e.service_name)
        return output


    def _validate_action(self, service_name, action):
        if action not in ['stop', 'start', 'restart']:
            raise InvalidActionException(service_name, action)


    def _validate_service(self, service_name):
        all_service_names = os.listdir(SERVICE_DIR)
        if service_name not in all_service_names:
            raise InvalidServiceException(service_name)


    def _run_action_for_service_validated(self, service, action):
        output = ''
        try:
            command = ["%s/%s" % (SERVICE_DIR, service), action]
            p = subprocess.Popen(command,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT,
                                 close_fds=True)
            output = p.communicate()[0]
            logger.debug("%s : return code %d", ' '.join(command), p.returncode)

            if p.returncode != 0:
                raise (output)
        except OSError:
            logger.exception("Error while executing /etc/init.d script")
            raise ("can't manage services")

        return output

services = Services()

@app.route('/services/<service>/<action>')
def services_action(service, action):
    res_action = services.action(service, action).rstrip()
    res = json.dumps({"Message": res_action})
    return make_response(res, 200, None, 'application/json')
