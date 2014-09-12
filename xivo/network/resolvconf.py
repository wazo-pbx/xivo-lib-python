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

import os
import logging
import subprocess
import re

from time import time
from shutil import copy2

from xivo.xivo_config import txtsubst
from xivo import system

Rcc = {'hostname_file': os.path.join(os.path.sep, 'etc', 'hostname'),
       'hostname_tpl_file': os.path.join('resolvconf', 'hostname'),
       'hostname_update_cmd': "/etc/init.d/hostname.sh start",
       'hosts_file': os.path.join(os.path.sep, 'etc', 'hosts'),
       'hosts_tpl_file': os.path.join('resolvconf', 'hosts'),
       'resolvconf_file': os.path.join(os.path.sep, 'etc', 'resolv.conf'),
       'resolvconf_tpl_file': os.path.join('resolvconf', 'resolv.conf')
       }


class ResolvConf(object):

    def __init__(self, cfg):
        """Load parameters, etc"""

        tpl_path = cfg.general.templates_path
        custom_tpl_path = cfg.general.custom_templates_path
        backup_path = cfg.general.backup_path

        if hasattr(cfg, 'resolvconf'):
            for x in Rcc.iterkeys():
                if hasattr(cfg.resolvconf, x):
                    Rcc[x] = getattr(cfg.resolvconf, x)

        for optname in ('hostname', 'hosts', 'resolvconf'):
            Rcc["%s_tpl_file" % optname] = os.path.join(tpl_path,
                                                        Rcc["%s_tpl_file" % optname])

            Rcc["%s_custom_tpl_file" % optname] = os.path.join(custom_tpl_path,
                                                           Rcc["%s_tpl_file" % optname])

            Rcc["%s_path" % optname] = os.path.dirname(Rcc["%s_file" % optname])
            Rcc["%s_backup_file" % optname] = os.path.join(backup_path,
                                                           Rcc["%s_file" % optname].lstrip(os.path.sep))
            Rcc["%s_backup_path" % optname] = os.path.join(backup_path,
                                                           Rcc["%s_path" % optname].lstrip(os.path.sep))

    def resolvconf(self, args):
        """
        >>> resolv_conf({'nameservers': '192.168.0.254'})
        >>> resolv_conf({'nameservers': ['192.168.0.254', '10.0.0.254']})
        >>> resolv_conf({'search': ['toto.tld', 'tutu.tld']
                     'nameservers': ['192.168.0.254', '10.0.0.254']})
        """

        if 'nameservers' in args:
            args['nameservers'] = extract_scalar(args['nameservers'])
            nameservers = unique_case_tuple(args['nameservers'])

            if len(nameservers) == len(args['nameservers']):
                args['nameservers'] = list(nameservers)
            else:
                raise ("duplicated nameservers in %r" % list(args['nameservers']))

        if 'search' in args:
            args['search'] = extract_scalar(args['search'])
            search = unique_case_tuple(args['search'])

            if len(search) == len(args['search']):
                args['search'] = list(search)
            else:
                raise ("duplicated search in %r" % list(args['search']))

            if len(''.join(args['search'])) > 255:
                raise ("maximum length exceeded for option search: %r" % list(args['search']))

        if not os.access(Rcc['resolvconf_path'], (os.X_OK | os.W_OK)):
            raise ("path not found or not writable or not executable: %r" % Rcc['resolvconf_path'])

        resolvconfbakfile = None

        try:
            resolvconfbakfile = _write_config_file('resolvconf',
                                                   _resolv_conf_variables(args))
            return True
        except Exception, e:
            if resolvconfbakfile:
                copy2(resolvconfbakfile, Rcc['resolvconf_file'])
            raise e.__class__(str(e))

    def hosts(self, args):
        """
        >>> hosts({'hostname':  'xivo',
                   'domain':    'localdomain'})
        """

        if not os.access(Rcc['hostname_path'], (os.X_OK | os.W_OK)):
            raise ("path not found or not writable or not executable: %r" % Rcc['hostname_path'])

        if not os.access(Rcc['hosts_path'], (os.X_OK | os.W_OK)):
             raise ("path not found or not writable or not executable: %r" % Rcc['hosts_path'])

        hostnamebakfile = None
        hostsbakfile = None

        try:
            hostnamebakfile = _write_config_file('hostname',
                                                 {'_XIVO_HOSTNAME': args['hostname']})

            hostsbakfile = _write_config_file('hosts',
                                              {'_XIVO_HOSTNAME': args['hostname'],
                                               '_XIVO_DOMAIN': args['domain']})

            if Rcc['hostname_update_cmd']:
                subprocess.call(Rcc['hostname_update_cmd'].strip().split())

            return True
        except Exception, e:
            if hostnamebakfile:
                copy2(hostnamebakfile, Rcc['hostname_file'])
            if hostsbakfile:
                 copy2(hostsbakfile, Rcc['hosts_file'])
            raise e.__class__(str(e))

    def _write_config_file(self, optname, xvars):
        backupfilename = None

        if not os.path.isdir(Rcc["%s_backup_path" % optname]):
            os.makedirs(Rcc["%s_backup_path" % optname])

        if os.access(Rcc["%s_file" % optname], os.R_OK):
            backupfilename = "%s.%d" % (Rcc["%s_backup_file" % optname], time())
            copy2(Rcc["%s_file" % optname], backupfilename)

        if os.access(Rcc["%s_custom_tpl_file" % optname], (os.F_OK | os.R_OK)):
            filename = Rcc["%s_custom_tpl_file" % optname]
        else:
            filename = Rcc["%s_tpl_file" % optname]

        template_file = open(filename)
        template_lines = template_file.readlines()
        template_file.close()

        txt = txtsubst(template_lines,
                       xvars,
                       Rcc["%s_file" % optname],
                       'utf8')

        system.file_writelines_flush_sync(Rcc["%s_file" % optname], txt)

        return backupfilename



    def _resolv_conf_variables(self, args):
        """
        nameservers:    !~~seqlen(1,3) [ !~ipv4_address_or_domain 192.168.0.254 ]
        search?:        !~~seqlen(1,6) [ !~search_domain example.com ]
        """
        xvars = {}
        xvars['_XIVO_NAMESERVER_LIST'] = \
             os.linesep.join(["nameserver %s"] * len(args['nameservers'])) % tuple(args['nameservers'])

        if 'search' in args:
            xvars['_XIVO_DNS_SEARCH'] = "search %s" % " ".join(args['search'])
        else:
            xvars['_XIVO_DNS_SEARCH'] = ""

        return xvars

def castint(s):
    if str(s).isdigit():
        return int(s)
    else:
        return s

def splitint(s):
    return map(castint, re.findall(r'(\d+|\D+)', str(s)))

def natsort(a, b):
    return cmp(splitint(a), splitint(b))

def is_scalar(var):
    """ Returns True if is scalar or False otherwise """
    return isinstance(var, (basestring, bool, int, float))

def extract_scalar_from_list(xlist):
    """ Extract scalar values from a list or tuple """
    return [x for x in xlist if is_scalar(x)]

def extract_scalar_from_dict(xdict):
    """ Extract scalar values from a dict natural ordered by key """
    return [xdict[key] for key in sorted(xdict.iterkeys(), natsort)
                            if is_scalar(xdict[key])]

def extract_scalar(var):
    """
    Extract scalar from tuple, list and dict
    Return tuple of scalar values
    """
    if isinstance(var, (tuple, list)):
        return tuple(extract_scalar_from_list(var))
    elif isinstance(var, dict):
        return tuple(extract_scalar_from_dict(var))
    elif is_scalar(var):
        return (var,)
    else:
        return

def unique_case_tuple(sequence):
    """ Build an ordered case-insensitive collection """
    xlist = dict(zip(map(str.lower, sequence), sequence)).values()
    return tuple([x for x in sequence if x in xlist])
