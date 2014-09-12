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
import re
import dumbnet
import netifaces
import subprocess

from time import time
from shutil import copy2

from xivo import network
from xivo import interfaces
from xivo import xivo_config
from xivo import system
from xivo import yaml_json

from xivo_sysconf.config import config

log = logging.getLogger('xivo_sysconf.modules.dnetintf')

class InetxParser:
    MATCH_SINGLEARG = re.compile('^\s*([^\s]+)\s+([^\s#]+)').match
    MATCH_MULTIARGS = re.compile('^\s*([^\s]+)\s+([^#]+)').match
    MATCH_HWADDRESS = re.compile('^\s*hwaddress\s+(\w+)\s+([a-fA-F0-9:]+)').match
    OPTIONS = {}

    @staticmethod
    def parse_multiargs(line):
        match = InetxParser.MATCH_MULTIARGS(line)

        if match:
            args = match.group(2).strip()
            if args:
                return (match.group(1), args)

        return (None, None)

    @staticmethod
    def parse_hwaddress(hwaddress):
        match = InetxParser.MATCH_HWADDRESS(hwaddress)

        if match:
            return ' '.join(match.groups())

    def __init__(self, filename):
        self.OPTIONS = {'hwaddress': self.parse_hwaddress}

        self.filename = filename
        self.fp = file(filename)
        self.interfaces = None

    def reloadfile(self):
        if self.fp and not self.fp.closed:
            self.fp.close()

        self.fp = file(self.filename)
        self.interfaces = {}

    def ifaces(self, reloadfile=False):
        if reloadfile:
            self.reloadfile()
        elif self.interfaces is None:
            self.interfaces = {}
        elif self.interfaces:
            return self.interfaces

        eni = interfaces.parse(self.fp)

        for block in eni:
            if not isinstance(block, interfaces.EniBlockIface):
                continue

            ifname = block.ifname
            self.interfaces[ifname] = [('name', ifname)]

            if isinstance(block, (interfaces.EniBlockFamilyInet, interfaces.EniBlockFamilyInet6)):
                self.interfaces[ifname].append(('family', block.family))
                self.interfaces[ifname].append(('method', block.method))

            for line in block.cooked_lines:
                if line.split(None, 1)[0] in ('name', 'iface', 'family', 'method'):
                    continue

                option, args = self.parse_multiargs(line)
                if not option:
                    continue
                elif option not in self.OPTIONS:
                    self.interfaces[ifname].append((option, args))
                    continue

                parsed = self.OPTIONS[option](line)
                if parsed:
                    self.interfaces[ifname].append((option, parsed))

        return self.interfaces

    def get(self, iface, reloadfile=False):
        if self.interfaces is None:
            self.ifaces()
        else:
            self.ifaces(reloadfile)

        return self.interfaces.get(iface)

    def close(self):
        if self.fp and not self.fp.closed:
            self.fp.close()


class NetworkConfig(dumbnet.intf):
    """
    Network configuration class.
    """

    INTF_TYPES = dict((getattr(dumbnet, x), x[10:].lower())
                      for x in dir(dumbnet) if x.startswith("INTF_TYPE_"))

    def __init__(self):
        dumbnet.intf.__init__(self)
        self.route = dumbnet.route()
        self.default_dst_ipv4 = dumbnet.addr('0.0.0.0/0')

    def __realloc__(self):
        dumbnet.intf.__init__(self)

    def _intf_ipv4_gateway(self, ifname):
        """
        Return the default gateway if it belongs to the interface
        """
        defgw = self.route.get(self.default_dst_ipv4)
        xaddr = dumbnet.intf.get(self, ifname)['addr']
        route = self.route.get(xaddr)

        if not defgw \
                or (route and defgw != route):
            return None

        defgwstr = str(defgw)
        address = network.parse_ipv4(dumbnet.ip_ntoa(xaddr.ip))
        netmask = network.bitmask_to_mask_ipv4(xaddr.bits)

        if network.ipv4_in_network(network.parse_ipv4(defgwstr),
                                   netmask,
                                   network.mask_ipv4(netmask, address)):
            return defgwstr

    def _intf_repr(self, ifent):
        """
        Return the configuration for a network interface as a dict like interfaces(5).
        """
        if not ifent \
                or ifent['type'] not in (dumbnet.INTF_TYPE_LOOPBACK, dumbnet.INTF_TYPE_ETH):
            return ifent

        ret = {'name': ifent['name']}

        if 'addr' not in ifent:
            ret['mtu'] = ifent['mtu']
            ret['flags'] = ifent['flags']
            ret['type'] = self.INTF_TYPES[ifent['type']]
            ret['typeid'] = ifent['type']

            if ret['type'] == 'eth':
                ret['family'] = 'inet'
            else:
                ret['family'] = 'unknown'

            if 'link_addr' in ifent:
                ret['hwaddress'] = str(ifent['link_addr'])

            return ret

        xaddr = ifent['addr']
        if xaddr.addrtype == dumbnet.ADDR_TYPE_IP:
            ret['address'] = dumbnet.ip_ntoa(xaddr.ip)
            ret['netmask'] = network.format_ipv4(
                network.bitmask_to_mask_ipv4(xaddr.bits))
            ret['broadcast'] = str(xaddr.bcast())
            ret['network'] = str(xaddr.net())
            ret['mtu'] = ifent['mtu']
            ret['flags'] = ifent['flags']
            ret['type'] = self.INTF_TYPES[ifent['type']]
            ret['typeid'] = ifent['type']
            ret['family'] = 'inet'

            gw = self._intf_ipv4_gateway(ifent['name'])

            if gw:
                ret['gateway'] = gw

            if 'dst_addr' in ifent:
                ret['pointopoint'] = str(ifent['dst_addr'])

            if 'link_addr' in ifent:
                ret['hwaddress'] = str(ifent['link_addr'])
        elif xaddr.addrtype == dumbnet.ADDR_TYPE_IP6:
            ret['address'] = dumbnet.ip6_ntoa(xaddr.ip6)
            ret['netmask'] = xaddr.bits
            ret['broadcast'] = str(xaddr.bcast())
            ret['mtu'] = ifent['mtu']
            ret['flags'] = ifent['flags']
            ret['type'] = self.INTF_TYPES[ifent['type']]
            ret['family'] = 'inet6'

            if 'link_addr' in ifent:
                ret['hwaddress'] = str(ifent['link_addr'])

        return ret

    def _iter_append(self, entry, l):
        l.append(self._intf_repr(entry))

    def get(self, name):
        """
        Return the configuration for a network interface as a dict.
        """
        return self._intf_repr(dumbnet.intf.get(self, name))

    def set(self, d, name=None):
        """
        Set the configuration for an interface from a dict like interfaces(5).
        """
        if name is not None:
            d['name'] = name

        iface = self.get(d['name'])

        address = d.get('address', iface['address'])
        netmask = d.get('netmask', iface['netmask'])

        d['addr'] = dumbnet.addr("%s/%s" % (address, netmask))

        newgateway = None
        delgateway = None

        if 'gateway' in d:
            if iface['type'] != 'eth' or iface['family'] != 'inet':
                raise NotImplementedError("This method only supports modify IPv4 gateway for ethernet interface")

            gwstr = network.format_ipv4(network.parse_ipv4("%s" % d['gateway']))

            if iface.get('gateway', None) != gwstr:
                newgateway = dumbnet.addr("%s" % d['gateway'])
        # If d hasn't gateway but iface has a gateway, remove previous gateway.
        elif 'gateway' in iface:
            if iface['type'] != 'eth' or iface['family'] != 'inet':
                raise NotImplementedError("This method only supports modify IPv4 gateway for ethernet interface")

            delgateway = d['addr']

        if 'pointopoint' in d:
            d['dst_addr'] = dumbnet.addr("%s" % d['pointopoint'])

        if 'hwaddress' in d:
            d['link_addr'] = dumbnet.addr("%s" % d['hwaddress'], dumbnet.ADDR_TYPE_ETH)

        dumbnet.intf.set(self, d)

        # If iface has previously a default gateway
        if delgateway:
            try:
                self.route.delete(self.default_dst_ipv4)
            except OSError, e:
                # If an error has occurred, rollback
                if 'gateway' in iface:
                    del iface['gateway']

                self.set(iface)
                raise OSError(str(e))
        elif newgateway:
            prevdefgw = self.route.get(self.default_dst_ipv4)
            try:
                self.route.delete(self.default_dst_ipv4)
            except OSError:
                prevdefgw = None

            try:
                # Set a new default gateway
                log.info("Set a new default gateway: %r:%r", self.default_dst_ipv4, newgateway)
                self.route.add(self.default_dst_ipv4, newgateway)
            except OSError, e:
                # If an error has occurred, rollback
                if 'gateway' in iface:
                    del iface['gateway']

                self.set(iface)

                # If there is a previous gateway
                if prevdefgw:
                    self.route.add(self.default_dst_ipv4, prevdefgw)
                raise OSError(str(e))

    def loop(self, callback, arg=None):
        """
        Iterate over the system interface table, invoking a user callback
        with each entry, returning the status of the callback routine.
        """
        l = []
        dumbnet.intf.loop(self, self._iter_append, l)

        for x in l:
            callback(x, arg)


class DNETIntf:
    """
    Network Interfaces class.
    """

    interfaces_file = os.path.join(os.path.sep, 'etc', 'network', 'interfaces')
    interfaces_path = os.path.dirname(config.network.interfaces_file)
    interfaces_tpl_file = os.path.join('network', 'interfaces')
    interfaces_custom_tpl_file = os.path.join(config.general.custom_templates_path, interfaces_tpl_file)

    CONFIG = {'interfaces_file': interfaces_file,
              'interfaces_tpl_file': interfaces_file,
              'netiface_up_cmd': "sudo /sbin/ifup",
              'netiface_down_cmd': "sudo /sbin/ifdown",
              'netiface_ip_delete_cmd': "sudo /bin/ip link delete",
              'lock_timeout': 60,
              'interfaces_path': interfaces_path,
              'backup_path': config.general.backup_path,
              'xivo_config_path': config.general.xivo_config_path,
              'templates_path': config.general.templates_path,
              'custom_templates_path': config.general.custom_templates_path,
              'interfaces_backup_file': os.path.join(config.general.backup_path, config.network.interfaces_file.lstrip(os.path.sep)),
              'interfaces_backup_path': os.path.join(config.general.backup_path, interfaces_path.lstrip(os.path.sep)),
              'interfaces_custom_tpl_file' : interfaces_custom_tpl_file
              }

    def __init__(self):
        self.netcfg = NetworkConfig()
        self.inetxparser = InetxParser(self.CONFIG['interfaces_file'])

        self.args = {}
        self.options = {}

    def get_netiface_info(self, iface):
        try:
            info = self.netcfg.get(iface)
        except OSError:
            return False

        if not info or 'family' not in info:
            return False

        info['carrier'] = False
        info['physicalif'] = False
        info['vlanif'] = False
        info['vlan-id'] = None
        info['vlan-raw-device'] = None
        info['aliasif'] = False
        info['alias-raw-device'] = None
        info['hwtypeid'] = None
        info['options'] = None

        if network.is_linux_netdev_if(iface):
            info['carrier'] = network.is_interface_plugged(iface)
            info['flags'] = network.get_interface_flags(iface)
            info['physicalif'] = network.is_linux_phy_if(iface)
            info['dummyif'] = network.is_linux_dummy_if(iface)
            info['vlanif'] = network.is_linux_vlan_if(iface)
            info['hwtypeid'] = network.get_interface_hwtypeid(iface)

            if not info['physicalif'] and 'gateway' in info:
                del info['gateway']

            if 'hwaddress' not in info:
                info['hwaddress'] = network.get_interface_hwaddress(iface)

            if 'mtu' not in info:
                info['mtu'] = network.get_interface_mtu(iface)
        else:
            if network.is_alias_if(iface):
                info['aliasif'] = True
                phyifname = network.phy_name_from_alias_if(iface)
                info['alias-raw-device'] = phyifname

                if network.is_linux_netdev_if(phyifname):
                    if 'gateway' in info:
                        try:
                            phyinfo = self.netcfg.get(phyifname)
                            if phyinfo.get('gateway') == info['gateway']:
                                del info['gateway']
                        except OSError:
                            pass

                    info['carrier'] = network.is_interface_plugged(phyifname)
                    info['hwtypeid'] = network.get_interface_hwtypeid(phyifname)

            if 'flags' not in info:
                info['flags'] = None

            if 'hwaddress' not in info:
                info['hwaddress'] = None

            if 'mtu' not in info:
                info['mtu'] = None

        if info['family'] in ('inet', 'inet6'):
            inetxparsed = self.inetxparser.get(iface)
            if inetxparsed:
                info['options'] = xivo_config.unreserved_interfaces_options(inetxparsed)

                xdict = dict(inetxparsed)
                info['method'] = xdict.get('method')
                info['vlan-id'] = xdict.get('vlan-id')
                info['vlan-raw-device'] = xdict.get('vlan-raw-device')

                if 'address' not in info \
                        and 'address' in xdict \
                        and 'netmask' in xdict:
                    info['address'] = xdict.get('address')
                    info['netmask'] = xdict['netmask']

                    if 'broadcast' in xdict:
                        info['broadcast'] = xdict['broadcast']

                    if 'network' in xdict:
                        info['network'] = xdict['network']

                if info['family'] == 'inet' \
                        and 'gateway' not in info \
                        and 'netmask' in info \
                        and 'network' in info \
                        and 'gateway' in xdict \
                        and network.ipv4_in_network(network.parse_ipv4(xdict['gateway']),
                                                    network.parse_ipv4(info['netmask']),
                                                    network.parse_ipv4(info['network'])):
                    info['gateway'] = xdict['gateway']
        else:
            info['method'] = None

        if info['vlanif']:
            vconfig = network.get_vlan_info(iface)
            info['vlan-id'] = vconfig.get('vlan-id', info['vlan-id'])
            info['vlan-raw-device'] = vconfig.get('vlan-raw-device', info['vlan-raw-device'])

        return info

    def discover_netifaces(self):
        """
        GET /discover_netifaces
        """

        rs = {}

        self.inetxparser.reloadfile()
        for iface in netifaces.interfaces():
            info = self.get_netiface_info(iface)
            if info:
                rs[iface] = info

        return rs

    def netiface(self, interface):
        """
        GET /netiface/<interface>

        >>> netiface('eth0')
        """

        self.inetxparser.reloadfile()
        print netifaces.ifaddresses(interface)

        res = self.get_netiface_info(interface)
        if res == False:
            res = {'Message': 'No interface'}
        return res

    def _get_valid_eth_ipv4(self, interface):
        if xivo_config.netif_managed(interface):

            try:
                eth = self.get_netiface_info(interface)
            except (OSError, TypeError), e:
                raise ("%s: %r", (e, interface))

            if not eth:
                return ({"Message" : "interface not found"})
            elif eth.get('type') != 'eth':
                return ({"Message": "invalid interface type"})
            elif eth.get('family') != 'inet':
                return ({"Message" : "invalid address family"})
        else:
            return ({"Message": "This interface is not managed by XiVO"})

        return eth

    def normalize_inet_options(self):
        if 'method' in self.args:
            if self.args['method'] == 'static':
                if not xivo_config.plausible_static(self.args, None):
                    return ({"Message": "invalid static arguments for command"})
            elif self.args['method'] == 'dhcp':
                for x in ('address', 'netmask', 'broadcast', 'gateway', 'mtu'):
                    if x in self.args:
                        del self.args[x]
        else:
            return ({"Message": "missing argument 'method'"})

    def get_interface_filecontent(self, conf):
        backupfilepath = None

        if not os.path.isdir(self.CONFIG['interfaces_backup_path']):
            os.makedirs(self.CONFIG['interfaces_backup_path'])

        if os.access(self.CONFIG['interfaces_file'], os.R_OK):
            backupfilepath = "%s.%d" % (self.CONFIG['interfaces_backup_file'], time())
            copy2(self.CONFIG['interfaces_file'], backupfilepath)
            old_lines = file(self.CONFIG['interfaces_file'])
        else:
            old_lines = ()

        if os.access(self.CONFIG['interfaces_custom_tpl_file'], (os.F_OK | os.R_OK)):
            filename = self.CONFIG['interfaces_custom_tpl_file']
        else:
            filename = self.CONFIG['interfaces_tpl_file']

        template_file = open(filename)
        template_lines = template_file.readlines()
        template_file.close()

        filecontent = xivo_config.txtsubst(
            template_lines,
            {
                '_XIVO_NETWORK_INTERFACES': ''.join(xivo_config.generate_interfaces(old_lines, conf))
            },
            self.CONFIG['interfaces_file'],
            'utf8')

        if old_lines:
            old_lines.close()

        return (filecontent, backupfilepath)

    def modify_physical_eth_ipv4(self, args):
        """
        POST /modify_physical_eth_ipv4

        >>> modify_physical_eth_ipv4({'ifname': 'eth0',
                                      'method': 'dhcp',
                                      'auto':   True,
                                     })

        method:    !~~enum(static,dhcp)
        address:   !~ipv4_address 192.168.0.1
        netmask:   !~netmask 255.255.255.0
        broadcast: !~ipv4_address 192.168.0.255
        gateway:   !~ipv4_address 192.168.0.254
        mtu:       !~~between(68,1500) 1500
        auto:      !!bool True
        up:        !!bool True
        options:   !~~seqlen(0,64) [ !~~seqlen(2,2) ['dns-search', 'toto.tld tutu.tld'],
                                     !~~seqlen(2,2) ['dns-nameservers', '127.0.0.1 192.168.0.254'] ]
        """
        self.args = args
        interface = args['ifname']

        eth = self._get_valid_eth_ipv4(interface)

        # allow dummy interfaces
        if not (eth['physicalif'] or eth['dummyif']):
            return ({"Message": "invalid interface, it is not a physical interface"})

        self.normalize_inet_options()

        interfaces_path = os.path.dirname(config.network.interfaces_file)

        if not os.access(interfaces_path, (os.X_OK | os.W_OK)):
            return ({"Message": "path not found or not writable or not executable: %r" % interfaces_path})

        self.args['auto'] = self.args.get('auto', True)
        self.args['family'] = 'inet'

        conf = {'netIfaces': {},
                'vlans': {},
                'customipConfs': {}}

        netifacesbakfile = None

        if self.CONFIG['netiface_down_cmd']:
            subprocess.call(self.CONFIG['netiface_down_cmd'].strip().split() + [eth['name']])

        for iface in netifaces.interfaces():
            conf['netIfaces'][iface] = 'reserved'

        conf['netIfaces'][eth['name']] = eth['name']
        conf['vlans'][eth['name']] = {0: eth['name']}
        conf['customipConfs'][eth['name']] = self.args

        filecontent, netifacesbakfile = self.get_interface_filecontent(conf)

        try:
            system.file_writelines_flush_sync(config.network.interfaces_file, filecontent)

            if self.args.get('up', True) and self.CONFIG['netiface_up_cmd']:
                subprocess.call(self.CONFIG['netiface_up_cmd'].strip().split() + [eth['name']])
        except Exception, e:
            if netifacesbakfile:
                copy2(netifacesbakfile, config.network.interfaces_file)
            raise e.__class__(str(e))
        return True
      
    def replace_virtual_eth_ipv4(self, args):
        """
        POST /replace_virtual_eth_ipv4

        >>> replace_virtual_eth_ipv4({'ifname': 'eth0:0',
                                      'method': 'dhcp',
                                      'auto':   True,
                                      'new_ifname': 'eth0:0'
                                     })
        ifname:        !!str vlan42
        method:        !~~enum(static,dhcp,manual)
        vlanid:        !~~between(0,65535) 42
        vlanrawdevice: !!str eth0
        address:       !~ipv4_address 172.16.42.1
        netmask:       !~netmask 255.255.255.0
        broadcast:     !~ipv4_address 172.16.42.255
        gateway:       !~ipv4_address 172.16.42.254
        mtu:           !~~between(68,1500) 1500
        auto:          !!bool True
        up:            !!bool True
        options:       !~~seqlen(0,64) [ !~~seqlen(2,2) ['dns-search', 'toto.tld tutu.tld'],
                                         !~~seqlen(2,2) ['dns-nameservers', '127.0.0.1 192.168.0.254'] ]
        """
        self.args = args
        phyifname = None
        phyinfo = None
        interface = args['ifname']

        if not isinstance(interface, basestring) \
            or not xivo_config.netif_managed(interface):
            return ({"Message": "invalid interface name, ifname: %r" % interface})

        info = self.get_netiface_info(interface)

        if info and info['physicalif']:
            return ({"Message": "invalid interface, it is a physical interface"})
        elif network.is_alias_if(self.args['ifname']):
            phyifname = network.phy_name_from_alias_if(self.args['ifname'])
            phyinfo = self.get_netiface_info(phyifname)
            if not phyinfo or True not in (phyinfo['physicalif'], phyinfo['vlanif']):
                return ({"Message": "invalid interface, it is not an alias interface"})
            elif self.args['method'] != 'static':
                return ({"Message": "invalid method, must be static"})

            if 'vlanrawdevice' in self.args:
                del self.args['vlanrawdevice']
            if 'vlanid' in self.args:
                del self.args['vlanid']
        elif network.is_vlan_if(self.args['ifname']):
            if not 'vlanrawdevice' in self.args:
                return ({"Message": "invalid arguments for command, missing vlanrawdevice"})
            if not 'vlanid' in self.args:
                return ({"Message": "invalid arguments for command, missing vlanid"})

            phyifname = self.args['vlanrawdevice']
            phyinfo = self.get_netiface_info(phyifname)
            if not phyinfo or not phyinfo['physicalif']:
                return ({"Message": "invalid vlanrawdevice, it is not a physical interface"})

            vconfig = network.get_vlan_info_from_ifname(self.args['ifname'])

            if 'vlan-id' not in vconfig:
                return ({"Message": "invalid vlan interface name"})
            elif vconfig['vlan-id'] != int(self.args['vlanid']):
                return ({"Message": "invalid vlanid"})
            elif vconfig.get('vlan-raw-device', self.args['vlanrawdevice']) != self.args['vlanrawdevice']:
                return ({"Message": "invalid vlanrawdevice"})

            self.args['vlan-id'] = self.args.pop('vlanid')
            self.args['vlan-raw-device'] = self.args.pop('vlanrawdevice')
        else:
            return ({"Message": "invalid ifname argument for command"})

        if phyinfo.get('type') != 'eth':
            return ({"Message": "invalid interface type"})
        elif phyinfo.get('family') != 'inet':
            return ({"Message": "invalid address family"})

        self.normalize_inet_options()

        if not os.access(self.CONFIG['interfaces_path'], (os.X_OK | os.W_OK)):
            return ({"Message": "path not found or not writable or not executable: %r" % self.CONFIG['interfaces_path']})

        self.args['auto'] = self.args.get('auto', True)
        self.args['family'] = 'inet'

        conf = {'netIfaces': {},
                'vlans': {},
                'customipConfs': {}}

        netifacesbakfile = None

        if self.CONFIG['netiface_down_cmd']:
            subprocess.call(self.CONFIG['netiface_down_cmd'].strip().split() + [self.options['ifname']])

        for iface in netifaces.interfaces():
            if self.options['ifname'] != iface:
                conf['netIfaces'][iface] = 'reserved'

        conf['netIfaces'][self.args['ifname']] = self.args['ifname']
        conf['vlans'][self.args['ifname']] = {self.args.get('vlan-id', 0): self.args['ifname']}
        conf['customipConfs'][self.args['ifname']] = self.args

        filecontent, netifacesbakfile = self.get_interface_filecontent(conf)

        try:
            system.file_writelines_flush_sync(self.CONFIG['interfaces_file'], filecontent)

            if self.args.get('up', True) and self.CONFIG['netiface_up_cmd']:
                subprocess.call(self.CONFIG['netiface_up_cmd'].strip().split() + [self.args['ifname']])
        except Exception, e:
            if netifacesbakfile:
                copy2(netifacesbakfile, self.CONFIG['interfaces_file'])
            raise e.__class__(str(e))
        return True

    def modify_eth_ipv4(self, args):
        """
        POST /modify_eth_ipv4

        >>> modify_eth_ipv4({'address':     '192.168.0.1',
                             'netmask':     '255.255.255.0',
                             'broadcast':   '192.168.0.255',
                             'gateway':     '192.168.0.254',
                             'mtu':         1500,
                             'auto':        True,
                             'up':          True,
                             'options':     [['dns-search', 'toto.tld tutu.tld'],
                                             ['dns-nameservers', '127.0.0.1 192.168.0.254']]},
                             'ifname':  'eth0'})

        address:   !~ipv4_address 192.168.0.1
        netmask:   !~netmask 255.255.255.0
        broadcast: !~ipv4_address 192.168.0.255
        gateway:   !~ipv4_address 192.168.0.254
        mtu:       !~~between(68,1500) 1500
        auto:      !!bool True
        up:        !!bool True
        options:   !~~seqlen(0,64) [ !~~seqlen(2,2) ['dns-search', 'toto.tld tutu.tld'],
                                  !~~seqlen(2,2) ['dns-nameservers', '127.0.0.1 192.168.0.254'] ]
        """
        self.args = args
        interface = args['ifname']
        interfaces_path = os.path.dirname(config.network.interfaces_file)

        eth = self._get_valid_eth_ipv4(interface)

        if 'up' in self.args:
            if self.args['up']:
                eth['flags'] |= dumbnet.INTF_FLAG_UP
            else:
                eth['flags'] &= ~dumbnet.INTF_FLAG_UP
            del self.args['up']

        if 'broadcast' not in self.args and 'broadcast' in eth:
            del eth['broadcast']

        if 'gateway' not in self.args and 'gateway' in eth:
            del eth['gateway']

        if 'mtu' not in self.args and 'mtu' in eth:
            del eth['mtu']

        eth.update(self.args)

        eth['auto'] = self.args.get('auto', True)

        if not xivo_config.plausible_static(eth, None):
            return ({"Message": "invalid arguments for command"})
        elif not os.access(interfaces_path, (os.X_OK | os.W_OK)):
            return ({"Message": "path not found or not writable or not executable: %r" % interfaces_path})

        conf = {'netIfaces': {},
                'vlans': {},
                'ipConfs': {}}

        ret = False
        netifacesbakfile = None

        if self.CONFIG['netiface_down_cmd'] \
                and subprocess.call(self.CONFIG['netiface_down_cmd'].strip().split() + [eth['name']]) == 0 \
                and not (eth['flags'] & dumbnet.INTF_FLAG_UP):
            ret = True

        for iface in netifaces.interfaces():
            conf['netIfaces'][iface] = 'reserved'

        eth['ifname'] = eth['name']
        conf['netIfaces'][eth['name']] = eth['name']
        conf['vlans'][eth['name']] = {eth.get('vlan-id', 0): eth['name']}
        conf['ipConfs'][eth['name']] = eth

        filecontent, netifacesbakfile = self.get_interface_filecontent(conf)

        try:
            system.file_writelines_flush_sync(self.CONFIG['interfaces_file'], filecontent)

            if self.CONFIG['netiface_up_cmd'] \
                    and (eth['flags'] & dumbnet.INTF_FLAG_UP) \
                    and subprocess.call(self.CONFIG['netiface_up_cmd'].strip().split() + [eth['name']]) == 0:
                ret = True

            if not ret:
                if 'gateway' in eth and not (eth['flags'] & dumbnet.INTF_FLAG_UP):
                    del eth['gateway']
                self.netcfg.set(eth)
        except Exception, e:
            if netifacesbakfile:
                copy2(netifacesbakfile, self.CONFIG['interfaces_file'])
            raise e.__class__(str(e))
        return True

    def change_state_eth_ipv4(self, args):
        """
        POST /change_state_eth_ipv4

        >>> change_state_eth_ipv4({'state': True},
                                  {'ifname':    'eth0'})
        state:  !!bool True
        """
        self.args = args
        interface = args['ifname']

        eth = self._get_valid_eth_ipv4(interface)

        conf = {'netIfaces': {},
                'vlans': {},
                'customipConfs': {}}

        ret = False
        netifacesbakfile = None

        for iface in netifaces.interfaces():
            conf['netIfaces'][iface] = 'reserved'

        if self.args['state']:
            eth['auto'] = True
            eth['flags'] |= dumbnet.INTF_FLAG_UP

            if self.CONFIG['netiface_up_cmd'] \
                    and subprocess.call(self.CONFIG['netiface_up_cmd'].strip().split() + [eth['name']]) == 0:
                ret = True
        else:
            eth['auto'] = False
            eth['flags'] &= ~dumbnet.INTF_FLAG_UP

            if self.CONFIG['netiface_down_cmd'] \
                    and subprocess.call(self.CONFIG['netiface_down_cmd'].strip().split() + [eth['name']]) == 0:
                ret = True

        eth['ifname'] = eth['name']
        conf['netIfaces'][eth['name']] = eth['name']
        conf['vlans'][eth['name']] = {eth.get('vlan-id', 0): eth['name']}
        conf['customipConfs'][eth['name']] = eth

        filecontent, netifacesbakfile = self.get_interface_filecontent(conf)

        try:
            system.file_writelines_flush_sync(self.CONFIG['interfaces_file'], filecontent)

            if not ret:
                if not self.args['state'] and 'gateway' in eth:
                    del eth['gateway']
                self.netcfg.set(eth)
        except Exception, e:
            if netifacesbakfile:
                copy2(netifacesbakfile, self.CONFIG['interfaces_file'])
            raise e.__class__(str(e))
        return True

    def delete_eth_ipv4(self, interface):
        """
        GET /delete_eth_ipv4

        >>> delete_eth_ipv4({},
                            {'ifname':  'eth0'})
        """
        eth = None

        try:
            eth = self._get_valid_eth_ipv4(interface)
        except e:
            if e.code == 404:
                pass

        conf = {'netIfaces': {}}

        ret = False
        netifacesbakfile = None
        ifname = self.options['ifname']

        for iface in netifaces.interfaces():
            conf['netIfaces'][iface] = 'reserved'

        conf['netIfaces'][ifname] = 'removed'

        if self.CONFIG['netiface_ip_delete_cmd'] \
                and subprocess.call(self.CONFIG['netiface_ip_delete_cmd'].strip().split() + [ifname]) == 0:
            ret = True

        filecontent, netifacesbakfile = self.get_interface_filecontent(conf)

        try:
            system.file_writelines_flush_sync(self.CONFIG['interfaces_file'], filecontent)

            if ret:
                return True
            elif not eth:
                return ({"Message": "interface not found"})

            eth['flags'] &= ~dumbnet.INTF_FLAG_UP
            if 'gateway' in eth:
                del eth['gateway']
            self.netcfg.set(eth)
        except e:
            raise e.__class__(e.code, e.text)
        except Exception, e:
            if netifacesbakfile:
                copy2(netifacesbakfile, self.CONFIG['interfaces_file'])
            raise e.__class__(str(e))
        return True

    def network_config(self):
        """
        GET /network_config

        Just returns the network configuration
        """
        netconf = xivo_config.load_current_configuration()
        return yaml_json.stringify_keys(netconf)

    def rename_ethernet_interface(self, args):
        """
        PUT /rename_ethernet_interface

        args ex:
        {'old_name': "eth42",
         'new_name': "eth1"}
        """
        xivo_config.rename_ethernet_interface(args['old_name'], args['new_name'])
        return True

    def swap_ethernet_interfaces(self, args):
        """
        POST /swap_ethernet_interfaces

        args ex:
        {'name1': "eth0",
         'name2': "eth1"}
        """
        xivo_config.swap_ethernet_interfaces(args['name1'], args['name2'])
        return True

    def _val_modify_network_config(self, args):
        """
        ad hoc validation function for modify_network_config command
        """
        if set(args) != set(['rel', 'old', 'chg']):
            return False
        if not isinstance(args['rel'], list):
            return False
        for elt in args['rel']:
            if not isinstance(elt, basestring):
                return False
        return True


    def modify_network_config(self, args):
        """
        PUT /modify_network_config
        """
        if not _val_modify_network_config(args):
            raise ("invalid arguments for command")
        try:
            check_conf = json_ops.compile_conj(args['rel'])
        except ValueError:
            raise ("invalid relation")

        current_config = xivo_config.load_current_configuration()
        if not check_conf(args['old'], current_config):
            raise ("Conflict between state wanted by client and current state")

    def routes(self, args):
        """
        auto eth0
        iface eth0 inet static
            address 192.168.32.242
            netmask 255.255.255.0
            gateway 192.168.32.254
            up ip route add 192.168.30.0/24 via 192.168.32.124 || true
        """
        ret = True
        args.sort(lambda x, y: cmp(x['iface'], y['iface']))
        iface = None

        network.route_flush()

        for route in args:
            if route['disable']:
                continue

            if route['iface'] != iface:
                iface = route['iface']

            try:
                (eid, output) = network.route_set(route['destination'], route['netmask'], route['gateway'], iface)
                if eid != 0 and route['current']:
                    ret = False
            except Exception, e:
                raise ('Cannot apply route')

        network.route_flush_cache()
        return ret
