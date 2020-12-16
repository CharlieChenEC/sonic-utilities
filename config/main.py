#!/usr/sbin/env python

import sys
import os
import click
import subprocess
import netaddr
import re
import syslog
import time
import netifaces
import json

import sonic_device_util
import ipaddress
from swsssdk import ConfigDBConnector, SonicV2Connector, SonicDBConfig
from minigraph import parse_device_desc_xml
from config_mgmt import ConfigMgmtDPB
from utilities_common.intf_filter import parse_interface_in_filter
from utilities_common.util_base import UtilHelper
from portconfig import get_child_ports, get_port_config_file_name

import aaa
import mlnx
import nat

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help', '-?'])

SONIC_GENERATED_SERVICE_PATH = '/etc/sonic/generated_services.conf'
SONIC_CFGGEN_PATH = '/usr/local/bin/sonic-cfggen'
SYSLOG_IDENTIFIER = "config"
VLAN_SUB_INTERFACE_SEPARATOR = '.'
ASIC_CONF_FILENAME = 'asic.conf'
DEFAULT_CONFIG_DB_FILE = '/etc/sonic/config_db.json'
NAMESPACE_PREFIX = 'asic'
INTF_KEY = "interfaces"

INIT_CFG_FILE = '/etc/sonic/init_cfg.json'

SYSTEMCTL_ACTION_STOP="stop"
SYSTEMCTL_ACTION_RESTART="restart"
SYSTEMCTL_ACTION_RESET_FAILED="reset-failed"

DEFAULT_NAMESPACE = ''
CFG_LOOPBACK_PREFIX = "Loopback"
CFG_LOOPBACK_PREFIX_LEN = len(CFG_LOOPBACK_PREFIX)
CFG_LOOPBACK_NAME_TOTAL_LEN_MAX = 11
CFG_LOOPBACK_ID_MAX_VAL = 999
CFG_LOOPBACK_NO="<0-999>"
# ========================== Syslog wrappers ==========================

def log_debug(msg):
    syslog.openlog(SYSLOG_IDENTIFIER)
    syslog.syslog(syslog.LOG_DEBUG, msg)
    syslog.closelog()


def log_info(msg):
    syslog.openlog(SYSLOG_IDENTIFIER)
    syslog.syslog(syslog.LOG_INFO, msg)
    syslog.closelog()


def log_warning(msg):
    syslog.openlog(SYSLOG_IDENTIFIER)
    syslog.syslog(syslog.LOG_WARNING, msg)
    syslog.closelog()


def log_error(msg):
    syslog.openlog(SYSLOG_IDENTIFIER)
    syslog.syslog(syslog.LOG_ERR, msg)
    syslog.closelog()


class AbbreviationGroup(click.Group):
    """This subclass of click.Group supports abbreviated subgroup/subcommand names
    """

    def get_command(self, ctx, cmd_name):
        # Try to get builtin commands as normal
        rv = click.Group.get_command(self, ctx, cmd_name)
        if rv is not None:
            return rv

        # Allow automatic abbreviation of the command.  "status" for
        # instance will match "st".  We only allow that however if
        # there is only one command.
        # If there are multiple matches and the shortest one is the common prefix of all the matches, return
        # the shortest one
        matches = []
        shortest = None
        for x in self.list_commands(ctx):
            if x.lower().startswith(cmd_name.lower()):
                matches.append(x)
                if not shortest:
                    shortest = x
                elif len(shortest) > len(x):
                    shortest = x

        if not matches:
            return None
        elif len(matches) == 1:
            return click.Group.get_command(self, ctx, matches[0])
        else:
            for x in matches:
                if not x.startswith(shortest):
                    break
            else:
                return click.Group.get_command(self, ctx, shortest)

            ctx.fail('Too many matches: %s' % ', '.join(sorted(matches)))


#
# Load asic_type for further use
#

try:
    version_info = sonic_device_util.get_sonic_version_info()
    asic_type = version_info['asic_type']
except (KeyError, TypeError):
    raise click.Abort()

#
# Load breakout config file for Dynamic Port Breakout
#

try:
    # Load the helper class
    helper = UtilHelper()
    (platform, hwsku) = helper.get_platform_and_hwsku()
except Exception as e:
    click.secho("Failed to get platform and hwsku with error:{}".format(str(e)), fg='red')
    raise click.Abort()

try:
    breakout_cfg_file = get_port_config_file_name(hwsku, platform)
except Exception as e:
    click.secho("Breakout config file not found with error:{}".format(str(e)), fg='red')
    raise click.Abort()

#
# Breakout Mode Helper functions
#

# Read given JSON file
def readJsonFile(fileName):
    try:
        with open(fileName) as f:
            result = json.load(f)
    except Exception as e:
        raise Exception(str(e))
    return result

def _get_option(ctx,args,incomplete):
    """ Provides dynamic mode option as per user argument i.e. interface name """
    all_mode_options = []
    interface_name = args[-1]

    if not os.path.isfile(breakout_cfg_file) or not breakout_cfg_file.endswith('.json'):
        return []
    else:
        breakout_file_input = readJsonFile(breakout_cfg_file)
        if interface_name in breakout_file_input[INTF_KEY]:
            breakout_mode_list = [v["breakout_modes"] for i ,v in breakout_file_input[INTF_KEY].items() if i == interface_name][0]
            breakout_mode_options = []
            for i in breakout_mode_list.split(','):
                    breakout_mode_options.append(i)
            all_mode_options = [str(c) for c in breakout_mode_options if incomplete in c]
            return all_mode_options

def shutdown_interfaces(ctx, del_intf_dict):
    """ shut down all the interfaces before deletion """
    for intf in del_intf_dict.keys():
        config_db = ctx.obj['config_db']
        if get_interface_naming_mode() == "alias":
            interface_name = interface_alias_to_name(intf)
            if interface_name is None:
                click.echo("[ERROR] interface name is None!")
                return False

        if interface_name_is_valid(intf) is False:
            click.echo("[ERROR] Interface name is invalid. Please enter a valid interface name!!")
            return False

        port_dict = config_db.get_table('PORT')
        if not port_dict:
            click.echo("port_dict is None!")
            return False

        if intf in port_dict.keys():
            config_db.mod_entry("PORT", intf, {"admin_status": "down"})
        else:
            click.secho("[ERROR] Could not get the correct interface name, exiting", fg='red')
            return False
    return True

def _validate_interface_mode(ctx, breakout_cfg_file, interface_name, target_brkout_mode, cur_brkout_mode):
    """ Validate Parent interface and user selected mode before starting deletion or addition process """
    breakout_file_input = readJsonFile(breakout_cfg_file)["interfaces"]

    if interface_name not in breakout_file_input:
        click.secho("[ERROR] {} is not a Parent port. So, Breakout Mode is not available on this port".format(interface_name), fg='red')
        return False

    # Check whether target breakout mode is available for the user-selected interface or not
    if target_brkout_mode not in breakout_file_input[interface_name]["breakout_modes"].strip(',').split():
        click.secho('[ERROR] Target mode {} is not available for the port {}'. format(target_brkout_mode, interface_name), fg='red')
        return False

    # Get config db context
    config_db = ctx.obj['config_db']
    port_dict = config_db.get_table('PORT')

    # Check whether there is any port in config db.
    if not port_dict:
        click.echo("port_dict is None!")
        return False

    # Check whether the  user-selected interface is part of  'port' table in config db.
    if interface_name not in port_dict.keys():
        click.secho("[ERROR] {} is not in port_dict".format(interface_name))
        return False
    click.echo("\nRunning Breakout Mode : {} \nTarget Breakout Mode : {}".format(cur_brkout_mode, target_brkout_mode))
    if (cur_brkout_mode == target_brkout_mode):
        click.secho("[WARNING] No action will be taken as current and desired Breakout Mode are same.", fg='magenta')
        sys.exit(0)
    return True

def load_ConfigMgmt(verbose):
    """ Load config for the commands which are capable of change in config DB. """
    try:
        cm = ConfigMgmtDPB(debug=verbose)
        return cm
    except Exception as e:
        raise Exception("Failed to load the config. Error: {}".format(str(e)))

def breakout_warnUser_extraTables(cm, final_delPorts, confirm=True):
    """
    Function to warn user about extra tables while Dynamic Port Breakout(DPB).
    confirm: re-confirm from user to proceed.
    Config Tables Without Yang model considered extra tables.
    cm =  instance of config MGMT class.
    """
    try:
        # check if any extra tables exist
        eTables = cm.tablesWithOutYang()
        # FIXME: There is no yang model defined for "BREAKOUT_CFG" yet
        #        Remove this from 'eTable' to make the implementatin of DPB ansible test easier
        eTables.pop('BREAKOUT_CFG', None)
        if len(eTables):
            # find relavent tables in extra tables, i.e. one which can have deleted
            # ports
            tables = cm.configWithKeys(configIn=eTables, keys=final_delPorts)
            if len(tables):
                click.secho("Below Config can not be verified, It may cause harm "\
                    "to the system\n {}".format(json.dumps(tables, indent=2)))
                click.confirm('Do you wish to Continue?', abort=True)
    except Exception as e:
        raise Exception("Failed in breakout_warnUser_extraTables. Error: {}".format(str(e)))
    return

def breakout_Ports(cm, delPorts=list(), portJson=dict(), force=False, \
    loadDefConfig=False, verbose=False):

    deps, ret = cm.breakOutPort(delPorts=delPorts,  portJson=portJson, \
                    force=force, loadDefConfig=loadDefConfig)
    # check if DPB failed
    if ret == False:
        if not force and deps:
            click.echo("Dependecies Exist. No further action will be taken")
            click.echo("*** Printing dependecies ***")
            for dep in deps:
                click.echo(dep)
            sys.exit(0)
        else:
            click.echo("[ERROR] Port breakout Failed!!! Opting Out")
            raise click.Abort()
        return

#
# Helper functions
#

# Execute action on list of systemd services
def execute_systemctl(list_of_services, action):
    num_asic = sonic_device_util.get_num_npus()
    generated_services_list, generated_multi_instance_services = _get_sonic_generated_services(num_asic)
    if ((generated_services_list == []) and
        (generated_multi_instance_services == [])):
        log_error("Failed to get generated services")
        return

    for service in list_of_services:
        if (service + '.service' in generated_services_list):
            try:
                click.echo("Executing {} of service {}...".format(action, service))
                run_command("systemctl {} {}".format(action, service))
            except SystemExit as e:
                log_error("Failed to execute {} of service {} with error {}".format(action, service, e))
                raise
        if (service + '.service' in generated_multi_instance_services):
            for inst in range(num_asic):
                try:
                    click.echo("Executing {} of service {}@{}...".format(action, service, inst))
                    run_command("systemctl {} {}@{}.service".format(action, service, inst))
                except SystemExit as e:
                    if action == SYSTEMCTL_ACTION_STOP:
                        log_warning("Received error {} when stopping service '{}'. Waiting to see if it stops ...".format(e, service))
                        if _wait_for_service_stop(service):
                            log_info("{} is stopped".format(service))
                        else:
                            log_error("Failed to execute {} of service {} with error {}".format(action, service, e))
                            raise
                    else:
                        log_error("Failed to execute {} of service {} with error {}".format(action, service, e))
                        raise

def run_command(command, display_cmd=False, ignore_error=False):
    """Run bash command and print output to stdout
    """
    if display_cmd == True:
        click.echo(click.style("Running command: ", fg='cyan') + click.style(command, fg='green'))

    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    (out, err) = proc.communicate()

    if len(out) > 0:
        click.echo(out)

    if proc.returncode != 0 and not ignore_error:
        sys.exit(proc.returncode)
    else:
        return (out, err)

# Validate whether a given namespace name is valid in the device.
def validate_namespace(namespace):
    if not sonic_device_util.is_multi_npu():
        return True

    namespaces = sonic_device_util.get_all_namespaces()
    if namespace in namespaces['front_ns'] + namespaces['back_ns']:
        return True
    else:
        return False

def interface_alias_to_name(interface_alias):
    """Return default interface name if alias name is given as argument
    """
    config_db = ConfigDBConnector()
    config_db.connect()
    port_dict = config_db.get_table('PORT')

    vlan_id = ""
    sub_intf_sep_idx = -1
    if interface_alias is not None:
        sub_intf_sep_idx = interface_alias.find(VLAN_SUB_INTERFACE_SEPARATOR)
        if sub_intf_sep_idx != -1:
            vlan_id = interface_alias[sub_intf_sep_idx + 1:]
            # interface_alias holds the parent port name so the subsequent logic still applies
            interface_alias = interface_alias[:sub_intf_sep_idx]

    if interface_alias is not None:
        if not port_dict:
            click.echo("port_dict is None!")
            raise click.Abort()
        for port_name in port_dict.keys():
            if interface_alias == port_dict[port_name]['alias']:
                return port_name if sub_intf_sep_idx == -1 else port_name + VLAN_SUB_INTERFACE_SEPARATOR + vlan_id

    # Interface alias not in port_dict, just return interface_alias, e.g.,
    # portchannel is passed in as argument, which does not have an alias
    return interface_alias if sub_intf_sep_idx == -1 else interface_alias + VLAN_SUB_INTERFACE_SEPARATOR + vlan_id


def interface_name_is_valid(interface_name):
    """Check if the interface name is valid
    """
    config_db = ConfigDBConnector()
    config_db.connect()
    port_dict = config_db.get_table('PORT')
    port_channel_dict = config_db.get_table('PORTCHANNEL')
    sub_port_intf_dict = config_db.get_table('VLAN_SUB_INTERFACE')

    if get_interface_naming_mode() == "alias":
        interface_name = interface_alias_to_name(interface_name)

    if interface_name is not None:
        if not port_dict:
            click.echo("port_dict is None!")
            raise click.Abort()
        for port_name in port_dict.keys():
            if interface_name == port_name:
                return True
        if port_channel_dict:
            for port_channel_name in port_channel_dict.keys():
                if interface_name == port_channel_name:
                    return True
        if sub_port_intf_dict:
            for sub_port_intf_name in sub_port_intf_dict.keys():
                if interface_name == sub_port_intf_name:
                    return True
    return False


def vlan_id_is_valid(vid):
    """Check if the vlan id is in acceptable range (between 1 and 4094)
    """

    if vid<1 or vid>4094:
        return False

    return True

def vni_id_is_valid(vni):
    """Check if the vni id is in acceptable range (between 1 and 2^24)
    """

    if (vni < 1) or (vni > 16777215):
        return False

    return True

def is_vni_vrf_mapped(ctx, vni):
    """Check if the vni is mapped to vrf
    """

    found = 0
    db = ctx.obj['db']
    vrf_table = db.get_table('VRF')
    vrf_keys = vrf_table.keys()
    if vrf_keys is not None:
      for vrf_key in vrf_keys:
        if ('vni' in vrf_table[vrf_key] and vrf_table[vrf_key]['vni'] == vni):
           found = 1
           break

    if (found == 1):
        print "VNI {} mapped to Vrf {}, Please remove VRF VNI mapping".format(vni, vrf_key)
def mclag_domain_id_is_valid(domain_id):
    """Check if the MCLAG domain id is in acceptable range (between 1 and 4095)
    """

    if domain_id not in range(1,4095):
        return False

    return True

def interface_name_to_alias(interface_name):
    """Return alias interface name if default name is given as argument
    """
    config_db = ConfigDBConnector()
    config_db.connect()
    port_dict = config_db.get_table('PORT')

    if interface_name is not None:
        if not port_dict:
            click.echo("port_dict is None!")
            raise click.Abort()
        for port_name in port_dict.keys():
            if interface_name == port_name:
                return port_dict[port_name]['alias']

    return None

def get_interface_table_name(interface_name):
    """Get table name by interface_name prefix
    """
    if interface_name.startswith("Ethernet"):
        if VLAN_SUB_INTERFACE_SEPARATOR in interface_name:
            return "VLAN_SUB_INTERFACE"
        return "INTERFACE"
    elif interface_name.startswith("PortChannel"):
        if VLAN_SUB_INTERFACE_SEPARATOR in interface_name:
            return "VLAN_SUB_INTERFACE"
        return "PORTCHANNEL_INTERFACE"
    elif interface_name.startswith("Vlan"):
        return "VLAN_INTERFACE"
    elif interface_name.startswith("Loopback"):
        return "LOOPBACK_INTERFACE"
    else:
        return ""

def interface_ipaddr_dependent_on_interface(config_db, interface_name):
    """Get table keys including ipaddress
    """
    data = []
    table_name = get_interface_table_name(interface_name)
    if table_name == "":
        return data
    keys = config_db.get_keys(table_name)
    for key in keys:
        if interface_name in key and len(key) == 2:
            data.append(key)
    return data

def is_interface_bind_to_vrf(config_db, interface_name):
    """Get interface if bind to vrf or not
    """
    table_name = get_interface_table_name(interface_name)
    if table_name == "":
        return False
    entry = config_db.get_entry(table_name, interface_name)
    if entry and entry.get("vrf_name"):
        return True
    return False

def del_interface_bind_to_vrf(config_db, vrf_name):
    """del interface bind to vrf
    """
    tables = ['INTERFACE', 'PORTCHANNEL_INTERFACE', 'VLAN_INTERFACE', 'LOOPBACK_INTERFACE']
    for table_name in tables:
        interface_dict = config_db.get_table(table_name)
        if interface_dict:
            for interface_name in interface_dict.keys():
                if interface_dict[interface_name].has_key('vrf_name') and vrf_name == interface_dict[interface_name]['vrf_name']:
                    interface_dependent = interface_ipaddr_dependent_on_interface(config_db, interface_name)
                    for interface_del in interface_dependent:
                        config_db.set_entry(table_name, interface_del, None)
                    config_db.set_entry(table_name, interface_name, None)

def set_interface_naming_mode(mode):
    """Modify SONIC_CLI_IFACE_MODE env variable in user .bashrc
    """
    user = os.getenv('SUDO_USER')
    bashrc_ifacemode_line = "export SONIC_CLI_IFACE_MODE={}".format(mode)

    # Ensure all interfaces have an 'alias' key in PORT dict
    config_db = ConfigDBConnector()
    config_db.connect()
    port_dict = config_db.get_table('PORT')

    if not port_dict:
        click.echo("port_dict is None!")
        raise click.Abort()

    for port_name in port_dict.keys():
        try:
            if port_dict[port_name]['alias']:
                pass
        except KeyError:
            click.echo("Platform does not support alias mapping")
            raise click.Abort()

    if not user:
        user = os.getenv('USER')

    if user != "root":
        bashrc = "/home/{}/.bashrc".format(user)
    else:
        click.get_current_context().fail("Cannot set interface naming mode for root user!")

    f = open(bashrc, 'r')
    filedata = f.read()
    f.close()

    if "SONIC_CLI_IFACE_MODE" not in filedata:
        newdata = filedata + bashrc_ifacemode_line
        newdata += "\n"
    else:
        newdata = re.sub(r"export SONIC_CLI_IFACE_MODE=\w+",
                         bashrc_ifacemode_line, filedata)
    f = open(bashrc, 'w')
    f.write(newdata)
    f.close()
    click.echo("Please logout and log back in for changes take effect.")


def get_interface_naming_mode():
    mode = os.getenv('SONIC_CLI_IFACE_MODE')
    if mode is None:
        mode = "default"
    return mode

# Get the local BGP ASN from DEVICE_METADATA
def get_local_bgp_asn(config_db):
    metadata = config_db.get_table('DEVICE_METADATA')
    return metadata['localhost']['bgp_asn']

def get_interface_vrf_name(config_db, interface_name):
    """Get interface vrf name, return 'default' if not bind to vrf
    """
    table_name = get_interface_table_name(interface_name)
    if table_name == "":
        return "default"
    entry = config_db.get_entry(table_name, interface_name)
    if entry and entry.get("vrf_name"):
        return entry.get("vrf_name")
    return "default"

@click.pass_context
def is_ipaddress_overlapped(ctx, interface_name, ip_addr):
    """Check if the ip address overlapped with existing networks in the same vrf
    """
    config_db = ctx.obj["config_db"]

    interface_dict = config_db.get_table('INTERFACE')
    interface_dict.update(config_db.get_table('PORTCHANNEL_INTERFACE'))
    interface_dict.update(config_db.get_table('VLAN_INTERFACE'))
    interface_dict.update(config_db.get_table('LOOPBACK_INTERFACE'))
    ip_network = ipaddress.ip_network(unicode(ip_addr), strict=False)

    for key in interface_dict.keys():
        if not isinstance(key, tuple):
            continue
        if ipaddress.ip_network(unicode(key[1]), strict=False).overlaps(ip_network):
            vrf_name_new = get_interface_vrf_name(config_db, interface_name)
            vrf_name_exist = get_interface_vrf_name(config_db, key[0])
            if vrf_name_new == vrf_name_exist:
                return True
    return False

def _is_neighbor_ipaddress(config_db, ipaddress):
    """Returns True if a neighbor has the IP address <ipaddress>, False if not
    """
    entry = config_db.get_entry('BGP_NEIGHBOR', ipaddress)
    return True if entry else False

def is_sag_configured_on_interface(config_db, interface_name):
    if interface_name.startswith("Vlan"):
        for addr_type in ['IPv4', 'IPv6']:
            if len(config_db.get_entry('SAG', (interface_name, addr_type))) >  0:
                return True
    return False

def set_sag_interface(ctx, db, addr_type, vlan_id, ip_addr) :
    separator = ','
    if len(db.get_entry('SAG', (vlan_id, addr_type))) ==  0:
        db.mod_entry('SAG', (vlan_id, addr_type),{'gwip@': ip_addr})
    else :
        origin_list = db.get_entry('SAG', (vlan_id, addr_type))['gwip']
        add_list = origin_list + [ip_addr.encode('ascii', 'ignore')]
        add_list = list(set(add_list))
        add_list.sort()
        if len(add_list) > 16 :
            ctx.fail("Exceeds the maximum ip address size of 16")
        db.mod_entry('SAG', (vlan_id, addr_type),{'gwip': add_list})


def delete_sag_interface(ctx, db, addr_type, vlan_id, ip_addr) :
    separator = ','
    if len(db.get_entry('SAG', (vlan_id, addr_type))) == 0 :
        pass
    elif len(db.get_entry('SAG', (vlan_id, addr_type))['gwip']) == 1 :
        if ip_addr == separator.join(db.get_entry('SAG', (vlan_id, addr_type))['gwip']) :
            db.set_entry('SAG', (vlan_id, addr_type),None)
    else :
        ip_list = db.get_entry('SAG', (vlan_id, addr_type))['gwip']
        if ip_addr in ip_list:
            ip_list.remove(ip_addr)
        db.mod_entry('SAG', (vlan_id, addr_type),{'gwip': ip_list})

def is_valid_port(config_db, port):
    """Check if port is in PORT table"""

    port_table = config_db.get_table('PORT')
    if port in port_table:
        return True

    return False

def is_valid_portchannel(config_db, port):
    """Check if port is in PORT_CHANNEL table"""

    pc_table = config_db.get_table('PORTCHANNEL')
    if port in pc_table:
        return True

    return False

def is_port_router_interface(config_db, port):
    """Check if port is a router interface"""

    interface_table = config_db.get_table('INTERFACE')
    for intf in interface_table:
        if port == intf[0]:
            return True

    return False

def is_pc_router_interface(config_db, pc):
    """Check if portchannel is a router interface"""

    pc_interface_table = config_db.get_table('PORTCHANNEL_INTERFACE')
    for intf in pc_interface_table:
        if pc == intf[0]:
            return True

    return False

def _get_all_neighbor_ipaddresses(config_db, ignore_local_hosts=False):
    """Returns list of strings containing IP addresses of all BGP neighbors
       if the flag ignore_local_hosts is set to True, additional check to see if
       if the BGP neighbor AS number is same as local BGP AS number, if so ignore that neigbor.
    """
    addrs = []
    bgp_sessions = config_db.get_table('BGP_NEIGHBOR')
    local_as = get_local_bgp_asn(config_db)
    for addr, session in bgp_sessions.iteritems():
        if not ignore_local_hosts or (ignore_local_hosts and local_as != session['asn']):
            addrs.append(addr)
    return addrs

def _get_neighbor_ipaddress_list_by_hostname(config_db, hostname):
    """Returns list of strings, each containing an IP address of neighbor with
       hostname <hostname>. Returns empty list if <hostname> not a neighbor
    """
    addrs = []
    bgp_sessions = config_db.get_table('BGP_NEIGHBOR')
    for addr, session in bgp_sessions.iteritems():
        if session.has_key('name') and session['name'] == hostname:
            addrs.append(addr)
    return addrs

def _change_bgp_session_status_by_addr(config_db, ipaddress, status, verbose):
    """Start up or shut down BGP session by IP address
    """
    verb = 'Starting' if status == 'up' else 'Shutting'
    click.echo("{} {} BGP session with neighbor {}...".format(verb, status, ipaddress))

    config_db.mod_entry('bgp_neighbor', ipaddress, {'admin_status': status})

def _change_bgp_session_status(config_db, ipaddr_or_hostname, status, verbose):
    """Start up or shut down BGP session by IP address or hostname
    """
    ip_addrs = []

    # If we were passed an IP address, convert it to lowercase because IPv6 addresses were
    # stored in ConfigDB with all lowercase alphabet characters during minigraph parsing
    if _is_neighbor_ipaddress(config_db, ipaddr_or_hostname.lower()):
        ip_addrs.append(ipaddr_or_hostname.lower())
    else:
        # If <ipaddr_or_hostname> is not the IP address of a neighbor, check to see if it's a hostname
        ip_addrs = _get_neighbor_ipaddress_list_by_hostname(config_db, ipaddr_or_hostname)

    if not ip_addrs:
        return False

    for ip_addr in ip_addrs:
        _change_bgp_session_status_by_addr(config_db, ip_addr, status, verbose)

    return True

def _validate_bgp_neighbor(config_db, neighbor_ip_or_hostname):
    """validates whether the given ip or host name is a BGP neighbor
    """
    ip_addrs = []
    if _is_neighbor_ipaddress(config_db, neighbor_ip_or_hostname.lower()):
        ip_addrs.append(neighbor_ip_or_hostname.lower())
    else:
        ip_addrs = _get_neighbor_ipaddress_list_by_hostname(config_db, neighbor_ip_or_hostname.upper())

    return ip_addrs

def _remove_bgp_neighbor_config(config_db, neighbor_ip_or_hostname):
    """Removes BGP configuration of the given neighbor
    """
    ip_addrs = _validate_bgp_neighbor(config_db, neighbor_ip_or_hostname)

    if not ip_addrs:
        return False

    for ip_addr in ip_addrs:
        config_db.mod_entry('bgp_neighbor', ip_addr, None)
        click.echo("Removed configuration of BGP neighbor {}".format(ip_addr))

    return True

def _change_hostname(hostname):
    current_hostname = os.uname()[1]
    if current_hostname != hostname:
        run_command('echo {} > /etc/hostname'.format(hostname), display_cmd=True)
        run_command('hostname -F /etc/hostname', display_cmd=True)
        run_command('sed -i "/\s{}$/d" /etc/hosts'.format(current_hostname), display_cmd=True)
        run_command('echo "127.0.0.1 {}" >> /etc/hosts'.format(hostname), display_cmd=True)

def storm_control_interface_validate(port_name):
    """Check if the interface name is valid
    """
    if get_interface_naming_mode() == "alias":
        port_name = interface_alias_to_name(port_name)
        if port_name is None:
            click.echo("'port_name' is None!")
            return False

    if (port_name.startswith("Ethernet")):
        if interface_name_is_valid(port_name) is False:
            click.echo("Interface name %s is invalid. Please enter a valid interface name" % (port_name))
            return False
    else:
        click.echo("Storm-control is supported only on Ethernet interfaces. Not supported on %s" % (port_name))
        return False

    return True

def storm_control_set_entry(port_name, kbps, storm_type):
    """Set the info of storm control setting into config db
    """
    if storm_control_interface_validate(port_name) is False:
        return False

    config_db = ConfigDBConnector()
    config_db.connect()
    key = port_name + '|' + storm_type
    entry = config_db.get_entry('PORT_STORM_CONTROL', key)

    if len(entry) == 0:
        config_db.set_entry('PORT_STORM_CONTROL', key, {'kbps': kbps})
    else:
        kbps_value = int(entry.get('kbps', 0))
        click.echo("Existing value of kbps %d" % (kbps_value))
        if kbps_value != kbps:
            config_db.mod_entry('PORT_STORM_CONTROL', key, {'kbps': kbps})

    return True

def storm_control_delete_entry(port_name, storm_type):
    """Remove the info of storm control setting from config db
    """
    if storm_control_interface_validate(port_name) is False:
        return False

    config_db = ConfigDBConnector()
    config_db.connect()
    key = port_name + '|' + storm_type
    entry = config_db.get_entry('PORT_STORM_CONTROL', key)

    if len(entry) == 0:
        click.echo("%s storm-control not enabled on interface %s" % (storm_type, port_name))
        return False
    else:
        config_db.set_entry('PORT_STORM_CONTROL', key, None)
        click.echo("deleted %s storm-control from interface %s" % (storm_type, port_name))

    return True


def _clear_qos():
    QOS_TABLE_NAMES = [
            'TC_TO_PRIORITY_GROUP_MAP',
            'MAP_PFC_PRIORITY_TO_QUEUE',
            'TC_TO_QUEUE_MAP',
            'DSCP_TO_TC_MAP',
            'SCHEDULER',
            'PFC_PRIORITY_TO_PRIORITY_GROUP_MAP',
            'PORT_QOS_MAP',
            'WRED_PROFILE',
            'QUEUE',
            'CABLE_LENGTH',
            'BUFFER_POOL',
            'BUFFER_PROFILE',
            'BUFFER_PG',
            'BUFFER_QUEUE']
    config_db = ConfigDBConnector()
    config_db.connect()
    for qos_table in QOS_TABLE_NAMES:
        config_db.delete_table(qos_table)

def _get_sonic_generated_services(num_asic):
    if not os.path.isfile(SONIC_GENERATED_SERVICE_PATH):
        return None
    generated_services_list = []
    generated_multi_instance_services = []
    with open(SONIC_GENERATED_SERVICE_PATH) as generated_service_file:
        for line in generated_service_file:
            if '@' in line:
                line = line.replace('@', '')
                if num_asic > 1:
                    generated_multi_instance_services.append(line.rstrip('\n'))
                else:
                    generated_services_list.append(line.rstrip('\n'))
            else:
                generated_services_list.append(line.rstrip('\n'))
    return generated_services_list, generated_multi_instance_services

def _wait_for_service_stop(service_name):
    # Check the service for 60 times with 1s interval
    for i in range(60):
        (srv_active, err) = run_command("systemctl is-active {}".format(service_name))
        if "inactive" in srv_active:
            return True
        time.sleep(1)

    (srv_status, err) = run_command("systemctl status {}".format(service_name))
    log_error("Wait {} to stop overtime, error: {}".format(service_name, err))
    log_error(srv_status)
    return False

# Callback for confirmation prompt. Aborts if user enters "n"
def _abort_if_false(ctx, param, value):
    if not value:
        ctx.abort()


def _get_disabled_services_list():
    disabled_services_list = []

    config_db = ConfigDBConnector()
    config_db.connect()
    feature_table = config_db.get_table('FEATURE')
    if feature_table is not None:
        for feature_name in feature_table.keys():
            if not feature_name:
                log_warning("Feature is None")
                continue

            status = feature_table[feature_name]['status']
            if not status:
                log_warning("Status of feature '{}' is None".format(feature_name))
                continue

            if status == "disabled":
                disabled_services_list.append(feature_name)
    else:
        log_warning("Unable to retreive FEATURE table")

    return disabled_services_list


def _stop_services():
    # on Mellanox platform pmon is stopped by syncd
    services_to_stop = [
        'mgmt-framework',
        'restapi',
        'swss',
        'lldp',
        'pmon',
        'bgp',
        'hostcfgd',
        'nat'
    ]

    if asic_type == 'mellanox' and 'pmon' in services_to_stop:
        services_to_stop.remove('pmon')

    execute_systemctl(services_to_stop, SYSTEMCTL_ACTION_STOP)


def _reset_failed_services():
    services_to_reset = [
        'bgp',
        'dhcp_relay',
        'hostcfgd',
        'hostname-config',
        'interfaces-config',
        'lldp',
        'ntp-config',
        'pmon',
        'radv',
        'rsyslog-config',
        'snmp',
        'swss',
        'syncd',
        'teamd',
        'nat',
        'sflow',
        'restapi',
        'mgmt-framework'
    ]

    execute_systemctl(services_to_reset, SYSTEMCTL_ACTION_RESET_FAILED)


def _restart_services():
    # on Mellanox platform pmon is started by syncd
    services_to_restart = [
        'hostname-config',
        'interfaces-config',
        'ntp-config',
        'rsyslog-config',
        'swss',
        'bgp',
        'pmon',
        'lldp',
        'hostcfgd',
        'nat',
        'sflow',
        'restapi',
        'mgmt-framework'
    ]

    disable_services = _get_disabled_services_list()

    for service in disable_services:
        if service in services_to_restart:
            services_to_restart.remove(service)

    if asic_type == 'mellanox' and 'pmon' in services_to_restart:
        services_to_restart.remove('pmon')

    execute_systemctl(services_to_restart, SYSTEMCTL_ACTION_RESTART)


def is_ipaddress(val):
    """ Validate if an entry is a valid IP """
    if not val:
        return False
    try:
        netaddr.IPAddress(str(val))
    except netaddr.core.AddrFormatError, ValueError:
        return False
    return True

def  interface_is_in_vlan(vlan_member_table, interface_name):
    """ Check if an interface  is in a vlan """
    for _,intf in vlan_member_table.keys():
        if intf == interface_name:
            return True

    return False

def  interface_is_in_portchannel(portchannel_member_table, interface_name):
    """ Check if an interface is part of portchannel """
    for _,intf in portchannel_member_table.keys():
        if intf == interface_name:
            return True

    return False

def interface_is_router_port(interface_table, interface_name):
    """ Check if an interface has router config """
    for intf in interface_table.keys():
        if (interface_name == intf[0]):
            return True

    return False

def interface_is_mirror_dst_port(config_db, interface_name):
    """ Check if port is already configured as mirror destination port """
    mirror_table = config_db.get_table('MIRROR_SESSION')
    for _,v in mirror_table.items():
        if 'dst_port' in v and v['dst_port'] == interface_name:
            return True

    return False

def interface_has_mirror_config(mirror_table, interface_name):
    """ Check if port is already configured with mirror config """
    for _,v in mirror_table.items():
        if 'src_port' in v and v['src_port'] == interface_name:
            return True
        if 'dst_port' in v and v['dst_port'] == interface_name:
            return True

    return False

def validate_mirror_session_config(config_db, session_name, dst_port, src_port, direction):
    """ Check if SPAN mirror-session config is valid """
    if len(config_db.get_entry('MIRROR_SESSION', session_name)) != 0:
        click.echo("Error: {} already exists".format(session_name))
        return False

    vlan_member_table = config_db.get_table('VLAN_MEMBER')
    mirror_table = config_db.get_table('MIRROR_SESSION')
    portchannel_member_table = config_db.get_table('PORTCHANNEL_MEMBER')
    interface_table = config_db.get_table('INTERFACE')

    if dst_port:
        if not interface_name_is_valid(dst_port):
            click.echo("Error: Destination Interface {} is invalid".format(dst_port))
            return False

        if interface_is_in_vlan(vlan_member_table, dst_port):
            click.echo("Error: Destination Interface {} has vlan config".format(dst_port))
            return False

        if interface_has_mirror_config(mirror_table, dst_port):
            click.echo("Error: Destination Interface {} already has mirror config".format(dst_port))
            return False

        if interface_is_in_portchannel(portchannel_member_table, dst_port):
            click.echo("Error: Destination Interface {} has portchannel config".format(dst_port))
            return False

        if interface_is_router_port(interface_table, dst_port):
            click.echo("Error: Destination Interface {} is a L3 interface".format(dst_port))
            return False

    if src_port:
        for port in src_port.split(","):
            if not interface_name_is_valid(port):
                click.echo("Error: Source Interface {} is invalid".format(port))
                return False
            if dst_port and dst_port == port:
                click.echo("Error: Destination Interface cant be same as Source Interface")
                return False
            if interface_has_mirror_config(mirror_table, port):
                click.echo("Error: Source Interface {} already has mirror config".format(port))
                return False

    if direction:
        if direction not in ['rx', 'tx', 'both']:
            click.echo("Error: Direction {} is invalid".format(direction))
            return False

    return True

# This is our main entrypoint - the main 'config' command
@click.group(cls=AbbreviationGroup, context_settings=CONTEXT_SETTINGS)
def config():
    """SONiC command line - 'config' command"""

    # Load the global config file database_global.json once.
    SonicDBConfig.load_sonic_global_db_config()

    if os.geteuid() != 0:
        exit("Root privileges are required for this operation")

    SonicDBConfig.load_sonic_global_db_config()


config.add_command(aaa.aaa)
config.add_command(aaa.tacacs)
config.add_command(aaa.ldap)
# === Add NAT Configuration ==========
config.add_command(nat.nat)

@config.command()
@click.option('-y', '--yes', is_flag=True, callback=_abort_if_false,
                expose_value=False, prompt='Existing files will be overwritten, continue?')
@click.argument('filename', required=False)
def save(filename):
    """Export current config DB to a file on disk.\n
       <filename> : Names of configuration file(s) to save, separated by comma with no spaces in between
    """
    num_asic = sonic_device_util.get_num_npus()
    cfg_files = []

    num_cfg_file = 1
    if sonic_device_util.is_multi_npu():
        num_cfg_file += num_asic

    # If the user give the filename[s], extract the file names.
    if filename is not None:
        cfg_files = filename.split(',')

        if len(cfg_files) != num_cfg_file:
            click.echo("Input {} config file(s) separated by comma for multiple files ".format(num_cfg_file))
            return

    """In case of multi-asic mode we have additional config_db{NS}.json files for
       various namespaces created per ASIC. {NS} is the namespace index.
    """
    for inst in range(-1, num_cfg_file-1):
        #inst = -1, refers to the linux host where there is no namespace.
        if inst is -1:
            namespace = None
        else:
            namespace = "{}{}".format(NAMESPACE_PREFIX, inst)

        # Get the file from user input, else take the default file /etc/sonic/config_db{NS_id}.json
        if cfg_files:
            file = cfg_files[inst+1]
        else:
            if namespace is None:
                file = DEFAULT_CONFIG_DB_FILE
            else:
                file = "/etc/sonic/config_db{}.json".format(inst)

        if namespace is None:
            command = "{} -d --print-data > {}".format(SONIC_CFGGEN_PATH, file)
        else:
            command = "{} -n {} -d --print-data > {}".format(SONIC_CFGGEN_PATH, namespace, file)

        log_info("'save' executing...")
        run_command(command, display_cmd=True)

@config.command()
@click.option('-y', '--yes', is_flag=True)
@click.argument('filename', required=False)
def load(filename, yes):
    """Import a previous saved config DB dump file.
       <filename> : Names of configuration file(s) to load, separated by comma with no spaces in between
    """
    if filename is None:
        message = 'Load config from the default config file(s) ?'
    else:
        message = 'Load config from the file(s) {} ?'.format(filename)

    if not yes:
        click.confirm(message, abort=True)

    num_asic = sonic_device_util.get_num_npus()
    cfg_files = []

    num_cfg_file = 1
    if sonic_device_util.is_multi_npu():
        num_cfg_file += num_asic

    # If the user give the filename[s], extract the file names.
    if filename is not None:
        cfg_files = filename.split(',')

        if len(cfg_files) != num_cfg_file:
            click.echo("Input {} config file(s) separated by comma for multiple files ".format(num_cfg_file))
            return

    """In case of multi-asic mode we have additional config_db{NS}.json files for
       various namespaces created per ASIC. {NS} is the namespace index.
    """
    for inst in range(-1, num_cfg_file-1):
        #inst = -1, refers to the linux host where there is no namespace.
        if inst is -1:
            namespace = None
        else:
            namespace = "{}{}".format(NAMESPACE_PREFIX, inst)

        # Get the file from user input, else take the default file /etc/sonic/config_db{NS_id}.json
        if cfg_files:
            file = cfg_files[inst+1]
        else:
            if namespace is None:
                file = DEFAULT_CONFIG_DB_FILE
            else:
                file = "/etc/sonic/config_db{}.json".format(inst)

        # if any of the config files in linux host OR namespace is not present, return
        if not os.path.isfile(file):
            click.echo("The config_db file {} doesn't exist".format(file))
            return

        if namespace is None:
            command = "{} -j {} --write-to-db".format(SONIC_CFGGEN_PATH, file)
        else:
            command = "{} -n {} -j {} --write-to-db".format(SONIC_CFGGEN_PATH, namespace, file)

        log_info("'load' executing...")
        run_command(command, display_cmd=True)


@config.command()
@click.option('-y', '--yes', is_flag=True)
@click.option('-l', '--load-sysinfo', is_flag=True, help='load system default information (mac, portmap etc) first.')
@click.option('-n', '--no_service_restart', default=False, is_flag=True, help='Do not restart docker services')
@click.argument('filename', required=False)
def reload(filename, yes, load_sysinfo, no_service_restart):
    """Clear current configuration and import a previous saved config DB dump file.
       <filename> : Names of configuration file(s) to load, separated by comma with no spaces in between
    """
    if filename is None:
        message = 'Clear current config and reload config from the default config file(s) ?'
    else:
        message = 'Clear current config and reload config from the file(s) {} ?'.format(filename)

    if not yes:
        click.confirm(message, abort=True)

    log_info("'reload' executing...")

    num_asic = sonic_device_util.get_num_npus()
    cfg_files = []

    num_cfg_file = 1
    if sonic_device_util.is_multi_npu():
        num_cfg_file += num_asic

    # If the user give the filename[s], extract the file names.
    if filename is not None:
        cfg_files = filename.split(',')

        if len(cfg_files) != num_cfg_file:
            click.echo("Input {} config file(s) separated by comma for multiple files ".format(num_cfg_file))
            return

    if load_sysinfo:
        command = "{} -j {} -v DEVICE_METADATA.localhost.hwsku".format(SONIC_CFGGEN_PATH, filename)
        proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        cfg_hwsku, err = proc.communicate()
        if err:
            click.echo("Could not get the HWSKU from config file, exiting")
            sys.exit(1)
        else:
            cfg_hwsku = cfg_hwsku.strip()

    #Stop services before config push
    if not no_service_restart:
        log_info("'reload' stopping services...")
        _stop_services()

    """ In Single AISC platforms we have single DB service. In multi-ASIC platforms we have a global DB
        service running in the host + DB services running in each ASIC namespace created per ASIC.
        In the below logic, we get all namespaces in this platform and add an empty namespace ''
        denoting the current namespace which we are in ( the linux host )
    """
    for inst in range(-1, num_cfg_file-1):
        # Get the namespace name, for linux host it is None
        if inst is -1:
            namespace = None
        else:
            namespace = "{}{}".format(NAMESPACE_PREFIX, inst)

        # Get the file from user input, else take the default file /etc/sonic/config_db{NS_id}.json
        if cfg_files:
            file = cfg_files[inst+1]
        else:
            if namespace is None:
                file = DEFAULT_CONFIG_DB_FILE
            else:
                file = "/etc/sonic/config_db{}.json".format(inst)

        #Check the file exists before proceeding.
        if not os.path.isfile(file):
            click.echo("The config_db file {} doesn't exist".format(file))
            continue

        if namespace is None:
            config_db = ConfigDBConnector()
        else:
            config_db = ConfigDBConnector(use_unix_socket_path=True, namespace=namespace)

        config_db.connect()
        client = config_db.get_redis_client(config_db.CONFIG_DB)
        client.flushdb()
        if load_sysinfo:
            if namespace is None:
                command = "{} -H -k {} --write-to-db".format(SONIC_CFGGEN_PATH, cfg_hwsku)
            else:
                command = "{} -H -k {} -n {} --write-to-db".format(SONIC_CFGGEN_PATH, cfg_hwsku, namespace)
            run_command(command, display_cmd=True)

        # For the database service running in linux host we use the file user gives as input
        # or by default DEFAULT_CONFIG_DB_FILE. In the case of database service running in namespace,
        # the default config_db<namespaceID>.json format is used.

        if namespace is None:
            if os.path.isfile(INIT_CFG_FILE):
                command = "{} -j {} -j {} --write-to-db".format(SONIC_CFGGEN_PATH, INIT_CFG_FILE, file)
            else:
                command = "{} -j {} --write-to-db".format(SONIC_CFGGEN_PATH, file)
        else:
            if os.path.isfile(INIT_CFG_FILE):
                command = "{} -j {} -j {} -n {} --write-to-db".format(SONIC_CFGGEN_PATH, INIT_CFG_FILE, file, namespace)
            else:
                command = "{} -j {} -n {} --write-to-db".format(SONIC_CFGGEN_PATH, file, namespace)

        run_command(command, display_cmd=True)
        client.set(config_db.INIT_INDICATOR, 1)

        # Migrate DB contents to latest version
        db_migrator='/usr/bin/db_migrator.py'
        if os.path.isfile(db_migrator) and os.access(db_migrator, os.X_OK):
            if namespace is None:
                command = "{} -o migrate".format(db_migrator)
            else:
                command = "{} -o migrate -n {}".format(db_migrator, namespace)
            run_command(command, display_cmd=True)

    # We first run "systemctl reset-failed" to remove the "failed"
    # status from all services before we attempt to restart them
    if not no_service_restart:
        _reset_failed_services()
        log_info("'reload' restarting services...")
        _restart_services()

@config.command("load_mgmt_config")
@click.option('-y', '--yes', is_flag=True, callback=_abort_if_false,
                expose_value=False, prompt='Reload mgmt config?')
@click.argument('filename', default='/etc/sonic/device_desc.xml', type=click.Path(exists=True))
def load_mgmt_config(filename):
    """Reconfigure hostname and mgmt interface based on device description file."""
    log_info("'load_mgmt_config' executing...")
    command = "{} -M {} --write-to-db".format(SONIC_CFGGEN_PATH, filename)
    run_command(command, display_cmd=True)
    #FIXME: After config DB daemon for hostname and mgmt interface is implemented, we'll no longer need to do manual configuration here
    config_data = parse_device_desc_xml(filename)
    hostname = config_data['DEVICE_METADATA']['localhost']['hostname']
    _change_hostname(hostname)
    mgmt_conf = netaddr.IPNetwork(config_data['MGMT_INTERFACE'].keys()[0][1])
    gw_addr = config_data['MGMT_INTERFACE'].values()[0]['gwaddr']
    command = "ifconfig eth0 {} netmask {}".format(str(mgmt_conf.ip), str(mgmt_conf.netmask))
    run_command(command, display_cmd=True)
    command = "ip route add default via {} dev eth0 table default".format(gw_addr)
    run_command(command, display_cmd=True, ignore_error=True)
    command = "ip rule add from {} table default".format(str(mgmt_conf.ip))
    run_command(command, display_cmd=True, ignore_error=True)
    command = "[ -f /var/run/dhclient.eth0.pid ] && kill `cat /var/run/dhclient.eth0.pid` && rm -f /var/run/dhclient.eth0.pid"
    run_command(command, display_cmd=True, ignore_error=True)
    click.echo("Please note loaded setting will be lost after system reboot. To preserve setting, run `config save`.")

@config.command("load_minigraph")
@click.option('-y', '--yes', is_flag=True, callback=_abort_if_false,
                expose_value=False, prompt='Reload config from minigraph?')
@click.option('-n', '--no_service_restart', default=False, is_flag=True, help='Do not restart docker services')
def load_minigraph(no_service_restart):
    """Reconfigure based on minigraph."""
    log_info("'load_minigraph' executing...")

    # get the device type
    command = "{} -m -v DEVICE_METADATA.localhost.type".format(SONIC_CFGGEN_PATH)
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    device_type, err = proc.communicate()
    if err:
        click.echo("Could not get the device type from minigraph, setting device type to Unknown")
        device_type = 'Unknown'
    else:
        device_type = device_type.strip()

    #Stop services before config push
    if not no_service_restart:
        log_info("'load_minigraph' stopping services...")
        _stop_services()

    # For Single Asic platform the namespace list has the empty string
    # for mulit Asic platform the empty string to generate the config
    # for host
    namespace_list = [DEFAULT_NAMESPACE]
    num_npus = sonic_device_util.get_num_npus()
    if num_npus > 1:
        namespace_list += sonic_device_util.get_namespaces()

    for namespace in namespace_list:
        if namespace is DEFAULT_NAMESPACE:
            config_db = ConfigDBConnector()
            cfggen_namespace_option = " "
            ns_cmd_prefix = " "
        else:
            config_db = ConfigDBConnector(use_unix_socket_path=True, namespace=namespace)
            cfggen_namespace_option = " -n {}".format(namespace)
            ns_cmd_prefix = "sudo ip netns exec {}".format(namespace)
        config_db.connect()
        client = config_db.get_redis_client(config_db.CONFIG_DB)
        client.flushdb()
        if os.path.isfile('/etc/sonic/init_cfg.json'):
            command = "{} -H -m -j /etc/sonic/init_cfg.json {} --write-to-db".format(SONIC_CFGGEN_PATH, cfggen_namespace_option)
        else:
            command = "{} -H -m --write-to-db {} ".format(SONIC_CFGGEN_PATH,cfggen_namespace_option)
        run_command(command, display_cmd=True)
        client.set(config_db.INIT_INDICATOR, 1)

        # These commands are not run for host on multi asic platform
        if num_npus == 1 or namespace is not DEFAULT_NAMESPACE:
            if device_type != 'MgmtToRRouter':
                run_command('{} pfcwd start_default'.format(ns_cmd_prefix), display_cmd=True)
            run_command("{} config qos reload".format(ns_cmd_prefix), display_cmd=True)

    if os.path.isfile('/etc/sonic/acl.json'):
        run_command("acl-loader update full /etc/sonic/acl.json", display_cmd=True)

    # Write latest db version string into db
    db_migrator='/usr/bin/db_migrator.py'
    if os.path.isfile(db_migrator) and os.access(db_migrator, os.X_OK):
        for namespace in namespace_list:
            if namespace is DEFAULT_NAMESPACE:
                cfggen_namespace_option = " "
            else:
                cfggen_namespace_option = " -n {}".format(namespace)
            run_command(db_migrator + ' -o set_version' + cfggen_namespace_option)

    # We first run "systemctl reset-failed" to remove the "failed"
    # status from all services before we attempt to restart them
    if not no_service_restart:
        _reset_failed_services()
        #FIXME: After config DB daemon is implemented, we'll no longer need to restart every service.
        log_info("'load_minigraph' restarting services...")
        _restart_services()
    click.echo("Please note setting loaded from minigraph will be lost after system reboot. To preserve setting, run `config save`.")


#
# 'hostname' command
#
@config.command('hostname')
@click.argument('new_hostname', metavar='<new_hostname>', required=True)
def hostname(new_hostname):
    """Change device hostname without impacting the traffic."""

    config_db = ConfigDBConnector()
    config_db.connect()
    config_db.mod_entry('DEVICE_METADATA' , 'localhost', {"hostname" : new_hostname})
    try:
        command = "service hostname-config restart"
        run_command(command, display_cmd=True)
    except SystemExit as e:
        click.echo("Restarting hostname-config  service failed with error {}".format(e))
        raise
    click.echo("Please note loaded setting will be lost after system reboot. To preserve setting, run `config save`.")

#
# 'portchannel' group ('config portchannel ...')
#
@config.group(cls=AbbreviationGroup)
@click.pass_context
def portchannel(ctx):
    config_db = ConfigDBConnector()
    config_db.connect()
    ctx.obj = {'db': config_db}

@portchannel.command('add')
@click.argument('portchannel_name', metavar='<portchannel_name>', required=True)
@click.option('--min-links', default=0, type=int)
@click.option('--fallback', default='false')
@click.pass_context
def add_portchannel(ctx, portchannel_name, min_links, fallback):
    """Add port channel"""
    db = ctx.obj['db']
    fvs = {'admin_status': 'up',
           'mtu': '9100'}
    if min_links != 0:
        fvs['min_links'] = str(min_links)
    if fallback != 'false':
        fvs['fallback'] = 'true'
    db.set_entry('PORTCHANNEL', portchannel_name, fvs)

@portchannel.command('del')
@click.argument('portchannel_name', metavar='<portchannel_name>', required=True)
@click.pass_context
def remove_portchannel(ctx, portchannel_name):
    """Remove port channel"""
    db = ctx.obj['db']
    db.set_entry('PORTCHANNEL', portchannel_name, None)

@portchannel.group(cls=AbbreviationGroup, name='member')
@click.pass_context
def portchannel_member(ctx):
    pass

@portchannel_member.command('add')
@click.argument('portchannel_name', metavar='<portchannel_name>', required=True)
@click.argument('port_name', metavar='<port_name>', required=True)
@click.pass_context
def add_portchannel_member(ctx, portchannel_name, port_name):
    """Add member to port channel"""
    db = ctx.obj['db']
    if interface_is_mirror_dst_port(db, port_name):
        ctx.fail("{} is configured as mirror destination port".format(port_name))
    db.set_entry('PORTCHANNEL_MEMBER', (portchannel_name, port_name),
            {'NULL': 'NULL'})

@portchannel_member.command('del')
@click.argument('portchannel_name', metavar='<portchannel_name>', required=True)
@click.argument('port_name', metavar='<port_name>', required=True)
@click.pass_context
def del_portchannel_member(ctx, portchannel_name, port_name):
    """Remove member from portchannel"""
    db = ctx.obj['db']
    db.set_entry('PORTCHANNEL_MEMBER', (portchannel_name, port_name), None)
    db.set_entry('PORTCHANNEL_MEMBER', portchannel_name + '|' + port_name, None)

#
# 'sag'group ('config sag ...')
#
@config.group()
@click.pass_context
def sag(ctx):
    """Static Anycast Gateway"""
    config_db = ConfigDBConnector()
    config_db.connect()
    ctx.obj = {'db': config_db}
    pass

@sag.group('mac_address')
@click.pass_context
def sag_mac_address(ctx):
    pass

@sag_mac_address.command('add')
@click.argument('mac_address', metavar='<mac_address>', required=True)
@click.pass_context
def add_sag_mac_address(ctx, mac_address):
    """Add mac address to sag"""
    db = ctx.obj['db']
    db.mod_entry('SAG_GLOBAL', 'IP', {'gwmac': mac_address})

@sag_mac_address.command('del')
@click.argument('mac_address', metavar='<mac_address>', required=True)
@click.pass_context
def del_sag_mac_address(ctx, mac_address):
    """Delete mac address from sag"""
    db = ctx.obj['db']
    db.mod_entry('SAG_GLOBAL', 'IP', None)

@sag.group('ipv4')
@click.pass_context
def sag_ipv4_knob(ctx):
    pass

@sag_ipv4_knob.command('enable')
@click.pass_context
def enable_sag_ipv4_knob(ctx):
    """ipv4 enable knob"""
    db = ctx.obj['db']
    db.mod_entry('SAG_GLOBAL', 'IP', {'IPv4': 'enable'})

@sag_ipv4_knob.command('disable')
@click.pass_context
def disable_sag_ipv4_knob(ctx):
    """ipv4 disable knob"""
    db = ctx.obj['db']
    db.mod_entry('SAG_GLOBAL', 'IP', {'IPv4': 'disable'})

@sag.group('ipv6')
@click.pass_context
def sag_ipv6_knob(ctx):
    pass

@sag_ipv6_knob.command('enable')
@click.pass_context
def enable_sag_ipv6_knob(ctx):
    """ipv4 enable knob"""
    db = ctx.obj['db']
    db.mod_entry('SAG_GLOBAL', 'IP', {'IPv6': 'enable'})

@sag_ipv6_knob.command('disable')
@click.pass_context
def disable_sag_ipv6_knob(ctx):
    """ipv4 disable knob"""
    db = ctx.obj['db']
    db.mod_entry('SAG_GLOBAL', 'IP', {'IPv6': 'disable'})

#
# 'mirror_session' group ('config mirror_session ...')
#
@config.group(cls=AbbreviationGroup, name='mirror_session')
def mirror_session():
    pass

#
# 'add' subgroup ('config mirror_session add ...')
#

@mirror_session.command('add')
@click.argument('session_name', metavar='<session_name>', required=True)
@click.argument('src_ip', metavar='<src_ip>', required=True)
@click.argument('dst_ip', metavar='<dst_ip>', required=True)
@click.argument('dscp', metavar='<dscp>', required=True)
@click.argument('ttl', metavar='<ttl>', required=True)
@click.argument('gre_type', metavar='[gre_type]', required=False)
@click.argument('queue', metavar='[queue]', required=False)
@click.option('--policer')
def add(session_name, src_ip, dst_ip, dscp, ttl, gre_type, queue, policer):
    """ Add ERSPAN mirror session.(Legacy support) """
    add_erspan(session_name, src_ip, dst_ip, dscp, ttl, gre_type, queue, policer)

@mirror_session.group(cls=AbbreviationGroup, name='erspan')
@click.pass_context
def erspan(ctx):
    """ ERSPAN mirror_session """
    pass


#
# 'add' subcommand
#

@erspan.command('add')
@click.argument('session_name', metavar='<session_name>', required=True)
@click.argument('src_ip', metavar='<src_ip>', required=True)
@click.argument('dst_ip', metavar='<dst_ip>', required=True)
@click.argument('dscp', metavar='<dscp>', required=True)
@click.argument('ttl', metavar='<ttl>', required=True)
@click.argument('gre_type', metavar='[gre_type]', required=False)
@click.argument('queue', metavar='[queue]', required=False)
@click.argument('src_port', metavar='[src_port]', required=False)
@click.argument('direction', metavar='[direction]', required=False)
@click.option('--policer')
def add(session_name, src_ip, dst_ip, dscp, ttl, gre_type, queue, policer, src_port, direction):
    """ Add ERSPAN mirror session """
    add_erspan(session_name, src_ip, dst_ip, dscp, ttl, gre_type, queue, policer, src_port, direction)

def gather_session_info(session_info, policer, queue, src_port, direction):
    if policer:
        session_info['policer'] = policer

    if queue:
        session_info['queue'] = queue

    if src_port:
        if get_interface_naming_mode() == "alias":
            src_port_list = []
            for port in src_port.split(","):
                src_port_list.append(interface_alias_to_name(port))
            src_port=",".join(src_port_list)

        session_info['src_port'] = src_port
        if not direction:
            direction = "both"
        session_info['direction'] = direction.upper()

    return session_info

def add_erspan(session_name, src_ip, dst_ip, dscp, ttl, gre_type, queue, policer, src_port=None, direction=None):
    session_info = {
            "type" : "ERSPAN",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dscp": dscp,
            "ttl": ttl
            }

    if gre_type:
        session_info['gre_type'] = gre_type

    session_info = gather_session_info(session_info, policer, queue, src_port, direction)

    """
    For multi-npu platforms we need to program all front asic namespaces
    """
    namespaces = sonic_device_util.get_all_namespaces()
    if not namespaces['front_ns']:
        config_db = ConfigDBConnector()
        config_db.connect()
        if validate_mirror_session_config(config_db, session_name, None, src_port, direction) is False:
            return
        config_db.set_entry("MIRROR_SESSION", session_name, session_info)
    else:
        per_npu_configdb = {}
        for front_asic_namespaces in namespaces['front_ns']:
            per_npu_configdb[front_asic_namespaces] = ConfigDBConnector(use_unix_socket_path=True, namespace=front_asic_namespaces)
            per_npu_configdb[front_asic_namespaces].connect()
            if validate_mirror_session_config(per_npu_configdb[front_asic_namespaces], session_name, None, src_port, direction) is False:
                return
            per_npu_configdb[front_asic_namespaces].set_entry("MIRROR_SESSION", session_name, session_info)

@mirror_session.group(cls=AbbreviationGroup, name='span')
@click.pass_context
def span(ctx):
    """ SPAN mirror session """
    pass

@span.command('add')
@click.argument('session_name', metavar='<session_name>', required=True)
@click.argument('dst_port', metavar='<dst_port>', required=True)
@click.argument('src_port', metavar='[src_port]', required=False)
@click.argument('direction', metavar='[direction]', required=False)
@click.argument('queue', metavar='[queue]', required=False)
@click.option('--policer')
def add(session_name, dst_port, src_port, direction, queue, policer):
    """ Add SPAN mirror session """
    add_span(session_name, dst_port, src_port, direction, queue, policer)

def add_span(session_name, dst_port, src_port, direction, queue, policer):
    if get_interface_naming_mode() == "alias":
        dst_port = interface_alias_to_name(dst_port)
        if dst_port is None:
            click.echo("Error: Destination Interface {} is invalid".format(dst_port))
            return

    session_info = {
            "type" : "SPAN",
            "dst_port": dst_port,
            }

    session_info = gather_session_info(session_info, policer, queue, src_port, direction)

    """
    For multi-npu platforms we need to program all front asic namespaces
    """
    namespaces = sonic_device_util.get_all_namespaces()
    if not namespaces['front_ns']:
        config_db = ConfigDBConnector()
        config_db.connect()
        if validate_mirror_session_config(config_db, session_name, dst_port, src_port, direction) is False:
            return
        config_db.set_entry("MIRROR_SESSION", session_name, session_info)
    else:
        per_npu_configdb = {}
        for front_asic_namespaces in namespaces['front_ns']:
            per_npu_configdb[front_asic_namespaces] = ConfigDBConnector(use_unix_socket_path=True, namespace=front_asic_namespaces)
            per_npu_configdb[front_asic_namespaces].connect()
            if validate_mirror_session_config(per_npu_configdb[front_asic_namespaces], session_name, dst_port, src_port, direction) is False:
                return
            per_npu_configdb[front_asic_namespaces].set_entry("MIRROR_SESSION", session_name, session_info)


@mirror_session.command()
@click.argument('session_name', metavar='<session_name>', required=True)
def remove(session_name):
    """ Delete mirror session """

    """
    For multi-npu platforms we need to program all front asic namespaces
    """
    namespaces = sonic_device_util.get_all_namespaces()
    if not namespaces['front_ns']:
        config_db = ConfigDBConnector()
        config_db.connect()
        config_db.set_entry("MIRROR_SESSION", session_name, None)
    else:
        per_npu_configdb = {}
        for front_asic_namespaces in namespaces['front_ns']:
            per_npu_configdb[front_asic_namespaces] = ConfigDBConnector(use_unix_socket_path=True, namespace=front_asic_namespaces)
            per_npu_configdb[front_asic_namespaces].connect()
            per_npu_configdb[front_asic_namespaces].set_entry("MIRROR_SESSION", session_name, None)

#
# 'pfcwd' group ('config pfcwd ...')
#
@config.group(cls=AbbreviationGroup)
def pfcwd():
    """Configure pfc watchdog """
    pass

@pfcwd.command()
@click.option('--action', '-a', type=click.Choice(['drop', 'forward', 'alert']))
@click.option('--restoration-time', '-r', type=click.IntRange(100, 60000))
@click.option('--verbose', is_flag=True, help="Enable verbose output")
@click.argument('ports', nargs=-1)
@click.argument('detection-time', type=click.IntRange(100, 5000))
def start(action, restoration_time, ports, detection_time, verbose):
    """
    Start PFC watchdog on port(s). To config all ports, use all as input.

    Example:
        config pfcwd start --action drop ports all detection-time 400 --restoration-time 400
    """
    cmd = "pfcwd start"

    if action:
        cmd += " --action {}".format(action)

    if ports:
        ports = set(ports) - set(['ports', 'detection-time'])
        cmd += " ports {}".format(' '.join(ports))

    if detection_time:
        cmd += " detection-time {}".format(detection_time)

    if restoration_time:
        cmd += " --restoration-time {}".format(restoration_time)

    run_command(cmd, display_cmd=verbose)

@pfcwd.command()
@click.option('--verbose', is_flag=True, help="Enable verbose output")
def stop(verbose):
    """ Stop PFC watchdog """

    cmd = "pfcwd stop"

    run_command(cmd, display_cmd=verbose)

@pfcwd.command()
@click.option('--verbose', is_flag=True, help="Enable verbose output")
@click.argument('poll_interval', type=click.IntRange(100, 3000))
def interval(poll_interval, verbose):
    """ Set PFC watchdog counter polling interval (ms) """

    cmd = "pfcwd interval {}".format(poll_interval)

    run_command(cmd, display_cmd=verbose)

@pfcwd.command('counter_poll')
@click.option('--verbose', is_flag=True, help="Enable verbose output")
@click.argument('counter_poll', type=click.Choice(['enable', 'disable']))
def counter_poll(counter_poll, verbose):
    """ Enable/disable counter polling """

    cmd = "pfcwd counter_poll {}".format(counter_poll)

    run_command(cmd, display_cmd=verbose)

@pfcwd.command('big_red_switch')
@click.option('--verbose', is_flag=True, help="Enable verbose output")
@click.argument('big_red_switch', type=click.Choice(['enable', 'disable']))
def big_red_switch(big_red_switch, verbose):
    """ Enable/disable BIG_RED_SWITCH mode """

    cmd = "pfcwd big_red_switch {}".format(big_red_switch)

    run_command(cmd, display_cmd=verbose)

@pfcwd.command('start_default')
@click.option('--verbose', is_flag=True, help="Enable verbose output")
def start_default(verbose):
    """ Start PFC WD by default configurations  """

    cmd = "pfcwd start_default"

    run_command(cmd, display_cmd=verbose)

#
# 'qos' group ('config qos ...')
#
@config.group(cls=AbbreviationGroup)
@click.pass_context
def qos(ctx):
    """QoS-related configuration tasks"""
    pass

@qos.command('clear')
def clear():
    """Clear QoS configuration"""
    log_info("'qos clear' executing...")
    _clear_qos()

@qos.command('reload')
def reload():
    """Reload QoS configuration"""
    log_info("'qos reload' executing...")
    _clear_qos()
    platform = sonic_device_util.get_platform()
    hwsku = sonic_device_util.get_hwsku()
    buffer_template_file = os.path.join('/usr/share/sonic/device/', platform, hwsku, 'buffers.json.j2')
    if os.path.isfile(buffer_template_file):
        command = "{} -d -t {} >/tmp/buffers.json".format(SONIC_CFGGEN_PATH, buffer_template_file)
        run_command(command, display_cmd=True)

        qos_template_file = os.path.join('/usr/share/sonic/device/', platform, hwsku, 'qos.json.j2')
        sonic_version_file = os.path.join('/etc/sonic/', 'sonic_version.yml')
        if os.path.isfile(qos_template_file):
            command = "{} -d -t {} -y {} >/tmp/qos.json".format(SONIC_CFGGEN_PATH, qos_template_file, sonic_version_file)
            run_command(command, display_cmd=True)

            # Apply the configurations only when both buffer and qos configuration files are presented
            command = "{} -j /tmp/buffers.json --write-to-db".format(SONIC_CFGGEN_PATH)
            run_command(command, display_cmd=True)
            command = "{} -j /tmp/qos.json --write-to-db".format(SONIC_CFGGEN_PATH)
            run_command(command, display_cmd=True)
        else:
            click.secho('QoS definition template not found at {}'.format(qos_template_file), fg='yellow')
    else:
        click.secho('Buffer definition template not found at {}'.format(buffer_template_file), fg='yellow')

#
# 'warm_restart' group ('config warm_restart ...')
#
@config.group(cls=AbbreviationGroup, name='warm_restart')
@click.pass_context
@click.option('-s', '--redis-unix-socket-path', help='unix socket path for redis connection')
def warm_restart(ctx, redis_unix_socket_path):
    """warm_restart-related configuration tasks"""
    kwargs = {}
    if redis_unix_socket_path:
        kwargs['unix_socket_path'] = redis_unix_socket_path
    config_db = ConfigDBConnector(**kwargs)
    config_db.connect(wait_for_init=False)

    # warm restart enable/disable config is put in stateDB, not persistent across cold reboot, not saved to config_DB.json file
    state_db = SonicV2Connector(host='127.0.0.1')
    state_db.connect(state_db.STATE_DB, False)
    TABLE_NAME_SEPARATOR = '|'
    prefix = 'WARM_RESTART_ENABLE_TABLE' + TABLE_NAME_SEPARATOR
    ctx.obj = {'db': config_db, 'state_db': state_db, 'prefix': prefix}

@warm_restart.command('enable')
@click.argument('module', metavar='<module>', default='system', required=False, type=click.Choice(["system", "swss", "bgp", "teamd"]))
@click.pass_context
def warm_restart_enable(ctx, module):
    state_db = ctx.obj['state_db']
    prefix = ctx.obj['prefix']
    _hash = '{}{}'.format(prefix, module)
    state_db.set(state_db.STATE_DB, _hash, 'enable', 'true')
    state_db.close(state_db.STATE_DB)

@warm_restart.command('disable')
@click.argument('module', metavar='<module>', default='system', required=False, type=click.Choice(["system", "swss", "bgp", "teamd"]))
@click.pass_context
def warm_restart_enable(ctx, module):
    state_db = ctx.obj['state_db']
    prefix = ctx.obj['prefix']
    _hash = '{}{}'.format(prefix, module)
    state_db.set(state_db.STATE_DB, _hash, 'enable', 'false')
    state_db.close(state_db.STATE_DB)

@warm_restart.command('neighsyncd_timer')
@click.argument('seconds', metavar='<seconds>', required=True, type=int)
@click.pass_context
def warm_restart_neighsyncd_timer(ctx, seconds):
    db = ctx.obj['db']
    if seconds not in range(1,9999):
        ctx.fail("neighsyncd warm restart timer must be in range 1-9999")
    db.mod_entry('WARM_RESTART', 'swss', {'neighsyncd_timer': seconds})

@warm_restart.command('bgp_timer')
@click.argument('seconds', metavar='<seconds>', required=True, type=int)
@click.pass_context
def warm_restart_bgp_timer(ctx, seconds):
    db = ctx.obj['db']
    if seconds not in range(1,3600):
        ctx.fail("bgp warm restart timer must be in range 1-3600")
    db.mod_entry('WARM_RESTART', 'bgp', {'bgp_timer': seconds})

@warm_restart.command('teamsyncd_timer')
@click.argument('seconds', metavar='<seconds>', required=True, type=int)
@click.pass_context
def warm_restart_teamsyncd_timer(ctx, seconds):
    db = ctx.obj['db']
    if seconds not in range(1,3600):
        ctx.fail("teamsyncd warm restart timer must be in range 1-3600")
    db.mod_entry('WARM_RESTART', 'teamd', {'teamsyncd_timer': seconds})

@warm_restart.command('bgp_eoiu')
@click.argument('enable', metavar='<enable>', default='true', required=False, type=click.Choice(["true", "false"]))
@click.pass_context
def warm_restart_bgp_eoiu(ctx, enable):
    db = ctx.obj['db']
    db.mod_entry('WARM_RESTART', 'bgp', {'bgp_eoiu': enable})

#
# 'vlan' group ('config vlan ...')
#
@config.group(cls=AbbreviationGroup)
@click.pass_context
@click.option('-s', '--redis-unix-socket-path', help='unix socket path for redis connection')
def vlan(ctx, redis_unix_socket_path):
    """VLAN-related configuration tasks"""
    kwargs = {}
    if redis_unix_socket_path:
        kwargs['unix_socket_path'] = redis_unix_socket_path
    config_db = ConfigDBConnector(**kwargs)
    config_db.connect(wait_for_init=False)
    ctx.obj = {'db': config_db}

@vlan.command('add')
@click.argument('vid', metavar='<vid>', required=True, type=int)
@click.argument('pvlan_type', metavar='<pvlan_type>', required=False, type=click.Choice(['primary', 'community', 'isolated']))
@click.pass_context
def add_vlan(ctx, vid, pvlan_type):
    if vid >= 1 and vid <= 4094:
        db = ctx.obj['db']
        vlan = 'Vlan{}'.format(vid)
        if len(db.get_entry('VLAN', vlan)) != 0:
            ctx.fail("{} already exists".format(vlan))
        vlan_entry = {'vlanid': vid}
        if pvlan_type:
            vlan_entry['private_type'] = pvlan_type
        db.set_entry('VLAN', vlan, vlan_entry)
    else :
        ctx.fail("Invalid VLAN ID {} (1-4094)".format(vid))

@vlan.command('del')
@click.argument('vid', metavar='<vid>', required=True, type=int)
@click.pass_context
def del_vlan(ctx, vid):
    """Delete VLAN"""
    log_info("'vlan del {}' executing...".format(vid))
    db = ctx.obj['db']
    vlan_name = 'Vlan{}'.format(vid)

    pvlan_association_table = db.get_table('PVLAN_ASSOCIATION')
    for k, v in pvlan_association_table.items():
        if k[0] == vlan_name or k[1] == vlan_name:
            ctx.fail('Not allow to remove {} which still associated with other private VLAN.'.format(vlan_name))

    keys = [ (k, v) for k, v in db.get_table('VLAN_MEMBER') if k == vlan_name ]
    for k in keys:
        db.set_entry('VLAN_MEMBER', k, None)
    db.set_entry('VLAN', vlan_name, None)


#
# 'member' group ('config vlan member ...')
#
@vlan.group(cls=AbbreviationGroup, name='member')
@click.pass_context
def vlan_member(ctx):
    pass


@vlan_member.command('add')
@click.argument('vid', metavar='<vid>', required=True, type=int)
@click.argument('interface_name', metavar='<interface_name>', required=True)
@click.option('-u', '--untagged', is_flag=True)
@click.pass_context
def add_vlan_member(ctx, vid, interface_name, untagged):
    """Add VLAN member"""
    log_info("'vlan member add {} {}' executing...".format(vid, interface_name))
    db = ctx.obj['db']
    vlan_name = 'Vlan{}'.format(vid)
    vlan = db.get_entry('VLAN', vlan_name)

    if get_interface_naming_mode() == "alias":
        interface_name = interface_alias_to_name(interface_name)
        if interface_name is None:
            ctx.fail("'interface_name' is None!")

    if len(vlan) == 0:
        ctx.fail("{} doesn't exist".format(vlan_name))
    if interface_is_mirror_dst_port(db, interface_name):
        ctx.fail("{} is configured as mirror destination port".format(interface_name))

    members = vlan.get('members', [])
    if interface_name in members:
        if get_interface_naming_mode() == "alias":
            interface_name = interface_name_to_alias(interface_name)
            if interface_name is None:
                ctx.fail("'interface_name' is None!")
            ctx.fail("{} is already a member of {}".format(interface_name,
                                                        vlan_name))
        else:
            ctx.fail("{} is already a member of {}".format(interface_name,
                                                        vlan_name))

    if is_valid_port(db, interface_name):
        is_port = True
    elif is_valid_portchannel(db, interface_name):
        is_port = False
    else:
        ctx.fail("{} does not exist".format(interface_name))

    if (is_port and is_port_router_interface(db, interface_name)) or \
       (not is_port and is_pc_router_interface(db, interface_name)):
        ctx.fail("{} is a L3 interface!".format(interface_name))

    members.append(interface_name)
    vlan['members'] = members
    db.set_entry('VLAN', vlan_name, vlan)
    db.set_entry('VLAN_MEMBER', (vlan_name, interface_name), {'tagging_mode': "untagged" if untagged else "tagged" })


@vlan_member.command('del')
@click.argument('vid', metavar='<vid>', required=True, type=int)
@click.argument('interface_name', metavar='<interface_name>', required=True)
@click.pass_context
def del_vlan_member(ctx, vid, interface_name):
    """Delete VLAN member"""
    log_info("'vlan member del {} {}' executing...".format(vid, interface_name))
    db = ctx.obj['db']
    vlan_name = 'Vlan{}'.format(vid)
    vlan = db.get_entry('VLAN', vlan_name)

    if get_interface_naming_mode() == "alias":
        interface_name = interface_alias_to_name(interface_name)
        if interface_name is None:
            ctx.fail("'interface_name' is None!")

    if len(vlan) == 0:
        ctx.fail("{} doesn't exist".format(vlan_name))
    members = vlan.get('members', [])
    if interface_name not in members:
        if get_interface_naming_mode() == "alias":
            interface_name = interface_name_to_alias(interface_name)
            if interface_name is None:
                ctx.fail("'interface_name' is None!")
            ctx.fail("{} is not a member of {}".format(interface_name, vlan_name))
        else:
            ctx.fail("{} is not a member of {}".format(interface_name, vlan_name))
    members.remove(interface_name)
    if len(members) == 0:
        del vlan['members']
    else:
        vlan['members'] = members
    db.set_entry('VLAN', vlan_name, vlan)
    db.set_entry('VLAN_MEMBER', (vlan_name, interface_name), None)

#
# 'pvlan' group ('config pvlan ...')
#
@config.group(cls=AbbreviationGroup)
@click.pass_context
def pvlan(ctx):
    """Private VLAN-related configuration tasks"""
    config_db = ConfigDBConnector()
    config_db.connect()
    ctx.obj = {'db': config_db}
    pass

#
# 'pvlan association' group ('config pvlan association ...')
#
@pvlan.group('association')
@click.pass_context
def pvlan_association(ctx):
    pass

#
# 'pvlan association' command ('config pvlan association add ...')
#
@pvlan_association.command('add')
@click.argument('primary_vid', metavar='<primary_vid>', required=True, type=int)
@click.argument('secondary_vid', metavar='<secondary_vid>', required=True, type=int)
@click.pass_context
def add_association(ctx, primary_vid, secondary_vid):
    if vlan_id_is_valid(primary_vid) is False:
        ctx.fail("Invalid Primary VLAN ID {} (1-4094)".format(primary_vid))
    if vlan_id_is_valid(secondary_vid) is False:
        ctx.fail("Invalid Secondary VLAN ID {} (1-4094)".format(secondary_vid))

    db = ctx.obj['db']
    primary_vlan = 'Vlan{}'.format(primary_vid)
    if len(db.get_entry('VLAN', primary_vlan)) == 0:
        ctx.fail("{} doesn't exist".format(primary_vlan))
    secondary_vlan = 'Vlan{}'.format(secondary_vid)
    if len(db.get_entry('VLAN', secondary_vlan)) == 0:
        ctx.fail("{} doesn't exist".format(secondary_vlan))

    db.set_entry('PVLAN_ASSOCIATION', (primary_vlan, secondary_vlan), {"NULL": "NULL"})

#
# 'pvlan association' command ('config pvlan association del ...')
#
@pvlan_association.command('del')
@click.argument('primary_vid', metavar='<primary_vid>', required=True, type=int)
@click.argument('secondary_vid', metavar='<secondary_vid>', required=True, type=int)
@click.pass_context
def del_association(ctx, primary_vid, secondary_vid):
    if vlan_id_is_valid(primary_vid) is False:
        ctx.fail("Invalid Primary VLAN ID {} (1-4094)".format(primary_vid))
    if vlan_id_is_valid(secondary_vid) is False:
        ctx.fail("Invalid Secondary VLAN ID {} (1-4094)".format(secondary_vid))

    db = ctx.obj['db']
    primary_vlan = 'Vlan{}'.format(primary_vid)
    if len(db.get_entry('VLAN', primary_vlan)) == 0:
        ctx.fail("{} doesn't exist".format(primary_vlan))
    secondary_vlan = 'Vlan{}'.format(secondary_vid)
    if len(db.get_entry('VLAN', secondary_vlan)) == 0:
        ctx.fail("{} doesn't exist".format(secondary_vlan))

    db.set_entry('PVLAN_ASSOCIATION', (primary_vlan, secondary_vlan), None)

def mvrf_restart_services():
    """Restart interfaces-config service and NTP service when mvrf is changed"""
    """
    When mvrf is enabled, eth0 should be moved to mvrf; when it is disabled,
    move it back to default vrf. Restarting the "interfaces-config" service
    will recreate the /etc/network/interfaces file and restart the
    "networking" service that takes care of the eth0 movement.
    NTP service should also be restarted to rerun the NTP service with or
    without "cgexec" accordingly.
    """
    cmd="service ntp stop"
    os.system (cmd)
    cmd="service rsyslog-config stop"
    os.system (cmd)
    cmd="systemctl restart interfaces-config"
    os.system (cmd)
    cmd="service ntp start"
    os.system (cmd)
    cmd="service rsyslog-config start"
    os.system (cmd)

def vrf_add_management_vrf(config_db):
    """Enable management vrf in config DB"""

    entry = config_db.get_entry('MGMT_VRF_CONFIG', "vrf_global")
    if entry and entry['mgmtVrfEnabled'] == 'true' :
        click.echo("ManagementVRF is already Enabled.")
        return None
    config_db.mod_entry('MGMT_VRF_CONFIG',"vrf_global",{"mgmtVrfEnabled": "true"})
    mvrf_restart_services()

def vrf_delete_management_vrf(config_db):
    """Disable management vrf in config DB"""

    entry = config_db.get_entry('MGMT_VRF_CONFIG', "vrf_global")
    if not entry or entry['mgmtVrfEnabled'] == 'false' :
        click.echo("ManagementVRF is already Disabled.")
        return None
    config_db.mod_entry('MGMT_VRF_CONFIG',"vrf_global",{"mgmtVrfEnabled": "false"})
    mvrf_restart_services()

@config.group(cls=AbbreviationGroup)
@click.pass_context
def snmpagentaddress(ctx):
    """SNMP agent listening IP address, port, vrf configuration"""
    config_db = ConfigDBConnector()
    config_db.connect()
    ctx.obj = {'db': config_db}

@snmpagentaddress.command('add')
@click.argument('agentip', metavar='<SNMP AGENT LISTENING IP Address>', required=True)
@click.option('-p', '--port', help="SNMP AGENT LISTENING PORT")
@click.option('-v', '--vrf', help="VRF Name mgmt/DataVrfName/None")
@click.pass_context
def add_snmp_agent_address(ctx, agentip, port, vrf):
    """Add the SNMP agent listening IP:Port%Vrf configuration"""

    #Construct SNMP_AGENT_ADDRESS_CONFIG table key in the format ip|<port>|<vrf>
    key = agentip+'|'
    if port:
        key = key+port
    key = key+'|'
    if vrf:
        key = key+vrf
    config_db = ctx.obj['db']
    config_db.set_entry('SNMP_AGENT_ADDRESS_CONFIG', key, {})

    #Restarting the SNMP service will regenerate snmpd.conf and rerun snmpd
    cmd="systemctl restart snmp"
    os.system (cmd)

@snmpagentaddress.command('del')
@click.argument('agentip', metavar='<SNMP AGENT LISTENING IP Address>', required=True)
@click.option('-p', '--port', help="SNMP AGENT LISTENING PORT")
@click.option('-v', '--vrf', help="VRF Name mgmt/DataVrfName/None")
@click.pass_context
def del_snmp_agent_address(ctx, agentip, port, vrf):
    """Delete the SNMP agent listening IP:Port%Vrf configuration"""

    key = agentip+'|'
    if port:
        key = key+port
    key = key+'|'
    if vrf:
        key = key+vrf
    config_db = ctx.obj['db']
    config_db.set_entry('SNMP_AGENT_ADDRESS_CONFIG', key, None)
    cmd="systemctl restart snmp"
    os.system (cmd)

@config.group(cls=AbbreviationGroup)
@click.pass_context
def snmptrap(ctx):
    """SNMP Trap server configuration to send traps"""
    config_db = ConfigDBConnector()
    config_db.connect()
    ctx.obj = {'db': config_db}

@snmptrap.command('modify')
@click.argument('ver', metavar='<SNMP Version>', type=click.Choice(['1', '2', '3']), required=True)
@click.argument('serverip', metavar='<SNMP TRAP SERVER IP Address>', required=True)
@click.option('-p', '--port', help="SNMP Trap Server port, default 162", default="162")
@click.option('-v', '--vrf', help="VRF Name mgmt/DataVrfName/None", default="None")
@click.option('-c', '--comm', help="Community", default="public")
@click.pass_context
def modify_snmptrap_server(ctx, ver, serverip, port, vrf, comm):
    """Modify the SNMP Trap server configuration"""

    #SNMP_TRAP_CONFIG for each SNMP version
    config_db = ctx.obj['db']
    if ver == "1":
        #By default, v1TrapDest value in snmp.yml is "NotConfigured". Modify it.
        config_db.mod_entry('SNMP_TRAP_CONFIG',"v1TrapDest",{"DestIp": serverip, "DestPort": port, "vrf": vrf, "Community": comm})
    elif ver == "2":
        config_db.mod_entry('SNMP_TRAP_CONFIG',"v2TrapDest",{"DestIp": serverip, "DestPort": port, "vrf": vrf, "Community": comm})
    else:
        config_db.mod_entry('SNMP_TRAP_CONFIG',"v3TrapDest",{"DestIp": serverip, "DestPort": port, "vrf": vrf, "Community": comm})

    cmd="systemctl restart snmp"
    os.system (cmd)

@snmptrap.command('del')
@click.argument('ver', metavar='<SNMP Version>', type=click.Choice(['1', '2', '3']), required=True)
@click.pass_context
def delete_snmptrap_server(ctx, ver):
    """Delete the SNMP Trap server configuration"""

    config_db = ctx.obj['db']
    if ver == "1":
        config_db.mod_entry('SNMP_TRAP_CONFIG',"v1TrapDest",None)
    elif ver == "2":
        config_db.mod_entry('SNMP_TRAP_CONFIG',"v2TrapDest",None)
    else:
        config_db.mod_entry('SNMP_TRAP_CONFIG',"v3TrapDest",None)
    cmd="systemctl restart snmp"
    os.system (cmd)

@vlan.group(cls=AbbreviationGroup, name='dhcp_relay')
@click.pass_context
def vlan_dhcp_relay(ctx):
    pass

@vlan_dhcp_relay.command('add')
@click.argument('vid', metavar='<vid>', required=True, type=int)
@click.argument('dhcp_relay_destination_ip', metavar='<dhcp_relay_destination_ip>', required=True)
@click.pass_context
def add_vlan_dhcp_relay_destination(ctx, vid, dhcp_relay_destination_ip):
    """ Add a destination IP address to the VLAN's DHCP relay """
    if not is_ipaddress(dhcp_relay_destination_ip):
        ctx.fail('Invalid IP address')
    db = ctx.obj['db']
    vlan_name = 'Vlan{}'.format(vid)
    vlan = db.get_entry('VLAN', vlan_name)

    if len(vlan) == 0:
        ctx.fail("{} doesn't exist".format(vlan_name))
    dhcp_relay_dests = vlan.get('dhcp_servers', [])
    if dhcp_relay_destination_ip in dhcp_relay_dests:
        click.echo("{} is already a DHCP relay destination for {}".format(dhcp_relay_destination_ip, vlan_name))
        return
    else:
        dhcp_relay_dests.append(dhcp_relay_destination_ip)
        vlan['dhcp_servers'] = dhcp_relay_dests
        db.set_entry('VLAN', vlan_name, vlan)
        click.echo("Added DHCP relay destination address {} to {}".format(dhcp_relay_destination_ip, vlan_name))
        try:
            click.echo("Restarting DHCP relay service...")
            run_command("systemctl restart dhcp_relay", display_cmd=False)
        except SystemExit as e:
            ctx.fail("Restart service dhcp_relay failed with error {}".format(e))

@vlan_dhcp_relay.command('del')
@click.argument('vid', metavar='<vid>', required=True, type=int)
@click.argument('dhcp_relay_destination_ip', metavar='<dhcp_relay_destination_ip>', required=True)
@click.pass_context
def del_vlan_dhcp_relay_destination(ctx, vid, dhcp_relay_destination_ip):
    """ Remove a destination IP address from the VLAN's DHCP relay """
    if not is_ipaddress(dhcp_relay_destination_ip):
        ctx.fail('Invalid IP address')
    db = ctx.obj['db']
    vlan_name = 'Vlan{}'.format(vid)
    vlan = db.get_entry('VLAN', vlan_name)

    if len(vlan) == 0:
        ctx.fail("{} doesn't exist".format(vlan_name))
    dhcp_relay_dests = vlan.get('dhcp_servers', [])
    if dhcp_relay_destination_ip in dhcp_relay_dests:
        dhcp_relay_dests.remove(dhcp_relay_destination_ip)
        if len(dhcp_relay_dests) == 0:
            del vlan['dhcp_servers']
        else:
            vlan['dhcp_servers'] = dhcp_relay_dests
        db.set_entry('VLAN', vlan_name, vlan)
        click.echo("Removed DHCP relay destination address {} from {}".format(dhcp_relay_destination_ip, vlan_name))
        try:
            click.echo("Restarting DHCP relay service...")
            run_command("systemctl restart dhcp_relay", display_cmd=False)
        except SystemExit as e:
            ctx.fail("Restart service dhcp_relay failed with error {}".format(e))
    else:
        ctx.fail("{} is not a DHCP relay destination for {}".format(dhcp_relay_destination_ip, vlan_name))

#
# 'bgp' group ('config bgp ...')
#

@config.group(cls=AbbreviationGroup)
def bgp():
    """BGP-related configuration tasks"""
    pass

#
# 'shutdown' subgroup ('config bgp shutdown ...')
#

@bgp.group(cls=AbbreviationGroup)
def shutdown():
    """Shut down BGP session(s)"""
    pass

@config.group(cls=AbbreviationGroup)
def kdump():
    """ Configure kdump """
    if os.geteuid() != 0:
        exit("Root privileges are required for this operation")

@kdump.command()
def disable():
    """Disable kdump operation"""
    config_db = ConfigDBConnector()
    if config_db is not None:
        config_db.connect()
        config_db.mod_entry("KDUMP", "config", {"enabled": "false"})
        run_command("sonic-kdump-config --disable")

@kdump.command()
def enable():
    """Enable kdump operation"""
    config_db = ConfigDBConnector()
    if config_db is not None:
        config_db.connect()
        config_db.mod_entry("KDUMP", "config", {"enabled": "true"})
        run_command("sonic-kdump-config --enable")

@kdump.command()
@click.argument('kdump_memory', metavar='<kdump_memory>', required=True)
def memory(kdump_memory):
    """Set memory allocated for kdump capture kernel"""
    config_db = ConfigDBConnector()
    if config_db is not None:
        config_db.connect()
        config_db.mod_entry("KDUMP", "config", {"memory": kdump_memory})
        run_command("sonic-kdump-config --memory %s" % kdump_memory)

@kdump.command('num-dumps')
@click.argument('kdump_num_dumps', metavar='<kdump_num_dumps>', required=True, type=int)
def num_dumps(kdump_num_dumps):
    """Set max number of dump files for kdump"""
    config_db = ConfigDBConnector()
    if config_db is not None:
        config_db.connect()
        config_db.mod_entry("KDUMP", "config", {"num_dumps": kdump_num_dumps})
        run_command("sonic-kdump-config --num_dumps %d" % kdump_num_dumps)

# 'all' subcommand
@shutdown.command()
@click.option('-v', '--verbose', is_flag=True, help="Enable verbose output")
def all(verbose):
    """Shut down all BGP sessions
       In the case of Multi-Asic platform, we shut only the EBGP sessions with external neighbors.
    """
    log_info("'bgp shutdown all' executing...")
    namespaces = [DEFAULT_NAMESPACE]
    ignore_local_hosts = False

    if sonic_device_util.is_multi_npu():
        ns_list = sonic_device_util.get_all_namespaces()
        namespaces = ns_list['front_ns']
        ignore_local_hosts = True

    # Connect to CONFIG_DB in linux host (in case of single ASIC) or CONFIG_DB in all the
    # namespaces (in case of multi ASIC) and do the sepcified "action" on the BGP neighbor(s)
    for namespace in namespaces:
        config_db = ConfigDBConnector(use_unix_socket_path=True, namespace=namespace)
        config_db.connect()
        bgp_neighbor_ip_list = _get_all_neighbor_ipaddresses(config_db, ignore_local_hosts)
        for ipaddress in bgp_neighbor_ip_list:
            _change_bgp_session_status_by_addr(config_db, ipaddress, 'down', verbose)

# 'neighbor' subcommand
@shutdown.command()
@click.argument('ipaddr_or_hostname', metavar='<ipaddr_or_hostname>', required=True)
@click.option('-v', '--verbose', is_flag=True, help="Enable verbose output")
def neighbor(ipaddr_or_hostname, verbose):
    """Shut down BGP session by neighbor IP address or hostname.
       User can specify either internal or external BGP neighbor to shutdown
    """
    log_info("'bgp shutdown neighbor {}' executing...".format(ipaddr_or_hostname))
    namespaces = [DEFAULT_NAMESPACE]
    found_neighbor = False

    if sonic_device_util.is_multi_npu():
        ns_list = sonic_device_util.get_all_namespaces()
        namespaces = ns_list['front_ns'] + ns_list['back_ns']

    # Connect to CONFIG_DB in linux host (in case of single ASIC) or CONFIG_DB in all the
    # namespaces (in case of multi ASIC) and do the sepcified "action" on the BGP neighbor(s)
    for namespace in namespaces:
        config_db = ConfigDBConnector(use_unix_socket_path=True, namespace=namespace)
        config_db.connect()
        if _change_bgp_session_status(config_db, ipaddr_or_hostname, 'down', verbose):
            found_neighbor = True

    if not found_neighbor:
        click.get_current_context().fail("Could not locate neighbor '{}'".format(ipaddr_or_hostname))

@bgp.group(cls=AbbreviationGroup)
def startup():
    """Start up BGP session(s)"""
    pass

# 'all' subcommand
@startup.command()
@click.option('-v', '--verbose', is_flag=True, help="Enable verbose output")
def all(verbose):
    """Start up all BGP sessions
       In the case of Multi-Asic platform, we startup only the EBGP sessions with external neighbors.
    """
    log_info("'bgp startup all' executing...")
    namespaces = [DEFAULT_NAMESPACE]
    ignore_local_hosts = False

    if sonic_device_util.is_multi_npu():
        ns_list = sonic_device_util.get_all_namespaces()
        namespaces = ns_list['front_ns']
        ignore_local_hosts = True

    # Connect to CONFIG_DB in linux host (in case of single ASIC) or CONFIG_DB in all the
    # namespaces (in case of multi ASIC) and do the sepcified "action" on the BGP neighbor(s)
    for namespace in namespaces:
        config_db = ConfigDBConnector(use_unix_socket_path=True, namespace=namespace)
        config_db.connect()
        bgp_neighbor_ip_list = _get_all_neighbor_ipaddresses(config_db, ignore_local_hosts)
        for ipaddress in bgp_neighbor_ip_list:
            _change_bgp_session_status_by_addr(config_db, ipaddress, 'up', verbose)

# 'neighbor' subcommand
@startup.command()
@click.argument('ipaddr_or_hostname', metavar='<ipaddr_or_hostname>', required=True)
@click.option('-v', '--verbose', is_flag=True, help="Enable verbose output")
def neighbor(ipaddr_or_hostname, verbose):
    log_info("'bgp startup neighbor {}' executing...".format(ipaddr_or_hostname))
    """Start up BGP session by neighbor IP address or hostname.
       User can specify either internal or external BGP neighbor to startup
    """
    namespaces = [DEFAULT_NAMESPACE]
    found_neighbor = False

    if sonic_device_util.is_multi_npu():
        ns_list = sonic_device_util.get_all_namespaces()
        namespaces = ns_list['front_ns'] + ns_list['back_ns']

    # Connect to CONFIG_DB in linux host (in case of single ASIC) or CONFIG_DB in all the
    # namespaces (in case of multi ASIC) and do the sepcified "action" on the BGP neighbor(s)
    for namespace in namespaces:
        config_db = ConfigDBConnector(use_unix_socket_path=True, namespace=namespace)
        config_db.connect()
        if _change_bgp_session_status(config_db, ipaddr_or_hostname, 'up', verbose):
            found_neighbor = True

    if not found_neighbor:
        click.get_current_context().fail("Could not locate neighbor '{}'".format(ipaddr_or_hostname))

#
# 'remove' subgroup ('config bgp remove ...')
#

@bgp.group(cls=AbbreviationGroup)
def remove():
    "Remove BGP neighbor configuration from the device"
    pass

@remove.command('neighbor')
@click.argument('neighbor_ip_or_hostname', metavar='<neighbor_ip_or_hostname>', required=True)
def remove_neighbor(neighbor_ip_or_hostname):
    """Deletes BGP neighbor configuration of given hostname or ip from devices
       User can specify either internal or external BGP neighbor to remove
    """
    namespaces = [DEFAULT_NAMESPACE]
    removed_neighbor = False

    if sonic_device_util.is_multi_npu():
        ns_list = sonic_device_util.get_all_namespaces()
        namespaces = ns_list['front_ns'] + ns_list['back_ns']

    # Connect to CONFIG_DB in linux host (in case of single ASIC) or CONFIG_DB in all the
    # namespaces (in case of multi ASIC) and do the sepcified "action" on the BGP neighbor(s)
    for namespace in namespaces:
        config_db = ConfigDBConnector(use_unix_socket_path=True, namespace=namespace)
        config_db.connect()
        if _remove_bgp_neighbor_config(config_db, neighbor_ip_or_hostname):
            removed_neighbor = True

    if not removed_neighbor:
        click.get_current_context().fail("Could not locate neighbor '{}'".format(neighbor_ip_or_hostname))

#
# 'interface' group ('config interface ...')
#

@config.group(cls=AbbreviationGroup)
@click.pass_context
def interface(ctx):
    """Interface-related configuration tasks"""
    config_db = ConfigDBConnector()
    config_db.connect()
    ctx.obj = {}
    ctx.obj['config_db'] = config_db

#
# 'startup' subcommand
#

@interface.command()
@click.argument('interface_name', metavar='<interface_name>', required=True)
@click.pass_context
def startup(ctx, interface_name):
    """Start up interface"""

    config_db = ctx.obj['config_db']
    if get_interface_naming_mode() == "alias":
        interface_name = interface_alias_to_name(interface_name)
        if interface_name is None:
            ctx.fail("'interface_name' is None!")

    intf_fs = parse_interface_in_filter(interface_name)
    if len(intf_fs) == 1 and interface_name_is_valid(interface_name) is False:
         ctx.fail("Interface name is invalid. Please enter a valid interface name!!")

    log_info("'interface startup {}' executing...".format(interface_name))
    port_dict = config_db.get_table('PORT')
    for port_name in port_dict.keys():
        if port_name in intf_fs:
            config_db.mod_entry("PORT", port_name, {"admin_status": "up"})

    portchannel_list = config_db.get_table("PORTCHANNEL")
    for po_name in portchannel_list.keys():
        if po_name in intf_fs:
            config_db.mod_entry("PORTCHANNEL", po_name, {"admin_status": "up"})

    subport_list = config_db.get_table("VLAN_SUB_INTERFACE")
    for sp_name in subport_list.keys():
        if sp_name in intf_fs:
            config_db.mod_entry("VLAN_SUB_INTERFACE", sp_name, {"admin_status": "up"})

#
# 'shutdown' subcommand
#

@interface.command()
@click.argument('interface_name', metavar='<interface_name>', required=True)
@click.pass_context
def shutdown(ctx, interface_name):
    """Shut down interface"""
    log_info("'interface shutdown {}' executing...".format(interface_name))
    config_db = ctx.obj['config_db']
    if get_interface_naming_mode() == "alias":
        interface_name = interface_alias_to_name(interface_name)
        if interface_name is None:
            ctx.fail("'interface_name' is None!")

    intf_fs = parse_interface_in_filter(interface_name)
    if len(intf_fs) == 1 and interface_name_is_valid(interface_name) is False:
        ctx.fail("Interface name is invalid. Please enter a valid interface name!!")

    port_dict = config_db.get_table('PORT')
    for port_name in port_dict.keys():
        if port_name in intf_fs:
            config_db.mod_entry("PORT", port_name, {"admin_status": "down"})

    portchannel_list = config_db.get_table("PORTCHANNEL")
    for po_name in portchannel_list.keys():
        if po_name in intf_fs:
            config_db.mod_entry("PORTCHANNEL", po_name, {"admin_status": "down"})

    subport_list = config_db.get_table("VLAN_SUB_INTERFACE")
    for sp_name in subport_list.keys():
        if sp_name in intf_fs:
            config_db.mod_entry("VLAN_SUB_INTERFACE", sp_name, {"admin_status": "down"})

#
# 'speed' subcommand
#

@interface.command()
@click.pass_context
@click.argument('interface_name', metavar='<interface_name>', required=True)
@click.argument('interface_speed', metavar='<interface_speed>', required=True)
@click.option('-v', '--verbose', is_flag=True, help="Enable verbose output")
def speed(ctx, interface_name, interface_speed, verbose):
    """Set interface speed"""
    if get_interface_naming_mode() == "alias":
        interface_name = interface_alias_to_name(interface_name)
        if interface_name is None:
            ctx.fail("'interface_name' is None!")

    log_info("'interface speed {} {}' executing...".format(interface_name, interface_speed))

    command = "portconfig -p {} -s {}".format(interface_name, interface_speed)
    if verbose:
        command += " -vv"
    run_command(command, display_cmd=verbose)

#
# 'breakout' subcommand
#

@interface.command()
@click.argument('interface_name', metavar='<interface_name>', required=True)
@click.argument('mode', required=True, type=click.STRING, autocompletion=_get_option)
@click.option('-f', '--force-remove-dependencies', is_flag=True,  help='Clear all depenedecies internally first.')
@click.option('-l', '--load-predefined-config', is_flag=True,  help='load predefied user configuration (alias, lanes, speed etc) first.')
@click.option('-y', '--yes', is_flag=True, callback=_abort_if_false, expose_value=False, prompt='Do you want to Breakout the port, continue?')
@click.option('-v', '--verbose', is_flag=True, help="Enable verbose output")
@click.pass_context
def breakout(ctx, interface_name, mode, verbose, force_remove_dependencies, load_predefined_config):
    """ Set interface breakout mode """
    if not os.path.isfile(breakout_cfg_file) or not breakout_cfg_file.endswith('.json'):
        click.secho("[ERROR] Breakout feature is not available without platform.json file", fg='red')
        raise click.Abort()

    # Connect to config db and get the context
    config_db = ConfigDBConnector()
    config_db.connect()
    ctx.obj['config_db'] = config_db

    target_brkout_mode = mode

    # Check if interface is parent port.
    cur_brkout_dict = config_db.get_table('BREAKOUT_CFG')

    if interface_name not in cur_brkout_dict.keys():
        click.secho("[ERROR] {} is not a Parent port. So, Breakout Mode is not available on this port".format(interface_name), fg='red')
        return click.Abort()

    # Get current breakout mode
    cur_brkout_mode = cur_brkout_dict[interface_name]["brkout_mode"]

    # Validate Interface and Breakout mode
    if not _validate_interface_mode(ctx, breakout_cfg_file, interface_name, mode, cur_brkout_mode):
        raise click.Abort()

    """ Interface Deletion Logic """
    # Get list of interfaces to be deleted
    del_ports = get_child_ports(interface_name, cur_brkout_mode, breakout_cfg_file)
    del_intf_dict = {intf: del_ports[intf]["speed"] for intf in del_ports}

    if del_intf_dict:
        """ shut down all the interface before deletion """
        ret = shutdown_interfaces(ctx, del_intf_dict)
        if not ret:
            raise click.Abort()
        click.echo("\nPorts to be deleted : \n {}".format(json.dumps(del_intf_dict, indent=4)))

    else:
        click.secho("[ERROR] del_intf_dict is None! No interfaces are there to be deleted", fg='red')
        raise click.Abort()

    """ Interface Addition Logic """
    # Get list of interfaces to be added
    add_ports = get_child_ports(interface_name, target_brkout_mode, breakout_cfg_file)
    add_intf_dict = {intf: add_ports[intf]["speed"] for intf in add_ports}

    if add_intf_dict:
        click.echo("Ports to be added : \n {}".format(json.dumps(add_intf_dict, indent=4)))
    else:
        click.secho("[ERROR] port_dict is None!", fg='red')
        raise click.Abort()

    """ Special Case: Dont delete those ports  where the current mode and speed of the parent port
                      remains unchanged to limit the traffic impact """

    click.secho("\nAfter running Logic to limit the impact", fg="cyan", underline=True)
    matched_item = [intf for intf, speed in del_intf_dict.items() if intf in add_intf_dict.keys() and speed == add_intf_dict[intf]]

    # Remove the interface which remains unchanged from both del_intf_dict and add_intf_dict
    map(del_intf_dict.pop, matched_item)
    map(add_intf_dict.pop, matched_item)

    click.secho("\nFinal list of ports to be deleted : \n {} \nFinal list of ports to be added :  \n {}".format(json.dumps(del_intf_dict, indent=4), json.dumps(add_intf_dict, indent=4), fg='green', blink=True))
    if len(add_intf_dict.keys()) == 0:
        click.secho("[ERROR] add_intf_dict is None! No interfaces are there to be added", fg='red')
        raise click.Abort()

    port_dict = {}
    for intf in add_intf_dict:
        if intf in add_ports.keys():
            port_dict[intf] = add_ports[intf]

    # writing JSON object
    with open('new_port_config.json', 'w') as f:
        json.dump(port_dict, f, indent=4)

    # Start Interation with Dy Port BreakOut Config Mgmt
    try:
        """ Load config for the commands which are capable of change in config DB """
        cm = load_ConfigMgmt(verbose)

        """ Delete all ports if forced else print dependencies using ConfigMgmt API """
        final_delPorts = [intf for intf in del_intf_dict.keys()]
        """ Warn user if tables without yang models exist and have final_delPorts """
        breakout_warnUser_extraTables(cm, final_delPorts, confirm=True)

        # Create a dictionary containing all the added ports with its capabilities like alias, lanes, speed etc.
        portJson = dict(); portJson['PORT'] = port_dict

        # breakout_Ports will abort operation on failure, So no need to check return
        breakout_Ports(cm, delPorts=final_delPorts, portJson=portJson, force=force_remove_dependencies, \
            loadDefConfig=load_predefined_config, verbose=verbose)

        # Set Current Breakout mode in config DB
        brkout_cfg_keys = config_db.get_keys('BREAKOUT_CFG')
        if interface_name.decode("utf-8") not in  brkout_cfg_keys:
            click.secho("[ERROR] {} is not present in 'BREAKOUT_CFG' Table!".\
                format(interface_name), fg='red')
            raise click.Abort()
        config_db.set_entry("BREAKOUT_CFG", interface_name,\
            {'brkout_mode': target_brkout_mode})
        click.secho("Breakout process got successfully completed.".\
            format(interface_name),  fg="cyan", underline=True)
        click.echo("Please note loaded setting will be lost after system reboot. To preserve setting, run `config save`.")

    except Exception as e:
        click.secho("Failed to break out Port. Error: {}".format(str(e)), \
            fg='magenta')
        sys.exit(0)

def _get_all_mgmtinterface_keys():
    """Returns list of strings containing mgmt interface keys
    """
    config_db = ConfigDBConnector()
    config_db.connect()
    return config_db.get_table('MGMT_INTERFACE').keys()

def mgmt_ip_restart_services():
    """Restart the required services when mgmt inteface IP address is changed"""
    """
    Whenever the eth0 IP address is changed, restart the "interfaces-config"
    service which regenerates the /etc/network/interfaces file and restarts
    the networking service to make the new/null IP address effective for eth0.
    "ntp-config" service should also be restarted based on the new
    eth0 IP address since the ntp.conf (generated from ntp.conf.j2) is
    made to listen on that particular eth0 IP address or reset it back.
    """
    cmd="systemctl restart interfaces-config"
    os.system (cmd)
    cmd="systemctl restart ntp-config"
    os.system (cmd)

#
# 'mtu' subcommand
#

@interface.command()
@click.pass_context
@click.argument('interface_name', metavar='<interface_name>', required=True)
@click.argument('interface_mtu', metavar='<interface_mtu>', required=True)
@click.option('-v', '--verbose', is_flag=True, help="Enable verbose output")
def mtu(ctx, interface_name, interface_mtu, verbose):
    """Set interface mtu"""
    if get_interface_naming_mode() == "alias":
        interface_name = interface_alias_to_name(interface_name)
        if interface_name is None:
            ctx.fail("'interface_name' is None!")

    command = "portconfig -p {} -m {}".format(interface_name, interface_mtu)
    if verbose:
        command += " -vv"
    run_command(command, display_cmd=verbose)

@interface.command()
@click.pass_context
@click.argument('interface_name', metavar='<interface_name>', required=True)
@click.argument('interface_fec', metavar='<interface_fec>', required=True)
@click.option('-v', '--verbose', is_flag=True, help="Enable verbose output")
def fec(ctx, interface_name, interface_fec, verbose):
    """Set interface fec"""
    if interface_fec not in ["rs", "fc", "none"]:
        ctx.fail("'fec not in ['rs', 'fc', 'none']!")
    if get_interface_naming_mode() == "alias":
        interface_name = interface_alias_to_name(interface_name)
        if interface_name is None:
            ctx.fail("'interface_name' is None!")

    command = "portconfig -p {} -f {}".format(interface_name, interface_fec)
    if verbose:
        command += " -vv"
    run_command(command, display_cmd=verbose)

#
# 'ip' subgroup ('config interface ip ...')
#

@interface.group(cls=AbbreviationGroup)
@click.pass_context
def ip(ctx):
    """Add or remove IP address"""
    pass

#
# 'add' subcommand
#

# get all ipv4 prefixes configured on the interface
@click.pass_context
def getIntfIPv4Addresses(ctx, db, tblName, ifName):

    keys = db.get_table(tblName).keys()

    intfIpMap = dict()
    for key in keys :
        if not isinstance(key, tuple) or len(key) < 2:
            continue

        if key[0] != ifName:
            continue

        try:
            ipv4_address = ipaddress.IPv4Address(key[1].split("/")[0])
            ipInfo = db.get_entry(tblName, key)
            intfIpMap[key[1]] = ipInfo
        except ipaddress.AddressValueError:
            continue

    return intfIpMap

@ip.command()
@click.argument('interface_name', metavar='<interface_name>', required=True)
@click.argument("ip_addr", metavar="<ip_addr>", required=True)
@click.argument('gw', metavar='<default gateway IP address>', required=False)
@click.option('--secondary', help="Specify a secondary IPv4 address", is_flag=True)
@click.pass_context
def add(ctx, interface_name, ip_addr, gw, secondary):
    """Add an IP address towards the interface"""
    config_db = ctx.obj["config_db"]
    if get_interface_naming_mode() == "alias":
        interface_name = interface_alias_to_name(interface_name)
        if interface_name is None:
            ctx.fail("'interface_name' is None!")

    try:
        ip_network = ipaddress.ip_network(unicode(ip_addr), strict=False)

        if interface_name == 'eth0':

            # Configuring more than 1 IPv4 or more than 1 IPv6 address fails.
            # Allow only one IPv4 and only one IPv6 address to be configured for IPv6.
            # If a row already exist, overwrite it (by doing delete and add).
            mgmtintf_key_list = _get_all_mgmtinterface_keys()

            for key in mgmtintf_key_list:
                # For loop runs for max 2 rows, once for IPv4 and once for IPv6.
                # No need to capture the exception since the ip_addr is already validated earlier
                ip_input = ipaddress.ip_interface(ip_addr)
                current_ip = ipaddress.ip_interface(key[1])
                if (ip_input.version == current_ip.version):
                    # If user has configured IPv4/v6 address and the already available row is also IPv4/v6, delete it here.
                    config_db.set_entry("MGMT_INTERFACE", ("eth0", key[1]), None)

            # Set the new row with new value
            if not gw:
                config_db.set_entry("MGMT_INTERFACE", (interface_name, ip_addr), {"NULL": "NULL"})
            else:
                config_db.set_entry("MGMT_INTERFACE", (interface_name, ip_addr), {"gwaddr": gw})
            mgmt_ip_restart_services()

            return

        table_name = get_interface_table_name(interface_name)
        if table_name == "":
            ctx.fail("'interface_name' is not valid. Valid names [Ethernet/PortChannel/Vlan/Loopback]")
        if not interface_name.startswith("Loopback") and ip_network.prefixlen == ip_network.max_prefixlen:
            ctx.fail("Bad mask /{} for IP address {}".format(ip_network.max_prefixlen, ip_addr))

        if not ip_network.is_link_local and is_ipaddress_overlapped(interface_name, ip_addr):
            ctx.fail("IP address {} overlaps with existing subnet".format(ip_addr))
        interface_entry = config_db.get_entry(table_name, interface_name)
        if len(interface_entry) == 0:
            if table_name == "VLAN_SUB_INTERFACE":
                config_db.set_entry(table_name, interface_name, {"admin_status": "up"})
            else:
                config_db.set_entry(table_name, interface_name, {"NULL": "NULL"})

        # secondary address logic for ipv4
        if ip_network.version == 4:
            ipMap = getIntfIPv4Addresses(config_db, table_name, interface_name)

            if secondary and len(ipMap) == 0:
                ctx.fail("Primary IPv4 address must be added first")
            if (not secondary) and len(ipMap) > 0:
                ctx.fail("Primary address already exists")

            if secondary:
                config_db.set_entry(table_name, (interface_name, ip_addr), {"NULL": "NULL", "secondary": "true"})
            else:
                config_db.set_entry(table_name, (interface_name, ip_addr), {"NULL": "NULL"})
        else:
            config_db.set_entry(table_name, (interface_name, ip_addr), {"NULL": "NULL"})

    except ValueError:
        ctx.fail("'ip_addr' is not valid.")

#
# 'del' subcommand
#

@ip.command()
@click.argument('interface_name', metavar='<interface_name>', required=True)
@click.argument("ip_addr", metavar="<ip_addr>", required=True)
@click.option('--secondary', help="Specify a secondary IPv4 address", is_flag=True)
@click.pass_context
def remove(ctx, interface_name, ip_addr, secondary):
    """Remove an IP address from the interface"""
    config_db = ctx.obj["config_db"]
    if get_interface_naming_mode() == "alias":
        interface_name = interface_alias_to_name(interface_name)
        if interface_name is None:
            ctx.fail("'interface_name' is None!")

    try:
        ip_network = ipaddress.ip_network(unicode(ip_addr), strict=False)

        if interface_name == 'eth0':
            config_db.set_entry("MGMT_INTERFACE", (interface_name, ip_addr), None)
            mgmt_ip_restart_services()
            return

        table_name = get_interface_table_name(interface_name)
        if table_name == "":
            ctx.fail("'interface_name' is not valid. Valid names [Ethernet/PortChannel/Vlan/Loopback]")

        # secondary address logic for ipv4
        ipMap = getIntfIPv4Addresses(config_db, table_name, interface_name)

        if ip_network.version == 4:
            v = ipMap.get(ip_addr)
            if v is not None:
                if secondary:
                    if v.get("secondary") != "true":
                        ctx.fail("No such address (" + ip_addr + ") configured on this interface as secondary address")
                else:
                    if v.get("secondary") == "true":
                        ctx.fail("No such address (" + ip_addr + ") configured on this interface as primary address")
                    if len(ipMap) > 1:
                        ctx.fail("Primary IPv4 address delete not permitted when secondary IPv4 address exists")
            else:
                ctx.fail("No such address (" + ip_addr + ") configured on this interface")

        config_db.set_entry(table_name, (interface_name, ip_addr), None)

        interface_dependent = interface_ipaddr_dependent_on_interface(config_db, interface_name)
        if len(interface_dependent) == 0 and is_interface_bind_to_vrf(config_db, interface_name) is False:
            if is_sag_configured_on_interface(config_db, interface_name) is False:
                config_db.set_entry(table_name, interface_name, None)

        command = "ip neigh flush dev {} {}".format(interface_name, ip_addr)
        run_command(command)
    except ValueError:
        ctx.fail("'ip_addr' is not valid.")

#
# 'transceiver' subgroup ('config interface transceiver ...')
#

@interface.group(cls=AbbreviationGroup)
@click.pass_context
def transceiver(ctx):
    """SFP transceiver configuration"""
    pass

#
# 'lpmode' subcommand ('config interface transceiver lpmode ...')
#

@transceiver.command()
@click.argument('interface_name', metavar='<interface_name>', required=True)
@click.argument('state', metavar='(enable|disable)', type=click.Choice(['enable', 'disable']))
@click.pass_context
def lpmode(ctx, interface_name, state):
    """Enable/disable low-power mode for SFP transceiver module"""
    if get_interface_naming_mode() == "alias":
        interface_name = interface_alias_to_name(interface_name)
        if interface_name is None:
            ctx.fail("'interface_name' is None!")

    if interface_name_is_valid(interface_name) is False:
        ctx.fail("Interface name is invalid. Please enter a valid interface name!!")

    cmd = "sudo sfputil lpmode {} {}".format("on" if state == "enable" else "off", interface_name)
    run_command(cmd)

#
# 'reset' subcommand ('config interface reset ...')
#

@transceiver.command()
@click.argument('interface_name', metavar='<interface_name>', required=True)
@click.pass_context
def reset(ctx, interface_name):
    """Reset SFP transceiver module"""
    if get_interface_naming_mode() == "alias":
        interface_name = interface_alias_to_name(interface_name)
        if interface_name is None:
            ctx.fail("'interface_name' is None!")

    if interface_name_is_valid(interface_name) is False:
        ctx.fail("Interface name is invalid. Please enter a valid interface name!!")

    cmd = "sudo sfputil reset {}".format(interface_name)
    run_command(cmd)

#
# 'vrf' subgroup ('config interface vrf ...')
#


@interface.group(cls=AbbreviationGroup)
@click.pass_context
def vrf(ctx):
    """Bind or unbind VRF"""
    pass

#
# 'bind' subcommand
#
@vrf.command()
@click.argument('interface_name', metavar='<interface_name>', required=True)
@click.argument('vrf_name', metavar='<vrf_name>', required=True)
@click.pass_context
def bind(ctx, interface_name, vrf_name):
    """Bind the interface to VRF"""
    config_db = ctx.obj["config_db"]
    if get_interface_naming_mode() == "alias":
        interface_name = interface_alias_to_name(interface_name)
        if interface_name is None:
            ctx.fail("'interface_name' is None!")

    table_name = get_interface_table_name(interface_name)
    if table_name == "":
        ctx.fail("'interface_name' is not valid. Valid names [Ethernet/PortChannel/Vlan/Loopback]")
    if is_interface_bind_to_vrf(config_db, interface_name) is True and \
        config_db.get_entry(table_name, interface_name).get('vrf_name') == vrf_name:
        return
    # Clean ip addresses if interface configured
    interface_dependent = interface_ipaddr_dependent_on_interface(config_db, interface_name)
    for interface_del in interface_dependent:
        config_db.set_entry(table_name, interface_del, None)
    config_db.set_entry(table_name, interface_name, None)

    # Disable IPv6 on the interface to prevent creating IPv6 link-local address
    cmd = 'sysctl -w net.ipv6.conf.{}.disable_ipv6=1 -q'.format(interface_name)
    run_command(cmd, display_cmd=False)

    # When config_db del entry and then add entry with same key, the DEL will lost.
    state_db = SonicV2Connector(host='127.0.0.1')
    state_db.connect(state_db.STATE_DB, False)
    _hash = '{}{}'.format('INTERFACE_TABLE|', interface_name)
    while state_db.get_all(state_db.STATE_DB, _hash) != None:
        time.sleep(0.01)
    state_db.close(state_db.STATE_DB)
    config_db.set_entry(table_name, interface_name, {"vrf_name": vrf_name})
    if table_name == "VLAN_INTERFACE":
        if is_sag_configured_on_interface(config_db, interface_name) is True:
            sag_ipv4_config_entry = config_db.get_entry('SAG',(interface_name,'IPv4'))
            sag_ipv6_config_entry = config_db.get_entry('SAG',(interface_name,'IPv6'))
            if sag_ipv4_config_entry != None:
                ip_address = sag_ipv4_config_entry.get('gwip')
                for ip_addr in ip_address:
                    delete_sag_interface(ctx, config_db,'IPv4', interface_name, ip_addr)
            if sag_ipv6_config_entry != None:
                ip_address = sag_ipv6_config_entry.get('gwip')
                for ip_addr in ip_address:
                    delete_sag_interface(ctx, config_db,'IPv6', interface_name, ip_addr)
            time.sleep(0.01)
            if sag_ipv4_config_entry != None:
                ip_address = sag_ipv4_config_entry.get('gwip')
                for ip_addr in ip_address:
                    set_sag_interface(ctx, config_db,'IPv4', interface_name, ip_addr)
            if sag_ipv6_config_entry != None:
                ip_address = sag_ipv6_config_entry.get('gwip')
                for ip_addr in ip_address:
                    set_sag_interface(ctx, config_db,'IPv6', interface_name, ip_addr)

    # Enable IPv6 on the interface to sync IPv6 link-local address
    cmd = 'sysctl -w net.ipv6.conf.{}.disable_ipv6=0 -q'.format(interface_name)
    run_command(cmd, display_cmd=False)
#
# 'unbind' subcommand
#

@vrf.command()
@click.argument('interface_name', metavar='<interface_name>', required=True)
@click.pass_context
def unbind(ctx, interface_name):
    """Unbind the interface to VRF"""
    config_db = ctx.obj["config_db"]
    if get_interface_naming_mode() == "alias":
        interface_name = interface_alias_to_name(interface_name)
        if interface_name is None:
            ctx.fail("interface is None!")

    table_name = get_interface_table_name(interface_name)
    if table_name == "":
        ctx.fail("'interface_name' is not valid. Valid names [Ethernet/PortChannel/Vlan/Loopback]")
    if is_interface_bind_to_vrf(config_db, interface_name) is False:
        return
    interface_dependent = interface_ipaddr_dependent_on_interface(config_db, interface_name)
    for interface_del in interface_dependent:
        config_db.set_entry(table_name, interface_del, None)
    config_db.set_entry(table_name, interface_name, None)

#
# 'sag' subgroup ('config interface sag ...')
#

@interface.group()
@click.pass_context
def sag(ctx):
    config_db = ConfigDBConnector()
    config_db.connect()
    state_db = SonicV2Connector(host='127.0.0.1')
    state_db.connect(state_db.STATE_DB, False)
    ctx.obj = {'config_db': config_db,'state_db':state_db}
    pass

@sag.group()
@click.pass_context
def ip(ctx):
    pass

@ip.command('add')
@click.argument('vlan_interface', metavar='<vlan_interface>', required=True)
@click.argument('ip_addr', metavar='<ip_addr>', required=True)
@click.pass_context
def add(ctx, vlan_interface, ip_addr) :
    ver = ipaddress.ip_interface(ip_addr).ip.version
    config_db = ctx.obj['config_db']
    state_db = ctx.obj['state_db']
    if state_db.keys(state_db.STATE_DB,'VLAN_TABLE|{}'.format(vlan_interface)) != None :
        if ver == 4 :
            #ipv4
            set_sag_interface(ctx, config_db,'IPv4', vlan_interface, ip_addr)
        else :
            #ipv6
            set_sag_interface(ctx, config_db,'IPv6', vlan_interface, ip_addr)
        table_name = get_interface_table_name(vlan_interface)
        if not table_name == "":
            interface_entry = config_db.get_entry(table_name, vlan_interface)
            if len(interface_entry) == 0:
                config_db.set_entry(table_name, vlan_interface, {"NULL": "NULL"})
    else: ctx.fail("'{}' does not exists in VLAN table ".format(vlan_interface))


@ip.command('del')
@click.argument('vlan_interface', metavar='<vlan_interface>', required=True)
@click.argument('ip_addr', metavar='<ip_addr>', required=True)
@click.pass_context
def delete(ctx, vlan_interface, ip_addr) :
    ver = ipaddress.ip_interface(ip_addr).ip.version
    config_db = ctx.obj['config_db']
    state_db = ctx.obj['state_db']
    if state_db.keys(state_db.STATE_DB,'VLAN_TABLE|{}'.format(vlan_interface)) != None :
        if ver == 4 :
            #ipv4
            delete_sag_interface(ctx, config_db,'IPv4', vlan_interface, ip_addr)
        else :
            #ipv6
            delete_sag_interface(ctx, config_db,'IPv6', vlan_interface, ip_addr)
        if is_sag_configured_on_interface(config_db, vlan_interface) is False:
            table_name = get_interface_table_name(vlan_interface)
            if not table_name == "":
                interface_dependent = interface_ipaddr_dependent_on_interface(config_db, vlan_interface)
                if len(interface_dependent) == 0 and is_interface_bind_to_vrf(config_db, vlan_interface) is False:
                    config_db.set_entry(table_name, vlan_interface, None)
    else: ctx.fail("'{}' does not exists in VLAN table ".format(vlan_interface))


#
# 'vrf' group ('config vrf ...')
#

@config.group(cls=AbbreviationGroup, name='vrf')
@click.pass_context
def vrf(ctx):
    """VRF-related configuration tasks"""
    config_db = ConfigDBConnector()
    config_db.connect()
    ctx.obj = {}
    ctx.obj['config_db'] = config_db

@vrf.command('add')
@click.argument('vrf_name', metavar='<vrf_name>', required=True)
@click.pass_context
def add_vrf(ctx, vrf_name):
    """Add vrf"""
    config_db = ctx.obj['config_db']
    if not vrf_name.startswith("Vrf") and not (vrf_name == 'mgmt') and not (vrf_name == 'management'):
        ctx.fail("'vrf_name' is not start with Vrf, mgmt or management!")
    if len(vrf_name) > 15:
        ctx.fail("'vrf_name' is too long!")
    if (vrf_name == 'mgmt' or vrf_name == 'management'):
        vrf_add_management_vrf(config_db)
    else:
        config_db.set_entry('VRF', vrf_name, {"NULL": "NULL"})

@vrf.command('del')
@click.argument('vrf_name', metavar='<vrf_name>', required=True)
@click.pass_context
def del_vrf(ctx, vrf_name):
    """Del vrf"""
    config_db = ctx.obj['config_db']
    if not vrf_name.startswith("Vrf") and not (vrf_name == 'mgmt') and not (vrf_name == 'management'):
        ctx.fail("'vrf_name' is not start with Vrf, mgmt or management!")
    if len(vrf_name) > 15:
        ctx.fail("'vrf_name' is too long!")
    if (vrf_name == 'mgmt' or vrf_name == 'management'):
        vrf_delete_management_vrf(config_db)
    else:
        del_interface_bind_to_vrf(config_db, vrf_name)
        config_db.set_entry('VRF', vrf_name, None)


@vrf.command('add_vrf_vni_map')
@click.argument('vrfname', metavar='<vrf-name>', required=True, type=str)
@click.argument('vni', metavar='<vni>', required=True)
@click.pass_context
def add_vrf_vni_map(ctx, vrfname, vni):
    db = ctx.obj['config_db']
    found = 0
    if vrfname not in db.get_table('VRF').keys():
        ctx.fail("vrf {} doesnt exists".format(vrfname))
    if not vni.isdigit():
        ctx.fail("Invalid VNI {}. Only valid VNI is accepted".format(vni))

    if (int(vni) < 1) or (int(vni) > 16777215):
        ctx.fail("Invalid VNI {}. Valid range [1 to 16777215].".format(vni))

    vxlan_table = db.get_table('VXLAN_TUNNEL_MAP')
    vxlan_keys = vxlan_table.keys()
    if vxlan_keys is not None:
        for key in vxlan_keys:
            if (vxlan_table[key]['vni'] == vni):
                found = 1
                break

    if (found == 0):
        ctx.fail(" VLAN VNI not mapped. Please create VLAN VNI map entry first ")

    found = 0
    vrf_table = db.get_table('VRF')
    vrf_keys = vrf_table.keys()
    if vrf_keys is not None:
        for vrf_key in vrf_keys:
            if ('vni' in vrf_table[vrf_key] and vrf_table[vrf_key]['vni'] == vni):
                found = 1
                break

    if (found == 1):
        ctx.fail("VNI already mapped to vrf {}".format(vrf_key))

    db.mod_entry('VRF', vrfname, {"vni": vni})

@vrf.command('del_vrf_vni_map')
@click.argument('vrfname', metavar='<vrf-name>', required=True, type=str)
@click.pass_context
def del_vrf_vni_map(ctx, vrfname):
    db = ctx.obj['config_db']
    if vrfname not in db.get_table('VRF').keys():
        ctx.fail("vrf {} doesnt exists".format(vrfname))

    db.mod_entry('VRF', vrfname, {"vni": 0})

#
# 'route' group ('config route ...')
#

@config.group(cls=AbbreviationGroup)
@click.pass_context
def route(ctx):
    """route-related configuration tasks"""
    pass

@route.command('add',context_settings={"ignore_unknown_options":True})
@click.argument('command_str', metavar='prefix [vrf <vrf_name>] <A.B.C.D/M> nexthop <[vrf <vrf_name>] <A.B.C.D>>|<dev <dev_name>>', nargs=-1, type=click.Path())
@click.pass_context
def add_route(ctx, command_str):
    """Add route command"""
    if len(command_str) < 4 or len(command_str) > 9:
        ctx.fail("argument is not in pattern prefix [vrf <vrf_name>] <A.B.C.D/M> nexthop <[vrf <vrf_name>] <A.B.C.D>>|<dev <dev_name>>!")
    if "prefix" not in command_str:
        ctx.fail("argument is incomplete, prefix not found!")
    if "nexthop" not in command_str:
        ctx.fail("argument is incomplete, nexthop not found!")
    for i in range(0,len(command_str)):
        if "nexthop" == command_str[i]:
            prefix_str = command_str[:i]
            nexthop_str = command_str[i:]
    vrf_name = ""
    cmd = 'sudo vtysh -c "configure terminal" -c "ip route'
    if prefix_str:
        if len(prefix_str) == 2:
            prefix_mask = prefix_str[1]
            cmd += ' {}'.format(prefix_mask)
        elif len(prefix_str) == 4:
            vrf_name = prefix_str[2]
            prefix_mask = prefix_str[3]
            cmd += ' {}'.format(prefix_mask)
        else:
            ctx.fail("prefix is not in pattern!")
    if nexthop_str:
        if len(nexthop_str) == 2:
            ip = nexthop_str[1]
            if vrf_name == "":
                cmd += ' {}'.format(ip)
            else:
                cmd += ' {} vrf {}'.format(ip, vrf_name)
        elif len(nexthop_str) == 3:
            dev_name = nexthop_str[2]
            if vrf_name == "":
                cmd += ' {}'.format(dev_name)
            else:
                cmd += ' {} vrf {}'.format(dev_name, vrf_name)
        elif len(nexthop_str) == 4:
            vrf_name_dst = nexthop_str[2]
            ip = nexthop_str[3]
            if vrf_name == "":
                cmd += ' {} nexthop-vrf {}'.format(ip, vrf_name_dst)
            else:
                cmd += ' {} vrf {} nexthop-vrf {}'.format(ip, vrf_name, vrf_name_dst)
        else:
            ctx.fail("nexthop is not in pattern!")
    cmd += '"'
    run_command(cmd)

@route.command('del',context_settings={"ignore_unknown_options":True})
@click.argument('command_str', metavar='prefix [vrf <vrf_name>] <A.B.C.D/M> nexthop <[vrf <vrf_name>] <A.B.C.D>>|<dev <dev_name>>', nargs=-1, type=click.Path())
@click.pass_context
def del_route(ctx, command_str):
    """Del route command"""
    if len(command_str) < 4 or len(command_str) > 9:
        ctx.fail("argument is not in pattern prefix [vrf <vrf_name>] <A.B.C.D/M> nexthop <[vrf <vrf_name>] <A.B.C.D>>|<dev <dev_name>>!")
    if "prefix" not in command_str:
        ctx.fail("argument is incomplete, prefix not found!")
    if "nexthop" not in command_str:
        ctx.fail("argument is incomplete, nexthop not found!")
    for i in range(0,len(command_str)):
        if "nexthop" == command_str[i]:
            prefix_str = command_str[:i]
            nexthop_str = command_str[i:]
    vrf_name = ""
    cmd = 'sudo vtysh -c "configure terminal" -c "no ip route'
    if prefix_str:
        if len(prefix_str) == 2:
            prefix_mask = prefix_str[1]
            cmd += ' {}'.format(prefix_mask)
        elif len(prefix_str) == 4:
            vrf_name = prefix_str[2]
            prefix_mask = prefix_str[3]
            cmd += ' {}'.format(prefix_mask)
        else:
            ctx.fail("prefix is not in pattern!")
    if nexthop_str:
        if len(nexthop_str) == 2:
            ip = nexthop_str[1]
            if vrf_name == "":
                cmd += ' {}'.format(ip)
            else:
                cmd += ' {} vrf {}'.format(ip, vrf_name)
        elif len(nexthop_str) == 3:
            dev_name = nexthop_str[2]
            if vrf_name == "":
                cmd += ' {}'.format(dev_name)
            else:
                cmd += ' {} vrf {}'.format(dev_name, vrf_name)
        elif len(nexthop_str) == 4:
            vrf_name_dst = nexthop_str[2]
            ip = nexthop_str[3]
            if vrf_name == "":
                cmd += ' {} nexthop-vrf {}'.format(ip, vrf_name_dst)
            else:
                cmd += ' {} vrf {} nexthop-vrf {}'.format(ip, vrf_name, vrf_name_dst)
        else:
            ctx.fail("nexthop is not in pattern!")
    cmd += '"'
    run_command(cmd)

#
# 'acl' group ('config acl ...')
#

@config.group(cls=AbbreviationGroup)
def acl():
    """ACL-related configuration tasks"""
    pass

#
# 'add' subgroup ('config acl add ...')
#

@acl.group(cls=AbbreviationGroup)
def add():
    """
    Add ACL configuration.
    """
    pass


def get_acl_bound_ports():
    config_db = ConfigDBConnector()
    config_db.connect()

    ports = set()
    portchannel_members = set()

    portchannel_member_dict = config_db.get_table("PORTCHANNEL_MEMBER")
    for key in portchannel_member_dict:
        ports.add(key[0])
        portchannel_members.add(key[1])

    port_dict = config_db.get_table("PORT")
    for key in port_dict:
        if key not in portchannel_members:
            ports.add(key)

    return list(ports)

#
# 'table' subcommand ('config acl add table ...')
#

@add.command()
@click.argument("table_name", metavar="<table_name>")
@click.argument("table_type", metavar="<table_type>")
@click.option("-d", "--description")
@click.option("-p", "--ports")
@click.option("-s", "--stage", type=click.Choice(["ingress", "egress"]), default="ingress")
def table(table_name, table_type, description, ports, stage):
    """
    Add ACL table
    """
    config_db = ConfigDBConnector()
    config_db.connect()

    table_info = {"type": table_type}

    if description:
        table_info["policy_desc"] = description
    else:
        table_info["policy_desc"] = table_name

    if ports:
        table_info["ports@"] = ports
    else:
        table_info["ports@"] = ",".join(get_acl_bound_ports())

    table_info["stage"] = stage

    config_db.set_entry("ACL_TABLE", table_name, table_info)

#
# 'remove' subgroup ('config acl remove ...')
#

@acl.group(cls=AbbreviationGroup)
def remove():
    """
    Remove ACL configuration.
    """
    pass

#
# 'table' subcommand ('config acl remove table ...')
#

@remove.command()
@click.argument("table_name", metavar="<table_name>")
def table(table_name):
    """
    Remove ACL table
    """
    config_db = ConfigDBConnector()
    config_db.connect()
    config_db.set_entry("ACL_TABLE", table_name, None)


#
# 'acl update' group
#

@acl.group(cls=AbbreviationGroup)
def update():
    """ACL-related configuration tasks"""
    pass


#
# 'full' subcommand
#

@update.command()
@click.argument('file_name', required=True)
def full(file_name):
    """Full update of ACL rules configuration."""
    log_info("'acl update full {}' executing...".format(file_name))
    command = "acl-loader update full {}".format(file_name)
    run_command(command)


#
# 'incremental' subcommand
#

@update.command()
@click.argument('file_name', required=True)
def incremental(file_name):
    """Incremental update of ACL rule configuration."""
    log_info("'acl update incremental {}' executing...".format(file_name))
    command = "acl-loader update incremental {}".format(file_name)
    run_command(command)


#
# 'dropcounters' group ('config dropcounters ...')
#

@config.group(cls=AbbreviationGroup)
def dropcounters():
    """Drop counter related configuration tasks"""
    pass


#
# 'install' subcommand ('config dropcounters install')
#
@dropcounters.command()
@click.argument("counter_name", type=str, required=True)
@click.argument("counter_type", type=str, required=True)
@click.argument("reasons",      type=str, required=True)
@click.option("-a", "--alias", type=str, help="Alias for this counter")
@click.option("-g", "--group", type=str, help="Group for this counter")
@click.option("-d", "--desc",  type=str, help="Description for this counter")
@click.option('-v', '--verbose', is_flag=True, help="Enable verbose output")
def install(counter_name, alias, group, counter_type, desc, reasons, verbose):
    """Install a new drop counter"""
    command = "dropconfig -c install -n '{}' -t '{}' -r '{}'".format(counter_name, counter_type, reasons)
    if alias:
        command += " -a '{}'".format(alias)
    if group:
        command += " -g '{}'".format(group)
    if desc:
        command += " -d '{}'".format(desc)

    run_command(command, display_cmd=verbose)


#
# 'delete' subcommand ('config dropcounters delete')
#
@dropcounters.command()
@click.argument("counter_name", type=str, required=True)
@click.option('-v', '--verbose', is_flag=True, help="Enable verbose output")
def delete(counter_name, verbose):
    """Delete an existing drop counter"""
    command = "dropconfig -c uninstall -n {}".format(counter_name)
    run_command(command, display_cmd=verbose)


#
# 'add_reasons' subcommand ('config dropcounters add_reasons')
#
@dropcounters.command('add-reasons')
@click.argument("counter_name", type=str, required=True)
@click.argument("reasons",      type=str, required=True)
@click.option('-v', '--verbose', is_flag=True, help="Enable verbose output")
def add_reasons(counter_name, reasons, verbose):
    """Add reasons to an existing drop counter"""
    command = "dropconfig -c add -n {} -r {}".format(counter_name, reasons)
    run_command(command, display_cmd=verbose)


#
# 'remove_reasons' subcommand ('config dropcounters remove_reasons')
#
@dropcounters.command('remove-reasons')
@click.argument("counter_name", type=str, required=True)
@click.argument("reasons",      type=str, required=True)
@click.option('-v', '--verbose', is_flag=True, help="Enable verbose output")
def remove_reasons(counter_name, reasons, verbose):
    """Remove reasons from an existing drop counter"""
    command = "dropconfig -c remove -n {} -r {}".format(counter_name, reasons)
    run_command(command, display_cmd=verbose)


#
# 'ecn' command ('config ecn ...')
#
@config.command()
@click.option('-profile', metavar='<profile_name>', type=str, required=True, help="Profile name")
@click.option('-rmax', metavar='<red threshold max>', type=int, help="Set red max threshold")
@click.option('-rmin', metavar='<red threshold min>', type=int, help="Set red min threshold")
@click.option('-ymax', metavar='<yellow threshold max>', type=int, help="Set yellow max threshold")
@click.option('-ymin', metavar='<yellow threshold min>', type=int, help="Set yellow min threshold")
@click.option('-gmax', metavar='<green threshold max>', type=int, help="Set green max threshold")
@click.option('-gmin', metavar='<green threshold min>', type=int, help="Set green min threshold")
@click.option('-v', '--verbose', is_flag=True, help="Enable verbose output")
def ecn(profile, rmax, rmin, ymax, ymin, gmax, gmin, verbose):
    """ECN-related configuration tasks"""
    log_info("'ecn -profile {}' executing...".format(profile))
    command = "ecnconfig -p %s" % profile
    if rmax is not None: command += " -rmax %d" % rmax
    if rmin is not None: command += " -rmin %d" % rmin
    if ymax is not None: command += " -ymax %d" % ymax
    if ymin is not None: command += " -ymin %d" % ymin
    if gmax is not None: command += " -gmax %d" % gmax
    if gmin is not None: command += " -gmin %d" % gmin
    if verbose: command += " -vv"
    run_command(command, display_cmd=verbose)


#
# 'pfc' group ('config interface pfc ...')
#

@interface.group(cls=AbbreviationGroup)
@click.pass_context
def pfc(ctx):
    """Set PFC configuration."""
    pass


#
# 'pfc asymmetric' ('config interface pfc asymmetric ...')
#

@pfc.command()
@click.argument('interface_name', metavar='<interface_name>', required=True)
@click.argument('status', type=click.Choice(['on', 'off']))
@click.pass_context
def asymmetric(ctx, interface_name, status):
    """Set asymmetric PFC configuration."""
    if get_interface_naming_mode() == "alias":
        interface_name = interface_alias_to_name(interface_name)
        if interface_name is None:
            ctx.fail("'interface_name' is None!")

    run_command("pfc config asymmetric {0} {1}".format(status, interface_name))

#
# 'pfc priority' command ('config interface pfc priority ...')
#

@pfc.command()
@click.argument('interface_name', metavar='<interface_name>', required=True)
@click.argument('priority', type=click.Choice([str(x) for x in range(8)]))
@click.argument('status', type=click.Choice(['on', 'off']))
@click.pass_context
def priority(ctx, interface_name, priority, status):
    """Set PFC priority configuration."""
    if get_interface_naming_mode() == "alias":
        interface_name = interface_alias_to_name(interface_name)
        if interface_name is None:
            ctx.fail("'interface_name' is None!")

    run_command("pfc config priority {0} {1} {2}".format(status, interface_name, priority))

#
# 'platform' group ('config platform ...')
#

@config.group(cls=AbbreviationGroup)
def platform():
    """Platform-related configuration tasks"""

if asic_type == 'mellanox':
    platform.add_command(mlnx.mlnx)

# 'firmware' subgroup ("config platform firmware ...")
@platform.group(cls=AbbreviationGroup)
def firmware():
    """Firmware configuration tasks"""
    pass

# 'install' subcommand ("config platform firmware install")
@firmware.command(
    context_settings=dict(
        ignore_unknown_options=True,
        allow_extra_args=True
    ),
    add_help_option=False
)
@click.argument('args', nargs=-1, type=click.UNPROCESSED)
def install(args):
    """Install platform firmware"""
    cmd = "fwutil install {}".format(" ".join(args))

    try:
        subprocess.check_call(cmd, shell=True)
    except subprocess.CalledProcessError as e:
        sys.exit(e.returncode)

# 'update' subcommand ("config platform firmware update")
@firmware.command(
    context_settings=dict(
        ignore_unknown_options=True,
        allow_extra_args=True
    ),
    add_help_option=False
)
@click.argument('args', nargs=-1, type=click.UNPROCESSED)
def update(args):
    """Update platform firmware"""
    cmd = "fwutil update {}".format(" ".join(args))

    try:
        subprocess.check_call(cmd, shell=True)
    except subprocess.CalledProcessError as e:
        sys.exit(e.returncode)

#
# 'watermark' group ("show watermark telemetry interval")
#

@config.group(cls=AbbreviationGroup)
def watermark():
    """Configure watermark """
    pass

@watermark.group(cls=AbbreviationGroup)
def telemetry():
    """Configure watermark telemetry"""
    pass

@telemetry.command()
@click.argument('interval', required=True)
def interval(interval):
    """Configure watermark telemetry interval"""
    command = 'watermarkcfg --config-interval ' + interval
    run_command(command)


#
# 'interface_naming_mode' subgroup ('config interface_naming_mode ...')
#

@config.group(cls=AbbreviationGroup, name='interface_naming_mode')
def interface_naming_mode():
    """Modify interface naming mode for interacting with SONiC CLI"""
    pass

@interface_naming_mode.command('default')
def naming_mode_default():
    """Set CLI interface naming mode to DEFAULT (SONiC port name)"""
    set_interface_naming_mode('default')

@interface_naming_mode.command('alias')
def naming_mode_alias():
    """Set CLI interface naming mode to ALIAS (Vendor port alias)"""
    set_interface_naming_mode('alias')

def is_loopback_name_valid(loopback_name):
    """Loopback name validation
    """

    if loopback_name[:CFG_LOOPBACK_PREFIX_LEN] != CFG_LOOPBACK_PREFIX :
        return False
    if (loopback_name[CFG_LOOPBACK_PREFIX_LEN:].isdigit() is False or
          int(loopback_name[CFG_LOOPBACK_PREFIX_LEN:]) > CFG_LOOPBACK_ID_MAX_VAL) :
        return False
    if len(loopback_name) > CFG_LOOPBACK_NAME_TOTAL_LEN_MAX:
        return False
    return True

#
# 'loopback' group ('config loopback ...')
#
@config.group()
@click.pass_context
@click.option('-s', '--redis-unix-socket-path', help='unix socket path for redis connection')
def loopback(ctx, redis_unix_socket_path):
    """Loopback-related configuration tasks"""
    kwargs = {}
    if redis_unix_socket_path:
        kwargs['unix_socket_path'] = redis_unix_socket_path
    config_db = ConfigDBConnector(**kwargs)
    config_db.connect(wait_for_init=False)
    ctx.obj = {'db': config_db}

@loopback.command('add')
@click.argument('loopback_name', metavar='<loopback_name>', required=True)
@click.pass_context
def add_loopback(ctx, loopback_name):
    config_db = ctx.obj['db']
    if is_loopback_name_valid(loopback_name) is False:
        ctx.fail("{} is invalid, name should have prefix '{}' and suffix '{}' "
                .format(loopback_name, CFG_LOOPBACK_PREFIX, CFG_LOOPBACK_NO))

    lo_intfs = [k for k,v in config_db.get_table('LOOPBACK_INTERFACE').iteritems() if type(k) != tuple]
    if loopback_name in lo_intfs:
        ctx.fail("{} already exists".format(loopback_name))

    config_db.set_entry('LOOPBACK_INTERFACE', loopback_name, {"NULL" : "NULL"})

@loopback.command('del')
@click.argument('loopback_name', metavar='<loopback_name>', required=True)
@click.pass_context
def del_loopback(ctx, loopback_name):
    config_db = ctx.obj['db']
    if is_loopback_name_valid(loopback_name) is False:
        ctx.fail("{} is invalid, name should have prefix '{}' and suffix '{}' "
                .format(loopback_name, CFG_LOOPBACK_PREFIX, CFG_LOOPBACK_NO))

    lo_config_db = config_db.get_table('LOOPBACK_INTERFACE')
    lo_intfs = [k for k,v in lo_config_db.iteritems() if type(k) != tuple]
    if loopback_name not in lo_intfs:
        ctx.fail("{} does not exists".format(loopback_name))

    ips = [ k[1] for k in lo_config_db if type(k) == tuple and k[0] == loopback_name ]
    for ip in ips:
        config_db.set_entry('LOOPBACK_INTERFACE', (loopback_name, ip), None)

    config_db.set_entry('LOOPBACK_INTERFACE', loopback_name, None)


@config.group(cls=AbbreviationGroup)
def ztp():
    """ Configure Zero Touch Provisioning """
    if os.path.isfile('/usr/bin/ztp') is False:
        exit("ZTP feature unavailable in this image version")

    if os.geteuid() != 0:
        exit("Root privileges are required for this operation")

@ztp.command()
@click.option('-y', '--yes', is_flag=True, callback=_abort_if_false,
                expose_value=False, prompt='ZTP will be restarted. You may lose switch data and connectivity, continue?')
@click.argument('run', required=False, type=click.Choice(["run"]))
def run(run):
    """Restart ZTP of the device."""
    command = "ztp run -y"
    run_command(command, display_cmd=True)

@ztp.command()
@click.option('-y', '--yes', is_flag=True, callback=_abort_if_false,
                expose_value=False, prompt='Active ZTP session will be stopped and disabled, continue?')
@click.argument('disable', required=False, type=click.Choice(["disable"]))
def disable(disable):
    """Administratively Disable ZTP."""
    command = "ztp disable -y"
    run_command(command, display_cmd=True)

@ztp.command()
@click.argument('enable', required=False, type=click.Choice(["enable"]))
def enable(enable):
    """Administratively Enable ZTP."""
    command = "ztp enable"
    run_command(command, display_cmd=True)

@interface.group('storm-control')
@click.pass_context
def storm_control(ctx):
    """ Configure storm-control"""
    pass

@storm_control.group('broadcast')
def broadcast():
    """ Configure broadcast storm-control"""
    pass

@broadcast.command('add')
@click.argument('port_name', metavar='<port_name>', required=True)
@click.argument('kbps', metavar='<kbps_value>', required=True, type=click.IntRange(0,100000000))
@click.pass_context
def add_broadcast_storm(ctx, port_name, kbps):
    click.echo("add broadcast storm-control")

    if storm_control_set_entry(port_name, kbps, 'broadcast') is False:
        ctx.fail("Unable to add broadcast storm-control")

@broadcast.command('del')
@click.argument('port_name', metavar='<port_name>', required=True)
@click.pass_context
def del_broadcast_storm(ctx, port_name):
    click.echo("del broadcast storm-control")

    if storm_control_delete_entry(port_name, 'broadcast') is False:
        ctx.fail("Unable to delete broadcast storm-control")

@storm_control.group('unknown-unicast')
def unknown_unicast():
    """ Configure unknown-unicast storm-control"""
    pass

@unknown_unicast.command('add')
@click.argument('port_name', metavar='<port_name>', required=True)
@click.argument('kbps', metavar='<kbps_value>', required=True, type=click.IntRange(0,100000000))
@click.pass_context
def add_unknown_unicast_storm(ctx, port_name, kbps):
    click.echo("add unknown-unicast storm-control")

    if storm_control_set_entry(port_name, kbps, 'unknown-unicast') is False:
        ctx.fail("Unable to add unknown-unicast storm-control")

@unknown_unicast.command('del')
@click.argument('port_name', metavar='<port_name>', required=True)
@click.pass_context
def del_unknown_unicast_storm(ctx, port_name):
    click.echo("del unknown-unicast storm-control")

    if storm_control_delete_entry(port_name, 'unknown-unicast') is False:
        ctx.fail("Unable to delete unknown-unicast storm-control")

@storm_control.group('unknown-multicast')
def unknown_multicast():
    """ Configure unknown-multicast storm-control"""
    pass

@unknown_multicast.command('add')
@click.argument('port_name', metavar='<port_name>', required=True)
@click.argument('kbps', metavar='<kbps_value>', required=True, type=click.IntRange(0,100000000))
@click.pass_context
def add_unknown_multicast_storm(ctx, port_name, kbps):
    click.echo("add unknown-multicast storm-control")

    if storm_control_set_entry(port_name, kbps, 'unknown-multicast') is False:
        ctx.fail("Unable to add unknown-multicast storm-control")

@unknown_multicast.command('del')
@click.argument('port_name', metavar='<port_name>', required=True)
@click.pass_context
def del_unknown_multicast_storm(ctx, port_name):
    click.echo("del unknown-multicast storm-control")

    if storm_control_delete_entry(port_name, 'unknown-multicast') is False:
        ctx.fail("Unable to delete unknown-multicast storm-control")

#
# 'syslog' group ('config syslog ...')
#
@config.group(cls=AbbreviationGroup, name='syslog')
@click.pass_context
def syslog_group(ctx):
    """Syslog server configuration tasks"""
    config_db = ConfigDBConnector()
    config_db.connect()
    ctx.obj = {'db': config_db}

@syslog_group.command('add')
@click.argument('syslog_ip_address', metavar='<syslog_ip_address>', required=True)
@click.pass_context
def add_syslog_server(ctx, syslog_ip_address):
    """ Add syslog server IP """
    if not is_ipaddress(syslog_ip_address):
        ctx.fail('Invalid ip address')
    db = ctx.obj['db']
    syslog_servers = db.get_table("SYSLOG_SERVER")
    if syslog_ip_address in syslog_servers:
        click.echo("Syslog server {} is already configured".format(syslog_ip_address))
        return
    else:
        db.set_entry('SYSLOG_SERVER', syslog_ip_address, {'NULL': 'NULL'})
        click.echo("Syslog server {} added to configuration".format(syslog_ip_address))
        try:
            click.echo("Restarting rsyslog-config service...")
            run_command("systemctl restart rsyslog-config", display_cmd=False)
        except SystemExit as e:
            ctx.fail("Restart service rsyslog-config failed with error {}".format(e))

@syslog_group.command('del')
@click.argument('syslog_ip_address', metavar='<syslog_ip_address>', required=True)
@click.pass_context
def del_syslog_server(ctx, syslog_ip_address):
    """ Delete syslog server IP """
    if not is_ipaddress(syslog_ip_address):
        ctx.fail('Invalid IP address')
    db = ctx.obj['db']
    syslog_servers = db.get_table("SYSLOG_SERVER")
    if syslog_ip_address in syslog_servers:
        db.set_entry('SYSLOG_SERVER', '{}'.format(syslog_ip_address), None)
        click.echo("Syslog server {} removed from configuration".format(syslog_ip_address))
    else:
        ctx.fail("Syslog server {} is not configured.".format(syslog_ip_address))
    try:
        click.echo("Restarting rsyslog-config service...")
        run_command("systemctl restart rsyslog-config", display_cmd=False)
    except SystemExit as e:
        ctx.fail("Restart service rsyslog-config failed with error {}".format(e))

#
# 'ntp' group ('config ntp ...')
#
@config.group(cls=AbbreviationGroup)
@click.pass_context
def ntp(ctx):
    """NTP server configuration tasks"""
    config_db = ConfigDBConnector()
    config_db.connect()
    ctx.obj = {'db': config_db}

@ntp.command('add')
@click.argument('ntp_ip_address', metavar='<ntp_ip_address>', required=True)
@click.pass_context
def add_ntp_server(ctx, ntp_ip_address):
    """ Add NTP server IP """
    if not is_ipaddress(ntp_ip_address):
        ctx.fail('Invalid ip address')
    db = ctx.obj['db']
    ntp_servers = db.get_table("NTP_SERVER")
    if ntp_ip_address in ntp_servers:
        click.echo("NTP server {} is already configured".format(ntp_ip_address))
        return
    else:
        db.set_entry('NTP_SERVER', ntp_ip_address, {'NULL': 'NULL'})
        click.echo("NTP server {} added to configuration".format(ntp_ip_address))
        try:
            click.echo("Restarting ntp-config service...")
            run_command("systemctl restart ntp-config", display_cmd=False)
        except SystemExit as e:
            ctx.fail("Restart service ntp-config failed with error {}".format(e))

@ntp.command('del')
@click.argument('ntp_ip_address', metavar='<ntp_ip_address>', required=True)
@click.pass_context
def del_ntp_server(ctx, ntp_ip_address):
    """ Delete NTP server IP """
    if not is_ipaddress(ntp_ip_address):
        ctx.fail('Invalid IP address')
    db = ctx.obj['db']
    ntp_servers = db.get_table("NTP_SERVER")
    if ntp_ip_address in ntp_servers:
        db.set_entry('NTP_SERVER', '{}'.format(ntp_ip_address), None)
        click.echo("NTP server {} removed from configuration".format(ntp_ip_address))
    else:
        ctx.fail("NTP server {} is not configured.".format(ntp_ip_address))
    try:
        click.echo("Restarting ntp-config service...")
        run_command("systemctl restart ntp-config", display_cmd=False)
    except SystemExit as e:
        ctx.fail("Restart service ntp-config failed with error {}".format(e))

#
# 'sflow' group ('config sflow ...')
#
@config.group(cls=AbbreviationGroup)
@click.pass_context
def sflow(ctx):
    """sFlow-related configuration tasks"""
    config_db = ConfigDBConnector()
    config_db.connect()
    ctx.obj = {'db': config_db}

#
# 'sflow' command ('config sflow enable')
#
@sflow.command()
@click.pass_context
def enable(ctx):
    """Enable sFlow"""
    config_db = ctx.obj['db']
    sflow_tbl = config_db.get_table('SFLOW')

    if not sflow_tbl:
        sflow_tbl = {'global': {'admin_state': 'up'}}
    else:
        sflow_tbl['global']['admin_state'] = 'up'

    config_db.mod_entry('SFLOW', 'global', sflow_tbl['global'])

    try:
        proc = subprocess.Popen("systemctl is-active sflow", shell=True, stdout=subprocess.PIPE)
        (out, err) = proc.communicate()
    except SystemExit as e:
        ctx.fail("Unable to check sflow status {}".format(e))

    if out != "active":
        log_info("sflow service is not enabled. Starting sflow docker...")
        run_command("sudo systemctl enable sflow")
        run_command("sudo systemctl start sflow")

#
# 'sflow' command ('config sflow disable')
#
@sflow.command()
@click.pass_context
def disable(ctx):
    """Disable sFlow"""
    config_db = ctx.obj['db']
    sflow_tbl = config_db.get_table('SFLOW')

    if not sflow_tbl:
        sflow_tbl = {'global': {'admin_state': 'down'}}
    else:
        sflow_tbl['global']['admin_state'] = 'down'

    config_db.mod_entry('SFLOW', 'global', sflow_tbl['global'])

#
# 'sflow' command ('config sflow polling-interval ...')
#
@sflow.command('polling-interval')
@click.argument('interval', metavar='<polling_interval>', required=True,
                type=int)
@click.pass_context
def polling_int(ctx, interval):
    """Set polling-interval for counter-sampling (0 to disable)"""
    if interval not in range(5, 301) and interval != 0:
        click.echo("Polling interval must be between 5-300 (0 to disable)")

    config_db = ctx.obj['db']
    sflow_tbl = config_db.get_table('SFLOW')

    if not sflow_tbl:
        sflow_tbl = {'global': {'admin_state': 'down'}}

    sflow_tbl['global']['polling_interval'] = interval
    config_db.mod_entry('SFLOW', 'global', sflow_tbl['global'])

def is_valid_sample_rate(rate):
    return rate in range(256, 8388608 + 1)


#
# 'sflow interface' group
#
@sflow.group(cls=AbbreviationGroup)
@click.pass_context
def interface(ctx):
    """Configure sFlow settings for an interface"""
    pass

#
# 'sflow' command ('config sflow interface enable  ...')
#
@interface.command()
@click.argument('ifname', metavar='<interface_name>', required=True, type=str)
@click.pass_context
def enable(ctx, ifname):
    if not interface_name_is_valid(ifname) and ifname != 'all':
        click.echo("Invalid interface name")
        return

    config_db = ctx.obj['db']
    intf_dict = config_db.get_table('SFLOW_SESSION')

    if intf_dict and ifname in intf_dict.keys():
        intf_dict[ifname]['admin_state'] = 'up'
        config_db.mod_entry('SFLOW_SESSION', ifname, intf_dict[ifname])
    else:
        config_db.mod_entry('SFLOW_SESSION', ifname, {'admin_state': 'up'})

#
# 'sflow' command ('config sflow interface disable  ...')
#
@interface.command()
@click.argument('ifname', metavar='<interface_name>', required=True, type=str)
@click.pass_context
def disable(ctx, ifname):
    if not interface_name_is_valid(ifname) and ifname != 'all':
        click.echo("Invalid interface name")
        return

    config_db = ctx.obj['db']
    intf_dict = config_db.get_table('SFLOW_SESSION')

    if intf_dict and ifname in intf_dict.keys():
        intf_dict[ifname]['admin_state'] = 'down'
        config_db.mod_entry('SFLOW_SESSION', ifname, intf_dict[ifname])
    else:
        config_db.mod_entry('SFLOW_SESSION', ifname,
                            {'admin_state': 'down'})

#
# 'sflow' command ('config sflow interface sample-rate  ...')
#
@interface.command('sample-rate')
@click.argument('ifname', metavar='<interface_name>', required=True, type=str)
@click.argument('rate', metavar='<sample_rate>', required=True, type=int)
@click.pass_context
def sample_rate(ctx, ifname, rate):
    if not interface_name_is_valid(ifname) and ifname != 'all':
        click.echo('Invalid interface name')
        return
    if not is_valid_sample_rate(rate):
        click.echo('Error: Sample rate must be between 256 and 8388608')
        return

    config_db = ctx.obj['db']
    sess_dict = config_db.get_table('SFLOW_SESSION')

    if sess_dict and ifname in sess_dict.keys():
        sess_dict[ifname]['sample_rate'] = rate
        config_db.mod_entry('SFLOW_SESSION', ifname, sess_dict[ifname])
    else:
        config_db.mod_entry('SFLOW_SESSION', ifname, {'sample_rate': rate})


#
# 'sflow collector' group
#
@sflow.group(cls=AbbreviationGroup)
@click.pass_context
def collector(ctx):
    """Add/Delete a sFlow collector"""
    pass

def is_valid_collector_info(name, ip, port):
    if len(name) > 16:
        click.echo("Collector name must not exceed 16 characters")
        return False

    if port not in range(0, 65535 + 1):
        click.echo("Collector port number must be between 0 and 65535")
        return False

    if not is_ipaddress(ip):
        click.echo("Invalid IP address")
        return False

    return True

#
# 'sflow' command ('config sflow collector add ...')
#
@collector.command()
@click.option('--port', required=False, type=int, default=6343,
              help='Collector port number')
@click.argument('name', metavar='<collector_name>', required=True)
@click.argument('ipaddr', metavar='<IPv4/v6_address>', required=True)
@click.pass_context
def add(ctx, name, ipaddr, port):
    """Add a sFlow collector"""
    ipaddr = ipaddr.lower()

    if not is_valid_collector_info(name, ipaddr, port):
        return

    config_db = ctx.obj['db']
    collector_tbl = config_db.get_table('SFLOW_COLLECTOR')

    if (collector_tbl and name not in collector_tbl.keys() and len(collector_tbl) == 2):
        click.echo("Only 2 collectors can be configured, please delete one")
        return

    config_db.mod_entry('SFLOW_COLLECTOR', name,
                        {"collector_ip": ipaddr,  "collector_port": port})
    return

#
# 'sflow' command ('config sflow collector del ...')
#
@collector.command('del')
@click.argument('name', metavar='<collector_name>', required=True)
@click.pass_context
def del_collector(ctx, name):
    """Delete a sFlow collector"""
    config_db = ctx.obj['db']
    collector_tbl = config_db.get_table('SFLOW_COLLECTOR')

    if name not in collector_tbl.keys():
        click.echo("Collector: {} not configured".format(name))
        return

    config_db.mod_entry('SFLOW_COLLECTOR', name, None)

#
# 'sflow agent-id' group
#
@sflow.group(cls=AbbreviationGroup, name='agent-id')
@click.pass_context
def agent_id(ctx):
    """Add/Delete a sFlow agent"""
    pass

#
# 'sflow' command ('config sflow agent-id add ...')
#
@agent_id.command()
@click.argument('ifname', metavar='<interface_name>', required=True)
@click.pass_context
def add(ctx, ifname):
    """Add sFlow agent information"""
    if ifname not in netifaces.interfaces():
        click.echo("Invalid interface name")
        return

    config_db = ctx.obj['db']
    sflow_tbl = config_db.get_table('SFLOW')

    if not sflow_tbl:
        sflow_tbl = {'global': {'admin_state': 'down'}}

    if 'agent_id' in sflow_tbl['global'].keys():
        click.echo("Agent already configured. Please delete it first.")
        return

    sflow_tbl['global']['agent_id'] = ifname
    config_db.mod_entry('SFLOW', 'global', sflow_tbl['global'])

#
# 'sflow' command ('config sflow agent-id del')
#
@agent_id.command('del')
@click.pass_context
def delete(ctx):
    """Delete sFlow agent information"""
    config_db = ctx.obj['db']
    sflow_tbl = config_db.get_table('SFLOW')

    if not sflow_tbl:
        sflow_tbl = {'global': {'admin_state': 'down'}}

    if 'agent_id' not in sflow_tbl['global'].keys():
        click.echo("sFlow agent not configured.")
        return

    sflow_tbl['global'].pop('agent_id')
    config_db.set_entry('SFLOW', 'global', sflow_tbl['global'])

#
# 'feature' command ('config feature name state')
#
@config.command('feature')
@click.argument('name', metavar='<feature-name>', required=True)
@click.argument('state', metavar='<feature-state>', required=True, type=click.Choice(["enabled", "disabled"]))
def feature_status(name, state):
    """ Configure status of feature"""
    config_db = ConfigDBConnector()
    config_db.connect()
    status_data = config_db.get_entry('FEATURE', name)

    if not status_data:
        click.echo(" Feature '{}' doesn't exist".format(name))
        return

    config_db.mod_entry('FEATURE', name, {'status': state})

#
# 'container' group ('config container ...')
#
@config.group(cls=AbbreviationGroup, name='container', invoke_without_command=False)
def container():
    """Modify configuration of containers"""
    pass

#
# 'feature' group ('config container feature ...')
#
@container.group(cls=AbbreviationGroup, name='feature', invoke_without_command=False)
def feature():
    """Modify configuration of container features"""
    pass

#
# 'autorestart' subcommand ('config container feature autorestart ...')
#
@feature.command(name='autorestart', short_help="Configure the status of autorestart feature for specific container")
@click.argument('container_name', metavar='<container_name>', required=True)
@click.argument('autorestart_status', metavar='<autorestart_status>', required=True, type=click.Choice(["enabled", "disabled"]))
def autorestart(container_name, autorestart_status):
    config_db = ConfigDBConnector()
    config_db.connect()
    container_feature_table = config_db.get_table('CONTAINER_FEATURE')
    if not container_feature_table:
        click.echo("Unable to retrieve container feature table from Config DB.")
        return

    if not container_feature_table.has_key(container_name):
        click.echo("Unable to retrieve features for container '{}'".format(container_name))
        return

    config_db.mod_entry('CONTAINER_FEATURE', container_name, {'auto_restart': autorestart_status})

#
# 'vxlan' group ('config vxlan ...')
#
@config.group()
@click.pass_context
def vxlan(ctx):
    config_db = ConfigDBConnector()
    config_db.connect()
    ctx.obj = {'db': config_db}

@vxlan.command('add')
@click.argument('vxlan_name', metavar='<vxlan_name>', required=True)
@click.argument('src_ip', metavar='<src_ip>', required=True)
@click.pass_context
def add_vxlan(ctx, vxlan_name, src_ip):
    """Add VXLAN"""
    if not is_ipaddress(src_ip):
        ctx.fail("{} invalid src ip address".format(src_ip))
    db = ctx.obj['db']

    vxlan_keys = db.keys('CONFIG_DB', "VXLAN_TUNNEL|*")
    if not vxlan_keys:
      vxlan_count = 0
    else:
      vxlan_count = len(vxlan_keys)

    if(vxlan_count > 0):
        ctx.fail("VTEP already configured.")

    fvs = {'src_ip': src_ip}
    db.set_entry('VXLAN_TUNNEL', vxlan_name, fvs)

@vxlan.command('del')
@click.argument('vxlan_name', metavar='<vxlan_name>', required=True)
@click.pass_context
def del_vxlan(ctx, vxlan_name):
    """Del VXLAN"""
    db = ctx.obj['db']

    vxlan_keys = db.keys('CONFIG_DB', "VXLAN_EVPN_NVO|*")
    if not vxlan_keys:
      vxlan_count = 0
    else:
      vxlan_count = len(vxlan_keys)

    if(vxlan_count > 0):
        ctx.fail("Please delete the EVPN NVO configuration.")

    vxlan_keys = db.keys('CONFIG_DB', "VXLAN_TUNNEL_MAP|*")
    if not vxlan_keys:
      vxlan_count = 0
    else:
      vxlan_count = len(vxlan_keys)

    if(vxlan_count > 0):
        ctx.fail("Please delete all VLAN VNI mappings.")

    db.set_entry('VXLAN_TUNNEL', vxlan_name, None)

@vxlan.group('evpn_nvo')
@click.pass_context
def vxlan_evpn_nvo(ctx):
    pass

@vxlan_evpn_nvo.command('add')
@click.argument('nvo_name', metavar='<nvo_name>', required=True)
@click.argument('vxlan_name', metavar='<vxlan_name>', required=True)
@click.pass_context
def add_vxlan_evpn_nvo(ctx, nvo_name, vxlan_name):
    """Add NVO"""
    db = ctx.obj['db']
    vxlan_keys = db.keys('CONFIG_DB', "VXLAN_EVPN_NVO|*")
    if not vxlan_keys:
      vxlan_count = 0
    else:
      vxlan_count = len(vxlan_keys)

    if(vxlan_count > 0):
        ctx.fail("EVPN NVO already configured")

    if len(db.get_entry('VXLAN_TUNNEL', vxlan_name)) == 0:
        ctx.fail("VTEP {} not configured".format(vxlan_name))

    fvs = {'source_vtep': vxlan_name}
    db.set_entry('VXLAN_EVPN_NVO', nvo_name, fvs)

@vxlan_evpn_nvo.command('del')
@click.argument('nvo_name', metavar='<nvo_name>', required=True)
@click.pass_context
def del_vxlan_evpn_nvo(ctx, nvo_name):
    """Del NVO"""
    db = ctx.obj['db']
    vxlan_keys = db.keys('CONFIG_DB', "VXLAN_TUNNEL_MAP|*")
    if not vxlan_keys:
      vxlan_count = 0
    else:
      vxlan_count = len(vxlan_keys)

    if(vxlan_count > 0):
        ctx.fail("Please delete all VLAN VNI mappings.")
    db.set_entry('VXLAN_EVPN_NVO', nvo_name, None)

@vxlan.group('map')
@click.pass_context
def vxlan_map(ctx):
    pass

@vxlan_map.command('add')
@click.argument('vxlan_name', metavar='<vxlan_name>', required=True)
@click.argument('vlan', metavar='<vlan_id>', required=True)
@click.argument('vni', metavar='<vni>', required=True)
@click.pass_context
def add_vxlan_map(ctx, vxlan_name, vlan, vni):
    """Add VLAN-VNI map entry"""
    if not vlan.isdigit():
        ctx.fail("Invalid vlan {}. Only valid vlan is accepted".format(vni))
    if vlan_id_is_valid(int(vlan)) is False:
        ctx.fail(" Invalid Vlan Id , Valid Range : 1 to 4094 ")
    if not vni.isdigit():
        ctx.fail("Invalid VNI {}. Only valid VNI is accepted".format(vni))
    #if (int(vni) < 1) or (int(vni) > 16777215):
    if vni_id_is_valid(int(vni)) is False:
        ctx.fail("Invalid VNI {}. Valid range [1 to 16777215].".format(vni))

    db = ctx.obj['db']
    vlan_name = "Vlan" + vlan

    if len(db.get_entry('VXLAN_TUNNEL', vxlan_name)) == 0:
        ctx.fail("VTEP {} not configured".format(vxlan_name))

    if len(db.get_entry('VLAN', vlan_name)) == 0:
        ctx.fail("{} not configured".format(vlan_name))

    vxlan_table = db.get_table('VXLAN_TUNNEL_MAP')
    vxlan_keys = vxlan_table.keys()
    if vxlan_keys is not None:
      for key in vxlan_keys:
        if (vxlan_table[key]['vlan'] == vlan_name):
           ctx.fail(" Vlan Id already mapped ")
        if (vxlan_table[key]['vni'] == vni):
           ctx.fail(" VNI Id already mapped ")

    fvs = {'vni': vni,
           'vlan' : vlan_name}
    mapname = vxlan_name + '|' + 'map_' + vni + '_' + vlan_name
    db.set_entry('VXLAN_TUNNEL_MAP', mapname, fvs)

@vxlan_map.command('del')
@click.argument('vxlan_name', metavar='<vxlan_name>', required=True)
@click.argument('vlan', metavar='<vlan_id>', required=True)
@click.argument('vni', metavar='<vni>', required=True)
@click.pass_context
def del_vxlan_map(ctx, vxlan_name, vlan, vni):
    """Del VLAN-VNI map entry"""
    if not vlan.isdigit():
        ctx.fail("Invalid vlan {}. Only valid vlan is accepted".format(vni))
    if vlan_id_is_valid(int(vlan)) is False:
        ctx.fail(" Invalid Vlan Id , Valid Range : 1 to 4094 ")
    if not vni.isdigit():
        ctx.fail("Invalid VNI {}. Only valid VNI is accepted".format(vni))
    #if (int(vni) < 1) or (int(vni) > 16777215):
    if vni_id_is_valid(int(vni)) is False:
        ctx.fail("Invalid VNI {}. Valid range [1 to 16777215].".format(vni))

    db = ctx.obj['db']
    if len(db.get_entry('VXLAN_TUNNEL', vxlan_name)) == 0:
        ctx.fail("VTEP {} not configured".format(vxlan_name))
    found = 0
    vrf_table = db.get_table('VRF')
    vrf_keys = vrf_table.keys()
    if vrf_keys is not None:
      for vrf_key in vrf_keys:
        if ('vni' in vrf_table[vrf_key] and vrf_table[vrf_key]['vni'] == vni):
           found = 1
           break

    if (found == 1):
        ctx.fail("VNI mapped to vrf {}, Please remove VRF VNI mapping".format(vrf_key))

    mapname = vxlan_name + '|' + 'map_' + vni + '_' + vlan
    db.set_entry('VXLAN_TUNNEL_MAP', mapname, None)
    mapname = vxlan_name + '|' + 'map_' + vni + '_Vlan' + vlan
    db.set_entry('VXLAN_TUNNEL_MAP', mapname, None)

@vxlan.group('map_range')
@click.pass_context
def vxlan_map_range(ctx):
    pass

@vxlan_map_range.command('add')
@click.argument('vxlan_name', metavar='<vxlan_name>', required=True)
@click.argument('vlan_start', metavar='<vlan_start>', required=True, type=int)
@click.argument('vlan_end', metavar='<vlan_end>', required=True, type=int)
@click.argument('vni_start', metavar='<vni_start>', required=True, type=int)
@click.pass_context
def add_vxlan_map_range(ctx, vxlan_name, vlan_start, vlan_end, vni_start):
    """Add Range of vlan-vni mappings"""
    if vlan_id_is_valid(vlan_start) is False:
        ctx.fail(" Invalid Vlan Id , Valid Range : 1 to 4094 ")
    if vlan_id_is_valid(vlan_end) is False:
        ctx.fail(" Invalid Vlan Id , Valid Range : 1 to 4094 ")
    if (vlan_start > vlan_end):
       ctx.fail("vlan_end should be greater or equal to vlan_start")
    if vni_id_is_valid(vni_start) is False:
        ctx.fail("Invalid VNI {}. Valid range [1 to 16777215].".format(vni_start))
    if vni_id_is_valid(vni_start+vlan_end-vlan_start) is False:
        ctx.fail("Invalid VNI End {}. Valid range [1 to 16777215].".format(vni_start))

    db = ctx.obj['db']
    if len(db.get_entry('VXLAN_TUNNEL', vxlan_name)) == 0:
        ctx.fail("VTEP {} not configured".format(vxlan_name))
    vlan_end = vlan_end + 1
    vxlan_table = db.get_table('VXLAN_TUNNEL_MAP')
    vxlan_keys = vxlan_table.keys()

    for vid in range (vlan_start, vlan_end):
       vlan_name = 'Vlan{}'.format(vid)
       vnid = vni_start+vid-vlan_start
       vni_name = '{}'.format(vnid)
       match_found = 'no'
       if len(db.get_entry('VLAN', vlan_name)) == 0:
         click.echo("{} not configured".format(vlan_name))
         continue
       if vxlan_keys is not None:
          for key in vxlan_keys:
            if (vxlan_table[key]['vlan'] == vlan_name):
              print(vlan_name + " already mapped")
              match_found = 'yes'
              break
            if (vxlan_table[key]['vni'] == vni_name):
              print("VNI:" + vni_name + " already mapped ")
              match_found = 'yes'
              break
       if (match_found == 'yes'):
         continue
       fvs = {'vni': vni_name,
              'vlan' : vlan_name}
       mapname = vxlan_name + '|' + 'map_' + vni_name + '_' + vlan_name
       db.set_entry('VXLAN_TUNNEL_MAP', mapname, fvs)

@vxlan_map_range.command('del')
@click.argument('vxlan_name', metavar='<vxlan_name>', required=True)
@click.argument('vlan_start', metavar='<vlan_start>', required=True, type=int)
@click.argument('vlan_end', metavar='<vlan_end>', required=True, type=int)
@click.argument('vni_start', metavar='<vni_start>', required=True, type=int)
@click.pass_context
def del_vxlan_map_range(ctx, vxlan_name, vlan_start, vlan_end, vni_start):
    """Del Range of vlan-vni mappings"""
    if vlan_id_is_valid(vlan_start) is False:
        ctx.fail(" Invalid Vlan Id , Valid Range : 1 to 4094 ")
    if vlan_id_is_valid(vlan_end) is False:
        ctx.fail(" Invalid Vlan Id , Valid Range : 1 to 4094 ")
    if (vlan_start > vlan_end):
       ctx.fail("vlan_end should be greater or equal to vlan_start")
    if vni_id_is_valid(vni_start) is False:
        ctx.fail("Invalid VNI {}. Valid range [1 to 16777215].".format(vni_start))
    if vni_id_is_valid(vni_start+vlan_end-vlan_start) is False:
        ctx.fail("Invalid VNI End {}. Valid range [1 to 16777215].".format(vni_start))

    db = ctx.obj['db']
    if len(db.get_entry('VXLAN_TUNNEL', vxlan_name)) == 0:
        ctx.fail("VTEP {} not configured".format(vxlan_name))

    vlan_end = vlan_end + 1
    for vid in range (vlan_start, vlan_end):
       vlan_name = 'Vlan{}'.format(vid)
       vnid = vni_start+vid-vlan_start
       vni_name = '{}'.format(vnid)
       if is_vni_vrf_mapped(ctx, vni_name) is False:
           print "Skipping Vlan {} VNI {} mapped delete. ".format(vlan_name, vni_name)
           continue

       mapname = vxlan_name + '|' + 'map_' + vni_name + '_' + vlan_name
       db.set_entry('VXLAN_TUNNEL_MAP', mapname, None)

#######
#
# 'neigh_suppress' group ('config neigh_suppress...')
#
@config.group('neigh_suppress')
@click.pass_context
def neigh_suppress(ctx):
    """ Neighbour Suppress VLAN-related configuration """
    config_db = ConfigDBConnector()
    config_db.connect()
    ctx.obj = {'db': config_db}

@neigh_suppress.command('enable')
@click.argument('vid', metavar='<vid>', required=True, type=int)
@click.pass_context
def enable_neigh_suppress(ctx, vid):
    db = ctx.obj['db']
    if vlan_id_is_valid(vid) is False:
        ctx.fail(" Invalid Vlan Id , Valid Range : 1 to 4094 ")
    vlan = 'Vlan{}'.format(vid)
    if len(db.get_entry('VLAN', vlan)) == 0:
        click.echo("{} doesn't exist".format(vlan))
        return
    fvs = {'suppress': "on"}
    db.set_entry('SUPPRESS_VLAN_NEIGH', vlan, fvs)

@neigh_suppress.command('disable')
@click.argument('vid', metavar='<vid>', required=True, type=int)
@click.pass_context
def disable_neigh_suppress(ctx, vid):
    db = ctx.obj['db']
    if vlan_id_is_valid(vid) is False:
        ctx.fail(" Invalid Vlan Id , Valid Range : 1 to 4094 ")
    vlan = 'Vlan{}'.format(vid)
    db.set_entry('SUPPRESS_VLAN_NEIGH', vlan, None)
#######
#
# 'mclag' group ('config mclag...')
#
@config.group(cls=AbbreviationGroup)
@click.pass_context
def mclag(ctx):
    """ Multi-Chassis Link Aggregation Group-related configuration """
    config_db = ConfigDBConnector()
    config_db.connect()
    ctx.obj = {'db': config_db}
    pass

#
# 'mclag' command ('config mclag add ...')
#
@mclag.command('add')
@click.argument('domain_id', metavar='<domain_id>', required=True)
@click.argument('local_ip_addr', metavar='<local_ip_addr>', required=True)
@click.argument('peer_ip_addr', metavar='<peer_ip_addr>', required=True)
@click.argument('peer_ifname', metavar='[peer_ifname]', required=False)
@click.pass_context
def add_mclag(ctx, domain_id, local_ip_addr, peer_ip_addr, peer_ifname):
    """Add MCLAG domain"""
    if not mclag_domain_id_is_valid(int(domain_id)):
        ctx.fail('Invalid Domain ID {}. Valid range [1 to 4095].'.format(domain_id))
    if not is_ipaddress(local_ip_addr):
        ctx.fail('Invalid Local IP address {}.'.format(local_ip_addr))
    if not is_ipaddress(peer_ip_addr):
        ctx.fail('Invalid Peer IP address {}.'.format(peer_ip_addr))

    data = {
        'source_ip': local_ip_addr,
        'peer_ip': peer_ip_addr
    }
    if peer_ifname is not None:
        interface_name = peer_ifname
        if get_interface_naming_mode() == 'alias':
            interface_name = interface_alias_to_name(peer_ifname)
            if interface_name is None:
                ctx.fail('\'peer_ifname\' is None!')
        data['peer_link'] = interface_name
        if interface_name.startswith('Ethernet') is False and interface_name.startswith('PortChannel') is False:
            ctx.fail('Invalid Peer interface name {}. It can only be ethernet port or port channel.'.format(peer_ifname))
        if interface_name_is_valid(interface_name) is False:
            ctx.fail('Invalid Peer interface name {}. Please enter existing interface.'.format(peer_ifname))

    db = ctx.obj['db']
    db.set_entry('MCLAG_DOMAIN', domain_id, data)

#
# 'mclag' command ('config mclag del ...')
#
@mclag.command('del')
@click.argument('domain_id', metavar='<domain_id>', required=True)
@click.pass_context
def del_mclag(ctx, domain_id):
    """Remove MCLAG domain"""
    db = ctx.obj['db']
    db.set_entry('MCLAG_DOMAIN', domain_id, None)

#
# 'mclag member' group ('config mclag member ...')
#
@mclag.group('member')
@click.pass_context
def mclag_member(ctx):
    pass

#
# 'mclag member' command ('config mclag member add ...')
#
@mclag_member.command('add')
@click.argument('domain_id', metavar='<domain_id>', required=True)
@click.argument('portchannel_name', metavar='<portchannel_name>', required=True)
@click.pass_context
def add_mclag_member(ctx, domain_id, portchannel_name):
    """Add member to MCLAG domain"""
    db = ctx.obj['db']
    domain = db.get_entry('MCLAG_DOMAIN', domain_id)
    if len(domain) == 0:
        ctx.fail('MCLAG Domain {} doesn\'t exist.'.format(domain_id))

    portchannel = portchannel_name
    if get_interface_naming_mode() == "alias":
        portchannel = interface_alias_to_name(portchannel)
        if portchannel is None:
            ctx.fail('\'portchannel_name\' is None!')
    if portchannel.startswith('PortChannel') is False:
        ctx.fail('Invalid portchannel name {}. MCLAG interfaces can be only portchannels.'.format(portchannel))
    if interface_name_is_valid(portchannel) is False:
        ctx.fail('Invalid portchannel name {}. Please enter existing portchannel.'.format(portchannel))

    db.set_entry('MCLAG_INTERFACE', (domain_id, portchannel), {'NULL': 'NULL'})

#
# 'mclag member' command ('config mclag member del ...')
#
@mclag_member.command('del')
@click.argument('domain_id', metavar='<domain_id>', required=True)
@click.argument('portchannel_name', metavar='<portchannel_name>', required=True)
@click.pass_context
def del_mclagl_member(ctx, domain_id, portchannel_name):
    """Remove member from MCLAG domain"""
    db = ctx.obj['db']
    db.set_entry('MCLAG_INTERFACE', (domain_id, portchannel_name), None)

#
# 'mclag unique-ip' group ('config mclag unique-ip ...')
#
@mclag.group('unique-ip')
@click.pass_context
def mclag_unique_ip(ctx):
    pass

#
# 'mclag unique-ip' command ('config mclag unique-ip add ...')
#
@mclag_unique_ip.command('add')
@click.argument('vlan_interface', metavar='<vlan_interface>', required=True)
@click.pass_context
def add_vlan_interface(ctx, vlan_interface):
    """Add Vlan interface"""
    if vlan_interface.startswith('Vlan') is False:
        ctx.fail('Invalid Vlan interface {}. Only VLAN interface supported currently.'.format(vlan_interface))

    db = ctx.obj['db']
    vlan = db.get_entry('VLAN', vlan_interface)
    if len(vlan) == 0:
        ctx.fail('Invalid Vlan interface {}. Please enter existing Vlan.'.format(vlan_interface))

    db.set_entry('MCLAG_UNIQUEIP_TABLE', vlan_interface, {'NULL': 'NULL'})

#
# 'mclag unique-ip' command ('config mclag unique-ip del ...')
#
@mclag_unique_ip.command('del')
@click.argument('vlan_interface', metavar='<vlan_interface>', required=True)
@click.pass_context
def del_vlan_interface(ctx, vlan_interface):
    """Remove Vlan interface """
    db = ctx.obj['db']
    db.set_entry('MCLAG_UNIQUEIP_TABLE', vlan_interface, None)

if __name__ == '__main__':
    config()

