<%
import ipaddress
import json
import os
import re
import time
from itertools import count, groupby
from typing import Union
from cloudvision.cvlib import (
    Tag,
    IdAllocator
)

campusLabel = 'Campus'
campusPodLabel = 'Campus-Pod'
accessPodLabel = 'Access-Pod'

old_veos_regex = r'(v|c)EOS(-)*(Lab)*'
new_veos_regex = r'CloudEOS(-)*(Lab)*'
veos_regex = f"({old_veos_regex})|({new_veos_regex})"

node_type_defaults = {
    "only-l2ls": {
        "spine": {
            "default_evpn_role": None,
            "mlag_support": True,
            "vtep": False,
            "connected_endpoints": True,
            "network_services_l2": True,
            "network_services_l3": False,
            "underlay_router": False,
            "uplink_type": "port-channel",
            "avd_type": "spine"
        },
        "leaf":{
            "default_evpn_role": None,
            "mlag_support": True,
            "vtep": False,
            "connected_endpoints": True,
            "network_services_l2": True,
            "network_services_l3": False,
            "underlay_router": False,
            "uplink_type": "port-channel",
            "avd_type": "leaf"
        },
        "memberleaf": {
            "default_evpn_role": None,
            "mlag_support": True,
            "vtep": False,
            "connected_endpoints": True,
            "network_services_l2": True,
            "network_services_l3": False,
            "underlay_router": False,
            "uplink_type": "port-channel",
            "avd_type": "leaf"
        }
    },
    "l2ls": {
        "spine": {
            "default_evpn_role": None,
            "mlag_support": True,
            "vtep": False,
            "connected_endpoints": False,
            "network_services_l2": True,
            "network_services_l3": True,
            "underlay_router": True,
            "uplink_type": "p2p",
            "avd_type": "spine"
        },
        "leaf":{
            "default_evpn_role": None,
            "mlag_support": True,
            "vtep": False,
            "connected_endpoints": True,
            "network_services_l2": True,
            "network_services_l3": False,
            "underlay_router": False,
            "uplink_type": "port-channel",
            "avd_type": "leaf"
        },
        "memberleaf": {
            "default_evpn_role": None,
            "mlag_support": True,
            "vtep": False,
            "connected_endpoints": True,
            "network_services_l2": True,
            "network_services_l3": False,
            "underlay_router": False,
            "uplink_type": "port-channel",
            "avd_type": "leaf"
        }
    },
    "l2ls-vxlan": {
        "spine": {
            "default_evpn_role": None,
            "mlag_support": True,
            "vtep": True,
            "connected_endpoints": False,
            "network_services_l2": True,
            "network_services_l3": True,
            "underlay_router": True,
            "uplink_type": "p2p",
            "avd_type": "spine"
        },
        "leaf":{
            "default_evpn_role": None,
            "mlag_support": True,
            "vtep": False,
            "connected_endpoints": True,
            "network_services_l2": True,
            "network_services_l3": False,
            "underlay_router": False,
            "uplink_type": "port-channel",
            "avd_type": "leaf"
        },
        "memberleaf": {
            "default_evpn_role": None,
            "mlag_support": True,
            "vtep": False,
            "connected_endpoints": True,
            "network_services_l2": True,
            "network_services_l3": False,
            "underlay_router": False,
            "uplink_type": "port-channel",
            "avd_type": "leaf"
        }
    },
    "l2ls-evpn": {
        "spine": {
            "default_evpn_role": "client",
            "mlag_support": True,
            "vtep": True,
            "connected_endpoints": False,
            "network_services_l2": True,
            "network_services_l3": True,
            "underlay_router": True,
            "uplink_type": "p2p",
            "avd_type": "spine"
        },
        "leaf":{
            "default_evpn_role": None,
            "mlag_support": True,
            "vtep": False,
            "connected_endpoints": True,
            "network_services_l2": True,
            "network_services_l3": False,
            "underlay_router": False,
            "uplink_type": "port-channel",
            "avd_type": "leaf"
        },
        "memberleaf": {
            "default_evpn_role": None,
            "mlag_support": True,
            "vtep": False,
            "connected_endpoints": True,
            "network_services_l2": True,
            "network_services_l3": False,
            "underlay_router": False,
            "uplink_type": "port-channel",
            "avd_type": "leaf"
        }
    },
    "l3ls": {
        "spine": {
            "default_evpn_role": None,
            "mlag_support": True,
            "vtep": False,
            "connected_endpoints": False,
            "network_services_l2": False,
            "network_services_l3": True,
            "underlay_router": True,
            "uplink_type": "p2p",
            "avd_type": "spine"
        },
        "leaf":{
            "default_evpn_role": None,
            "mlag_support": True,
            "vtep": False,
            "connected_endpoints": True,
            "network_services_l2": True,
            "network_services_l3": True,
            "underlay_router": True,
            "uplink_type": "p2p",
            "avd_type": "l3leaf"
        },
        "memberleaf": {
            "default_evpn_role": None,
            "mlag_support": True,
            "vtep": False,
            "connected_endpoints": True,
            "network_services_l2": True,
            "network_services_l3": False,
            "underlay_router": False,
            "uplink_type": "port-channel",
            "avd_type": "l2leaf"
        }
    },
    "l3ls-vxlan": {
        "spine": {
            "default_evpn_role": None,
            "mlag_support": True,
            "vtep": True,
            "connected_endpoints": False,
            "network_services_l2": False,
            "network_services_l3": True,
            "underlay_router": True,
            "uplink_type": "p2p",
            "avd_type": "spine"
        },
        "leaf":{
            "default_evpn_role": None,
            "mlag_support": True,
            "vtep": True,
            "connected_endpoints": True,
            "network_services_l2": True,
            "network_services_l3": True,
            "underlay_router": True,
            "uplink_type": "p2p",
            "avd_type": "l3leaf"
        },
        "memberleaf": {
            "default_evpn_role": None,
            "mlag_support": True,
            "vtep": False,
            "connected_endpoints": True,
            "network_services_l2": True,
            "network_services_l3": False,
            "underlay_router": False,
            "uplink_type": "port-channel",
            "avd_type": "l2leaf"
        }
    },
    "l3ls-evpn": {
        "spine": {
            "default_evpn_role": "server",
            "mlag_support": True,
            "vtep": True,
            "connected_endpoints": False,
            "network_services_l2": False,
            "network_services_l3": True,
            "underlay_router": True,
            "uplink_type": "p2p",
            "avd_type": "spine"
        },
        "leaf":{
            "default_evpn_role": "client",
            "mlag_support": True,
            "vtep": True,
            "connected_endpoints": True,
            "network_services_l2": True,
            "network_services_l3": True,
            "underlay_router": True,
            "uplink_type": "p2p",
            "avd_type": "l3leaf"
        },
        "memberleaf": {
            "default_evpn_role": None,
            "mlag_support": True,
            "vtep": False,
            "connected_endpoints": True,
            "network_services_l2": True,
            "network_services_l3": False,
            "underlay_router": False,
            "uplink_type": "port-channel",
            "avd_type": "l2leaf"
        }
    }
}

fabric_variables = {
    "bgp_peer_groups": {
        "IPv4_UNDERLAY_PEERS": {
            "name": "IPv4-UNDERLAY-PEERS",
            "password": None
        },
        "MLAG_IPv4_UNDERLAY_PEER": {
            "name": "MLAG-IPv4-UNDERLAY-PEER",
            "password": None,
        },
        "EVPN_OVERLAY_PEERS": {
            "name": "EVPN-OVERLAY-PEERS",
            "password": None
        }
    },
    "bfd_multihop": {
        "interval": 300,
        "min_rx": 300,
        "multiplier": 3
    },
    "evpn_ebgp_multihop": 3,
    "evpn_hostflap_detection": {
        "enabled": False,
        "threshold": 5,
        "window": 180
    },
    "interface_descriptions":{
        "underlay_l3_ethernet_interfaces": "P2P_LINK_TO_{link['peer'].upper()}_{link['peer_interface']}",
        "underlay_l2_ethernet_interfaces": "TO_{link['peer'].upper()}_{link['peer_interface']}",
        "underlay_port_channel_interfaces": "{link['peer'].upper()}_Po{link.get('peer_channel_group_id')}",
        "router_id_interface": "ROUTER_ID",
        "vtep_source_interface": "VTEP_VXLAN_Tunnel_Source",
        "mlag_ethernet_interfaces": "MLAG_{mlag_peer}_{mlag_peer_interface}",
        "mlag_port_channel_interface": "MLAG_PEER_{mlag_peer}_Po{mlag_port_channel_id}"
    },
    "p2p_interface_settings": [],
    "fabric_ip_addressing": {
        "mlag": {
            "algorithm": "first_id",
            "ipv4_prefix_length": 31,
            "bgp_numbering": "first_id"
        },
        "p2p_uplinks": {
            "ipv4_prefix_length": 31
        }
    }
}

platform_settings = {
    "jericho-fixed": {
        "regexes": [r'DCS-7280\w(R|R2)\D*-.+', r'DCS-7048T', r'DCS-7020\w(R|RW)\D*-.+'],
        "reload_delay": {
            "mlag": 900,
            "non_mlag": 1020
        },
        "tcam_profile": "vxlan-routing",
        "info": "Configured in standard settings"
    },
    "jericho-chassis": {
        "regexes": [r'DCS-75\d\d'],
        "reload_delay": {
            "mlag": 900,
            "non_mlag": 1020
        },
        "tcam_profile": "vxlan-routing",
        "info": "Configured in standard settings"
    },
    "jericho2-fixed": {
        "regexes": [r'DCS-7280\w(R3)\D*-.+'],
        "reload_delay": {
            "mlag": 900,
            "non_mlag": 1020
        },
        "tcam_profile": None,
        "info": "Configured in standard settings"
    },
    "jericho2-chassis": {
        "regexes": [r'DCS-78\d\d'],
        "reload_delay": {
            "mlag": 900,
            "non_mlag": 1020
        },
        "tcam_profile": None,
        "info": "Configured in standard settings"
    },
    "trident3x1-fixed": {
        "regexes": [r'CCS-720DP-24S', r'CCS-720DT-24', r'CCS-710P'],
        "reload_delay": {
            "mlag": 300,
            "non_mlag": 330
        },
        "tcam_profile": None,
        "info": "Configured in standard settings",
        "ip_locking": {
            "support": True
        },
        "per_interface_mtu": False
    },
    "trident3x2-fixed": {
        "regexes": [r'CCS-720DP-48S', r'CCS-720DT-48', r'CCS-722XP', r'DCS-7010TX', r'DCS-7050(S|T)X-\d\d'],
        "reload_delay": {
            "mlag": 300,
            "non_mlag": 330
        },
        "tcam_profile": None,
        "info": "Configured in standard settings",
        "ip_locking": {
            "support": True
        },
        "per_interface_mtu": False
    },
    "trident3x3-fixed": {
        "regexes": [r'CCS-720XP-\d\d', r'CCS-720DP-\d\dZS', r'CCS-720DF-\d\d'],
        "reload_delay": {
            "mlag": 300,
            "non_mlag": 330
        },
        "tcam_profile": None,
        "info": "Configured in standard settings",
        "ip_locking": {
            "support": True
        }
    },
    "trident3x4-chassis": {
        "regexes": [r'CCS-75\d'],
        "reload_delay": {
            "mlag": 300,
            "non_mlag": 330
        },
        "tcam_profile": None,
        "info": "Configured in standard settings",
        "ip_locking": {
            "support": True
        },
        "per_interface_mtu": False
    },
    "trident3x5|7-fixed": {
        "regexes": [r'DCS-7050\wX3'],
        "reload_delay": {
            "mlag": 300,
            "non_mlag": 330
        },
        "tcam_profile": None,
        "info": "Configured in standard settings",
        "ip_locking": {
            "support": True
        }
    },
    "7358X4": {
        "regexes": ["7358X4"],
        "tcam_profile": None,
        "reload_delay": {
            "mlag": 300,
            "non_mlag": 330,
        },
        "bgp_update_wait_for_convergence": True,
        "bgp_update_wait_install": False,
    },
    "veos": {
        "regexes": [old_veos_regex, new_veos_regex],
        "reload_delay": {
            "mlag": 300,
            "non_mlag": 330
        },
        "tcam_profile": None,
        "ip_locking": {
            "support": True
        },
        "bgp_update_wait_for_convergence": False,
        "bgp_update_wait_install": False,
    },
    "default": {
        "regexes": [r'.+'],
        "reload_delay": {
            "mlag": 300,
            "non_mlag": 330
        },
        "tcam_profile": None,
        "info": "Configured in standard settings"
    }
}

ptp_profiles = [
    {
        "profile": "aes67-r16-2016",
        "announce": {
            "interval": 0,
            "timeout": 3,
        },
        "delay_req": -3,
        "sync_message": {
            "interval": -3
        },
        "transport": "ipv4"
    },
    {
        "profile": "smpte2059-2",
        "announce": {
            "interval": -2,
            "timeout": 3,
        },
        "delay_req": -4,
        "sync_message": {
            "interval": -4
        },
        "transport": "ipv4"
    },
    {
        "profile": "aes67",
        "announce": {
            "interval": 2,
            "timeout": 3,
        },
        "delay_req": 0,
        "sync_message": {
            "interval": 0
        },
        "transport": "ipv4"
    }
]


pool_name_mapper = {
  "leaf_loopback_ipv4_pool": "Access Pod Router ID Subnet",
  "memberleaf_loopback_ipv4_pool": "Access Pod Router ID Subnet",
  "spine_loopback_ipv4_pool": "Spine Router ID Subnet",
  "leaf_vtep_loopback_ipv4_pool": "VTEP Address Range",
  "memberleaf_vtep_loopback_ipv4_pool": "VTEP Address Range",
  "spine_vtep_loopback_ipv4_pool": "VTEP Address Range",
  "leaf_uplink_ipv4_pool": "Uplink Subnet Pool",
  "memberleaf_uplink_ipv4_pool": "Uplink Subnet Pool",
  "spine_uplink_ipv4_pool": "Uplink Subnet Pool",
  "leaf_inband_management_subnet": "Inband Management Subnet",
  "memberleaf_inband_management_subnet": "Inband Management Subnet",
  "spine_inband_management_subnet": "Inband Management Subnet",
}


# Turning on DEBUG_LEVEL will impact performance
DEBUG_LEVEL = 0
if DEBUG_LEVEL:
    ctx.benchmarkingOn()


def dump_my_switch_facts(stage):
    if DEBUG_LEVEL > 2:
        ctx.info(f"{my_device.id} FACTS Stage {stage}: \n{json.dumps(my_switch_facts_neighbors[my_device.id], sort_keys=True, indent=4, default=vars)}")


def dump_my_config(stage):
    if DEBUG_LEVEL > 2:
        ctx.info(f"{my_device.id} CONFIG Stage {stage}: \n{json.dumps(my_config, sort_keys=True, indent=4, default=vars)}")


@ctx.benchmark
def duplicate_values(anydict):
    return [(key, value) for key, value in anydict.items() if list(
               anydict.values()).count(value) > 1]


@ctx.benchmark
def str_to_bool(text):
    if str(text).strip().lower() in ["enable", "enabled", "yes", "true"]:
        return True
    elif str(text).strip().lower() in ["disable", "disabled", "no", "false"]:
        return False
    return None


@ctx.benchmark
def compare_eos_versions(version1, version2):
    version1 = re.sub(r'[a-zA-Z]', "", version1)
    version2 = re.sub(r'[a-zA-Z]', "", version2)
    versions1 = [int(v) for v in version1.split(".")]
    versions2 = [int(v) for v in version2.split(".")]
    for i in range(max(len(versions1),len(versions2))):
        v1 = versions1[i] if i < len(versions1) else 0
        v2 = versions2[i] if i < len(versions2) else 0
        if v1 > v2:
            return 1
        elif v1 <v2:
            return -1
    return 0


@ctx.benchmark
def validIPAddress(ip):
    '''
    Returns True for a valid ipv4 address
    Returns False for a valid ipv6 address
    Return None for a nonvalid ip address
    '''
    try:
        return True if type(ipaddress.ip_address(ip)) is ipaddress.IPv4Address else False
    except ValueError:
        return None


@ctx.benchmark
def validateIPNetwork(ip_network, network_name=None):
    '''
    Returns True for a valid ipv4 network
    Returns False for a valid ipv6 network
    Return None for a nonvalid ip network
    '''
    try:
        return True if type(ipaddress.ip_network(ip_network)) is ipaddress.IPv4Network else False
    except ValueError as e:
        error_message = f""
        if network_name is not None:
            error_message += f"Error with {network_name}: "
        error_message += f"{e}"
        assert False, error_message


@ctx.benchmark
def extend_ip_ranges(ip_ranges):
    '''
    Args:
        ip_ranges: list of strings that resemble ip address ranges (i.e. 192.168.0.4-192.168.0.12)
    '''
    output = []
    for ip_range in ip_ranges:
        ip_elements = [
            ipaddress.ip_address(element.strip()) for element in ip_range.strip().split("-")
        ]
        if ip_elements[0] <= ip_elements[1]:
            ip_addresses = range(int(ip_elements[0]), int(ip_elements[1]) + 1)
        else:
            ip_addresses = range(int(ip_elements[0]), int(ip_elements[1]) - 1, -1)

        output.extend([str(ipaddress.ip_address(ip)) for ip in ip_addresses])
    return output


@ctx.benchmark
def get_ip_from_subnet(hostname, type, network, pool, index):
  poolname = type + '_' + pool
  # Avoid using network.hosts() due to performance impact.
  # When indexing directly into networks of mask less than /31,
  # exclude identification and broadcast addresses
  num_addresses = network.num_addresses
  if network.prefixlen < 31:
      index +=1
      num_addresses = network.num_addresses - 1
  assert index < num_addresses,\
      f"Device {hostname} is exceeding {pool_name_mapper[poolname]} " \
      f"of {network.with_prefixlen}. " \
      f"The maximum address is {list(network.hosts())[-1]}. " \
      f"The size of the subnet must be increased in the studio inputs."
  return network[index]


@ctx.benchmark
def get_host_from_network(switch_facts, pool, index):
  network = ipaddress.ip_network(switch_facts[pool])
  return get_ip_from_subnet(switch_facts['hostname'],
                            switch_facts['type'],
                            network, pool, index)


@ctx.benchmark
def convert_dicts(dictionary, primary_key="name", secondary_key=None):
    """
    The `arista.avd.convert_dicts` filter will convert a dictionary containing nested dictionaries to a list of
    dictionaries. It inserts the outer dictionary keys into each list item using the primary_key `name` (key name is
    configurable) and if there is a non-dictionary value,it inserts this value to
    secondary key (key name is configurable), if secondary key is provided.
    This filter is intended for:
    - Seemless data model migration from dictionaries to lists.
    - Improve Ansible's processing performance when dealing with large dictionaries by converting them to lists of dictionaries.
    Note: If there is a non-dictionary value with no secondary key provided, it will pass through untouched
    To use this filter:
    ```jinja
    {# convert list of dictionary with default `name:` as the primary key and None secondary key #}
    {% set example_list = example_dictionary | arista.avd.convert_dicts %}
    {% for example_item in example_list %}
    item primary key is {{ example_item.name }}
    {% endfor %}
    {# convert list of dictionary with `id:` set as the primary key and `types:` set as the secondary key #}
    {% set example_list = example_dictionary | arista.avd.convert_dicts('id','types') %}
    {% for example_item in example_list %}
    item primary key is {{ example_item.id }}
    item secondary key is {{ example_item.types }}
    {% endfor %}
    ```
    Parameters
    ----------
    dictionary : any
        Nested Dictionary to convert - returned untouched if not a nested dictionary and list
    primary_key : str, optional
        Name of primary key used when inserting outer dictionary keys into items.
    secondary_key : str, optional
        Name of secondary key used when inserting dictionary values which are list into items.
    Returns
    -------
    any
        Returns list of dictionaries or input variable untouched if not a nested dictionary/list.
    """
    if not isinstance(dictionary, (dict, list)) or os.environ.get("AVD_DISABLE_CONVERT_DICTS"):
        # Not a dictionary/list, return the original
        return dictionary
    elif isinstance(dictionary, list):
        output = []
        for element in dictionary:
            if not isinstance(element, dict):
                item = {}
                item.update({primary_key: element})
                output.append(item)
            elif primary_key not in element and secondary_key is not None:
                # if element of nested dictionary is a dictionary but primary key is missing, insert primary and secondary keys.
                for key in element:
                    output.append(
                        {
                            primary_key: key,
                            secondary_key: element[key],
                        }
                    )
            else:
                output.append(element)
        return output
    else:
        output = []
        for key in dictionary:
            if secondary_key is not None:
                # Add secondary key for the values if secondary key is provided
                item = {}
                item.update({primary_key: key})
                item.update({secondary_key: dictionary[key]})
                output.append(item)
            else:
                if not isinstance(dictionary[key], dict):
                    # Not a nested dictionary
                    output.append({primary_key: key})
                else:
                    # Nested dictionary
                    item = dictionary[key].copy()
                    item.update({primary_key: key})
                    output.append(item)
        return output


@ctx.benchmark
def list_compress(list_to_compress):
    if not isinstance(list_to_compress, list):
        raise TypeError(f"value must be of type list, got {type(list_to_compress)}")
    G = (list(x) for y, x in groupby(sorted(list_to_compress), lambda x, c=count(): next(c) - x))
    return ",".join("-".join(map(str, (g[0], g[-1])[: len(g)])) for g in G)


@ctx.benchmark
def string_to_list(string_to_convert):
    numbers = []
    segments = [segment.strip() for segment in string_to_convert.split(",") if segment.strip() != ""]
    for segment in segments:
        if "-" in segment:
            for i in range(int(segment.split("-")[0]), int(segment.split("-")[1]) + 1):
                if i not in numbers:
                    numbers.append(i)
        else:
            if int(segment) not in numbers:
                numbers.append(int(segment))
    return numbers


@ctx.benchmark
def convert(text):
    return int(text) if text.isdigit() else text.lower()


@ctx.benchmark
def natural_sort(iterable, sort_key=None):
    if iterable is None:
        return []

    @ctx.benchmark
    def alphanum_key(key):
        if sort_key is not None and isinstance(key, dict):
            return [convert(c) for c in re.split("([0-9]+)", str(key.get(sort_key, key)))]
        else:
            return [convert(c) for c in re.split("([0-9]+)", str(key))]

    return sorted(iterable, key=alphanum_key)


@ctx.benchmark
def range_expand(range_to_expand):
    if not (isinstance(range_to_expand, list) or isinstance(range_to_expand, str)):
        raise TypeError(f"value must be of type list or str, got {type(range_to_expand)}")

    result = []

    # If we got a list, unpack it and run this function recursively
    if isinstance(range_to_expand, list):
        for r in range_to_expand:
            result.extend(range_expand(r))

    # Must be a str now
    else:
        prefix = ""

        # Unpack list in string
        for one_range in range_to_expand.split(","):
            if one_range is None:
                continue

            # Find prefix (if any)
            regex = r"^(.*?)(((\d+)-)?(\d+)\/)?(((\d+)-)?(\d+)\/)?(((\d+)-)?(\d+))(\.((\d+)-)?(\d+))?"
            # Number of groups in this regex.
            regex_groups = 17
            # Groups one-by-one:
            # Group 1  (.*?)                                                                           matches prefix ex. Ethernet, Eth, Po, Port-Channel
            # Group 2       (((\d+)-)?(\d+)\/)?                                                        matches module(s) and slash ex. 12/, 1-3/
            # Group 3        ((\d+)-)?                                                                 matches first module and dash ex. 1-
            # Group 4         (\d+)                                                                    matches first module ex. 1
            # Group 5                 (\d+)                                                            matches last module ex. 12, 3
            # Group 6                          (((\d+)-)?(\d+)\/)?                                     matches parent interface(s) and slash ex. 47/, 1-48/
            # Group 7                           ((\d+)-)?                                              matches parent interface(s) and dash ex. 47-
            # Group 8                            (\d+)                                                 matches first parent interface ex. 1
            # Group 9                                    (\d+)                                         matches last parent interface ex. 47, 48
            # Group 10                                            (((\d+)-)?(\d+))                     matches (breakout) interface(s) ex. 1, 1-4, 1-48
            # Group 11                                             ((\d+)-)?                           matches first interfaces and dash ex. 1-, 1-
            # Group 12                                              (\d+)                              matches first interface
            # Group 13                                                      (\d+)                      matches last interface ex. 1, 4, 48
            # Group 14                                                            (\.((\d+)-)?(\d+))?  matches dot and sub-interface(s) ex. .141, .12-15
            # Group 15                                                               ((\d+)-)?         matches first sub-interface and dash ex. 12-
            # Group 16                                                                (\d+)            matches first sub-interface ex. 12
            # Group 17                                                                        (\d+)    matches last sub-interface ex. 141, 15
            # Remember that the groups() object is 0-based and the group numbers above are 1-based
            search_result = re.search(regex, one_range)
            if search_result:
                if len(search_result.groups()) == regex_groups:
                    groups = search_result.groups()
                    first_module = last_module = None
                    first_parent_interface = last_parent_interface = None
                    first_interface = last_interface = None
                    first_subinterface = last_subinterface = None
                    # Set prefix if found (otherwise use last set prefix)
                    if groups[0]:
                        prefix = groups[0]
                    if groups[4]:
                        last_module = int(groups[4])
                    if groups[3]:
                        first_module = int(groups[3])
                    else:
                        first_module = last_module
                    if groups[8]:
                        last_parent_interface = int(groups[8])
                    if groups[7]:
                        first_parent_interface = int(groups[7])
                    else:
                        first_parent_interface = last_parent_interface
                    if groups[12]:
                        last_interface = int(groups[12])
                    if groups[11]:
                        first_interface = int(groups[11])
                    else:
                        first_interface = last_interface
                    if groups[16]:
                        last_subinterface = int(groups[16])
                    if groups[15]:
                        first_subinterface = int(groups[15])
                    else:
                        first_subinterface = last_subinterface

                    @ctx.benchmark
                    def expand_subinterfaces(interface_string):
                        result = []
                        if last_subinterface:
                            for subinterface in range(first_subinterface, last_subinterface + 1):
                                result.append(f"{interface_string}.{subinterface}")
                        else:
                            result.append(interface_string)
                        return result

                    @ctx.benchmark
                    def expand_interfaces(interface_string):
                        result = []
                        for interface in range(first_interface, last_interface + 1):
                            for res in expand_subinterfaces(f"{interface_string}{interface}"):
                                result.append(res)
                        return result

                    @ctx.benchmark
                    def expand_parent_interfaces(interface_string):
                        result = []
                        if last_parent_interface:
                            for parent_interface in range(first_parent_interface, last_parent_interface + 1):
                                for res in expand_interfaces(f"{interface_string}{parent_interface}/"):
                                    result.append(res)
                        else:
                            for res in expand_interfaces(f"{interface_string}"):
                                result.append(res)
                        return result

                    @ctx.benchmark
                    def expand_module(interface_string):
                        result = []
                        if last_module:
                            for module in range(first_module, last_module + 1):
                                for res in expand_parent_interfaces(f"{interface_string}{module}/"):
                                    result.append(res)
                        else:
                            for res in expand_parent_interfaces(f"{interface_string}"):
                                result.append(res)
                        return result

                    result.extend(expand_module(prefix))

                else:
                    raise IndexError(f"Invalid range, got {one_range} and found {search_result.groups()}")

    return result


@ctx.benchmark
def default(*values):
    """
    Accepts any number of arguments. Return the first value which is not None
    Last resort is to return None.
    Parameters
    ----------
    *values : any
        One or more values to test
    Returns
    -------
    any
        First value which is not None
    """

    for value in values:
        if value is not None:
            return value
    return None

@ctx.benchmark
def unique(in_list):
    list_set = set(in_list)
    return list(list_set)

@ctx.benchmark
def compare_dicts(dict1: dict, dict2: dict, ignore_keys: set[str] | None = None) -> tuple[bool, set[str]]:
    keys1 = set(dict1).difference(ignore_keys or [])
    keys2 = set(dict2).difference(ignore_keys or [])
    result = keys1 == keys2 and all(dict1[key] == dict2[key] for key in keys1)
    if result:
        return (result, set())

    # We have some difference, so now compare again listing the keys that differ.
    diff_keys = keys1.difference(keys2)
    same_keys = keys1.intersection(keys2)
    diff_keys.update(key for key in same_keys if dict1[key] != dict2[key])

    return (result, diff_keys)

@ctx.benchmark
def get(dictionary, key, default=None, required=False, org_key=None, separator="."):
    """
    Get a value from a dictionary or nested dictionaries.
    Key supports dot-notation like "foo.bar" to do deeper lookups.
    Returns the supplied default value or None if the key is not found and required is False.
    Parameters
    ----------
    dictionary : dict
        Dictionary to get key from
    key : str
        Dictionary Key - supporting dot-notation for nested dictionaries
    default : any
        Default value returned if the key is not found
    required : bool
        Fail if the key is not found
    org_key : str
        Internal variable used for raising exception with the full key name even when called recursively
    separator: str
        String to use as the separator parameter in the split function. Useful in cases when the key
        can contain variables with "." inside (e.g. hostnames)
    Returns
    -------
    any
        Value or default value
    Raises
    ------
    AristaAvdMissingVariableError
        If the key is not found and required == True
    """

    if org_key is None:
        org_key = key
    keys = str(key).split(separator)
    value = dictionary.get(keys[0])
    if value is None:
        if required is True:
            raise TypeError(org_key)
        return default
    else:
        if len(keys) > 1:
            return get(value, separator.join(keys[1:]), default=default, required=required, org_key=org_key, separator=separator)
        else:
            return value


@ctx.benchmark
def get_all(data, path: str, required: bool = False, org_path=None):
    """
    Get all values from data matching a data path.
    Path supports dot-notation like "foo.bar" to do deeper lookups. Lists will be unpacked recursively.
    Returns an empty list if the path is not found and required is False.
    Parameters
    ----------
    data : any
        Data to walk through
    path : str
        Data Path - supporting dot-notation for nested dictionaries/lists
    required : bool
        Fail if the path is not found
    org_path : str
        Internal variable used for raising exception with the full path even when called recursively
    Returns
    -------
    list [ any ]
        List of values matching data path or empty list if no matches are found.
    Raises
    ------
    AristaAvdMissingVariableError
        If the path is not found and required == True
    """

    if org_path is None:
        org_path = path

    path_elements = str(path).split(".")
    if isinstance(data, list):
        output = []
        for data_item in data:
            output.extend(get_all(data_item, path, required=required, org_path=org_path))

        return output

    elif isinstance(data, dict):
        value = data.get(path_elements[0])

        if value is None:
            if required:
                raise TypeError(org_path)

            return []

        if len(path_elements) > 1:
            return get_all(value, ".".join(path_elements[1:]), required=required, org_path=org_path)

        else:
            return [value]

    return []


@ctx.benchmark
def get_item(list_of_dicts: list, key, value, default=None, required=False, case_sensitive=False, var_name=None):
    """
    Get one dictionary from a list of dictionaries by matching the given key and value
    Returns the supplied default value or None if there is no match and "required" is False.
    Will return the first matching item if there are multiple matching items.
    Parameters
    ----------
    list_of_dicts : list(dict)
        List of Dictionaries to get list item from
    key : any
        Dictionary Key to match on
    value : any
        Value that must match
    default : any
        Default value returned if the key and value is not found
    required : bool
        Fail if there is no match
    case_sensitive : bool
        If the search value is a string, the comparison will ignore case by default
    var_name : str
        String used for raising exception with the full variable name
    Returns
    -------
    any
        Dict or default value
    Raises
    ------
    AristaAvdMissingVariableError
        If the key and value is not found and "required" == True
    """

    if var_name is None:
        var_name = key

    if (not isinstance(list_of_dicts, list)) or list_of_dicts == [] or value is None or key is None:
        if required is True:
            raise KeyError(var_name)
        return default

    for list_item in list_of_dicts:
        if not isinstance(list_item, dict):
            # List item is not a dict as required. Skip this item
            continue
        if list_item.get(key) == value:
            # Match. Return this item
            return list_item

    # No Match
    if required is True:
        raise KeyError(var_name)
    return default

@ctx.benchmark
def append_if_not_duplicate(
    list_of_dicts: list[dict],
    primary_key: str,
    new_dict: dict,
    context: str,
    context_keys: list[str],
    ignore_same_dict: bool = True,
    ignore_keys: set[str] | None = None,
) -> None:
    if (found_dict := get_item(list_of_dicts, primary_key, new_dict[primary_key])) is None:
        list_of_dicts.append(new_dict)
        return

    if (compare_result := compare_dicts(new_dict, found_dict, ignore_keys))[0] and ignore_same_dict:
        return

    context_keys.extend(sorted(compare_result[1]))
    context_item_a = str({context_key: get(new_dict, context_key) for context_key in context_keys})
    context_item_b = str({context_key: get(found_dict, context_key) for context_key in context_keys})
    raise AristaAvdDuplicateDataError(context, context_item_a, context_item_b)

@ctx.benchmark
def strip_null_from_data(data, strip_values_tuple=(None,)):
    """
    strip_null_from_data Generic function to strip null entries regardless type of variable.
    Parameters
    ----------
    data : Any
        Data to look for null content to strip out
    Returns
    -------
    Any
        Cleaned data with no null.
    """
    if isinstance(data, dict):
        return strip_empties_from_dict(data, strip_values_tuple)
    elif isinstance(data, list):
        return strip_empties_from_list(data, strip_values_tuple)
    return data


@ctx.benchmark
def strip_empties_from_list(
    data,
    strip_values_tuple=(
        None,
        "",
        [],
        {},
    ),
):
    """
    strip_empties_from_list Remove entries with null value from a list
    Parameters
    ----------
    data : Any
        data to filter
    strip_values_tuple : tuple, optional
        Value to remove from data, by default (None, "", [], {},)
    Returns
    -------
    Any
        Cleaned list with no strip_values_tuple
    """
    new_data = []
    for v in data:
        if isinstance(v, dict):
            v = strip_empties_from_dict(v, strip_values_tuple)
        elif isinstance(v, list):
            v = strip_empties_from_list(v, strip_values_tuple)
        if v not in strip_values_tuple:
            new_data.append(v)
    return new_data


@ctx.benchmark
def strip_empties_from_dict(
    data,
    strip_values_tuple=(
        None,
        "",
        [],
        {},
    ),
):
    """
    strip_empties_from_dict Remove entries with null value from a dict
    Parameters
    ----------
    data : Any
        data to filter
    strip_values_tuple : tuple, optional
        Value to remove from data, by default (None, "", [], {},)
    Returns
    -------
    Any
        Cleaned dict with no strip_values_tuple
    """
    new_data = {}
    for k, v in data.items():
        if isinstance(v, dict):
            v = strip_empties_from_dict(v, strip_values_tuple)
        elif isinstance(v, list):
            v = strip_empties_from_list(v, strip_values_tuple)
        if v not in strip_values_tuple:
            new_data[k] = v
    return new_data


@ctx.benchmark
def set_studio_outputs(switch_facts, l3_egress_interfaces, l2_egress_interfaces):
    """
    This sets the outputs of the Fabric Studio.
    To be used as Inputs by other studios, such as Services Studios.
    Currently the key/value store for passing the outputs is tags.
    The following are the current outputs:
        - NetworkServices - device capability for L3 and/or L2 services
        - mlag_peer_link - device mlag peer link/port-channel
        - bgp_as - AS to indicate taht bgp is being used
        - router_id
        - Vtep - to indicate EVPN overlay is being used
        - Uplinks - the L2 uplinks
        - Downlinks - the L2 downlinks
    """
    device_id = switch_facts['serial_number']
    dev = ctx.topology.getDevices(deviceIds=[device_id])[0]

    # NodeId tag
    # Create/Update/Apply the NodeId tag
    # dev._assignTag(ctx, Tag('NodeId', str(switch_facts['id'])))

    # Role tag
    role_dict = {"spine": "Spine", "leaf": "Leaf", "memberleaf": "Member-Leaf"}
    if dev_role := switch_facts.get("type"):
        # Allow dual role tags for DC Leaf being used as Campus Spine
        if switch_facts.get('dcLeaf-CampusSpine'):
            dev._assignTag(ctx, Tag('Role', role_dict[dev_role]),
                replaceValue=False)
        else:
            dev._assignTag(ctx, Tag('Role', role_dict[dev_role]),
                replaceValue=True)
    # Update network services tags
    # if switch_facts.get('network_services_l3'):
    #     dev._assignTag(ctx, Tag('NetworkServices', 'L3'), replaceValue=False)
    # else:
    #     dev._unassignTag(ctx, Tag('NetworkServices', 'L3'))
    # if switch_facts.get('network_services_l2'):
    #     dev._assignTag(ctx, Tag('NetworkServices', 'L2'), replaceValue=False)
    # else:
    #     dev._unassignTag(ctx, Tag('NetworkServices', 'L2'))
    # Update mlag_peer_link
    # if switch_facts.get('mlag') and switch_facts.get('mlag_port_channel_id'):
    #     mlag_peer_link = f"Port-Channel{switch_facts['mlag_port_channel_id']}"
    #     dev._assignTag(ctx, Tag('mlag_peer_link', mlag_peer_link))
    # else:
    #     dev._unassignTag(ctx, Tag('mlag_peer_link', None))

    # Update routing tags
    # bgp_tags = {"bgp_as": switch_facts.get('bgp_as'), "router_id": switch_facts.get('router_id')}
    # if switch_facts.get('underlay_router') \
    #     and (switch_facts['underlay_routing_protocol'] == "bgp"
    #         or switch_facts['overlay_routing_protocol'] == "bgp"):
    #     # Set bgp as and router id tags
    #     for label, value in bgp_tags.items():
    #         dev._assignTag(ctx, Tag(str(label), str(value)))
    # else:
    #     # Remove possible bgp tags
    #     for label, value in bgp_tags.items():
    #         # Remove tags with same label that don't match proper value
    #         if value is None:
    #             dev._unassignTag(ctx, Tag(str(label), None))
    # Update Vtep tag
    # if switch_facts.get('vtep'):
    #     dev._assignTag(ctx, Tag('Vtep', 'True'))
    # else:
    #     dev._unassignTag(ctx, Tag('Vtep', None))

    # Required for services to know purpose of links,
    # Currently tagging: fabric/uplink/downlink/mlag/egress links.
    # Ensure only the studio identified links are tagged as such,
    # handling potential changes in the topology/inputs
    # Note: Do not update uplink tags for Campus Spine that's also DC Leaf,
    #       let the L3LS studio update DC Leaf uplinks for this case.
    if switch_facts.get('dcLeaf-CampusSpine'):
        uplinkTagUnAssigns, uplinkTagAssigns = [], []
    else:
        uplinkTagUnAssigns, uplinkTagAssigns = get_xlink_outputs(switch_facts, 'Uplink')
    downlinkTagUnAssigns, downlinkTagAssigns = get_xlink_outputs(switch_facts, 'Downlink')
    mlagTagUnAssigns, mlagTagAssigns = get_mlag_outputs(switch_facts)
    egressTagUnAssigns, egressTagAssigns = get_egress_outputs(
        switch_facts, l3_egress_interfaces, l2_egress_interfaces)
    linkTagUnAssigns = (egressTagUnAssigns +
        mlagTagUnAssigns + uplinkTagUnAssigns + downlinkTagUnAssigns)
    linkTagAssigns = (egressTagAssigns +
        mlagTagAssigns + uplinkTagAssigns + downlinkTagAssigns)
    ctx.tags._unassignInterfaceTags(linkTagUnAssigns)
    ctx.tags._assignInterfaceTags(linkTagAssigns)


@ctx.benchmark
def add_tagAssigns(tagAssigns, tag, nodes, intfs, device_id):
    """
    Add tags to tagAssigns for nodes/intfs
    Note: pair node and intf entries by same array index
    """
    if len(intfs) != len(nodes):
        return
    for i, nodeId in enumerate(nodes):
        if nodeId != device_id:
            continue
        intf = intfs[i].split('.')[0]    # handle subinterfaces
        tagAssigns.append((nodeId, intf, tag.label,
                   tag.value, False))
    return tagAssigns


@ctx.benchmark
def get_fabric_outputs(switch_facts):
    """
    This returns the fabric link outputs of the Fabric Studio.
    """
    device_id = switch_facts['serial_number']
    dev = ctx.topology.getDevices(deviceIds=[device_id])[0]
    tag = Tag('Link-Type', 'Fabric')
    currTagLinks = dev.getInterfacesByTag(ctx, tag)
    currTagLinks = [intf.name for intf in currTagLinks]
    tagAssigns = []
    tagUnAssigns = []
    # add link fabric tags to uplinks/downlinks
    intfs = list(switch_facts.get('topology', {}).get('links',{}).keys())
    add_tagAssigns(tagAssigns, tag, [device_id] * len(intfs), intfs, device_id)
    # add link fabric tags to mlag interfaces
    intfs = switch_facts.get('mlag_peer_switch_interfaces', [])
    add_tagAssigns(tagAssigns, tag, [device_id] * len(intfs), intfs, device_id)
    # remove duplicates
    tagAssigns = list(set(tagAssigns))
    # update based on changes
    linksToTag = [assign[1] for assign in tagAssigns]
    linksToUnTag = [lnk for lnk in currTagLinks if lnk not in linksToTag]
    for lnk in linksToUnTag:
        tagUnAssigns.append((device_id, lnk, tag.label, tag.value))
    return tagUnAssigns, tagAssigns


@ctx.benchmark
def get_mlag_outputs(switch_facts):
    """
    This returns the mlag link outputs of the Fabric Studio.
    """
    device_id = switch_facts['serial_number']
    dev = ctx.topology.getDevices(deviceIds=[device_id])[0]
    tag = Tag('Link-Type', 'MLAG')
    ftag = Tag('Link-Type', 'Fabric')
    currTagLinks = dev.getInterfacesByTag(ctx, tag)
    currTagLinks = [intf.name for intf in currTagLinks]
    tagAssigns = []
    tagUnAssigns = []
    # add link mlag tags to mlag interfaces
    intfs = switch_facts.get('mlag_peer_switch_interfaces', [])
    add_tagAssigns(tagAssigns, tag, [device_id] * len(intfs), intfs, device_id)
    add_tagAssigns(tagAssigns, ftag, [device_id] * len(intfs), intfs, device_id)
    # remove duplicates
    tagAssigns = list(set(tagAssigns))
    # update based on changes
    linksToTag = [assign[1] for assign in tagAssigns]
    linksToUnTag = [lnk for lnk in currTagLinks if lnk not in linksToTag]
    for lnk in linksToUnTag:
        tagUnAssigns.append((device_id, lnk, tag.label, tag.value))
        tagUnAssigns.append((device_id, lnk, ftag.label, ftag.value))
    return tagUnAssigns, tagAssigns


@ctx.benchmark
def get_egress_outputs(switch_facts, l3_egress_interfaces, l2_egress_interfaces):
    """
    This returns the egress link outputs of the Fabric Studio.
    """
    device_id = switch_facts['serial_number']
    dev = ctx.topology.getDevices(deviceIds=[device_id])[0]
    tag = Tag('Link-Type', 'Egress')
    currTagLinks = dev.getInterfacesByTag(ctx, tag)
    currTagLinks = [intf.name for intf in currTagLinks]
    tagAssigns = []
    tagUnAssigns = []
    # add link egress tags to l3 egress interfaces
    for egressIntf in l3_egress_interfaces:
        if not (intfs := egressIntf.get('interfaces')) or not (
            nodes := egressIntf.get('nodes')):
            continue
        add_tagAssigns(tagAssigns, tag, nodes, intfs, device_id)
    # add link egress tags to l2 egress interfaces
    for endpoints_info in l2_egress_interfaces.values():
        for endpoint in endpoints_info:
            for adapter in endpoint.get("adapters", []):
                if not (intfs := adapter.get('switch_ports')) or not (
                    nodes := adapter.get('switches')):
                    continue
                add_tagAssigns(tagAssigns, tag, nodes, intfs, device_id)
    # remove duplicates
    tagAssigns = list(set(tagAssigns))
    # update based on changes
    linksToTag = [assign[1] for assign in tagAssigns]
    linksToUnTag = [lnk for lnk in currTagLinks if lnk not in linksToTag]
    for lnk in linksToUnTag:
        tagUnAssigns.append((device_id, lnk, tag.label, tag.value))
    return tagUnAssigns, tagAssigns


@ctx.benchmark
def get_xlink_outputs(switch_facts, type: str):
    """
    This returns the Uplinks or Downlinks outputs of the Fabric Studio.
    type is either Uplink or Downlink
    """
    device_id = switch_facts['serial_number']
    dev = ctx.topology.getDevices(deviceIds=[device_id])[0]
    tag = Tag('Link-Type', type)
    ftag = Tag('Link-Type', 'Fabric')
    currTagLinks = dev.getInterfacesByTag(ctx, tag)
    currTagLinks = [intf.name for intf in currTagLinks]
    tagAssigns = []
    tagUnAssigns = []
    typeKey = f'{type.lower()}_interfaces'
    intfs = []
    for link in switch_facts.get(typeKey, []):
        intfs.append(link)
    add_tagAssigns(tagAssigns, tag, [device_id] * len(intfs), intfs, device_id)
    add_tagAssigns(tagAssigns, ftag, [device_id] * len(intfs), intfs, device_id)
    linksToTag = [assign[1] for assign in tagAssigns]
    linksToUnTag = [lnk for lnk in currTagLinks if lnk not in linksToTag]
    for lnk in linksToUnTag:
        tagUnAssigns.append((device_id, lnk, tag.label, tag.value))
        tagUnAssigns.append((device_id, lnk, ftag.label, ftag.value))
    return tagUnAssigns, tagAssigns


@ctx.benchmark
def set_uplinks_downlinks(switch_facts):
    uplinks = {}
    downlinks = {}
    uplink_type = None
    downlink_type = None
    if switch_facts.get('type') == 'spine':
        uplink_type = None
        downlink_type = 'leaf'
    elif switch_facts.get('type') == 'leaf':
        uplink_type = 'spine'
        downlink_type = 'memberleaf'
    elif switch_facts.get('type') == 'memberleaf':
        uplink_type = 'leaf'
        downlink_type = None
    for link, linkInfo in switch_facts.get('topology', {}).get(
            'links', {}).items():
        if linkInfo.get('type') != 'underlay_l2':
            continue
        if linkInfo.get('peer_type') == uplink_type:
            if (po := linkInfo.get('channel_group_id')):
                uplinks.setdefault('Po%s' % po, []).append(link)
            else:
                uplinks.setdefault(link)
        if linkInfo.get('peer_type') == downlink_type:
            if (po := linkInfo.get('channel_group_id')):
                downlinks.setdefault('Po%s' % po, []).append(link)
            else:
                downlinks.setdefault(link)
    switch_facts['Uplinks'] = uplinks
    switch_facts['Downlinks'] = downlinks



# Get egress device functions
@ctx.benchmark
def get_external_devices(external_devices, no_assert=False):
    '''
    Get connectivity details for egress devices in AVD format. Includes getting:
        - l2 connected endpoint data
        - l3 edge interfaces
        - network services bgp peerings
        - network services svis used for transit peerings over trunk
    '''
    avd_connected_endpoints = {}
    avd_l3_interfaces = []
    avd_bgp_peerings = []
    for external_device in external_devices:
        if "trunk" in external_device["egressConnectionGroup"].get("egressConnection", ""):
            # Add endpoint type to avd_connected_endpoints dict
            connected_endpoint = get_external_connected_endpoint(external_device)
            if not connected_endpoint:
                continue
            endpoint_type = connected_endpoint.pop("type")
            if not avd_connected_endpoints.get(endpoint_type):
                avd_connected_endpoints[endpoint_type] = []
            avd_connected_endpoints[endpoint_type].append(connected_endpoint)
            avd_bgp_peerings += get_egress_svi_peerings(external_device)
        elif external_device["egressConnectionGroup"].get("egressConnection", "") == "p2p":
            l3_edge, bgp_peers = get_l3_edge_p2p(external_device, no_assert=no_assert)
            if l3_edge:
                avd_l3_interfaces += l3_edge
            if bgp_peers:
                avd_bgp_peerings += bgp_peers
        elif external_device["egressConnectionGroup"].get("egressConnection", "") == "subinterfaces":
            l3_edge, bgp_peers = get_l3_edge_subinterfaces(external_device, no_assert=no_assert)
            if l3_edge:
                avd_l3_interfaces += l3_edge
            if bgp_peers:
                avd_bgp_peerings += bgp_peers
    return avd_connected_endpoints, avd_l3_interfaces, avd_bgp_peerings

@ctx.benchmark
def get_external_connected_endpoint(connected_endpoint):
    '''
    Get connectivity details for egress devices in AVD connected endpoints format.
    '''
    if not connected_endpoint:
        return
    tmp_connected_endpoint = {
        "name": connected_endpoint["name"],
        "type": connected_endpoint["uplinkDeviceType"]
    }
    adapter = {}
    adapter["switches"] = []
    adapter["switch_ports"] = []
    adapter["endpoint_ports"] = []
    adapter["descriptions"] = []
    for link in connected_endpoint["egressInterfaces"]:
        link_details = link['egressInterface'].inputs['interfaces']
        if not link_details:
            continue
        switch_serial_number = next(iter(link_details))
        switch_interface = list(link_details.values())[0][0]
        endpoint_interface = link['externalDeviceInterface']
        adapter["switches"].append(switch_serial_number)
        adapter["switch_ports"].append(switch_interface)
        adapter["endpoint_ports"].append(endpoint_interface)
        description = f"TO_{connected_endpoint['name'].upper()}"
        if endpoint_interface:
            description += f"_{endpoint_interface.upper()}"
        adapter["descriptions"].append(description)

    # Enable/Disable
    if connected_endpoint.get("enabled", "").strip():
        adapter["enabled"] = str_to_bool(connected_endpoint["enabled"])
    # Speed
    if connected_endpoint.get("speed", "").strip():
        adapter["speed"] = connected_endpoint["speed"]
    # Mode
    adapter["mode"] = "trunk"
    # vlans
    if connected_endpoint.get("vlans"):
        # VLANs
        if connected_endpoint["vlans"].get("vlans", "").strip():
            adapter["vlans"] = connected_endpoint["vlans"]["vlans"]
        if connected_endpoint["vlans"].get("stpInterOp"):
            adapter["allow_vlan_1"] = True
    # PTP
    if connected_endpoint.get("ptp"):
        adapter["ptp"] = {
            "enabled": str_to_bool(connected_endpoint["ptp"]["enabled"].strip()),
            "profile": connected_endpoint["ptp"]["profile"],
            "endpoint_role": connected_endpoint["ptp"]["endpointRole"]
        }
        # Need to set the below to null so we remove unconfigured interfaces from output
        if not adapter["ptp"]["enabled"]:
            adapter["ptp"]["profile"] = None
            adapter["ptp"]["endpoint_role"] = None
    # EOS CLI
    if connected_endpoint.get("eosCli"):
        adapter["raw_eos_cli"] = connected_endpoint["eosCli"]
    # port-channel
    if connected_endpoint.get("portChannel"):
        port_channel = {}
        # membership
        port_channel["member"] = str_to_bool(connected_endpoint["portChannel"].get("portChannel"))
        if port_channel["member"]:
            # mode
            port_channel_mode = connected_endpoint["portChannel"].get("portChannelMode")
            port_channel["mode"] = port_channel_mode if port_channel_mode else "active"
            # description
            description = connected_endpoint["portChannel"].get("description")
            port_channel["description"] = description if description else f"TO_{connected_endpoint['name'].upper()}"
            # channel id
            port_channel["channel_id"] = connected_endpoint["portChannel"].get("portChannelId")
            # enabled
            port_channel["enabled"] = connected_endpoint["portChannel"].get("portChannelEnabled")
            # mlag
            port_channel_mlag = connected_endpoint["portChannel"].get("mlag")
            if port_channel_mlag:
                port_channel["mlag"] = str_to_bool(port_channel_mlag)
            if port_channel_mlag:
                port_channel["mlag"] = str_to_bool(port_channel_mlag)
            # EOS CLI
            if connected_endpoint["portChannel"].get("eosCli"):
                port_channel["raw_eos_cli"] = connected_endpoint["portChannel"]["eosCli"]

        adapter["port_channel"] = port_channel

    tmp_connected_endpoint["adapters"] = [adapter]
    return tmp_connected_endpoint

@ctx.benchmark
def get_l3_edge_p2p(external_device, no_assert=False):
    '''
    Get connectivity details for egress devices in AVD l3_edge format.
    '''
    avd_l3_edge_interfaces = []
    avd_l3_edge_bgp_peers = []
    routing_protocol = external_device["egressConnectionGroup"].get("egressRouting").lower()
    for interface in external_device["egressInterfaces"]:
        l3_edge_interface = {}
        link_details = interface['egressInterface'].inputs['interfaces']
        if not link_details:
            continue
        switch_serial_number = next(iter(link_details))
        switch_interface = list(link_details.values())[0][0]
        endpoint_interface = interface.get('externalDeviceInterface', "")
        l3_edge_interface["nodes"] = [switch_serial_number]
        l3_edge_interface["interfaces"] = [switch_interface]
        l3_edge_interface["speed"] = external_device['speed'] if external_device.get('speed') else None
        l3_edge_interface["raw_eos_cli"] = external_device['eosCli'] if external_device.get('eosCli') else None
        l3_edge_interface["vrf"] = interface["vrf"] if interface.get("vrf") else "default"
        ip_address = interface['egressInterfaceIpAddress'] if interface.get('egressInterfaceIpAddress', '').strip() != "" else None
        if not no_assert:
            assert ip_address, f"Please enter an IP address for {switch_interface} connected to {external_device['name']}"
        l3_edge_interface["ip_addresses"] = [ip_address]
        description = f"TO_{external_device['name'].upper()}"
        if endpoint_interface:
            description += f"_{endpoint_interface.upper()}"
        l3_edge_interface["descriptions"] = [description]
        if get(external_device, "multicast.enabled"):
            l3_edge_interface["pim"] = {"enabled": True}
        if routing_protocol:
            if routing_protocol.lower() == "ospf" and get(external_device, "ospf"):
                l3_edge_interface["ospf"] = strip_null_from_data(
                    get_network_services_ospf_interface(external_device['ospf'])
                )
                l3_edge_interface["ospf"]["enabled"] = True
            elif routing_protocol.lower() == "ebgp":
                neighbor_ip_address = interface['neighborIpAddress'].split("/")[0] if interface.get('neighborIpAddress', '').strip() != "" else None
                my_asn = my_switch_facts_neighbors[switch_serial_number].get("bgp_as")
                if not no_assert:
                    assert neighbor_ip_address, f"Please enter a neighbor IP address for {switch_interface} connected to {external_device['name']}"
                    assert my_asn, f"{my_switch_facts_neighbors[switch_serial_number]['hostname']} requires a BGP ASN in order to set up a bgp peering to {external_device['name']}."
                    assert external_device['bgp'].get('remoteAs'), f"Please provide a BGP ASN for {external_device['name']}"
                # BGP info
                peer = get_network_services_bgp_peer(external_device['bgp'])
                peer['nodes'] = l3_edge_interface["nodes"]
                peer["vrf"] = l3_edge_interface["vrf"]
                peer['ip_address'] = neighbor_ip_address
                peer['password'] = interface['password'] if interface.get('password', '').strip() else None
                if not peer.get('description'):
                    peer['description'] = description
                avd_l3_edge_bgp_peers.append(peer)

        avd_l3_edge_interfaces.append(l3_edge_interface)

    return avd_l3_edge_interfaces, avd_l3_edge_bgp_peers

@ctx.benchmark
def get_l3_edge_subinterfaces(external_device, no_assert=False):
    '''
    Get connectivity details for egress devices in AVD proposed l3 edge format.
    '''
    avd_l3_edge_interfaces = []
    avd_l3_edge_bgp_peers = []
    routing_protocol = external_device["egressConnectionGroup"].get("egressRouting", "").lower()
    for interface in external_device["egressInterfaces"]:
        link_details = interface['egressInterface'].inputs['interfaces']
        if not link_details:
            continue
        switch_serial_number = next(iter(link_details))
        switch_interface = list(link_details.values())[0][0]
        endpoint_interface = interface.get('externalDeviceInterface', "")
        for subinterface in interface["subinterfaces"]:
            l3_edge_interface = {}
            l3_edge_interface["interfaces"] = [f"{switch_interface}.{subinterface['vlan']}"]
            l3_edge_interface["nodes"] = [switch_serial_number]
            l3_edge_interface["speed"] = external_device['speed'] if external_device.get('speed') else None
            l3_edge_interface["raw_eos_cli"] = external_device['eosCli'] if external_device.get('eosCli') else None
            l3_edge_interface["vrf"] = subinterface["vrf"] if subinterface.get("vrf") else "default"
            ip_address = subinterface['ipAddress'] if subinterface.get('ipAddress', '').strip() != "" else None
            if not no_assert:
                assert ip_address, f"Please enter an IP address for the subinterface {switch_interface} - {l3_edge_interface} connected to {external_device['name']}"
            l3_edge_interface["ip_addresses"] = [ip_address]
            description = subinterface.get("description")
            if not description:
                description = f"TO_{external_device['name'].upper()}"
                if endpoint_interface:
                    description += f"_{endpoint_interface.upper()}"
            l3_edge_interface["description"] = description
            if get(external_device, "multicast.enabled"):
                l3_edge_interface["pim"] = {"enabled": True}
            if routing_protocol:
                if routing_protocol == "ospf" and get(external_device, "ospf"):
                    l3_edge_interface["ospf"] = strip_null_from_data(
                        get_network_services_ospf_interface(external_device['ospf'])
                    )
                    l3_edge_interface["ospf"]["enabled"] = True
                if routing_protocol == "ebgp":
                    neighbor_ip_address = subinterface['neighborIpAddress'].split("/")[0] if subinterface.get('neighborIpAddress', '').strip() != "" else None
                    my_asn = my_switch_facts_neighbors[switch_serial_number].get("bgp_as")
                    if not no_assert:
                        assert neighbor_ip_address, f"Please enter a neighbor IP address for the subinterface {switch_interface} - {l3_edge_interface} connected to {external_device['name']}"
                        assert my_asn, f"{my_switch_facts_neighbors[switch_serial_number]['hostname']} requires a BGP ASN in order to set up a bgp peering to {external_device['name']}."
                        assert external_device['bgp'].get('remoteAs'), f"Please provide a BGP ASN for {external_device['name']}"
                    # BGP info
                    peer = get_network_services_bgp_peer(external_device['bgp'])
                    peer['nodes'] = l3_edge_interface["nodes"]
                    peer["vrf"] = l3_edge_interface["vrf"]
                    peer['ip_address'] = neighbor_ip_address
                    peer['password'] = subinterface['password'] if subinterface.get('password', '').strip() else None
                    if not peer.get('description'):
                        peer['description'] = description
                    avd_l3_edge_bgp_peers.append(peer)

            avd_l3_edge_interfaces.append(l3_edge_interface)

    return avd_l3_edge_interfaces, avd_l3_edge_bgp_peers

@ctx.benchmark
def get_egress_transit_svis(svis):
    '''
    Get svis used for transit peerings to egress devices in AVD network services format format.
    '''
    avd_svis = []
    for svi in svis:
        nodes = []
        devices = []
        for tag_matcher in svi["devices"]:
            tag_query = tag_matcher['tagQuery']
            tag_match_nodes = tag_query.inputs['devices']
            devices += tag_match_nodes
            if tag_match_nodes:
                nodes.append(
                    {
                        "node": tag_match_nodes[0],
                        "ip_address": tag_matcher["ipAddress"]
                    }
                )
        vrf = svi['vrf'] if svi.get('vrf', '') != "" else "default"
        assert svi.get('name'), f"Please enter a name for SVI {svi['id']} in Egress Connectivity section."
        avd_svi = {
            "devices": devices,
            "id": svi['id'],
            "enabled": True,
            "no_autostate": True,
            "name": svi['name'],
            "vrf": vrf,
            "vxlan": False,
            "nodes": nodes,
            "ip_helpers": {}
        }
        if svi.get('virtualIpAddress', '') != "":
            avd_svi["ip_virtual_router_addresses"] = [svi['virtualIpAddress']]
        if get(svi, "ospf.enabled"):
            avd_svi["ospf"] = strip_null_from_data(
                get_network_services_ospf_interface(svi["ospf"])
            )
        if get(svi, "multicast.enabled"):
            avd_svi["pim"] = {"enabled": True}
        if get(svi, "eosCli"):
            avd_svi["raw_eos_cli"] = svi["eosCli"]
        avd_svis.append(avd_svi)
    return avd_svis

@ctx.benchmark
def get_egress_svi_peerings(external_device):
    '''
    Get BGP peerings associated with svis used for transit peerings to egress devices in AVD network services format format.
    '''
    avd_svi_bgp_peerings = []
    routing_protocol = external_device["egressConnectionGroup"].get("egressRouting").lower()
    if (neighbor_asn := external_device['bgp'].get('remoteAs')) and routing_protocol == "ebgp":
        # BGP info
        bgp_peer = external_device['bgp']
        # Get nodes
        nodes = []
        for link in external_device["egressInterfaces"]:
            link_details = link['egressInterface'].inputs['interfaces']
            if not link_details:
                continue
            switch_serial_number = next(iter(link_details))
            nodes.append(switch_serial_number)
        # Set neighbor info
        for neighbor in external_device["neighborInfo"]:
            vrf = neighbor['vrf'] if neighbor.get('vrf', "").strip() != "" else "default"
            ip_address = neighbor['ipAddress'] if neighbor.get('ipAddress', "").strip() != "" else None
            if not ip_address:
                continue
            # BGP info
            peer = get_network_services_bgp_peer(external_device['bgp'])
            peer['nodes'] = nodes
            peer["vrf"] = vrf
            peer['ip_address'] = ip_address
            peer['password'] = neighbor['password'] if neighbor.get('password', '').strip() else None
            peer['update_source'] = neighbor['updateSource'] if neighbor.get('updateSource', '').strip() else None
            if not peer.get('description'):
                peer['description'] = description
            if neighbor.get('description'):
                peer['description'] = neighbor["description"]
            avd_svi_bgp_peerings.append(peer)
    return avd_svi_bgp_peerings

@ctx.benchmark
def get_egress_static_routes(egress_static_routes):
    '''
    Get static routes for egress connectivity in AVD network_services format.
    '''
    avd_static_routes = []
    for sr in egress_static_routes:
        nodes = []
        for tag_matcher in sr["devices"]:
            tag_query = tag_matcher['tagQuery']
            nodes += tag_query.inputs['devices']
        static_route = {
            "destination_address_prefix": sr["routeDetails"]["destinationAddressPrefix"],
            "name": sr["description"].replace(" ", "_"),
            "nodes": nodes
        }
        # vrf
        if sr["routeDetails"].get("vrf", "") == "":
            static_route["vrf"] = "default"
        else:
            static_route["vrf"] = sr["routeDetails"]["vrf"]
        # gateway
        if sr["routeDetails"].get("gateway", "") == "":
            static_route["gateway"] = None
        else:
            static_route["gateway"] = sr["routeDetails"]["gateway"]
        # interface
        if sr["routeDetails"].get("interface", "") == "":
            static_route["interface"] = None
        else:
            static_route["interface"] = sr["routeDetails"]["interface"]
        # distance
        if sr["routeDetails"].get("distance", "") == "":
            static_route["distance"] = None
        else:
            static_route["distance"] = sr["routeDetails"]["distance"]
        # distance
        if sr["routeDetails"].get("tag", "") == "":
            static_route["tag"] = None
        else:
            static_route["tag"] = sr["routeDetails"]["tag"]
        # metric
        if sr["routeDetails"].get("metric", "") == "":
            static_route["metric"] = None
        else:
            static_route["metric"] = sr["routeDetails"]["metric"]

        avd_static_routes.append(static_route)
    return avd_static_routes

@ctx.benchmark
def add_egress_l3_interfaces_to_network_services(egress_l3_interfaces, switch_facts):
    '''
    Adds L3 interfaces and BGP Peerings from the egress connectivity section to the AVD network services
    '''
    for l3_interface in egress_l3_interfaces:
        l3_interface = l3_interface.copy()
        egress_vrf = l3_interface.pop("vrf")
        vrf = get_egress_vrf(egress_vrf, switch_facts["network_services"])
        assert vrf, f"VRF {egress_vrf} referenced in egress interfaces but not found in Network Services.  Please create VRF {egress_vrf} under Network Services."
        # Add l3 interfaces
        if not vrf.get("l3_interfaces"):
            vrf["l3_interfaces"] = []
        vrf["l3_interfaces"].append(l3_interface)
    return switch_facts

@ctx.benchmark
def add_egress_bgp_peers_to_network_services(egress_bgp_peers, switch_facts):
    '''
    Adds SVI BGP Peerings from the egress connectivity section to the AVD network services
    '''
    for bgp_peer in egress_bgp_peers:
        bgp_peer = bgp_peer.copy()
        egress_vrf = bgp_peer.pop("vrf")
        vrf = get_egress_vrf(egress_vrf, switch_facts["network_services"])
        assert vrf, f"VRF {egress_vrf} referenced in egress BGP Peers but not found in Network Services.  Please create VRF {egress_vrf} under Network Services."
        if not vrf.get("bgp_peers"):
            vrf["bgp_peers"] = []
        vrf["bgp_peers"].append(bgp_peer)
    return switch_facts

@ctx.benchmark
def add_egress_svis_to_network_services(egress_svis, switch_facts):
    '''
    Adds SVIs from the egress connectivity section to the AVD network services
    '''
    for svi in egress_svis:
        svi = svi.copy()
        egress_vrf = svi.pop("vrf")
        vrf = get_egress_vrf(egress_vrf, switch_facts["network_services"])
        assert vrf, f"VRF {egress_vrf} referenced in egress SVIs but not found in Network Services.  Please create VRF {egress_vrf} under Network Services."
        if not vrf.get("svis"):
            vrf["svis"] = []
        vrf["svis"].append(svi)
    return switch_facts

@ctx.benchmark
def add_egress_srs_to_network_services(egress_srs, switch_facts):
    '''
    Adds static routes from the egress connectivity section to the AVD network services
    '''
    for sr in egress_srs:
        sr = sr.copy()
        egress_vrf = sr.pop("vrf")
        vrf = get_egress_vrf(egress_vrf, switch_facts["network_services"])
        assert vrf, f"VRF {egress_vrf} referenced in egress interfaces but not found in Network Services.  Please create VRF {egress_vrf} under Network Services."
        if not vrf.get("static_routes"):
            vrf["static_routes"] = []
        vrf["static_routes"].append(sr)

    return switch_facts


@ctx.benchmark
def device_matches_resolver_query(resolver, device_id):
    _, ctx_resolver = resolver.resolveWithContext(device_id)
    if ctx_resolver and ctx_resolver.query_str.strip() != "":
        return True
    else:
        return False


@ctx.benchmark
def get_mlag_peer(switch_facts):
    mlag_peer_switch_facts = None
    if switch_facts["type"] != "memberleaf":
        for tmp_switch_facts in my_switch_facts_neighbors.values():
            if switch_facts["type"] == tmp_switch_facts["type"] and \
                    switch_facts["group"] == tmp_switch_facts["group"] and \
                    switch_facts["serial_number"] != tmp_switch_facts["serial_number"]:
                return tmp_switch_facts
    elif switch_facts.get('access_pod_details'):
        for mlag_pair in switch_facts['access_pod_details']["memberLeafMlagPairs"]:
            mlag_primary_tag_query = mlag_pair['mlagPrimary']
            mlag_secondary_tag_query = mlag_pair['mlagSecondary']
            if switch_facts["serial_number"] in mlag_primary_tag_query.inputs['devices'] \
                    and len(mlag_secondary_tag_query.inputs['devices']) == 1:
                return my_switch_facts_neighbors[mlag_secondary_tag_query.inputs['devices'][0]]
            elif switch_facts["serial_number"] in mlag_secondary_tag_query.inputs['devices'] \
                    and len(mlag_primary_tag_query.inputs['devices']) == 1:
                return my_switch_facts_neighbors[mlag_primary_tag_query.inputs['devices'][0]]

    return mlag_peer_switch_facts


@ctx.benchmark
def get_mlag_ip(switch_facts, mlag_peer_ipv4_pool, mlag_peer_subnet_mask, mlag_role):
    validateIPNetwork(mlag_peer_ipv4_pool, network_name=f"MLAG Peering Pool for {switch_facts['type']}s in {switch_facts['campus']} -> {switch_facts['campus_pod']}")
    mlag_subnet = ipaddress.ip_network(mlag_peer_ipv4_pool)
    assert mlag_subnet.prefixlen <= mlag_peer_subnet_mask, f"MLAG Subnet mask length set for {switch_facts['hostname']} must be longer than the mask of the mlag subnet -> {str(mlag_subnet)}"
    # Check formula
    if switch_facts["fabric_ip_addressing"]["mlag"]["algorithm"] != "same_subnet" and mlag_subnet.prefixlen != mlag_peer_subnet_mask:
        # first_id formula
        index = int(switch_facts["mlag_primary_id"]) - 1
        # odd_id formula
        if switch_facts["fabric_ip_addressing"]["mlag"]["algorithm"] == "odd_id":
            index = _mlag_odd_id_based_offset(switch_facts)
    else:
        index = 0
    assert index < len(list(mlag_subnet.subnets(new_prefix=mlag_peer_subnet_mask))), f"There is not enough address space to allocate unique /31 subnets for the number of MLAG pairs in {switch_facts['campus']} -> {switch_facts['campus_pod']}. If you wish to re-use the same /31 pool for all MLAG pairs, enter a /30 or /31 size pool."
    mlag_subnet = list(mlag_subnet.subnets(new_prefix=mlag_peer_subnet_mask))[index]
    if mlag_role == "primary":
        return list(mlag_subnet.hosts())[0]
    elif mlag_role == "secondary":
        return list(mlag_subnet.hosts())[1]
    return


@ctx.benchmark
def get_router_id(switch_facts):
    validateIPNetwork(switch_facts["loopback_ipv4_pool"], network_name=f"Router ID Pool for {switch_facts['type']}s in {switch_facts['campus']} -> {switch_facts['campus_pod']}")
    switch_id = switch_facts["id"]
    offset = switch_facts["loopback_ipv4_offset"]
    return get_host_from_network(switch_facts, 'loopback_ipv4_pool', (switch_id - 1) + offset)


@ctx.benchmark
def get_vtep_loopback(switch_facts, offset=None):
    validateIPNetwork(switch_facts["vtep_loopback_ipv4_pool"], network_name=f"VTEP Source Address Pool for {switch_facts['type']}s in {switch_facts['campus']} -> {switch_facts['campus_pod']}")
    if offset is None:
        offset=0
    if switch_facts["type"] == "spine":
        return get_host_from_network(switch_facts,
                                     'vtep_loopback_ipv4_pool', 0)
    index = switch_facts["id"] - 1
    if switch_facts.get("mlag_primary_id"):
        index = switch_facts["mlag_primary_id"] - 1
    index += offset
    return get_host_from_network(switch_facts,
                                 'vtep_loopback_ipv4_pool', index)


@ctx.benchmark
def get_child_inband_management_ip(switch_facts, offset=0):
    validateIPNetwork(switch_facts["inband_management_subnet"], network_name=f"Inband Management Pool in {switch_facts['campus']} -> {switch_facts['campus_pod']}")
    ib_mgmt_subnet_length = ipaddress.ip_network(switch_facts["inband_management_subnet"]).prefixlen
    # Use same virtual ip, primary mlag switch ip, and secondary mlag switch ip on all gateways
    host_addresses = list(ipaddress.ip_network(switch_facts['inband_management_subnet']).hosts())
    ib_hosts_in_pod = []
    # get switches in same pod
    leaf_switches_in_pod = natural_sort([tmp_switch_facts for tmp_switch_facts in my_switch_facts_neighbors.values() if tmp_switch_facts['group'] == switch_facts['group'] and tmp_switch_facts['type'] == 'leaf'], sort_key="id")
    memberleaf_switches_in_pod = natural_sort([tmp_switch_facts for tmp_switch_facts in my_switch_facts_neighbors.values() if tmp_switch_facts['group'] == switch_facts['group'] and tmp_switch_facts['type'] == 'memberleaf'], sort_key="id")
    if "l2ls" in switch_facts["campus_type"]:
        index = switch_facts["id"] - 1 + offset
    elif "l3ls" in switch_facts["campus_type"]:
        ib_hosts_in_pod = memberleaf_switches_in_pod
        for i, tmp_switch_facts in enumerate(ib_hosts_in_pod):
            if tmp_switch_facts['serial_number'] == switch_facts['serial_number']:
                index = i
                break

    ip_address = host_addresses[int(index) + 3]


    return f"{ip_address}/{ib_mgmt_subnet_length}"


@ctx.benchmark
def get_p2p_uplinks_ip(switch_facts, uplink_switch_facts, uplink_switch_index, index):
    if switch_facts.get('type') not in ["leaf", "spine"] or \
            switch_facts.get('uplink_ipv4_pool') is None or \
            switch_facts.get('uplink_ipv4_subnet_mask') is None:
        return
    uplink_ipv4_pool = switch_facts['uplink_ipv4_pool'].split(",")
    uplink_subnet_mask = switch_facts['uplink_ipv4_subnet_mask']
    uplink_offset = switch_facts['uplink_offset'] if switch_facts.get('uplink_offset') else 0
    switch_id = switch_facts['id']
    uplink_switch_id = uplink_switch_facts['id']

    previous_switches_seen = switch_facts['uplink_switches_ids'][:uplink_switch_index]
    number_of_times_uplink_switch_has_been_seen = previous_switches_seen.count(uplink_switch_facts['serial_number'])

    max_uplink_switches = 2
    max_parallel_uplinks = 1
    assert number_of_times_uplink_switch_has_been_seen < max_parallel_uplinks, \
        f"There are too many uplinks from {switch_facts['hostname']} to " \
        f"{uplink_switch_facts['hostname']}. " \
        f"The maximum allowed is {max_parallel_uplinks}."

    if len(uplink_ipv4_pool) > 1:
        uplink_ipv4_pool = uplink_ipv4_pool[uplink_switch_id - 1]
        uplink_switch_id = 1
        max_uplink_switches = 1
    else:
        uplink_ipv4_pool = uplink_ipv4_pool[0]

    validateIPNetwork(uplink_ipv4_pool, network_name=f"Uplink IP Pool for {switch_facts['type']}s in {switch_facts['campus']} -> {switch_facts['campus_pod']}")
    # Valid subnet checks
    child_subnets = list(ipaddress.ip_network(uplink_ipv4_pool).subnets(new_prefix=uplink_subnet_mask))
    max_leafs_possible = (len(child_subnets) - uplink_offset) / \
        (max_uplink_switches * max_parallel_uplinks)
    # This should provide starting index for potential uplink /31s
    # for this switch
    leaf_node_base_index = (switch_id - 1) * max_uplink_switches * max_parallel_uplinks
    # This should provide uplink switch index within above /31s
    spine_link_offset = (uplink_switch_id - 1) * max_parallel_uplinks + number_of_times_uplink_switch_has_been_seen
    # Note uplink_offset accounts for any offset from other uplink
    # switch layers
    child_subnet_index = leaf_node_base_index + spine_link_offset + uplink_offset
    assert len(child_subnets) - 1 >= child_subnet_index, \
        f"Not enough subnets in uplink pool {uplink_ipv4_pool}, {len(child_subnets)} subnets. " \
        f"Based on the nodeIDs it seems to need atleast {child_subnet_index} subnets."
    child_subnet = child_subnets[child_subnet_index]
    return get_ip_from_subnet(switch_facts['hostname'],
                              switch_facts['type'],
                              child_subnet, 'uplink_ipv4_pool', index)


@ctx.benchmark
def get_network_services_bgp_peer(peer_inputs):
    '''
    Parses studio inputs and returns bgp peer in AVD network services format
    '''
    peer = {}
    if peer_inputs.get("nodes"):
        peer['nodes'] = peer_inputs["nodes"]
    if peer_inputs.get("neighborIpAddress"):
        peer['ip_address'] = peer_inputs["neighborIpAddress"]
    if peer_inputs.get("remoteAs"):
        peer['remote_as'] = peer_inputs["remoteAs"]
    if peer_inputs.get("description"):
        peer['description'] = peer_inputs["description"]
    if peer_inputs.get('password', '').strip() != "":
        peer["password"] = peer_inputs["password"]
    if peer_inputs.get("sendCommunity"):
        peer['send_community'] = peer_inputs["sendCommunity"]
    if peer_inputs.get('nextHopSelf'):
        peer['next_hop_self'] = str_to_bool(peer_inputs['nextHopSelf'])
    if get(peer_inputs, "maxRoutes.maximumRoutes") is not None:
        peer['maximum_routes'] = peer_inputs['maxRoutes']['maximumRoutes']
    if get(peer_inputs, "maxRoutes.warningLimit") is not None:
        peer['warning_limit_routes'] = peer_inputs['maxRoutes']['warningLimit']
    if get(peer_inputs, "defaultOriginate.bgpPeerDefaultOriginateEnable"):
        peer['default_originate'] = {
            "always": peer_inputs['defaultOriginate'].get('always')
        }
    if peer_inputs.get('updateSource', '').strip() != "":
        peer['update_source'] = peer_inputs['updateSource']
    if peer_inputs.get('ebgpMultihop') is not None:
        peer['ebgp_multihop'] = peer_inputs['ebgpMultihop']
    if get(peer_inputs, "nextHop.ipv4NextHop"):
        peer['set_ipv4_next_hop'] = peer_inputs['nextHop']['ipv4NextHop']
    if get(peer_inputs, "nextHop.ipv6NextHop"):
        peer['set_ipv6_next_hop'] = peer_inputs['nextHop']['ipv6NextHop']
    if get(peer_inputs, "routeMap.routeMapOut"):
        peer['route_map_out'] = peer_inputs['routeMap']['routeMapOut']
    if get(peer_inputs, "routeMap.routeMapIn"):
        peer['route_map_in'] = peer_inputs['routeMap']['routeMapIn']
    if peer_inputs.get('weight'):
        peer['weight'] = peer_inputs['weight']
    if peer_inputs.get('localAs'):
        peer['local_as'] = peer_inputs['localAs']
    return peer


@ctx.benchmark
def get_network_services_ospf_interface(ospf_inputs):
    '''
    Parses studio inputs and returns l3 interface ospf data in AVD network services format
    '''
    ospf = {}
    if ospf_inputs.get('enabled'):
        ospf['enabled'] = ospf_inputs['enabled']
    if ospf_inputs.get('pointToPoint') is not None:
        ospf['point_to_point'] = ospf_inputs['pointToPoint']
    ospf["area"] = ospf_inputs.get("area", "0.0.0.0")
    if ospf_inputs.get("cost"):
        ospf["cost"] = ospf_inputs["cost"]
    if (ospf_authentication := ospf_inputs.get("authentication","").lower()):
        ospf["authentication"] = ospf_authentication
        if ospf_authentication == "simple":
            ospf["simple_auth_key"] =ospf_inputs["simpleAuthKey"]
        elif ospf_authentication == "message-digest":
            ospf["message_digest_keys"] = []
            for key in ospf_inputs["messageDigestKeys"]:
                mdk = {
                    "id": key["id"],
                    "hash_algorithm": key["hashAlgorithm"],
                    "key": key["key"]
                }
                ospf["message_digest_keys"].append(mdk)
    return ospf


@ctx.benchmark
def get_egress_vrf(vrf_name, network_services):
    '''
    Returns vrf based on name if found in any tenant in AVD network services
    '''
    for tenant in network_services:
        for vrf in tenant.get("vrfs", []):
            if vrf["name"] == vrf_name:
                return vrf
    return None


@ctx.benchmark
def set_mlag_switch_facts(switch_facts):
    if switch_facts.get("mlag_support"):
        mlag_peer_switch_facts = get_mlag_peer(switch_facts)
        if mlag_peer_switch_facts is not None:
            switch_facts["mlag"] = True
        else:
            switch_facts["mlag"] = False

        if switch_facts["mlag"] and mlag_peer_switch_facts is not None:
            switch_facts["mlag_peer"] = mlag_peer_switch_facts["hostname"]
            switch_facts["mlag_peer_serial_number"] = mlag_peer_switch_facts["serial_number"]
    else:
        switch_facts["mlag"] = False

    return switch_facts


@ctx.benchmark
def set_switch_facts(switch_facts):
    # device_id from switch_facts
    device_id = switch_facts["serial_number"]

    # set campus pod routing protocols if not set
    if not campus_pod_details.get("campusPodRoutingProtocols"):
        campus_pod_details["campusPodRoutingProtocols"] = {
            "campusPodUnderlayRoutingProtocol": None
        }

    # Set defaults for fabricConfigurations
    if not campus_pod_details.get("fabricConfigurations"):
        campus_pod_details["fabricConfigurations"] = {}

    if not campus_pod_details["fabricConfigurations"].get("mstInstances"):
        campus_pod_details["fabricConfigurations"]["mstInstances"] = []

    if not campus_pod_details["fabricConfigurations"].get("ospfDetails"):
        campus_pod_details["fabricConfigurations"]["ospfDetails"] = {
                "processId": 100,
                "area": "0.0.0.0",
                "maxLsa": 12000,
                "bfd": False
        }

    if not campus_pod_details["fabricConfigurations"].get("multicast"):
        campus_pod_details["fabricConfigurations"]["multicast"] = {}

    if not campus_pod_details["fabricConfigurations"].get("ptp"):
        campus_pod_details["fabricConfigurations"]["ptp"] = {}

    if not campus_pod_details["fabricConfigurations"].get("inbandManagementDetails"):
        campus_pod_details["fabricConfigurations"]["inbandManagementDetails"] = {}

    if not campus_pod_details["fabricConfigurations"].get("ipLocking"):
        campus_pod_details["fabricConfigurations"]["ipLocking"] = {}

    # Set Dot1x defaults
    if not campus_pod_details["fabricConfigurations"].get("dot1x"):
        campus_pod_details["fabricConfigurations"]["dot1x"] = {"enable": False}
    if not campus_pod_details["fabricConfigurations"]["dot1x"].get("dynamicAuthorization"):
        campus_pod_details["fabricConfigurations"]["dot1x"]["dynamicAuthorization"] = {}
    if not campus_pod_details["fabricConfigurations"]["dot1x"].get("macBasedAuthentication"):
        campus_pod_details["fabricConfigurations"]["dot1x"]["macBasedAuthentication"] = {}
    if not campus_pod_details["fabricConfigurations"]["dot1x"].get("lldpBypass"):
        campus_pod_details["fabricConfigurations"]["dot1x"]["lldpBypass"] = None
    if not campus_pod_details["fabricConfigurations"]["dot1x"].get("radiusAvPair"):
        campus_pod_details["fabricConfigurations"]["dot1x"]["radiusAvPair"] = {}
    if not campus_pod_details["fabricConfigurations"]["dot1x"].get("radiusAvPairUsernameFormat"):
        campus_pod_details["fabricConfigurations"]["dot1x"]["radiusAvPairUsernameFormat"] = {}

    # Set MTU defaults
    if not campus_pod_details["fabricConfigurations"].get("mtu"):
        campus_pod_details["fabricConfigurations"]["mtu"] = {"p2pUplinksMtu": 9200}

    # Set EVPN defaults
    if not campus_pod_details["fabricConfigurations"].get("evpn"):
        campus_pod_details["fabricConfigurations"]["evpn"] = {"evpnEbgpMultihop": 3}

    access_pod_details = campus_pod_details["accessPods"].resolve(device=device_id)
    if access_pod_details:
        access_pod_details = access_pod_details["accessPodFacts"]

    # Get fabric details
    if switch_facts["underlay_router"]:
        switch_facts["underlay_routing_protocol"] = campus_pod_details["campusPodRoutingProtocols"]["campusPodUnderlayRoutingProtocol"].lower()
        if campus_pod_details["campusPodRoutingProtocols"].get("campusPodOverlayRoutingProtocol") and campus_pod_details["design"]["vxlanOverlay"]:
            switch_facts["overlay_routing_protocol"] = campus_pod_details["campusPodRoutingProtocols"]["campusPodOverlayRoutingProtocol"].lower()
        else:
            switch_facts["overlay_routing_protocol"] = ""
    else:
        switch_facts["underlay_routing_protocol"] = ""
        switch_facts["overlay_routing_protocol"] = ""
    # Get MLAG ip addressing and bgp numbering formulas
    switch_facts["fabric_ip_addressing"] = fabric_variables["fabric_ip_addressing"]

    # Get node defaults from user inputs
    if switch_facts["type"] == "spine":
        node_defaults = campus_pod_details.get("spineDefaults", {})
    else:
        node_defaults = campus_pod_details.get("accessPodDefaults", {})

    # Set STP defaults
    if not node_defaults.get("spanningTreeDetails"):
        node_defaults["spanningTreeDetails"] = {
            "spanningTreeMode": "mstp",
            "spineSpanningTreePriority": None,
            "leafSpanningTreePriority": None,
            "memberLeafSpanningTreePriority": None
        }
    # Set uplink defaults
    if not node_defaults.get("uplinkInterfaceDetails"):
        node_defaults["uplinkInterfaceDetails"] = {
            "leafUplinksEosCli": "",
            "memberLeafUplinksEosCli": "",
            "leafPortChannelUplinksEosCli": "",
            "memberLeafPortChannelUplinksEosCli": ""
        }

    # Set MLAG defaults
    if not node_defaults.get("mlagDetails"):
        node_defaults["mlagDetails"] = {
            "mlagPeerVlan": 4094,
            "mlagPeerL3Vlan": None,
            "mlagPeerIPv4Pool": "169.254.0.0/31",
            "mlagPeerL3IPv4Pool": "",
            "mlagPeerLinkEosCli": "",
            "mlagDomainId": "MLAG",
            "mlagPortChannelId": None,
            "mlagPeerInterfacesEosCli": "",
            "virtualRouterMacAddress": "00:1c:73:00:00:99",
            "mlagDualPrimaryDetection": False
        }

    # Set BGP defaults
    if not node_defaults.get("bgpDetails"):
        node_defaults["bgpDetails"] = {
            "bgpAsns": "",
            "bgpDefaults": ""
        }
    # TBD - not sure how this logic makes sense if invoking
    # set_switch_facts for neighbors of spines and leafs.
    # ie. if the user explicitly enters asns, are they supposed to enter
    # the same range for both spines and leafs, and is this going to
    # handle that nodeIds may overlap for spines and leafs?
    if not (bgpAsns := node_defaults.get("bgpDetails").get("bgpAsns", "")):
        if switch_facts["type"] == "spine":
            bgpAsns = "65000"
        elif switch_facts["type"] == "leaf":
            bgpAsns = "65001-65535"

    # Set OSPF defaults
    if not node_defaults.get("ospfDetails"):
        node_defaults["ospfDetails"] = {
            "ospfDefaults": "redistribute connected"
        }

    # Set PTP defaults
    if not node_defaults.get("ptpDetails"):
        node_defaults["ptpDetails"] = {
            "priority1": None,
            "leafPriority1": None,
            "memberLeafPriority1": None
        }

    # Get spanning tree details
    if switch_facts["network_services_l2"]:
        switch_facts["spanning_tree_mode"] = node_defaults["spanningTreeDetails"].get("spanningTreeMode", "").lower()
        if switch_facts["type"] == "spine":
            if switch_facts["network_services_l2"] and switch_facts["network_services_l3"]:
                switch_facts["spanning_tree_priority"] = node_defaults["spanningTreeDetails"].get("spineSpanningTreePriority") if node_defaults["spanningTreeDetails"].get("spineSpanningTreePriority") else 4096
            else:
                switch_facts["spanning_tree_priority"] = node_defaults["spanningTreeDetails"].get("spineSpanningTreePriority")
        elif switch_facts["type"] == "leaf":
            if switch_facts["network_services_l2"] and switch_facts["network_services_l3"]:
                switch_facts["spanning_tree_priority"] = node_defaults["spanningTreeDetails"].get("leafSpanningTreePriority") if node_defaults["spanningTreeDetails"].get("leafSpanningTreePriority") else 4096
            else:
                switch_facts["spanning_tree_priority"] = node_defaults["spanningTreeDetails"].get("leafSpanningTreePriority")
        elif switch_facts["type"] == "memberleaf":
            switch_facts["spanning_tree_priority"] = node_defaults["spanningTreeDetails"].get("memberLeafSpanningTreePriority")

        if switch_facts["spanning_tree_mode"] == "mstp":
            if len(campus_pod_details["fabricConfigurations"].get("mstInstances", [])) > 0:
                switch_facts["mst_instances"] = {}
                for instance in campus_pod_details["fabricConfigurations"]["mstInstances"]:
                    # vlans
                    if instance.get("mstInstanceVlans", "").strip() != "":
                        vlans = list_compress(string_to_list(instance["mstInstanceVlans"]))
                        switch_facts["mst_instances"][instance["mstInstanceId"]] = {"vlans": vlans}
                        # priority
                        if switch_facts["type"] == "spine":
                            spanning_tree_priority = instance.get("mstInstanceSpineStpPriority")
                        elif switch_facts["type"] == "leaf":
                            spanning_tree_priority = instance.get("mstInstanceLeafStpPriority")
                        else:  # switch_facts["type"] == "memberleaf"
                            spanning_tree_priority = instance.get("mstInstanceMemberLeafStpPriority")

                        switch_facts["mst_instances"][instance["mstInstanceId"]]["spanning_tree_priority"] = spanning_tree_priority if spanning_tree_priority is not None else switch_facts["spanning_tree_priority"]

    # Get uplink interfaces
    if switch_facts["type"] == "leaf":
        switch_facts["uplink_interface_cli"] = node_defaults["uplinkInterfaceDetails"].get("leafUplinksEosCli")
        switch_facts["uplink_port_channel_interface_cli"] = node_defaults["uplinkInterfaceDetails"].get("leafPortChannelUplinksEosCli")
    elif switch_facts["type"] == "memberleaf":
        switch_facts["uplink_interface_cli"] = node_defaults["uplinkInterfaceDetails"].get("memberLeafUplinksEosCli")
        switch_facts["uplink_port_channel_interface_cli"] = node_defaults["uplinkInterfaceDetails"].get("memberLeafPortChannelUplinksEosCli")
    else:
        switch_facts["uplink_interface_cli"] = ""
        switch_facts["uplink_port_channel_interface_cli"] = ""

    # virtual router mac
    if switch_facts["network_services_l2"] and switch_facts["network_services_l3"]:
        switch_facts["virtual_router_mac_address"] = node_defaults["mlagDetails"]["virtualRouterMacAddress"]

    # Get mlag settings
    if (switch_facts.get("mlag_peer_serial_number")) and (mlag_peer_switch_facts := my_switch_facts_neighbors.get(switch_facts['mlag_peer_serial_number'])):
        if switch_facts["underlay_router"]:
            switch_facts["mlag_l3"] = True
        else:
            switch_facts["mlag_l3"] = False
        mlag_domain_id = node_defaults["mlagDetails"].get("mlagDomainId", "").strip()
        if mlagPortChannelIdOverride := node_defaults['mlagDetails'].get(
            'mlagPortChannelId'):
            switch_facts["mlag_port_channel_id"] = mlagPortChannelIdOverride
        if not mlag_domain_id:
            mlag_domain_id = "MLAG"
        if mlag_domain_id == "Use Group Name":
            mlag_domain_id = switch_facts["group"]
        switch_facts["mlag_group"] = mlag_domain_id
        switch_facts["mlag_peer_vlan"] =  node_defaults["mlagDetails"]["mlagPeerVlan"]
        switch_facts["mlag_peer_ipv4_pool"] = node_defaults["mlagDetails"]["mlagPeerIPv4Pool"]
        switch_facts["mlag_peer_subnet_mask"] = fabric_variables["fabric_ip_addressing"]["mlag"]["ipv4_prefix_length"]
        if switch_facts.get("underlay_router"):
            # Set mlag_peer_l3_vlan if there is value set in studio input
            if node_defaults['mlagDetails']['mlagPeerL3Vlan'] is not None \
                    and node_defaults['mlagDetails']['mlagPeerL3IPv4Pool'].strip() != "":
                switch_facts['mlag_peer_l3_vlan'] = node_defaults['mlagDetails']['mlagPeerL3Vlan']
                switch_facts['mlag_peer_l3_ipv4_pool'] = node_defaults['mlagDetails']['mlagPeerL3IPv4Pool']
                switch_facts['mlag_peer_l3_subnet_mask'] = switch_facts["mlag_peer_subnet_mask"]
            else:
                switch_facts['mlag_peer_l3_vlan'] = switch_facts['mlag_peer_vlan']
                switch_facts['mlag_peer_l3_ipv4_pool'] = switch_facts["mlag_peer_ipv4_pool"]
                switch_facts['mlag_peer_l3_subnet_mask']= switch_facts["mlag_peer_subnet_mask"]
        switch_facts["mlag_dual_primary_detection"] = node_defaults["mlagDetails"]["mlagDualPrimaryDetection"]
        switch_facts["mlag_lacp_mode"] = "active"
        switch_facts["reload_delay_mlag"] = switch_facts['platform_settings']['reload_delay']['mlag']
        switch_facts["reload_delay_non_mlag"] = switch_facts['platform_settings']['reload_delay']['non_mlag']

        # switch_facts["mlag_ibgp_origin_incomplete"] = True

        if int(switch_facts["id"]) < int(mlag_peer_switch_facts["id"]):
            switch_facts["mlag_primary_id"] = int(switch_facts["id"])
            switch_facts["mlag_secondary_id"] = int(mlag_peer_switch_facts["id"])
            switch_facts["mlag_role"] = "primary"

            switch_facts["mlag_ip"] = str(get_mlag_ip(switch_facts, switch_facts["mlag_peer_ipv4_pool"],
                                                        switch_facts["mlag_peer_subnet_mask"], "primary"))

            switch_facts["mlag_peer_ip"] = str(get_mlag_ip(switch_facts, switch_facts["mlag_peer_ipv4_pool"],
                                                            switch_facts["mlag_peer_subnet_mask"], "secondary"))

            if switch_facts.get("underlay_router"):
                switch_facts["mlag_l3_ip"] = str(get_mlag_ip(switch_facts, switch_facts["mlag_peer_l3_ipv4_pool"],
                                                                switch_facts["mlag_peer_l3_subnet_mask"], "primary"))

                switch_facts["mlag_peer_l3_ip"] = str(get_mlag_ip(switch_facts, switch_facts["mlag_peer_l3_ipv4_pool"],
                                                                    switch_facts["mlag_peer_l3_subnet_mask"], "secondary"))

        else:
            switch_facts["mlag_primary_id"] = int(mlag_peer_switch_facts["id"])
            switch_facts["mlag_secondary_id"] = int(switch_facts["id"])
            switch_facts["mlag_role"] = "secondary"

            switch_facts["mlag_ip"] = str(get_mlag_ip(switch_facts,
                switch_facts["mlag_peer_ipv4_pool"], switch_facts["mlag_peer_subnet_mask"], "secondary"))

            switch_facts["mlag_peer_ip"] = str(get_mlag_ip(switch_facts, switch_facts["mlag_peer_ipv4_pool"],
                                                            switch_facts["mlag_peer_subnet_mask"], "primary"))


            if switch_facts.get("underlay_router"):


                switch_facts["mlag_l3_ip"] = str(get_mlag_ip(switch_facts, switch_facts["mlag_peer_l3_ipv4_pool"],
                                                                switch_facts["mlag_peer_l3_subnet_mask"], "secondary"))

                switch_facts["mlag_peer_l3_ip"] = str(get_mlag_ip(switch_facts, switch_facts["mlag_peer_l3_ipv4_pool"],
                                                                    switch_facts["mlag_peer_l3_subnet_mask"], "primary"))

        # Set mlag interfaces
        # Set from topology studio
        switch_facts["mlag_interfaces"], switch_facts["mlag_peer_switch_interfaces"] = set_mlag_interfaces_from_topology(switch_facts)

        if len(switch_facts.get("mlag_interfaces", [])) > 0:
            switch_facts["mlag_interfaces_cli"] = node_defaults["mlagDetails"].get("mlagPeerInterfacesEosCli")
            switch_facts["mlag_peer_link_cli"] = node_defaults["mlagDetails"].get("mlagPeerLinkEosCli")


    # Get router related facts
    if switch_facts["underlay_router"] and node_defaults.get("routerIdPool"):
        switch_facts["loopback_ipv4_pool"] = node_defaults["routerIdPool"]

        if switch_facts["type"] == "spine":
            switch_facts["loopback_ipv4_offset"] = 0
        elif switch_facts["type"] == "leaf":
            if campus_pod_details["spineDefaults"]["routerIdPool"] == campus_pod_details["accessPodDefaults"]["routerIdPool"]:
                # Offset is 2
                switch_facts["loopback_ipv4_offset"] = 2
            else:
                switch_facts["loopback_ipv4_offset"] = 0

        # switch_facts["loopback_ipv4_description"]  =

        if switch_facts.get("underlay_routing_protocol"):
            # Set Router ID
            switch_facts["router_id_loopback_interface"] = "Loopback0"
            switch_facts["router_id"] = str(get_router_id(switch_facts))

            # Set uplink ipv4 pool
            switch_facts["uplink_ipv4_pool"] = node_defaults.get("uplinkIpv4Pool")
            switch_facts["uplink_ipv4_subnet_mask"] = fabric_variables["fabric_ip_addressing"]["p2p_uplinks"].get("ipv4_prefix_length", 31)

        # Set BGP parameters
        # Get asns
        asns = range_expand(bgpAsns)
        if set_bgp_as(switch_facts, avd_bgp_peers) and asns:
            # Set asns
            if len(asns) > 1:
                index = switch_facts["id"] - 1
                if switch_facts.get("mlag_primary_id"):
                    index = switch_facts["mlag_primary_id"] - 1
                if switch_facts["fabric_ip_addressing"]["mlag"]["bgp_numbering"] == "odd_id":
                    index = _mlag_odd_id_based_offset(switch_facts)
                switch_facts["bgp_as"] = asns[index]
            elif len(asns) == 1:
                switch_facts["bgp_as"] = asns[0]
            elif device_id == my_device.id:
                ctx.warning(f"No ASNs provided for "
                            f"Campus:{switch_facts['campus']} -> "
                            f"Campus-Pod:{switch_facts['campus_pod']}")
            # Set bgp defaults
            switch_facts["bgp_defaults"] = node_defaults["bgpDetails"]["bgpDefaults"]

            # Set bgp max paths
            switch_facts["bgp_maximum_paths"] = get(node_defaults, "bgpDetails.maximumPaths.bgpMaximumPaths")

            # Set bgp ecmp
            switch_facts["bgp_ecmp"] = get(node_defaults, "bgpDetails.maximumPaths.bgpEcmp")

            # Update wait-for-convergence
            switch_facts["bgp_update_wait_for_convergence"] = get(node_defaults, "bgpDetails.bgpUpdateWaitForConvergence", False)
            # Update wait-install
            switch_facts["bgp_update_wait_install"] = get(node_defaults, "bgpDetails.bgpUpdateWaitInstall", False)

            # bgp graceful restart
            if get(node_defaults, "bgpDetails.bgpGracefulRestart.enabled", False):
                switch_facts["bgp_graceful_restart"] = {
                    "enabled": True,
                    "restart_time": get(node_defaults, "bgpDetails.bgpGracefulRestart.restartTime", 300)
                }

            # bgp distance
            switch_facts["bgp_distance"] = {
                "external_routes": get(node_defaults, "bgpDetails.bgpDistance.externalRoutes"),
                "internal_routes": get(node_defaults, "bgpDetails.bgpDistance.internalRoutes"),
                "local_routes": get(node_defaults, "bgpDetails.bgpDistance.localRoutes")
            }

            # Set evpn role and evpn neighbors
            switch_facts["evpn_role"] = None
            switch_facts["evpn_route_server_ids"] = []
            switch_facts['evpn_route_servers_info'] = []
            if switch_facts["underlay_router"] is True and switch_facts["default_evpn_role"] is not None:
                # Set evpn role
                switch_facts["evpn_role"] = switch_facts.get("default_evpn_role")

                # Set default
                if switch_facts["evpn_role"] == "client":
                    # Set default evpn route servers
                    switch_facts["evpn_route_server_ids"] = switch_facts["uplink_switches_ids"]

                # Override default evpn route servers with user inputs
                if len(node_defaults["bgpDetails"].get("evpnRouteServers", [])) > 0:
                    evpn_route_server_ids = []
                    evpn_route_servers_info = []
                    for rs in node_defaults["bgpDetails"]["evpnRouteServers"]:
                        # Look up input to see if it matches the hostname of a switch in the campus pod
                        if (neighbor_info := my_switch_facts_neighbors_by_hostname.get(rs["hostname"])):
                            evpn_route_server_ids.append(neighbor_info["serial_number"])
                        else:
                            assert rs.get("ipAddress") and rs.get("remoteAs"), f"Could not find {rs['hostname']} in Campus Pod. Please enter IP Address and ASN for this remote EVPN route server neighbor."
                            evpn_route_servers_info.append({
                                "hostname": rs["hostname"],
                                "ip_address": rs["ipAddress"],
                                "bgp_as": rs["remoteAs"]
                            })
                    switch_facts["evpn_route_server_ids"] = evpn_route_server_ids
                    switch_facts["evpn_route_servers_info"] = evpn_route_servers_info

        # Set OSPF parameters
        if switch_facts["underlay_routing_protocol"] == "ospf":
            switch_facts["underlay_ospf_process_id"] = campus_pod_details["fabricConfigurations"]["ospfDetails"]["processId"]
            switch_facts["underlay_ospf_area"] = campus_pod_details["fabricConfigurations"]["ospfDetails"]["area"]
            switch_facts["underlay_ospf_max_lsa"] = campus_pod_details["fabricConfigurations"]["ospfDetails"]["maxLsa"]
            switch_facts["underlay_ospf_bfd_enable"] = campus_pod_details["fabricConfigurations"]["ospfDetails"]["bfd"]
            switch_facts["underlay_ospf_graceful_restart"] = {
                "enabled": get(node_defaults, "ospfDetails.ospfGracefulRestart.enabled", False),
                "grace_period": get(node_defaults, "ospfDetails.ospfGracefulRestart.gracePeriod", 600)
            }
            switch_facts["underlay_ospf_auto_cost_reference_bandwidth"] = get(node_defaults, "ospfDetails.ospfAutoCostReferenceBandwidth")
            switch_facts["ospf_defaults"] = node_defaults["ospfDetails"]["ospfDefaults"]

    if switch_facts["underlay_router"] and switch_facts["vtep"]:
        switch_facts["vtep_loopback_ipv4_pool"] = node_defaults.get("vtepLoopbackIPv4Pool")
        switch_facts["vtep_loopback"] = "Loopback1"
        if get(campus_pod_details, "accessPodDefaults.vtepLoopbackIPv4Pool") == get(campus_pod_details, "spineDefaults.vtepLoopbackIPv4Pool"):
            spine_offset = 2
        else:
            spine_offset = 0

        switch_facts["vtep_ip"] =  str(get_vtep_loopback(switch_facts, offset=spine_offset))

    # Get multicast
    switch_facts["underlay_multicast"] = campus_pod_details["fabricConfigurations"]["multicast"].get("underlayMulticast")
    if switch_facts["underlay_multicast"]:
        switch_facts["rps"] = []
        switch_facts["ipv6_rps"] = []
        for rp in campus_pod_details["fabricConfigurations"]["multicast"].get("rps", []):
            if validIPAddress(rp['ipAddress']) is True:
                switch_facts["rps"].append({"ip_address": rp['ipAddress'], "group_address": rp['groupAddress']})
            elif validIPAddress(rp['ipAddress']) is False:
                ctx.error(f"This studio currently does not support IPv6 Rendezvous Points")
                switch_facts["ipv6_rps"].append({"ip_address": rp['ipAddress'], "group_address": rp['groupAddress']})

    # Get PTP
    if switch_facts["type"] == "leaf":
        node_defaults["ptpDetails"]["priority1"] = node_defaults["ptpDetails"].get("leafPriority1")
    elif switch_facts["type"] == "memberleaf":
        node_defaults["ptpDetails"]["priority1"] = node_defaults["ptpDetails"].get("memberLeafPriority1")
    else:
        node_defaults["ptpDetails"]["priority1"] = node_defaults["ptpDetails"].get("priority1")

    # get ptp values at campus pod level
    ptp_enabled = campus_pod_details["fabricConfigurations"]["ptp"].get("enabled", False)  # get(self._hostvars, "ptp.enabled")
    default_ptp_domain = campus_pod_details["fabricConfigurations"]["ptp"].get("domain", 127)  # get(self._hostvars, "ptp.domain", default=127)
    default_ptp_profile = campus_pod_details["fabricConfigurations"]["ptp"].get("profile", "aes67-r16-2016")  # get(self._hostvars, "ptp.profile", default="aes67-r16-2016")


    # Check to see if the Access Pod has been selected for ptp config
    if ptp_enabled and switch_facts["type"] in ["leaf", "memberleaf"]:
        ptp_enabled = False
        for tag_matcher in campus_pod_details["fabricConfigurations"]["ptp"]["devices"]:
            tag_query = tag_matcher['tagQuery']
            if switch_facts["serial_number"] in tag_query.inputs['devices']:
                ptp_enabled = True
                break

    # get ptp values at node type level
    default_priority1 = node_defaults["ptpDetails"]["priority1"]
    default_priority2 = switch_facts["id"] % 256

    # get ptp values at access pod level
    if access_pod_details and access_pod_details.get("ptp"):
        default_priority1 = access_pod_details["ptp"]["priority1"]
        default_priority2 = access_pod_details["ptp"]["priority2"]

    # Get node-type ptp settings, node-group ptp settings, and node-level ptp settings
    ptp = {"enabled": ptp_enabled}
    # Get other settings
    if ptp["enabled"] is True:
        auto_clock_identity = node_defaults["ptpDetails"].get("autoClockIdentity")
        priority1 = default_priority1
        priority2 = default_priority2
        if auto_clock_identity:
            clock_identity_prefix = node_defaults["ptpDetails"]["ptpClockIdentityPrefix"]
            default_clock_indentity = f"{clock_identity_prefix}:{priority1:02x}:00:{priority2:02x}"
        else:
            default_clock_indentity = None
        ptp["device_config"] = {}
        ptp["device_config"]["mode"] = "boundary"
        ptp["device_config"]["forward_unicast"] = False
        ptp["device_config"]["clock_identity"] = default_clock_indentity
        ptp["device_config"]["source"] = {"ip": None}
        ptp["device_config"]["priority1"] = priority1
        ptp["device_config"]["priority2"] =  priority2
        ptp["device_config"]["ttl"] = 1
        ptp["device_config"]["domain"] = default_ptp_domain
        ptp["device_config"]["message_type"] = {
            "general": {
                "dscp": None,
            },
            "event": {
                "dscp": None,
            }
        }
        ptp["device_config"]["monitor"] = {
            "enabled": True,
            "threshold": {
                "offset_from_master": 250,
                "mean_path_delay": 1500,
                "drop": {
                    "offset_from_master": None,
                    "mean_path_delay": None,
                }
            },
            "missing_message": {
                "intervals": {
                    "announce": None,
                    "follow_up": None,
                    "sync": None
                },
                "sequence_ids": {
                    "enabled": True,
                    "announce": 3,
                    "delay_resp": 3,
                    "follow_up": 3,
                    "sync": 3
                }
            }
        }
        ptp["profile"] = default_ptp_profile
        switch_facts["ptp"] = strip_null_from_data(ptp, (None, {}))

    # Get inband management details
    if campus_pod_details["fabricConfigurations"].get("inbandManagementDetails"):
        # Set campus pod level variables
        # Only support default VRF for inband management as of today
        inband_mgmt_vrf = campus_pod_details["fabricConfigurations"]["inbandManagementDetails"].get("inbandManagementVrf", "default")
        switch_facts["inband_management_vrf"] = inband_mgmt_vrf if inband_mgmt_vrf.strip() != "" else "default"
        # All access pods to use same inband management subnet if it is an l2 campus design or an l3 vxlan design
        if "l2ls" in switch_facts["campus_type"]:  # or ("l3ls" in switch_facts["campus_type"] and "vxlan" in switch_facts["campus_type"]):
            # All access pods to use same VLAN ID for inband management
            switch_facts["inband_management_vlan"] = campus_pod_details["fabricConfigurations"]["inbandManagementDetails"].get("inbandManagementVlan")
            switch_facts["inband_management_subnet"] = campus_pod_details["fabricConfigurations"]["inbandManagementDetails"].get("inbandManagementSubnet")
            switch_facts["inband_management_gateway"] = campus_pod_details["fabricConfigurations"]["inbandManagementDetails"].get("inbandManagementGateway")
        # Each access pod requires its own unique inband management subnet (l3 campus w/no vxlan)
        elif switch_facts["type"] in ["leaf", "memberleaf"] and ("l3ls" in switch_facts["campus_type"]):
            # All access pods to use same VLAN ID for inband management
            switch_facts["inband_management_vlan"] = campus_pod_details["fabricConfigurations"]["inbandManagementDetails"].get("inbandManagementVlan")
            access_pod_inband_management_resolver = campus_pod_details["fabricConfigurations"]["inbandManagementDetails"]["accessPods"].resolve(device=device_id)
            access_pod_inband_mgmt_subnet = access_pod_inband_management_resolver["inbandManagementDetails"].get("inbandManagementSubnet")
            if switch_facts.get("inband_management_vlan"):
                assert access_pod_inband_mgmt_subnet, f"Inband Mgmt VLAN was provided but no subnet was provided. Please enter an inband management subnet for {switch_facts['campus']} -> {switch_facts['campus_pod']}-> {switch_facts['group']}"
            switch_facts["inband_management_subnet"] = access_pod_inband_mgmt_subnet
            switch_facts["inband_management_gateway"] = access_pod_inband_management_resolver["inbandManagementDetails"].get("inbandManagementGateway")
        # All network devices to use same dhcp server
        switch_facts["inband_management_ip_helpers"] = campus_pod_details["fabricConfigurations"]["inbandManagementDetails"].get("ipHelperAddresses", [])
        # Set boot vlan for devices that need to advertise inband ztp vlan to l2 downstream devices
        if switch_facts.get("network_services_l2"):
            switch_facts["advertise_inband_ztp_vlan"] = True
        # Set boot vlan for L2 child switches
        if ("l2ls" in switch_facts["campus_type"] and switch_facts["type"] in ["leaf", "memberleaf"]) or \
                ("l3ls" in switch_facts["campus_type"] and switch_facts["type"] in [ "memberleaf"]) or \
                ("l2ls" in switch_facts["campus_type"] and switch_facts["type"] == "spine" and not switch_facts["network_services_l3"]):

            if switch_facts.get("inband_management_vlan") and switch_facts.get("inband_management_subnet"):
                switch_facts["inband_management_role"] = "child"
                # inbound management parent devices
                switch_facts["inband_management_parents"] = switch_facts["uplink_switches_ids"]

                # inband management gateway
                if not switch_facts.get("inband_management_gateway"):
                    switch_facts["inband_management_gateway"] = str(get_host_from_network(switch_facts, "inband_management_subnet", 0))

                # inband management interface
                switch_facts["inband_management_interface"] = "Vlan{}".format(switch_facts["inband_management_vlan"])

        inband_mgmt_ip = None
        if switch_facts.get("inband_management_role", "") == "child":
            offset = 0
            if ("l2ls" in switch_facts["campus_type"] and spines_l2_only and switch_facts["type"] != "spine"):
                offset = 2
            inband_mgmt_ip = get_child_inband_management_ip(switch_facts, offset=offset)
        elif switch_facts.get("inband_management_subnet"):
            if switch_facts.get("mlag") and switch_facts["mlag_role"] == "secondary":
                inband_mgmt_ip = str(get_host_from_network(switch_facts, "inband_management_subnet", 2))
            else:
                inband_mgmt_ip = str(get_host_from_network(switch_facts, "inband_management_subnet", 1))
            # Set an inband mgmt interface for parent switch
            if not switch_facts.get("inband_management_interface"):
                switch_facts["inband_management_interface"] = "Vlan{}".format(switch_facts["inband_management_vlan"])
        if inband_mgmt_ip:
            switch_facts["inband_mgmt_ip"] = str(inband_mgmt_ip)

    # IP locking
    ip_locking_details = campus_pod_details["fabricConfigurations"].get("ipLocking")
    if ip_locking_details and (ip_locking_enabled := ip_locking_details.get("enable")):
        switch_facts["ip_locking"] = {
            "enabled": ip_locking_enabled,
            "ipv4_enforcement_enabled": True,
            "ipv6_enforcement_enabled": True,
        }
        if get(ip_locking_details, "ipv4LockingEnforcementEnabled", True) is False:
            switch_facts["ip_locking"]["ipv4_enforcement_enabled"] = False
        if get(ip_locking_details, "ipv6LockingEnforcementEnabled", True) is False:
            switch_facts["ip_locking"]["ipv6_enforcement_enabled"] = False

        switch_facts["ip_locking"]["mac_expiration_disabled"] = ip_locking_details.get("macExpirationDisabled", False)
        # Get DHCP Servers
        switch_facts["ip_locking"]["dhcp_servers"] = ip_locking_details["dhcpServers"]

        # Define source interface
        switch_facts["ip_locking"]["local_interface"] = get(ip_locking_details, "localInterface", default=switch_facts.get("inband_management_interface"))

    # Dot1x
    dot1x_enabled = campus_pod_details["fabricConfigurations"].get("dot1x", {}).get("enable")
    if dot1x_enabled:
        dot1x_details = campus_pod_details["fabricConfigurations"]["dot1x"]
        switch_facts["dot1x"] = {
            "system_auth_control": dot1x_details["enable"],
            "dynamic_authorization": dot1x_details["dynamicAuthorization"].get("enable"),
            "protocol_lldp_bypass": dot1x_details["lldpBypass"],
            "mac_based_authentication": {},
            "radius_av_pair": {},
            "radius_av_pair_username_format": {}
        }
        if get(dot1x_details, "dynamicAuthorization.port"):
            switch_facts["dot1x"]["dynamic_authorization_port"] = dot1x_details["dynamicAuthorization"]["port"]
        if get(dot1x_details, "macBasedAuthentication.delay"):
            switch_facts["dot1x"]["mac_based_authentication"]["delay"] = dot1x_details["macBasedAuthentication"]["delay"]
        if get(dot1x_details, "macBasedAuthentication.holdPeriod"):
            switch_facts["dot1x"]["mac_based_authentication"]["hold_period"] = dot1x_details["macBasedAuthentication"]["holdPeriod"]
        if get(dot1x_details, "radiusAvPair.serviceType"):
            switch_facts["dot1x"]["radius_av_pair"]["service_type"] = dot1x_details["radiusAvPair"]["serviceType"]
        if get(dot1x_details, "radiusAvPair.framedMtu"):
            switch_facts["dot1x"]["radius_av_pair"]["framed_mtu"] = dot1x_details["radiusAvPair"]["framedMtu"]
        dot1x_lldp = {
            "system_name": {},
            "system_description": {}
        }
        if get(dot1x_details, "radiusAvPair.lldp.systemName.enabled"):
            dot1x_lldp["system_name"] = {
                "enabled": dot1x_details["radiusAvPair"]["lldp"]["systemName"]["enabled"],
                "auth_only": get(dot1x_details, "radiusAvPair.lldp.systemName.authOnly", False)
            }
        if get(dot1x_details, "radiusAvPair.lldp.systemDescription.enabled"):
            dot1x_lldp["system_description"] = {
                "enabled": dot1x_details["radiusAvPair"]["lldp"]["systemDescription"]["enabled"],
                "auth_only": get(dot1x_details, "radiusAvPair.lldp.systemDescription.authOnly", False)
            }
        switch_facts["dot1x"]["radius_av_pair"]["lldp"] = dot1x_lldp
        dot1x_dhcp = {
            "hostname": {},
            "parameter_request_list": {},
            "vendor_class_id": {}
        }
        if get(dot1x_details, "radiusAvPair.dhcp.hostname.enabled"):
            dot1x_dhcp["hostname"] = {
                "enabled": dot1x_details["radiusAvPair"]["dhcp"]["hostname"]["enabled"],
                "auth_only": get(dot1x_details, "radiusAvPair.dhcp.hostname.authOnly", False)
            }
        if get(dot1x_details, "radiusAvPair.dhcp.parameterRequestList.enabled"):
            dot1x_dhcp["parameter_request_list"] = {
                "enabled": dot1x_details["radiusAvPair"]["dhcp"]["parameterRequestList"]["enabled"],
                "auth_only": get(dot1x_details, "radiusAvPair.dhcp.parameterRequestList.authOnly", False)
            }
        if get(dot1x_details, "radiusAvPair.dhcp.vendorClassId.enabled"):
            dot1x_dhcp["vendor_class_id"] = {
                "enabled": dot1x_details["radiusAvPair"]["dhcp"]["vendorClassId"]["enabled"],
                "auth_only": get(dot1x_details, "radiusAvPair.dhcp.vendorClassId.authOnly", False)
            }
        switch_facts["dot1x"]["radius_av_pair"]["dhcp"] = dot1x_dhcp
        if get(dot1x_details, "radiusAvPairUsernameFormat.delimiter") and get(dot1x_details, "radiusAvPairUsernameFormat.macStringCase"):
            switch_facts["dot1x"]["radius_av_pair_username_format"] = {
                "delimiter": dot1x_details["radiusAvPairUsernameFormat"]["delimiter"].lower(),
                "mac_string_case": dot1x_details["radiusAvPairUsernameFormat"]["macStringCase"].lower()
            }

    # MTU
    if re.match(veos_regex, switch_facts.get('platform', '')):
        switch_facts["p2p_uplinks_mtu"] = 1500
    else:
        p2p_uplinks_mtu = campus_pod_details["fabricConfigurations"]["mtu"].get("p2pUplinksMtu")
        switch_facts["p2p_uplinks_mtu"] = p2p_uplinks_mtu if p2p_uplinks_mtu else 9200

    switch_facts["default_interface_mtu"] = None
    if not get(switch_facts, "platform_settings.per_interface_mtu", True):
        switch_facts["p2p_uplinks_mtu"] = None
        switch_facts["default_interface_mtu"] = p2p_uplinks_mtu

    # for regex in jericho_platform_regexes:
    #     if re.search(regex, switch_facts["platform"]):
    #         switch_facts["reload_delay_mlag"] = 780
    #         switch_facts["reload_delay_non_mlag"] = 1020
    #         break

    # Check devices has unique IPv4 Pool.
    overlap_pool_check(switch_facts)
    return switch_facts


@ctx.benchmark
def get_device_interfaces(switch_facts):
    device_id = switch_facts['serial_number']
    interfaces = []

    for interface in ctx.topology.getDevices(deviceIds=[device_id])[0].getInterfaces():
        peer_device, peer_interface = interface.getPeerInfo()
        if peer_device and "Ethernet" in interface.name and "Management" not in peer_interface.name:
            interfaces.append({
                "interface_name": interface.name,
                "peer_interface_name": peer_interface.name,
                "peer_hostname": peer_device.hostName,
                "peer_serial_number": peer_device.id
            })

    return natural_sort(interfaces, sort_key='interface_name')


@ctx.benchmark
def set_mlag_interfaces_from_topology(switch_facts):
    device_id = switch_facts['serial_number']

    # initialize mlag interfaces
    mlag_interfaces = []
    mlag_peer_interfaces = []

    for interface in natural_sort(switch_facts["interfaces"], sort_key="interface_name"):
        neighbor = my_switch_facts_neighbors.get(interface["peer_serial_number"])
        if neighbor:
            # Leaf case
            if switch_facts['type'] == "leaf" and neighbor['type'] == "leaf":
                mlag_interfaces.append(interface["interface_name"])
                mlag_peer_interfaces.append(interface["peer_interface_name"])

            # Spine case
            elif switch_facts['type'] == "spine" and neighbor['type'] == "spine":
                mlag_interfaces.append(interface["interface_name"])
                mlag_peer_interfaces.append(interface["peer_interface_name"])

            # Member leaf case
            elif neighbor['serial_number'] == switch_facts["mlag_peer_serial_number"]:
                mlag_interfaces.append(interface["interface_name"])
                mlag_peer_interfaces.append(interface["peer_interface_name"])

    return mlag_interfaces, mlag_peer_interfaces


@ctx.benchmark
def get_uplink_info_from_topology(switch_facts):
    # Initialize return variables
    uplink_interfaces = []
    uplink_switches_switch_facts = []
    uplink_switches = []
    uplink_switches_ids = []
    uplink_switch_interfaces = []
    uplink_info_tuples = []

    device_id = switch_facts['serial_number']

    memberleafs_downstream = None  #  Used to account for topologies where a member leaf uplinks to another memberleaf

    for interface in natural_sort(switch_facts["interfaces"], sort_key="interface_name"):
        neighbor = my_switch_facts_neighbors.get(interface["peer_serial_number"])
        if neighbor:
            # Leaf case
            if switch_facts['type'] == "leaf":
                if neighbor['type'] == "spine":
                    uplink_info_tuples.append((interface['interface_name'], neighbor['hostname'], neighbor['serial_number'], interface["peer_interface_name"]))

            # Member Leaf case
            elif switch_facts['type'] == "memberleaf":
                if neighbor['type'] in ["leaf", "memberleaf"]:
                    uplink_info_tuples.append((interface['interface_name'], neighbor['hostname'], neighbor['serial_number'], interface["peer_interface_name"]))
                    if neighbor["type"] == "memberleaf":
                        memberleafs_downstream = True


    # to account for topologies where a memberleaf uplinks to another memberleaf,
    # cycle through memberleafs' uplinks to remove false memberleaf to memberleaf uplinks
    neighbors_to_remove = []
    if switch_facts['type'] == "memberleaf" and memberleafs_downstream:
        for uplink_info_tuple in uplink_info_tuples:
            uplink_switch_facts = my_switch_facts_neighbors.get(uplink_info_tuple[2])
            if (
                    (uplink_switch_facts["serial_number"] == switch_facts.get("mlag_peer_serial_number", ""))
                    or
                    (uplink_switch_facts and uplink_switch_facts["type"] == "memberleaf" and switch_facts["id"] < uplink_switch_facts["id"])
                    ):
                neighbors_to_remove.append(uplink_info_tuple)
    for neighbor_tuple in neighbors_to_remove:
        uplink_info_tuples.remove(neighbor_tuple)

    uplink_interfaces = [uplink_info_tuple[0] for uplink_info_tuple in uplink_info_tuples]
    uplink_switches = [uplink_info_tuple[1] for uplink_info_tuple in uplink_info_tuples]
    uplink_switches_ids = [uplink_info_tuple[2] for uplink_info_tuple in uplink_info_tuples]
    uplink_switch_interfaces = [uplink_info_tuple[3] for uplink_info_tuple in uplink_info_tuples]
    unique_uplink_switches_ids = set(uplink_switches_ids)
    if switch_facts.get("uplink_type", "") == "port-channel":
        assert len(unique_uplink_switches_ids) <= 2, f"{switch_facts['hostname']} has too many uplink neighbors in the fabric for an L2 port-channel: {uplink_switches_ids}"
        if len(unique_uplink_switches_ids) == 2:
            primary_neighbor = my_switch_facts_neighbors[unique_uplink_switches_ids.pop()]
            secondary_neighbor_id = unique_uplink_switches_ids.pop()
            assert primary_neighbor.get("mlag") and primary_neighbor["mlag_peer_serial_number"] == secondary_neighbor_id, \
                   f"{switch_facts['hostname']} must have only 1 logical uplink neighbor in the fabric for an L2 port-channel: {uplink_switches_ids}"

    return uplink_interfaces, uplink_switches, uplink_switches_ids, uplink_switch_interfaces


@ctx.benchmark
def set_switch_uplink_info(switch_facts):
    # Get interface info from topology studio
    switch_facts["uplink_interfaces"], switch_facts["uplink_switches"], switch_facts["uplink_switches_ids"], switch_facts["uplink_switch_interfaces"]  = get_uplink_info_from_topology(switch_facts)

    return switch_facts


@ctx.benchmark
def set_switch_downlink_info(switch_facts):
    '''
    Using switch_facts uplink info which is previously set by set_switch_uplink_info(switch_facts. campus_resolver), set the
    downlink info for switch_facts using the uplink info from other switches in my_switch_facts_neighbors
    '''
    switch_facts["downlink_switches_ids"] = []
    if switch_facts["type"] == "spine":
        for tmp_switch_sn, tmp_switch_facts in my_switch_facts_neighbors.items():
            if tmp_switch_facts["type"] == "leaf" and switch_facts["serial_number"] in tmp_switch_facts["uplink_switches_ids"] \
                    and tmp_switch_sn not in switch_facts["downlink_switches_ids"]:
                switch_facts["downlink_switches_ids"].append(tmp_switch_sn)
    elif switch_facts["type"] in ["leaf", "memberleaf"]:
        for tmp_switch_sn, tmp_switch_facts in my_switch_facts_neighbors.items():
            if tmp_switch_facts["type"] == "memberleaf" and tmp_switch_facts["group"] == switch_facts["group"] \
                    and switch_facts["serial_number"] in tmp_switch_facts["uplink_switches_ids"] and tmp_switch_sn not in switch_facts["downlink_switches_ids"]:
                switch_facts["downlink_switches_ids"].append(tmp_switch_sn)

    return switch_facts


@ctx.benchmark
def set_topology_facts(switch_facts):
    topology_facts = {
        "links": {}
    }
    if switch_facts["uplink_type"] == "p2p":
        for i, uplink_interface in enumerate(switch_facts["uplink_interfaces"]):
            link_facts = {}
            uplink_switch_id = switch_facts["uplink_switches_ids"][i]
            uplink_switch_facts = my_switch_facts_neighbors.get(uplink_switch_id)
            if uplink_switch_facts:
                link_facts["peer_id"] = uplink_switch_facts["serial_number"]
                link_facts["peer"] = uplink_switch_facts["hostname"]
                link_facts["peer_interface"] = switch_facts["uplink_switch_interfaces"][i]
                link_facts["peer_type"] = uplink_switch_facts["type"]
                link_facts["peer_bgp_as"] = uplink_switch_facts.get("bgp_as")
                link_facts["type"] = "underlay_p2p"
                link_facts["speed"] = uplink_switch_facts.get("uplink_interface_speed", "auto")
                link_facts["ip_address"] = str(get_p2p_uplinks_ip(switch_facts, uplink_switch_facts, i, 1))
                link_facts["subnet_mask"] = str(switch_facts["uplink_ipv4_subnet_mask"])
                link_facts["peer_ip_address"] = str(get_p2p_uplinks_ip(switch_facts, uplink_switch_facts, i, 0))
                link_facts["eos_cli"] = switch_facts.get("uplink_interface_cli", "")
                # multicast/pim
                if switch_facts.get("underlay_multicast"):
                    link_facts["underlay_multicast"] = True
                else:
                    link_facts["underlay_multicast"] = False
                # ptp
                if switch_facts.get("ptp") is not None and switch_facts["ptp"].get("enabled") is True:
                    link_facts["ptp"] = {"enable": True}

            topology_facts["links"][uplink_interface] = link_facts

    elif switch_facts["uplink_type"] == "port-channel":
        for i, uplink_interface in enumerate(switch_facts["uplink_interfaces"]):
            link_facts = {}
            uplink_switch_id = switch_facts["uplink_switches_ids"][i]
            uplink_switch_facts = my_switch_facts_neighbors.get(uplink_switch_id, {})
            link_facts["peer_id"] = uplink_switch_facts.get("serial_number")
            link_facts["peer"] = uplink_switch_facts.get("hostname", switch_facts["uplink_switches"][i])
            link_facts["peer_interface"] = switch_facts["uplink_switch_interfaces"][i]
            link_facts["peer_type"] = uplink_switch_facts.get("type")
            # Campus Service has a field here for allowed_vlans
            if switch_facts.get("allow_all_vlans", False) is False:
                # add list of vlans allowed on uplink interface
                uplink_vlans = list(set(range_expand(switch_facts["vlans"])))
                # if uplink switch has a list of vlans, remove the vlans that this switch has but uplink switch doesn't have
                if uplink_switch_facts.get("vlans") is not None:
                    uplink_vlans = list(set(range_expand(switch_facts["vlans"])) & set(range_expand(uplink_switch_facts.get("vlans", ""))))
                # add inband management vlan
                if switch_facts.get("inband_management_vlan"):
                    uplink_vlans.append(switch_facts["inband_management_vlan"])
                link_facts["vlans"] = [int(vlan) for vlan in uplink_vlans]
            link_facts["type"] = "underlay_l2"
            link_facts["speed"] = switch_facts.get("uplink_interface_speed", "auto")
            if uplink_switch_facts.get("mlag") is not None and uplink_switch_facts.get("mlag") is True:
                link_facts["channel_description"] = uplink_switch_facts["mlag_group"]

            # Used to determine whether or not port-channel towards uplink switch should have an mlag id
            unique_uplink_switches = set(switch_facts["uplink_switches_ids"])
            if switch_facts.get("mlag"):
                link_facts["peer_channel_description"] = switch_facts["mlag_group"]

                mlag_peer_switch_facts = my_switch_facts_neighbors[switch_facts["mlag_peer_serial_number"]]
                # Updating unique_uplink_switches with this switch's mlag peer's uplink switches
                unique_uplink_switches.update(mlag_peer_switch_facts.get("uplink_switches_ids"))

            # Only enable mlag for this port-channel on the uplink switch if there are multiple unique uplink switches
            link_facts["peer_mlag"] = len(unique_uplink_switches) > 1

            if switch_facts.get("mlag_role", "") == "secondary" and len(mlag_peer_switch_facts.get("uplink_interfaces", [])):
                link_facts["channel_group_id"] = "".join(re.findall(r'\d', mlag_peer_switch_facts["uplink_interfaces"][0]))
                link_facts["peer_channel_group_id"] = "".join(re.findall(r'\d', mlag_peer_switch_facts["uplink_switch_interfaces"][0]))
            else:
                link_facts["channel_group_id"] = "".join(re.findall(r'\d', switch_facts["uplink_interfaces"][0]))
                link_facts["peer_channel_group_id"] = "".join(re.findall(r'\d', switch_facts["uplink_switch_interfaces"][0]))

            if switch_facts.get("ptp") is not None and switch_facts["ptp"].get("enabled") is True:
                link_facts["ptp"] = {"enable": True}

            if switch_facts.get("uplink_interface_cli"):
                link_facts["eos_cli"] = switch_facts.get("uplink_interface_cli", "")

            if switch_facts.get("uplink_port_channel_interface_cli"):
                link_facts["port_channel_eos_cli"] = switch_facts["uplink_port_channel_interface_cli"]

            topology_facts["links"][uplink_interface] = link_facts

    switch_facts["topology"] = topology_facts
    return switch_facts


@ctx.benchmark
def set_base_config(config, switch_facts):
    # hostname
    config["hostname"] = switch_facts["hostname"]
    # IP locking
    # Check to see whether ip locking should be configured or not based on node type properties
    # Check to see if ip locking is supported on platform
    if switch_facts["connected_endpoints"] \
            and get(switch_facts, "ip_locking.enabled") \
            and get(switch_facts, "platform_settings.ip_locking.support") is True:

        config["address_locking"] = {}

        if switch_facts["network_services_l3"]:
            ctx.warning(f"IP Locking enforcement will not work on {switch_facts['hostname']} if ip helpers are configured.")

        # Add DHCP Servers
        if len(switch_facts["ip_locking"].get("dhcp_servers", [])) > 0:
            config["address_locking"]["dhcp_servers"] = []
            for dhcp_server_info in switch_facts["ip_locking"].get("dhcp_servers", []):
                config["address_locking"]["dhcp_servers"].append(dhcp_server_info["ipAddress"])
            config["address_locking"]["local_interface"] = switch_facts["ip_locking"].get("local_interface")

        # Note below is only supported on certain hardware
        if switch_facts["ip_locking"]["mac_expiration_disabled"]:
            config["address_locking"]["locked_address"] = {
                "expiration_mac": {
                    "enforcement": {
                        "disabled": True
                    }
                }
            }

        # Note below is only supported on certain hardware
        if switch_facts["ip_locking"]["ipv4_enforcement_enabled"] is False:
            if not get(config, "address_locking.locked_address"):
                config["address_locking"]["locked_address"] = {}
            config["address_locking"]["locked_address"]["ipv4"] = {
                "enforcement": {
                    "disabled": True
                }
            }

        # Note below is only supported on certain hardware (not supported on vEOS)
        if switch_facts["ip_locking"]["ipv6_enforcement_enabled"] is False:
            if not get(config, "address_locking.locked_address"):
                config["address_locking"]["locked_address"] = {}
            config["address_locking"]["locked_address"]["ipv6"] = {
                "enforcement": {
                    "disabled": True
                }
            }

    # Default interfaces MTU
    # Commenting out to avoid potential issues created from global mtu setting affecting the mgmt interface
    # if switch_facts.get("default_interface_mtu") is not None:
    #     config["interface_defaults"] = {"mtu": switch_facts["default_interface_mtu"]}

    # Set spanning tree
    if switch_facts.get("spanning_tree_mode"):
        # Set stp mode
        config["spanning_tree"]["mode"] = switch_facts["spanning_tree_mode"]
        # Set default stp priority
        if switch_facts.get("spanning_tree_priority"):
            if config["spanning_tree"]["mode"] == "mstp":
                # Base spanning tree settings
                config["spanning_tree"]["mst_instances"] = {
                    0: {"priority": switch_facts["spanning_tree_priority"]}
                }
                config['spanning_tree']['mst'] = {
                    'configuration': {
                        "instances": {}
                    }
                }
            elif config["spanning_tree"]["mode"] == "rapid-pvst":
                config["spanning_tree"]["rapid_pvst_instances"] = {
                    1: {"priority": switch_facts["spanning_tree_priority"]}
                }
            elif config["spanning_tree"]["mode"] == "rstp":
                config["spanning_tree"]["rstp_priority"] = switch_facts["spanning_tree_priority"]
        # Set mst instance stp priority
        if config["spanning_tree"]["mode"] == "mstp":
            if not config['spanning_tree'].get('mst_instances'):
                config['spanning_tree']['mst_instances'] = {}
            if switch_facts.get("mst_instances") and not config['spanning_tree'].get('mst'):
                config['spanning_tree']['mst'] = {
                    'configuration': {
                        "instances": {}
                    }
                }
            # MST instance collection user inputs
            for instance in convert_dicts(switch_facts.get("mst_instances", {}), primary_key='id'):
                # instance priority
                config["spanning_tree"]["mst_instances"][instance["id"]] = {"priority": instance["spanning_tree_priority"]}
                # instance vlans
                if instance.get("vlans") is not None:
                    config["spanning_tree"]["mst"]["configuration"]["instances"][instance["id"]] = {"vlans": instance["vlans"]}

    # Set tcam profile
    if switch_facts["platform_settings"].get("tcam_profile") is not None:
        config["tcam_profile"] = {
            "system": switch_facts["platform_settings"]["tcam_profile"]
        }
    # Set routing
    config["service_routing_protocols_model"] = "multi-agent"
    config["ip_routing"] = True

    # Set ptp
    if switch_facts.get("ptp") and switch_facts["ptp"].get("enabled") is True:
        config["ptp"] = switch_facts["ptp"]["device_config"]

    # Set multicast
    if switch_facts["underlay_router"]:
        config["ip_routing"] = True
        if switch_facts.get("underlay_multicast"):
            config["router_multicast"] = {
                "ipv4": {
                    "routing": True
                },
                "vrfs": []
            }
            if len(switch_facts["rps"]) > 0 or len(switch_facts["ipv6_rps"]) > 0:
                config["router_pim_sparse_mode"] = {"vrfs": []}
            # IPv4 RPs
            if len(switch_facts["rps"]) > 0:
                config["router_pim_sparse_mode"]["ipv4"] = {"rp_addresses": {}}
            for rp in switch_facts["rps"]:
                if rp["ip_address"] not in config["router_pim_sparse_mode"]["ipv4"]["rp_addresses"]:
                    config["router_pim_sparse_mode"]["ipv4"]["rp_addresses"][rp["ip_address"]] = {"groups": {}}

                if rp["ip_address"] in config["router_pim_sparse_mode"]["ipv4"]["rp_addresses"] \
                        and rp.get("group_address", "").strip() != "" \
                        and rp["group_address"] not in config["router_pim_sparse_mode"]["ipv4"]["rp_addresses"][rp["ip_address"]]["groups"]:
                    config["router_pim_sparse_mode"]["ipv4"]["rp_addresses"][rp["ip_address"]]["groups"].update({rp["group_address"]: None})

            # IPv6 RPs
            if len(switch_facts["ipv6_rps"]) > 0:
                config["router_pim_sparse_mode"]["ipv6"] = {"rp_addresses": {}}
            for rp in switch_facts["ipv6_rps"]:
                if rp["ip_address"] not in config["router_pim_sparse_mode"]["ipv6"]["rp_addresses"]:
                    config["router_pim_sparse_mode"]["ipv6"]["rp_addresses"][rp["ip_address"]] = {"groups": {}}

                if rp["ip_address"] in config["router_pim_sparse_mode"]["ipv6"]["rp_addresses"] \
                        and rp.get("group_address", "").strip() != "" \
                        and rp["group_address"] not in config["router_pim_sparse_mode"]["ipv6"]["rp_addresses"][rp["ip_address"]]["groups"]:
                    config["router_pim_sparse_mode"]["ipv6"]["rp_addresses"][rp["ip_address"]]["groups"].update({rp["group_address"]: None})

    # Set router-bgp
    if switch_facts["underlay_router"] \
       and (switch_facts["underlay_routing_protocol"] == "ebgp" \
       or switch_facts["overlay_routing_protocol"] == "ebgp"):
        config["router_bgp"]["as"] = switch_facts["bgp_as"]
        config["router_bgp"]["router_id"] = switch_facts["router_id"]
        config["router_bgp"]["bgp_defaults"] = switch_facts["bgp_defaults"]
        platform_bgp_update_wait_for_convergence = (
            get(switch_facts["platform_settings"], "bgp_update_wait_for_convergence", default=True) is True
        )
        platform_bgp_update_wait_install = get(switch_facts["platform_settings"], "bgp_update_wait_install", default=True) is True
        if get(switch_facts, "bgp_update_wait_for_convergence", default=False) is True and platform_bgp_update_wait_for_convergence:
            config["router_bgp"].setdefault("updates", {})["wait_for_convergence"] = True
        if get(switch_facts, "bgp_update_wait_install", default=True) is True and platform_bgp_update_wait_install:
          config["router_bgp"].setdefault("updates", {})["wait_install"] = True
        if get(switch_facts, "bgp_graceful_restart.enabled") is True:
            config["router_bgp"].update(
                {
                    "graceful_restart": {
                        "enabled": True,
                        "restart_time": get(switch_facts, "bgp_graceful_restart.restart_time", default=300),
                    },
                },
            )
        config["router_bgp"]["distance"] = switch_facts["bgp_distance"]
        if switch_facts.get("bgp_maximum_paths"):
            config["router_bgp"]["maximum_paths"] = switch_facts["bgp_maximum_paths"]
        if switch_facts.get("bgp_ecmp"):
            config["router_bgp"]["ecmp"] = switch_facts["bgp_ecmp"]

    # Set dot1x
    if switch_facts["connected_endpoints"] and get(switch_facts, "dot1x.system_auth_control"):
        dynamic_auth_port = switch_facts["dot1x"].pop("dynamic_authorization_port", None)
        if switch_facts["dot1x"].get("dynamic_authorization") and dynamic_auth_port:
            config["radius_server"] = {
                "dynamic_authorization": {
                    "port": dynamic_auth_port
                }
            }
        config["dot1x"] = strip_null_from_data(switch_facts["dot1x"], strip_values_tuple=(None, "", {}, [], False))

    return config


@ctx.benchmark
def set_mlag_config(config, switch_facts):
    if not switch_facts.get('mlag') or not switch_facts['mlag_interfaces']:
        return config
    # Set spanning tree relevant config
    if switch_facts['mlag_l3'] is True and switch_facts['mlag_peer_l3_vlan'] != switch_facts['mlag_peer_vlan']:
        config['spanning_tree']['no_spanning_tree_vlan'] = ",".join(
            [str(switch_facts['mlag_peer_l3_vlan']), str(switch_facts['mlag_peer_vlan'])]
        )
    else:
        config['spanning_tree']['no_spanning_tree_vlan'] = switch_facts['mlag_peer_vlan']

    # Set mlag vlan
    if switch_facts['mlag_l3'] is True and switch_facts['mlag_peer_l3_vlan'] != switch_facts['mlag_peer_vlan']:
        config['vlans'][switch_facts['mlag_peer_l3_vlan']] = {
            "tenant": "system",
            "name": "LEAF_PEER_L3",
            "trunk_groups": ['LEAF_PEER_L3']
        }
    config['vlans'][switch_facts['mlag_peer_vlan']] = {
        "tenant": "system",
        "name": "MLAG_PEER",
        "trunk_groups": ['MLAG']
    }

    # Set mlag svis
    # set mlag l3 svi
    if switch_facts['mlag_l3'] and switch_facts['mlag_peer_l3_vlan'] != switch_facts['mlag_peer_vlan']:
        config['vlan_interfaces'][f"Vlan{switch_facts['mlag_peer_l3_vlan']}"] = {
            "description": "MLAG_PEER_L3_PEERING",
            "shutdown": False,
            "ip_address": f"{switch_facts['mlag_l3_ip']}/{switch_facts['mlag_peer_l3_subnet_mask']}",
            "no_autostate": True,
            "mtu": switch_facts['p2p_uplinks_mtu']
        }

    # set mlag svi
    config['vlan_interfaces'][f"Vlan{switch_facts['mlag_peer_vlan']}"] = {
        "description": "MLAG_PEER",
        "shutdown": False,
        "ip_address": f"{switch_facts['mlag_ip']}/{switch_facts['mlag_peer_subnet_mask']}",
        "no_autostate": True,
        "mtu": switch_facts['p2p_uplinks_mtu']
    }

    if switch_facts['mlag_l3'] is True:
        if switch_facts['underlay_routing_protocol'] == "ospf":
            config['vlan_interfaces'][f"Vlan{switch_facts['mlag_peer_l3_vlan']}"]['ospf_network_point_to_point'] = True
            config['vlan_interfaces'][f"Vlan{switch_facts['mlag_peer_l3_vlan']}"]['ospf_area'] = switch_facts['underlay_ospf_area']

        if switch_facts["underlay_multicast"]:
            config['vlan_interfaces'][f"Vlan{switch_facts['mlag_peer_l3_vlan']}"]["pim"] = {"ipv4": {"sparse_mode": True}}


    # Set port-channel interfaces
    if not switch_facts.get("mlag_port_channel_id"):
        switch_facts["mlag_port_channel_id"] = "".join(re.findall(r'\d', switch_facts["mlag_interfaces"][0]))
    mlag_peer = switch_facts['mlag_peer']
    mlag_port_channel_id = switch_facts['mlag_port_channel_id']
    config['port_channel_interfaces'][f"Port-Channel{switch_facts['mlag_port_channel_id']}"] = {
        "description": eval(f"f\"{fabric_variables['interface_descriptions']['mlag_port_channel_interface']}\""),
        "type": "switched",
        "shutdown": False,
        "mode": "trunk",
        "trunk_groups": ['MLAG'],
        "eos_cli": switch_facts["mlag_peer_link_cli"]
    }
    if switch_facts['mlag_l3'] is True and switch_facts['mlag_peer_l3_vlan'] != switch_facts['mlag_peer_vlan']:
        config['port_channel_interfaces'][f"Port-Channel{switch_facts['mlag_port_channel_id']}"]['trunk_groups']\
            .append("LEAF_PEER_L3")

    if switch_facts.get("ptp") and switch_facts["ptp"].get("enabled") is True:
        ptp_config = {}
        # Apply PTP profile config
        ptp_profile = get_item(ptp_profiles, "profile", switch_facts["ptp"]["profile"], default={})
        ptp_config.update(ptp_profile)

        ptp_config["enable"] = True
        ptp_config.pop("profile", None)
        config['port_channel_interfaces'][f"Port-Channel{switch_facts['mlag_port_channel_id']}"]["ptp"] = ptp_config

    # Initialize ZTP variable
    enable_port_channel_lacp_fallback = False
    # Set ethernet interfaces
    for i, iface in enumerate(switch_facts['mlag_interfaces']):
        mlag_peer = switch_facts['mlag_peer']
        mlag_peer_interface = switch_facts['mlag_peer_switch_interfaces'][i]
        config['ethernet_interfaces'][iface] = {
            "peer": mlag_peer,
            "peer_interface": mlag_peer_interface,
            "peer_type": "mlag",
            "description": eval(f"f\"{fabric_variables['interface_descriptions']['mlag_ethernet_interfaces']}\""),
            "type": "switched",
            "shutdown": False,
            "channel_group": {
                "id": switch_facts['mlag_port_channel_id'],
                "mode": switch_facts['mlag_lacp_mode']
            },
            "speed": switch_facts.get("mlag_interfaces_speed", "auto"),
            "eos_cli": switch_facts["mlag_interfaces_cli"]
        }
        # Check to enable port_channel lacp fallback
        if not enable_port_channel_lacp_fallback and iface in switch_facts.get('inband_ztp_interfaces', []):
            enable_port_channel_lacp_fallback = True

    # Can make an assumption that inband management vlan for mlag peer will be same as this device
    if switch_facts.get("advertise_inband_ztp_vlan") \
            and switch_facts.get("inband_management_vlan") \
            and enable_port_channel_lacp_fallback:
        lacp_fallback_mode = fabric_variables["inband_ztp"]["lacp_fallback_mode"]
        lacp_fallback_timeout = fabric_variables["inband_ztp"]["lacp_fallback_timeout"]
        config['port_channel_interfaces'][f"Port-Channel{switch_facts['mlag_port_channel_id']}"]["lacp_fallback_mode"] = lacp_fallback_mode
        config['port_channel_interfaces'][f"Port-Channel{switch_facts['mlag_port_channel_id']}"]["lacp_fallback_timeout"] = lacp_fallback_timeout

    # Set mlag config
    config['mlag_configuration'] = {
        "enabled": True,
        "domain_id": switch_facts['mlag_group'],
        "local_interface": f"Vlan{switch_facts['mlag_peer_vlan']}",
        "peer_address": switch_facts['mlag_peer_ip'],
        "peer_link": f"Port-Channel{switch_facts['mlag_port_channel_id']}",
    }
    if switch_facts.get('reload_delay_mlag') is not None:
        config['mlag_configuration']["reload_delay_mlag"] = switch_facts["reload_delay_mlag"]
    if switch_facts.get('reload_delay_non_mlag') is not None:
        config['mlag_configuration']["reload_delay_non_mlag"] = switch_facts["reload_delay_non_mlag"]

    if (switch_facts.get("mlag_dual_primary_detection")) \
            and (mlag_peer_sn := switch_facts.get('mlag_peer_serial_number')) \
            and (mlag_peer_switch_facts := my_switch_facts_neighbors.get(mlag_peer_sn)) \
            and (peer_inband_mgmt_ip := mlag_peer_switch_facts.get("inband_mgmt_ip")):
        if peer_inband_mgmt_ip:
            config['mlag_configuration'].update(
                {
                    "peer_address_heartbeat": {
                        "peer_ip": mlag_peer_switch_facts["inband_mgmt_ip"].split("/")[0]
                    },
                    "dual_primary_detection_delay": 5,
                }
            )

    # Kept because we might add a knob later and enable this
    # Set route maps
    # Origin Incomplete for MLAG iBGP learned routes
    # if switch_facts['mlag_l3'] is True and \
    #         switch_facts['mlag_ibgp_origin_incomplete'] is True and \
    #         switch_facts['underlay_routing_protocol'] == "ebgp":
    #     config['route_maps']["RM-MLAG-PEER-IN"] = {
    #         "sequence_numbers": {
    #             10: {
    #                 "type": "permit",
    #                 "set": ["origin incomplete"],
    #                 "description": "Make routes learned over MLAG Peer-link less "
    #                             "preferred on spines to ensure optimal routing"
    #             }
    #         }
    #     }

    # Set bgp config
    if switch_facts['mlag_l3'] is True and switch_facts['underlay_routing_protocol'] == "ebgp":
        (config['router_bgp']['peer_groups']
        [fabric_variables['bgp_peer_groups']['MLAG_IPv4_UNDERLAY_PEER']['name']]) = {
            "type": "ipv4",
            "remote_as": switch_facts['bgp_as'],
            "next_hop_self": True,
            "send_community": "all"
        }
        if fabric_variables['bgp_peer_groups']['MLAG_IPv4_UNDERLAY_PEER']['password'] is not None:
            (config['router_bgp']['peer_groups']
            [fabric_variables['bgp_peer_groups']['MLAG_IPv4_UNDERLAY_PEER']['name']]['password']) = \
                fabric_variables['bgp_peer_groups']['MLAG_IPv4_UNDERLAY_PEER']['password']
        # Kept because we might add a knob later and enable this
        # if switch_facts['mlag_ibgp_origin_incomplete'] is True:
        #     (config['router_bgp']['peer_groups']
        #     [fabric_variables['bgp_peer_groups']['MLAG_IPv4_UNDERLAY_PEER']['name']]['route_map_in']) = \
        #         "RM-MLAG-PEER-IN"
        (config['router_bgp']['address_family_ipv4']['peer_groups']
        [fabric_variables['bgp_peer_groups']['MLAG_IPv4_UNDERLAY_PEER']['name']]) = {
            "activate": True
        }
        config['router_bgp']['neighbor_interfaces'][f"Vlan{switch_facts['mlag_peer_l3_vlan']}"] = {
            "peer_group": fabric_variables['bgp_peer_groups']['MLAG_IPv4_UNDERLAY_PEER']['name'],
            "remote_as": switch_facts['bgp_as'],
            "description": switch_facts['mlag_peer']
        }
        config['router_bgp']['neighbors'][switch_facts['mlag_peer_l3_ip']] = {
            "peer_group": fabric_variables['bgp_peer_groups']['MLAG_IPv4_UNDERLAY_PEER']['name'],
            "description": switch_facts['mlag_peer']
        }

    return config


@ctx.benchmark
def set_underlay_config(config, switch_facts):
    # logic
    underlay_data = {}
    underlay_data["links"] = switch_facts["topology"]["links"]
    switch_facts["downlink_interfaces"] = []

    # First add interface details from devices whose uplink interface neighbors are this switch
    for sn in switch_facts["downlink_switches_ids"]:
        neighbor_switch_facts = my_switch_facts_neighbors[sn]
        for neighbor_link, neighbor_link_info in neighbor_switch_facts["topology"]["links"].items():
            if neighbor_link_info["peer_id"] == switch_facts["serial_number"]:
                link = {}
                link["peer_id"] = neighbor_switch_facts["serial_number"]
                link["peer"] = neighbor_switch_facts["hostname"]
                link["peer_interface"] = neighbor_link
                link["peer_type"] = neighbor_switch_facts["type"]
                link["peer_bgp_as"] = neighbor_switch_facts.get("bgp_as")
                link["type"] = neighbor_link_info["type"]
                link["speed"] = neighbor_link_info.get("speed", "auto")
                link["ip_address"] = neighbor_link_info.get("peer_ip_address")
                link["subnet_mask"] = neighbor_link_info.get("subnet_mask")
                link["peer_ip_address"] = neighbor_link_info.get("ip_address")
                link["vlans"] = neighbor_link_info.get("vlans")
                link["channel_group_id"] = neighbor_link_info.get("peer_channel_group_id")
                link["peer_channel_group_id"] = neighbor_link_info.get("channel_group_id")
                link["mlag"] = neighbor_link_info.get("peer_mlag")
                link["channel_description"] = neighbor_link_info.get("peer_channel_description")
                # multicast/pim
                link["underlay_multicast"] = neighbor_link_info.get("underlay_multicast")
                # ptp
                link["ptp"] = neighbor_link_info.get("ptp")
                # eos cli
                link["eos_cli"] = neighbor_link_info.get("eos_cli", "")
                link["port_channel_eos_cli"] = neighbor_link_info.get("port_channel_eos_cli", "")
                # Set interface
                interface = neighbor_link_info["peer_interface"]
                switch_facts["downlink_interfaces"].append(interface)
                # inband ztp
                if neighbor_switch_facts.get("inband_management_vlan") and interface in switch_facts.get('inband_ztp_interfaces', []):
                    link["ztp_vlan"] = neighbor_switch_facts["inband_management_vlan"]

                underlay_data["links"][interface] = link

    # Set Ethernet interfaces
    for iface in underlay_data["links"]:
        link = underlay_data["links"][iface]
        if link["type"] == "underlay_p2p":
            config["ethernet_interfaces"][iface] = {
                "peer": link["peer"],
                "peer_interface": link["peer_interface"],
                "peer_type": link["peer_type"],
                "description": eval(f"f\"{fabric_variables['interface_descriptions']['underlay_l3_ethernet_interfaces']}\""),
                "speed": link.get("speed", "auto"),
                "mtu": switch_facts["p2p_uplinks_mtu"],
                "type": "routed",
                "shutdown": False,
                "ip_address": "{}/{}".format(link["ip_address"], link["subnet_mask"])
            }
            # ospf
            if switch_facts["underlay_routing_protocol"] == "ospf":
                config["ethernet_interfaces"][iface]["ospf_network_point_to_point"] = True
                config["ethernet_interfaces"][iface]["ospf_area"] = switch_facts["underlay_ospf_area"]
            # multicast/pim
            if link.get("underlay_multicast"):
                config["ethernet_interfaces"][iface]["pim"] = {
                    "ipv4": {"sparse_mode": True}
                }
            # ptp
            if link.get("ptp") and link["ptp"].get("enable") is True:
                ptp_config = {}
                # Apply PTP profile config
                ptp_profile = get_item(ptp_profiles, "profile", switch_facts["ptp"]["profile"], default={})
                ptp_config.update(ptp_profile)

                ptp_config["enable"] = True
                ptp_config.pop("profile", None)
                config["ethernet_interfaces"][iface]["ptp"] = ptp_config

        elif link["type"] == "underlay_l2":
            config["ethernet_interfaces"][iface] = {
                "type": "switched",
                "shutdown": False,
                "speed": link.get("speed", "auto")
            }
            if link.get("peer"):
                config["ethernet_interfaces"][iface]["peer"] = link["peer"]
            if link.get("peer_interface"):
                config["ethernet_interfaces"][iface]["peer_interface"] = link["peer_interface"]
            if link.get("peer_type"):
                config["ethernet_interfaces"][iface]["peer_type"] = link["peer_type"]
            if link.get("peer") and link.get("peer_interface"):
                config["ethernet_interfaces"][iface]["description"] = eval(f"f\"{fabric_variables['interface_descriptions']['underlay_l2_ethernet_interfaces']}\"")

            if link.get("channel_group_id"):
                config["ethernet_interfaces"][iface]["channel_group"] = {
                    "id": link["channel_group_id"],
                    "mode": "active"
                }

        # Add EOS CLI
        config["ethernet_interfaces"][iface]["eos_cli"] = link.get("eos_cli", "")

    # Set Port-Channel interfaces
    port_channel_list = [] # go through this
    for iface in underlay_data["links"]:
        link = underlay_data["links"][iface]
        if link["type"] == "underlay_l2" and \
                link.get("channel_group_id") and \
                link.get("channel_group_id") not in port_channel_list:
            port_channel_list.append(link["channel_group_id"])
            port_channel = {
                "description": eval(f"f\"{fabric_variables['interface_descriptions']['underlay_port_channel_interfaces']}\""),
                "type": "switched",
                "shutdown": False,
                "mode": "trunk"
            }
            if link.get("port_channel_eos_cli"):
                port_channel["eos_cli"] = link["port_channel_eos_cli"]
            if switch_facts.get("mlag") and link.get("mlag", True):
                port_channel["mlag"] = link["channel_group_id"]
            if link.get('vlans'):
                port_channel['vlans'] = list_compress(link['vlans'])

            if link.get("ptp") and link["ptp"].get("enable") is True:
                ptp_config = {}
                # Apply PTP profile config
                ptp_profile = get_item(ptp_profiles, "profile", switch_facts["ptp"]["profile"], default={})
                ptp_config.update(ptp_profile)
                ptp_config["enable"] = True
                ptp_config.pop("profile", None)
                port_channel["ptp"] = ptp_config

            if switch_facts.get("advertise_inband_ztp_vlan") and link.get("ztp_vlan"):
                lacp_fallback_mode = fabric_variables["inband_ztp"]["lacp_fallback_mode"]
                lacp_fallback_timeout = fabric_variables["inband_ztp"]["lacp_fallback_timeout"]
                port_channel["lacp_fallback_mode"] = lacp_fallback_mode
                port_channel["lacp_fallback_timeout"] = lacp_fallback_timeout

            config["port_channel_interfaces"]["Port-Channel{}".format(link["channel_group_id"])] = port_channel


    # L2 and L3
    if switch_facts["network_services_l2"] == True and \
        switch_facts["network_services_l3"] == True:
        # set viritual router mac address
        config["ip_virtual_router_mac_address"] = switch_facts["virtual_router_mac_address"]

    # Routing
    if switch_facts["underlay_router"] == True:
        # Set loopback interfaces
        if switch_facts.get("router_id"):
            config["loopback_interfaces"][switch_facts["router_id_loopback_interface"]] = {
                "description": eval(f"f\"{fabric_variables['interface_descriptions']['router_id_interface']}\""),
                "shutdown": False,
                "ip_address": "{}/32".format(switch_facts["router_id"]),
            }
            if switch_facts["underlay_routing_protocol"] == "ospf":
                # config["loopback_interfaces"][switch_facts["router_id_loopback_interface"]]["ospf_network_point_to_point"] = True
                config["loopback_interfaces"][switch_facts["router_id_loopback_interface"]]["ospf_area"] = switch_facts["underlay_ospf_area"]
        if switch_facts["vtep"] == True:
            config["loopback_interfaces"][switch_facts["vtep_loopback"]] = {
               "description": eval(f"f\"{fabric_variables['interface_descriptions']['vtep_source_interface']}\""),
               "shutdown": False,
               "ip_address": "{}/32".format(switch_facts["vtep_ip"])
            }
            if switch_facts.get("vtep_vvtep_ip") and switch_facts.get("evpn_services_l2_only") is not None and \
                switch_facts.get("evpn_services_l2_only") == False:
                config["loopback_interfaces"][switch_facts["vtep_loopback"]] = [switch_facts["vtep_vvtep_ip"] ]
            if switch_facts["underlay_routing_protocol"] == "ospf":
                config["loopback_interfaces"][switch_facts["vtep_loopback"]]["ospf_area"] = switch_facts["underlay_ospf_area"]

        # Set bgp if necessary
        if switch_facts["underlay_routing_protocol"] == "ebgp":
            config["router_bgp"]["peer_groups"][fabric_variables["bgp_peer_groups"]["IPv4_UNDERLAY_PEERS"]["name"]] = {
                "type": "ipv4",
                "send_community": "all"
            }
            if fabric_variables["bgp_peer_groups"]["IPv4_UNDERLAY_PEERS"]["password"] is not None:
                config["router_bgp"]["peer_groups"][fabric_variables["bgp_peer_groups"]["IPv4_UNDERLAY_PEERS"]["name"]] \
                    ["password"] = fabric_variables["bgp_peer_groups"]["IPv4_UNDERLAY_PEERS"]["password"]
            config["router_bgp"]["address_family_ipv4"]["peer_groups"][fabric_variables["bgp_peer_groups"]["IPv4_UNDERLAY_PEERS"]["name"]] = {
                "activate": True,
            }
            config["router_bgp"]["redistribute_routes"]["connected"] = {
                # "route_map": "RM-CONN-2-BGP"
            }
            for iface, link in underlay_data["links"].items():
                if link["type"] == "underlay_p2p":
                    config["router_bgp"]["neighbors"][link["peer_ip_address"]] = {
                        "peer_group": fabric_variables["bgp_peer_groups"]["IPv4_UNDERLAY_PEERS"]["name"],
                        "remote_as": link["peer_bgp_as"],
                        "description": "{}_{}".format(link["peer"], link["peer_interface"])
                    }
            # Create prefix lists
            # config["prefix_lists"]["PL-LOOPBACKS-EVPN-OVERLAY"] = {
            #     "sequence_numbers": {
            #         10: {
            #             "action": "permit {} eq 32".format(switch_facts["loopback_ipv4_pool"])
            #         }
            #     }
            # }
            # if switch_facts.get("vtep_ip") is not None:
            #     config["prefix_lists"]["PL-LOOPBACKS-EVPN-OVERLAY"]["sequence_numbers"][20] = {
            #         "action": "permit {} eq 32".format(switch_facts["vtep_loopback_ipv4_pool"])
            #     }
            # if switch_facts.get("vtep_vvtep_ip") is not None \
            #    and switch_facts.get("evpn_services_l2_only") is not None \
            #    and switch_facts.get("evpn_services_l2_only") == False:
            #     config["prefix_lists"]["PL-LOOPBACKS-EVPN-OVERLAY"]["sequence_numbers"][30] = {
            #         "action": "permit {}".format(switch_facts["vtep_vvtep_ip"])
            #     }
            # Create route-maps
            # config["route_maps"]["RM-CONN-2-BGP"] = {
            #     "sequence_numbers": {
            #         10: {
            #             "type": "permit",
            #             "match": ["ip address prefix-list PL-LOOPBACKS-EVPN-OVERLAY"]
            #         }
            #     }
            # }
        if switch_facts["underlay_routing_protocol"] == "ospf":
            process_id = {
                "id": switch_facts["underlay_ospf_process_id"],
                "passive_interface_default": True,
                "router_id": switch_facts["router_id"],
                "no_passive_interfaces": [],
                "max_lsa": switch_facts["underlay_ospf_max_lsa"],
                "eos_cli": switch_facts["ospf_defaults"]
            }
            if get(switch_facts["underlay_ospf_graceful_restart"], "enabled", False):
                process_id["graceful_restart"] = switch_facts["underlay_ospf_graceful_restart"]
            if switch_facts.get("underlay_ospf_auto_cost_reference_bandwidth"):
                process_id["auto_cost_reference_bandwidth"] = switch_facts["underlay_ospf_auto_cost_reference_bandwidth"]
            for iface, link in underlay_data["links"].items():
                if link["type"] == "underlay_p2p":
                    process_id["no_passive_interfaces"].append(iface)
            if switch_facts.get("mlag_l3") is not None and switch_facts.get("mlag_l3") == True:
                process_id["no_passive_interfaces"].append(f"Vlan{switch_facts['mlag_peer_l3_vlan']}")
            if switch_facts["underlay_ospf_bfd_enable"] == True:
                process_id["bfd_enable"] = True
            config["router_ospf"]["process_ids"] = [process_id]
    return config


@ctx.benchmark
def set_overlay_config(config, switch_facts):
    if not switch_facts.get("underlay_router"):
        return config
    if switch_facts["overlay_routing_protocol"] != "ebgp":
        return config

    overlay_data = {}
    # Set auto generated evpn route servers
    overlay_data["evpn_route_servers"] = {}
    for rs_id in switch_facts["evpn_route_server_ids"]:
        rs_switch_facts = my_switch_facts_neighbors[rs_id]
        if rs_switch_facts["evpn_role"] == "server":
            server = {
                "bgp_as": rs_switch_facts["bgp_as"],
                "ip_address": rs_switch_facts["router_id"]
            }
            overlay_data["evpn_route_servers"][rs_switch_facts["hostname"]] = server

    # Set user input evpn route servers
    for rs_info in switch_facts.get("evpn_route_servers_info", []):
        server = {
            "bgp_as": rs_info["bgp_as"],
            "ip_address": rs_info["ip_address"]
        }
        overlay_data["evpn_route_servers"][rs_info["hostname"]] = server

    # Set evpn route clients
    overlay_data["evpn_route_clients"] = {}
    if switch_facts["evpn_role"] == "server":
        for campus_switch_facts in my_switch_facts_neighbors.values():
            if campus_switch_facts.get("evpn_role") is not None and campus_switch_facts["evpn_role"] == "client":
                if switch_facts['serial_number'] in campus_switch_facts["evpn_route_server_ids"]:
                    client = {
                        "bgp_as": campus_switch_facts["bgp_as"],
                        "ip_address": campus_switch_facts["router_id"]
                    }
                    overlay_data["evpn_route_clients"][campus_switch_facts["hostname"]] = client

    # Set ebgp
    config["router_bgp"]["peer_groups"][fabric_variables["bgp_peer_groups"]["EVPN_OVERLAY_PEERS"]["name"]] = {
        "type": "evpn",
        "update_source": switch_facts["router_id_loopback_interface"],
        "bfd": True,
        "ebgp_multihop": str(fabric_variables["evpn_ebgp_multihop"]),
        "send_community": "all",
        "maximum_routes": 0,
    }
    if switch_facts["evpn_role"] == "server":
        config["router_bgp"]["peer_groups"][fabric_variables["bgp_peer_groups"]["EVPN_OVERLAY_PEERS"]["name"]]\
        ["next_hop_unchanged"] = True
    if fabric_variables["bgp_peer_groups"]["EVPN_OVERLAY_PEERS"]["password"] is not None:
        config["router_bgp"]["peer_groups"][fabric_variables["bgp_peer_groups"]["EVPN_OVERLAY_PEERS"]["name"]]\
        ["password"] = fabric_variables["bgp_peer_groups"]["EVPN_OVERLAY_PEERS"]["password"]
    config["router_bgp"]["address_family_ipv4"]["peer_groups"][fabric_variables["bgp_peer_groups"]["EVPN_OVERLAY_PEERS"]["name"]] = {
        "activate": False
    }
    config["router_bgp"]["address_family_evpn"]["peer_groups"][fabric_variables["bgp_peer_groups"]["EVPN_OVERLAY_PEERS"]["name"]] = {
        "activate": True
    }
    if switch_facts.get("vtep_ip") and fabric_variables["evpn_hostflap_detection"]["enabled"] == True:
        config["router_bgp"]["address_family_evpn"]["evpn_hostflap_detection"] = {
            "window": fabric_variables["evpn_hostflap_detection"]["window"],
            "threshold": fabric_variables["evpn_hostflap_detection"]["threshold"],
            "enabled": fabric_variables["evpn_hostflap_detection"]["enabled"]
        }
    # Overlay network peering
    for rs, info in overlay_data["evpn_route_servers"].items():
        config["router_bgp"]["neighbors"][info["ip_address"]] = {
            "peer_group": fabric_variables["bgp_peer_groups"]["EVPN_OVERLAY_PEERS"]["name"],
            "description": rs,
            "remote_as": info["bgp_as"]
        }
    for cs, info in overlay_data["evpn_route_clients"].items():
        config["router_bgp"]["neighbors"][info["ip_address"]] = {
            "peer_group": fabric_variables["bgp_peer_groups"]["EVPN_OVERLAY_PEERS"]["name"],
            "description": cs,
            "remote_as": info["bgp_as"]
        }
    return config


@ctx.benchmark
def set_vxlan_config(config, switch_facts):
    if switch_facts.get("vtep") == True:
        config["vxlan_interface"] = {
            "Vxlan1": {
                "description": "{}_VTEP".format(switch_facts["hostname"]),
                "vxlan": {
                    "source_interface": switch_facts["vtep_loopback"],
                    "udp_port": 4789,
                    "vrfs": {},
                    "vlans": {}
                }
            }
        }
        if switch_facts.get("mlag"):
            config["vxlan_interface"]["Vxlan1"]["vxlan"]["virtual_router_encapsulation_mac_address"] = "mlag-system-id"
    return config


@ctx.benchmark
def set_inband_management_config(config, switch_facts):
    if switch_facts.get("inband_management_role", "") == "child":
        # child-vlans
        config["vlans"][switch_facts["inband_management_vlan"]] = {
            "tenant": "system",
            "name": "L2LEAF_INBAND_MGMT"
        }
        # child-management-interfaces
        config["management_interfaces"] = {
            switch_facts["inband_management_interface"]: {
                "description": "L2LEAF_INBAND_MGMT",
                "shutdown": False,
                "mtu": switch_facts["p2p_uplinks_mtu"],
                "ip_address": switch_facts.get("inband_mgmt_ip"),
                "gateway": switch_facts["inband_management_gateway"],
                "type": "inband"
            }
        }
        # child-static-routes
        config["static_routes"].append(
            {
                "destination_address_prefix": "0.0.0.0/0",
                "gateway": switch_facts["inband_management_gateway"]
            }
        )

    else:
        # parent-logic
        inband_management_data = {
            "vlans": [],
            "subnets": [],
            "ip_helpers_details": []
        }
        for tmp_switch_facts in my_switch_facts_neighbors.values():
            if switch_facts["serial_number"] in tmp_switch_facts.get("inband_management_parents", []):
                inband_management_data["role"] = "parent"
                if (ib_mgmt_subnet := tmp_switch_facts.get("inband_management_subnet")) and (ib_mgmt_subnet not in inband_management_data["subnets"]):
                    inband_management_data["vlans"].append(tmp_switch_facts["inband_management_vlan"])
                    inband_management_data["subnets"].append(tmp_switch_facts["inband_management_subnet"])
                    inband_management_data["ip_helpers_details"].append(tmp_switch_facts.get("inband_management_ip_helpers"))

        if (ib_mgmt_vlan := switch_facts.get("inband_management_vlan")) and (ib_mgmt_vlan not in inband_management_data["vlans"]):
            if (ib_mgmt_subnet := switch_facts.get("inband_management_subnet")):
                inband_management_data["vlans"].append(ib_mgmt_vlan)
                inband_management_data["subnets"].append(ib_mgmt_subnet)
                inband_management_data["ip_helpers_details"].append(switch_facts.get("inband_management_ip_helpers"))
            else:
                ctx.warning(f"No inband management subnet provided for VLAN "
                            f"{ib_mgmt_vlan} in "
                            f"Campus:{switch_facts['campus']} -> "
                            f"Campus-Pod:{switch_facts['campus_pod']}")

        if inband_management_data.get("role", "") == "parent" or len(inband_management_data["vlans"]) > 0:
            # parent-vrfs
            if switch_facts["inband_management_vrf"] != "default" and switch_facts["inband_management_vrf"] not in config["vrfs"]:
                config["vrfs"][switch_facts["inband_management_vrf"]] = {
                    "tenant": "system",
                    "ip_routing": True
                }
            # parent-vlans
            for vlan in inband_management_data.get("vlans", []):
                config["vlans"][vlan] = {
                    "tenant": "system",
                    "name": "L2LEAF_INBAND_MGMT"
                }
            # parent-vlan-interfaces
            for i, subnet in enumerate(inband_management_data.get("subnets", [])):
                vlan_interface = {
                    "description": "L2LEAF_INBAND_MGMT",
                    "no_autostate": True,
                    "shutdown": False,
                    "vrf": switch_facts["inband_management_vrf"],
                    "mtu": switch_facts["p2p_uplinks_mtu"],
                    "ip_virtual_router_addresses": [str(list(ipaddress.ip_network(subnet).hosts())[0])],
                    "ip_attached_host_route_export": {
                        "distance": 19
                    },
                    "ip_helpers": {}
                }
                for ip_helper in inband_management_data["ip_helpers_details"][i]:
                    vlan_interface['ip_helpers'][ip_helper["dhcpServer"]] = {
                        "source_interface": ip_helper.get("dhcpSourceInterface")
                    }

                if switch_facts.get("mlag") and switch_facts["mlag_role"] == "secondary":
                    ip_address = list(ipaddress.ip_network(subnet).hosts())[2]
                else:
                    ip_address = list(ipaddress.ip_network(subnet).hosts())[1]

                subnet_mask = subnet.split("/")[-1]
                vlan_interface["ip_address"] = f"{ip_address}/{subnet_mask}"

                config["vlan_interfaces"]["Vlan{}".format(inband_management_data["vlans"][i])] = vlan_interface
            # Set virtual router mac address unless it will be set in network services
            if switch_facts["network_services_l2"] is True and switch_facts["network_services_l3"] is True:
                config["ip_virtual_router_mac_address"] = switch_facts["virtual_router_mac_address"].lower()

            if switch_facts["underlay_router"] is True and switch_facts["underlay_routing_protocol"] == "ebgp":
                # parent-router-bgp
                config["router_bgp"]["redistribute_routes"]["attached-host"] = {}

          #       # parent-prefix-lists
          #       config["prefix_lists"]["PL-L2LEAF-INBAND-MGMT"] = {
          #           "sequence_numbers": {}
          #       }
          #       for i, subnet in enumerate(inband_management_data.get("subnets", [])):
          #           config["prefix_lists"]["PL-L2LEAF-INBAND-MGMT"]["sequence_numbers"][(i+1)*10] = {
          #               "action": f"permit {subnet}"
          #           }

          #       # parent-route-maps
          #       # sequence 10 is set in underlay so avoid setting it here
          #       config["route_maps"]["RM-CONN-2-BGP"]["sequence_numbers"][20] = {
          #           "type": "permit",
          #           "match": ["ip address prefix-list PL-L2LEAF-INBAND-MGMT"]
          #       }

    return config


@ctx.benchmark
def get_tenant_vrf(vrf, switch_facts):
    device_id = switch_facts['serial_number']
    avd_vrf = {"name": vrf["name"]}
    avd_vrf['vrf_id'] = vrf.get('vrfId')
    # select attribute formats
    avd_vrf['attr_format_rt'] = get(advanced_services_settings,
        "attributeFormats.vrfAttributeFormats.vrfRouteTargetFormat")
    avd_vrf['attr_format_rd'] = get(advanced_services_settings,
        "attributeFormats.vrfAttributeFormats.vrfRouteDistinguisherFormat")
    # mlag l3 peering
    if get(vrf, "vrfMlagIbgpPeeringDetails.ibgpVlanId"):
        avd_vrf["enable_mlag_ibgp_peering_vrfs"] = True
        avd_vrf['mlag_ibgp_peering_vlan'] = vrf["vrfMlagIbgpPeeringDetails"]["ibgpVlanId"]
        if vrf["vrfMlagIbgpPeeringDetails"].get("ibgpPeeringIpv4Pool"):
            avd_vrf['mlag_ibgp_peering_ipv4_pool'] = vrf["vrfMlagIbgpPeeringDetails"]["ibgpPeeringIpv4Pool"]

    # vtep diagnostic
    if get(vrf, "vtepDiagnostic.loopbackInterface"):
        avd_vrf['vtep_diagnostic'] = {
            "loopback": vrf["vtepDiagnostic"]["loopbackInterface"]
        }
        if (campuses_vtep_diagnostic := vrf['vtepDiagnostic'].get('campuses').resolve(device=device_id)) \
                and (campus_pods_vtep_diagnostic := campuses_vtep_diagnostic['campusPods'].resolve(device=device_id)):
            avd_vrf['vtep_diagnostic']["loopback_ip_range"] = campus_pods_vtep_diagnostic["ipv4Pool"]

    # l3 interfaces
    if get(vrf, "l3Interfaces") and device_matches_resolver_query(vrf["l3Interfaces"], device_id):
        avd_vrf["l3_interfaces"] = []
        # Populate l3_interfaces list in tenant vrf with user input l3 interfaces
        for l3_interface in vrf['l3Interfaces'].resolve(device=device_id).get("interfaces", []):
            interface = {}
            interface["interfaces"] = [l3_interface["name"]]
            interface["nodes"] = [device_id]
            interface["ip_addresses"] = [l3_interface["ipAddress"]]
            interface["enabled"] = l3_interface["enabled"]
            if l3_interface.get("description", "") != "":
                interface["description"] = l3_interface["description"]
            if l3_interface.get("mtu"):
                interface["mtu"] = l3_interface["mtu"]
            if l3_interface.get("eosCli"):
                interface["raw_eos_cli"] = l3_interface["eosCli"]
            # Check ospf
            if l3_interface.get("ospf"):
                interface["ospf"] = strip_null_from_data(
                    get_network_services_ospf_interface(l3_interface["ospf"])
                )

            # multicast
            if l3_interface.get("multicast") is not None and l3_interface["multicast"].get("pim"):
                interface["multicast"] = True
            else:
                interface["multicast"] = False

            # ptp
            if l3_interface.get("ptp") is not None and l3_interface["ptp"].get("enable"):
                interface["ptp"] = {"enable": True}

            # add interface
            avd_vrf["l3_interfaces"].append(interface)

    # static routes
    if len(vrf.get("staticRoutes", [])) > 0:
        avd_vrf['static_routes'] = []
        for sr in vrf["staticRoutes"]:
            nodes = []
            for tag_matcher in sr["devices"]:
                tag_query = tag_matcher['tagQuery']
                nodes += tag_query.inputs['devices']
            static_route = {
                "destination_address_prefix": sr["routeDetails"]["destinationAddressPrefix"],
                "name": sr["description"].replace(" ", "_"),
                "nodes": nodes
            }
            # gateway
            if sr["routeDetails"].get("gateway", "") == "":
                static_route["gateway"] = None
            else:
                static_route["gateway"] = sr["routeDetails"]["gateway"]
            # interface
            if sr["routeDetails"].get("interface", "") == "":
                static_route["interface"] = None
            else:
                static_route["interface"] = sr["routeDetails"]["interface"]
            # distance
            if sr["routeDetails"].get("distance", "") == "":
                static_route["distance"] = None
            else:
                static_route["distance"] = sr["routeDetails"]["distance"]
            # distance
            if sr["routeDetails"].get("tag", "") == "":
                static_route["tag"] = None
            else:
                static_route["tag"] = sr["routeDetails"]["tag"]
            # metric
            if sr["routeDetails"].get("metric", "") == "":
                static_route["metric"] = None
            else:
                static_route["metric"] = sr["routeDetails"]["metric"]

            avd_vrf["static_routes"].append(static_route)

    # redistribute static routes
    if get(vrf, "redistributeStaticRoutes"):
        avd_vrf['redistribute_static'] = vrf["redistributeStaticRoutes"]

    # bgp peers
    if len(vrf.get('vrfBgpPeers', [])) > 0:
        avd_vrf['bgp_peers'] = []
        for bgp_peer in vrf["vrfBgpPeers"]:
            peer = get_network_services_bgp_peer(bgp_peer)
            nodes = []
            for tag_matcher in bgp_peer["devices"]:
                tag_query = tag_matcher['tagQuery']
                nodes += tag_query.inputs['devices']
            peer['nodes'] = nodes
            avd_vrf['bgp_peers'].append(peer)

    # bgp cli
    if get(vrf, "bgp.eosCli"):
        avd_vrf["bgp"] = {"raw_eos_cli": vrf["bgp"]["eosCli"]}

    # ospf configuration
    if get(vrf, "ospfConfiguration") or (vrf["name"] == "default" and switch_facts.get("underlay_routing_protocol") == "ospf"):
        if get(vrf, "ospfConfiguration"):
            ospf = {"enabled": vrf["ospfConfiguration"]["enabled"]}
            # process_id
            if vrf["ospfConfiguration"].get("processId"):
                ospf["process_id"] = vrf["ospfConfiguration"]["processId"]
            # max lsa
            if vrf["ospfConfiguration"].get("maxLsa"):
                ospf["max_lsa"] = vrf["ospfConfiguration"]["maxLsa"]
            # bfd
            if vrf["ospfConfiguration"].get("vrfOspfBfd"):
                ospf["bfd"] = vrf["ospfConfiguration"]["vrfOspfBfd"]

            # redistribute bgp
            if vrf["ospfConfiguration"].get("redistributeBgp"):
                ospf["redistribute_bgp"] = {
                    "enabled": vrf["ospfConfiguration"]["redistributeBgp"].get("enabled"),
                    "route_map": vrf["ospfConfiguration"]["redistributeBgp"].get("routeMap")
                }
            # redistribute connected
            if vrf["ospfConfiguration"].get("redistributeConnected"):
                ospf["redistribute_connected"] = {
                    "enabled": vrf["ospfConfiguration"]["redistributeConnected"].get("enabled"),
                    "route_map": vrf["ospfConfiguration"]["redistributeConnected"].get("routeMap")
                }
            # structured config for eos_cli (need to do it this way for AVD purposes)
            ospf["eos_cli"] = vrf["ospfConfiguration"]["eosCli"]

        else:
            ospf = {
                "enabled":True,
                "process_id": switch_facts.get("underlay_ospf_process_id"),
                "max_lsa": switch_facts.get("underlay_ospf_max_lsa"),
                "bfd": switch_facts.get("underlay_ospf_bfd_enable")
            }
        # add ospf details to vrf
        avd_vrf["ospf"] = ospf

    # redistribute ospf
    if get(vrf, "redistributeOspf"):
        avd_vrf["redistribute_ospf"] = vrf["redistributeOspf"]

    # additional_route_targets
    additional_route_targets = []
    for rt in vrf.get('vrfAdditionalRouteTargets', []):
        route_target = {}
        nodes = []
        for tag_matcher in rt["devices"]:
            tag_query = tag_matcher['tagQuery']
            nodes += tag_query.inputs['devices']
        route_target['nodes'] = nodes
        route_target['type'] = rt['type']
        route_target['address_family'] = rt['addressFamily']
        route_target['route_target'] = rt['routeTarget']
        additional_route_targets.append(route_target)

    if len(additional_route_targets) > 0:
        avd_vrf['additional_route_targets'] = additional_route_targets

    # multicast
    if vrf["name"] == "default" and switch_facts["underlay_multicast"]:
        avd_vrf['multicast_enabled'] = True
    elif get(vrf, "multicast") and switch_facts["underlay_multicast"]:
        avd_vrf['multicast_enabled'] = str_to_bool(vrf['multicast']['enabled'])

    # rps
    rps = get(vrf, "multicast.pimRpAddresses", [])
    rp_groups = []
    for rp in rps:
        if len(rp.get("rpIpAddresses", [])) > 0:
            # Add RP addresses
            rp_group_info = {
                "rps": rp["rpIpAddresses"]
            }
            # Add group addresses
            if len(rp.get("groupAddresses", [])) > 0:
                rp_group_info["groups"] = rp["groupAddresses"]
            # Add nodes
            nodes = []
            for tag_matcher in rp["devices"]:
                tag_query = tag_matcher['tagQuery']
                tag_match_nodes = tag_query.inputs['devices']
                nodes += tag_match_nodes
            if len(nodes) > 0:
                rp_group_info["nodes"] = nodes
            rp_groups.append(rp_group_info)
    if len(rp_groups) > 0:
        avd_vrf["pim_rp_addresses"] = rp_groups

    # ip_helpers
    if len(vrf.get("dhcpHelpers", [])) > 0:
        avd_vrf["ip_helpers"] = []
        for helper in vrf["dhcpHelpers"]:
            ip_helper = {
                "ip_helper": helper["dhcpServer"]
            }
            if helper.get("sourceInterface"):
                ip_helper["source_interface"] = helper["sourceInterface"]
            if helper.get("sourceVrf"):
                ip_helper["source_vrf"] = helper["sourceVrf"]

            avd_vrf["ip_helpers"].append(ip_helper)

    # vni override
    if get(vrf, "overrideAttributes.vni"):
        avd_vrf["vrf_vni"] = vrf["overrideAttributes"]["vni"]
    # rd override
    if get(vrf, "overrideAttributes.routeDistinguisher"):
        avd_vrf["rd_override"] = vrf["overrideAttributes"]["routeDistinguisher"]
    # rt override
    if get(vrf, "overrideAttributes.routeTarget"):
        avd_vrf["rt_override"] = vrf["overrideAttributes"]["routeTarget"]

    return avd_vrf


def get_tenant_svi(svi, switch_facts, campus_type=""):
    # initialize pod_info
    pod_info = {}
    device_id = switch_facts["serial_number"]
    avd_svi = {"id": svi["id"]}
    # select attribute formats
    avd_svi['attr_format_rt'] = get(advanced_services_settings,
        "attributeFormats.vlanBasedMacVrfAttributeFormats.macVrfRouteTargetFormat")
    avd_svi['attr_format_rd'] = get(advanced_services_settings,
        "attributeFormats.vlanBasedMacVrfAttributeFormats.macVrfRouteDistinguisherFormat")
    # Get devices
    devices = []
    # Automatically add spine switches in an L2 campus
    if campus_type and "L2" in campus_type and (switch_facts["type"] == "spine" or switch_facts["network_services_l2"] and switch_facts["network_services_l3"]):
        devices.append(device_id)
    elif get(svi, "devices"):
        for tag_matcher in svi["devices"]:
            tag_query = tag_matcher['tagQuery']
            devices += tag_query.inputs['devices']
            # Get pod info
            if switch_facts["serial_number"] in tag_query.inputs['devices']:
                if not campus_type:
                    pod_info = svi["pods"].resolve(device=device_id).get('sviIpInfo') if svi.get("pods") else {}
                elif campus_type == "L3":
                    pod_info = tag_matcher
                else:
                    pod_info = {}
                break


    # Assign devices
    avd_svi["devices"] = devices

    #vxlan
    avd_svi["vxlan"] = str_to_bool(svi.get("vxlan", "No"))
    # ip address virtual
    if avd_svi["vxlan"] and get(svi, 'ipAddressVirtual'):
        avd_svi["ip_address_virtual"] = svi["ipAddressVirtual"]
    # ip virtual router subnet
    elif not avd_svi["vxlan"] and pod_info.get('ipVirtualRouterSubnet'):
        avd_svi["ip_virtual_router_subnet"] = pod_info["ipVirtualRouterSubnet"]
    elif not avd_svi["vxlan"]:
        avd_svi["ip_virtual_router_subnet"] = svi.get("ipVirtualRouterSubnet")

    # name
    access_pod_vlan_name = pod_info["name"] if pod_info.get("name") else None
    campus_pod_vlan_name = svi["name"] if svi.get("name") else None
    vlan_name = default(access_pod_vlan_name, campus_pod_vlan_name)
    assert vlan_name, f"No name is configured for SVI {svi['id']}."
    avd_svi["name"] = vlan_name

    # shutdown
    avd_svi["enabled"] = True
    if get(svi, "enabled"):
        avd_svi["enabled"] = str_to_bool(svi.get("enabled", "Yes"))

    # node specific info
    avd_svi["nodes"] = {}
    if get(svi, "nodes") and svi["nodes"].resolve(device=device_id):
        if device_id not in avd_svi["nodes"]:
            avd_svi["nodes"][device_id] = {}
        if (node_ip := get(svi["nodes"].resolve(device=device_id), "sviNodeDetails.ipAddress")):
            avd_svi["nodes"][device_id].update({"ip_address": node_ip})
        if (node_virtual_router_ip := get(svi["nodes"].resolve(device=device_id), "sviNodeDetails.ipVirtualRouterAddress")):
            avd_svi["nodes"][device_id].update({"ip_virtual_router_addresses": [node_virtual_router_ip]})

    # node shutdown
    if get(pod_info, "enabled"):
        if device_id not in avd_svi["nodes"]:
            avd_svi["nodes"][device_id] = {}
        avd_svi["nodes"][device_id].update({"enabled": str_to_bool(pod_info.get("enabled"))})

    # convert node dict to list
    if get(avd_svi, "nodes"):
        avd_svi["nodes"] = convert_dicts(avd_svi["nodes"], primary_key="node")
    else:
        del(avd_svi["nodes"])

    # mtu
    if get(svi, "mtu"):
        avd_svi["mtu"] = svi["mtu"]
    # ip helpers
    # or is needed because different variable name is used under vxlan tenants ip helpers input schema
    if len(svi.get("dhcpHelpers", [])) > 0 or len(svi.get("dhcpServerDetails", [])) > 0:
        dhcp_helpers = svi["dhcpHelpers"] if svi.get("dhcpHelpers") else svi.get("dhcpServerDetails")
        avd_svi["ip_helpers"] = []
        for helper in dhcp_helpers:
            ip_helper = {
                "ip_helper": helper["dhcpServer"]
            }
            if helper.get("sourceInterface"):
                ip_helper["source_interface"] = helper["sourceInterface"]
            if helper.get("sourceVrf"):
                ip_helper["source_vrf"] = helper["sourceVrf"]

            avd_svi["ip_helpers"].append(ip_helper)
    # multicast
    if switch_facts.get("underlay_multicast"):
        if get(svi, "multicast.underlayMulticastEnabled"):
            avd_svi["underlay_multicast"] = str_to_bool(svi["multicast"]["underlayMulticastEnabled"])
        if get(svi, "multicast.evnpL2MulticastEnabled"):
            avd_svi["evpn_l2_multicast"] = {"enabled": str_to_bool(svi["multicast"]["evnpL2MulticastEnabled"])}
        if get(svi, "multicast.evnpL3MulticastEnabled"):
            avd_svi["evpn_l3_multicast"] = {"enabled": str_to_bool(svi["multicast"]["evnpL3MulticastEnabled"])}

    # eos cli
    if get(svi, "eosCli"):
        avd_svi["raw_eos_cli"] = svi["eosCli"]

    #vxlan attribute overrides
    if avd_svi["vxlan"]:
        # vni override
        if get(svi, "overrideAttributes.vni"):
            avd_svi["vni_override"] = svi["overrideAttributes"]["vni"]
        # rd override
        if get(svi, "overrideAttributes.routeDistinguisher"):
            avd_svi["rd_override"] = svi["overrideAttributes"]["routeDistinguisher"]
        # rt override
        if get(svi, "overrideAttributes.routeTarget"):
            avd_svi["rt_override"] = svi["overrideAttributes"]["routeTarget"]

    return avd_svi


def get_tenant_l2vlan(l2vlan, switch_facts, campus_type=""):
    device_id = switch_facts["serial_number"]
    avd_l2vlan = {"id": l2vlan["id"]}
    # select attribute formats
    avd_l2vlan['attr_format_rt'] = get(advanced_services_settings,
        "attributeFormats.vlanBasedMacVrfAttributeFormats.macVrfRouteTargetFormat")
    avd_l2vlan['attr_format_rd'] = get(advanced_services_settings,
        "attributeFormats.vlanBasedMacVrfAttributeFormats.macVrfRouteDistinguisherFormat")
    # Get devices
    devices = []
    # Automatically add spine switches in an L2 campus
    if campus_type and campus_type == "L2" and (switch_facts["type"] == "spine" or switch_facts["network_services_l2"] and switch_facts["network_services_l3"]):
        devices.append(device_id)
    elif get(l2vlan, "devices"):
        for tag_matcher in l2vlan["devices"]:
            tag_query = tag_matcher['tagQuery']
            devices += tag_query.inputs['devices']

    avd_l2vlan["devices"] = devices
    # name
    assert get(l2vlan, "name"), f"No name is configured for L2 VLAN {l2vlan['id']}."
    avd_l2vlan["name"] = l2vlan["name"]

    # vxlan
    avd_l2vlan["vxlan"] = l2vlan.get("vxlan")
    if avd_l2vlan["vxlan"]:
        # vni override
        if l2vlan["overrideAttributes"].get("vni"):
            avd_l2vlan["vni_override"] = l2vlan["overrideAttributes"]["vni"]
        # rd override
        if l2vlan["overrideAttributes"].get("routeDistinguisher"):
            avd_l2vlan["rd_override"] = l2vlan["overrideAttributes"]["routeDistinguisher"]
        # rt override
        if l2vlan["overrideAttributes"].get("routeTarget"):
            avd_l2vlan["rt_override"] = l2vlan["overrideAttributes"]["routeTarget"]

    return avd_l2vlan

@ctx.benchmark
def get_tenants(tenants, switch_facts):
    '''
    Convert studio services data model to avd network services data model

    Args:

    Returns:
        all_services: a dictionary that conforms to avd's network services data model
    '''
    avd_tenants = []
    for tenant in tenants:
        avd_tenant = {
            "name": tenant['name'],
            "vrfs": [],
            "l2vlans": [],
            "mac_vrf_vni_base": tenant["macVrfVniBase"]
        }
        # Parse VRFs
        for vrf in tenant['vrfs']:
            # get vrf in avd format
            avd_vrf = get_tenant_vrf(vrf, switch_facts)
            # svis
            if len(vrf.get("svis", [])) > 0:
                avd_vrf["svis"] = []
                for svi in vrf["svis"]:
                    # get svi in avd format
                    avd_svi = get_tenant_svi(svi, switch_facts)

                    # append svi
                    avd_vrf["svis"].append(avd_svi)

            # append vrf
            avd_tenant["vrfs"].append(avd_vrf)

        for l2vlan in tenant['l2Vlans']:
            avd_l2vlan = get_tenant_l2vlan(l2vlan, switch_facts, campus_type="")

            # append l2vlan
            avd_tenant["l2vlans"].append(avd_l2vlan)

        # add tenant
        avd_tenants.append(avd_tenant)

    return avd_tenants


@ctx.benchmark
def get_campus_tenants(switch_facts):
    '''
    Convert studio campus services data model to avd network services data model
    Args:
    Returns:
        all_services: a dictionary that conforms to avd's network services data model
    '''
    avd_tenants = []
    # Used to check for duplicate VLANs
    svis_seen = []
    if not campus_services_details:
        return avd_tenants

    # Add default vrf to campus_services vrfs if not present
    if "default" not in [vrf["name"] for vrf in campus_services_details.get("vrfs", [])]:
        campus_services_details["vrfs"].insert(0, {"name":"default"})

    campus_name = "Campus"
    campus_pod_name = "Pod"
    tenant_name = f"{campus_name}_{campus_pod_name}"
    avd_tenant = {
        "name": tenant_name,
        "vrfs": [],
        "l2vlans": []
        # "mac_vrf_vni_base": 10000
    }

    avd_vrfs = {}
    for i, vrf in enumerate(campus_services_details.get("vrfs", [])):
        avd_vrf = get_tenant_vrf(vrf, switch_facts)
        avd_vrf["vrf_id"] = i + 1
        avd_vrf["svis"] = []
        avd_vrfs[vrf["name"]] = avd_vrf

    campus_type = campus_pod_services_details["campusType"]
    for svi in campus_pod_services_details.get("svis", []):
        svi_vrf = svi["vrf"] if svi.get("vrf") else "default"
        # get svi in avd format
        avd_svi = get_tenant_svi(svi, switch_facts, campus_type=campus_type)

        # append svi to avd_vrfs
        avd_vrfs[svi_vrf]["svis"].append(avd_svi)
        # append svi to svis_seen
        svis_seen.append(avd_svi["id"])

    avd_tenant["vrfs"] = convert_dicts(avd_vrfs, "name")

    for l2vlan in campus_pod_services_details.get('l2Vlans', []):
        # Check that l2vlan is not also in SVIs
        assert l2vlan["id"] not in svis_seen, f"VLAN {l2vlan['id']} is present in SVIs and L2 VLANs list under {switch_facts['campus']}" \
                                              f" -> {switch_facts['campus_pod']} Campus Pod. Please remove the VLAN ID from one of the lists."
        # get l2vlan in avd format
        avd_l2vlan = get_tenant_l2vlan(l2vlan, switch_facts, campus_type=campus_type)

        # append l2vlan
        avd_tenant["l2vlans"].append(avd_l2vlan)

    avd_tenants.append(avd_tenant)
    return avd_tenants


@ctx.benchmark
def get_vrf_id(vrf) -> int:
    vrf_id = default(vrf.get("vrf_id"), vrf.get("vrf_vni"))
    if vrf_id is None:
        raise Error(f"'vrf_id' or 'vrf_vni' for VRF '{vrf['name']} must be set.")
    return int(vrf_id)


@ctx.benchmark
def get_vrf_vni(vrf) -> int:
    vrf_vni = default(vrf.get("vrf_vni"), vrf.get("vrf_id"))
    if vrf_vni is None:
        raise Error(f"'vrf_vni' or 'vrf_id' for VRF '{vrf['name']} must be set.")
    return int(vrf_vni)


# Attribute translations to evals
ip_vrf_admin_field_key_words = {
    "VRF ID": "get_vrf_id_eval(vrf)",
    "Router-ID": "switch_facts['router_id']",
    "VTEP Source IP": "switch_facts['vtep_ip']"
}
vlan_based_mac_vrf_admin_field_key_words = {
    "VNI": "get_vlan_mac_vrf_vni_eval(vlan, tenant)",
    "VLAN": "vlan['id']",
    "Router-ID": "switch_facts['router_id']",
    "VTEP Source IP": "switch_facts['vtep_ip']"
}


@ctx.benchmark
def get_vrf_rd(switch_facts, vrf) -> str:
    """
    Return a string with the route-destinguisher for one VRF
    """
    def get_vrf_id_eval(vrf):
        return get_vrf_id(vrf)
    switch_attr = []
    for attr_segment in vrf['attr_format_rd'].split(":"):
        if ip_vrf_admin_field_key_words.get(attr_segment):
            switch_attr.append(str(eval(
                ip_vrf_admin_field_key_words[attr_segment])))
    return ':'.join(switch_attr)


@ctx.benchmark
def get_vrf_rt(switch_facts: dict, vrf: dict) -> str:
    """
    Return a string with the route-target for one VRF
    """
    def get_vrf_id_eval(vrf):
        return get_vrf_id(vrf)
    switch_attr = []
    for attr_segment in vrf['attr_format_rt'].split(":"):
        if ip_vrf_admin_field_key_words.get(attr_segment):
            switch_attr.append(str(eval(
                ip_vrf_admin_field_key_words[attr_segment])))
    return ':'.join(switch_attr)


@ctx.benchmark
def get_vlan_mac_vrf_vni(vlan, tenant) -> int:
    mac_vrf_vni_base = default(tenant.get("mac_vrf_vni_base"), tenant.get("mac_vrf_id_base"))
    if mac_vrf_vni_base is None:
        raise Error(
            "'rt_override' or 'vni_override' or "
            "'mac_vrf_id_base' or 'mac_vrf_vni_base' must be set. "
            f"Unable to set EVPN RD/RT for vlan {vlan['id']} "
            f"in Tenant '{vlan['tenant']}'"
        )
    return mac_vrf_vni_base + int(vlan["id"])


@ctx.benchmark
def get_vlan_rd(switch_facts, vlan, tenant) -> str:
    """
    Return a string with the route-destinguisher for one VLAN
    """
    def get_vlan_mac_vrf_vni_eval(vlan, tenant):
        return get_vlan_mac_vrf_vni(vlan, tenant)
    rd_override = default(vlan.get("rd_override"), vlan.get("rt_override"), vlan.get("vni_override"))
    if ":" in str(rd_override):
        return rd_override
    if rd_override is not None:
        return f"{switch_facts['router_id']}:{rd_override}"
    switch_attr = []
    for attr_segment in vlan['attr_format_rd'].split(":"):
        if vlan_based_mac_vrf_admin_field_key_words.get(attr_segment):
            switch_attr.append(str(eval(
                vlan_based_mac_vrf_admin_field_key_words[attr_segment])))
        else:
            switch_attr.append(attr_segment)
    return ':'.join(switch_attr)


@ctx.benchmark
def get_vlan_rt(switch_facts: dict, vlan: dict, tenant: dict) -> str:
    """
    Return a string with the route-target for one VLAN
    """
    def get_vlan_mac_vrf_vni_eval(vlan, tenant):
        return get_vlan_mac_vrf_vni(vlan, tenant)
    rt_override = default(vlan.get("rt_override"), vlan.get("vni_override"))
    if ":" in str(rt_override):
        return rt_override
    if rt_override is not None:
        return f"{rt_override}:{rt_override}"
    switch_attr = []
    for attr_segment in vlan['attr_format_rt'].split(":"):
        if vlan_based_mac_vrf_admin_field_key_words.get(attr_segment):
            switch_attr.append(str(eval(
                vlan_based_mac_vrf_admin_field_key_words[attr_segment])))
        else:
            switch_attr.append(attr_segment)
    return ':'.join(switch_attr)


@ctx.benchmark
def _get_vlan_interface_config_for_svi(switch_facts, svi, vrf, svi_profiles={}) -> dict:
    # detect if a svi_profile exists
    if svi.get("profile"):
        # If exists, create a shortpath to access profile data
        svi_profile = svi_profiles[svi.get('profile')]
    else:
        svi_profile = {}

    svi_name = svi.get("name") # | default(svi.get("name"), svi_profile.name)

    svi_description = svi.get("description", svi_name)

    svi_enabled = svi.get("enabled")  # | default(svi_profile.enabled)

    # Virtual Router IPv4 Subnet
    svi_ip_virtual_router_subnet = svi.get("ip_virtual_router_subnet")

    svi_ip_virtual_router_addresses = svi.get("ip_virtual_router_addresses", [])

    svi_ipv6_virtual_router_addresses = svi.get("ipv6_virtual_router_addresses", [])

    svi_ip_address_virtual = svi.get("ip_address_virtual")  # default(svi.get("ip_address_virtual"), svi_profile.ip_address_virtual)

    svi_ip_address_virtual_secondaries = svi.get("ip_address_virtual_secondaries")  # default(svi.get("ip_address_virtual_secondaries"), svi_profile.ip_address_virtual_secondaries)

    svi_mtu = svi.get("mtu")  # default(svi.get("mtu"), svi_profile.get("mtu"))

    svi_ip_helpers = default(svi.get("ip_helpers"), vrf.get("ip_helpers"), svi_profile.get("ip_helpers"))

    svi_ipv6_helpers = svi.get("ipv6_helpers")

    svi_raw_eos_cli = svi.get("raw_eos_cli")  # default(svi.get("raw_eos_cli"), svi_profile.get("raw_eos_cli"))

    vlan = {}
    if svi_description.strip() != "":
        svi["description"] = svi_description

    # shutdown
    if svi_enabled is True:
        svi["shutdown"] = False
    else:
        svi["shutdown"] = True
    for node in svi.get("nodes", []):
        if switch_facts["serial_number"] == node["node"] and node.get("enabled") is not None:
            svi["shutdown"] = not node["enabled"]

    svi["vrf"] = vrf["name"]

    if svi_ip_virtual_router_subnet:
        if get(advanced_services_settings, "servicesAllocations.gatewayAddressConvention", True):
            svi["ip_virtual_router_addresses"] = [ str(list(ipaddress.ip_network(svi_ip_virtual_router_subnet).hosts())[0]) ]
            if switch_facts.get("mlag_role") == "secondary":
                ip_address = list(ipaddress.ip_network(svi_ip_virtual_router_subnet).hosts())[2]
            else:
                ip_address = list(ipaddress.ip_network(svi_ip_virtual_router_subnet).hosts())[1]
        else:
            svi["ip_virtual_router_addresses"] = [ str(list(ipaddress.ip_network(svi_ip_virtual_router_subnet).hosts())[-1]) ]
            if switch_facts.get("mlag_role") == "secondary":
                ip_address = list(ipaddress.ip_network(svi_ip_virtual_router_subnet).hosts())[-2]
            else:
                ip_address = list(ipaddress.ip_network(svi_ip_virtual_router_subnet).hosts())[-3]
        svi["ip_address"] = f"{ip_address}/{ipaddress.ip_network(svi_ip_virtual_router_subnet).prefixlen}"
    # IPv4 address configuration
    for node in svi.get("nodes", []):
        if switch_facts["serial_number"] == node["node"]:
            if node.get("ip_address"):
                svi["ip_address"] = node["ip_address"]
            if node.get("ip_virtual_router_addresses"):
                svi["ip_virtual_router_addresses"] = node["ip_virtual_router_addresses"]


    # # IPv6 address configuration
    # if svi.get("nodes",{}).get(switch_facts['serial_number'], {}).get("ipv6_address"):
    #     svi["ipv6_address"] = svi["nodes"][switch_facts['serial_number']]["ipv6_address"]

    # # Virtual Router IPv4 Address
    # svi["ip_virtual_router_addresses"] = svi_ip_virtual_router_addresses

    # # Virtual Router IPv6 Address
    # svi["ipv6_virtual_router_addresses"] = svi_ipv6_virtual_router_addresses

    # # Virtual Secondary IP address
    # if svi_ip_address_virtual_secondaries is not None:
    #     svi["ip_address_virtual_secondaries"] = svi_ip_address_virtual_secondaries

    # Virtual IP address
    if svi_ip_address_virtual is not None:
        svi["ip_address_virtual"] = svi_ip_address_virtual

    # MTU definition
    if svi_mtu is not None:
        svi["mtu"] = svi_mtu  if get(switch_facts, "platform_settings.per_interface_mtu", True) else None

    # IPv4 helper configuration
    svi["ip_helpers"] = {}
    if svi_ip_helpers is not None and len(svi_ip_helpers) > 0:
        # Turn on global dhcp smart relay option
        # config["ip_dhcp_relay"] = {"information_option": True}
        # Set helper addresses
        for helper in svi_ip_helpers:
            svi["ip_helpers"][helper['ip_helper']] = {
                "vrf": helper.get("source_vrf")
            }
            if helper.get("source_interface", "").strip() != "":
                svi["ip_helpers"][helper['ip_helper']]["source_interface"] = helper["source_interface"]
    # Add extra helper for cv endpoints
    if switch_facts["network_services_l2"] and switch_facts["network_services_l3"] \
            and get(advanced_services_settings, "cvFeatureSettings.dhcpSnoopingForClientId"):
        svi['ip_helpers']["127.0.0.1"] = {
            "vrf": "default",
            "source_interface": switch_facts["router_id_loopback_interface"]
        }

    # IPv6 helper configuration
    if svi_ipv6_helpers is not None and len(svi_ipv6_helpers) > 0:
        # Turn on global dhcp smart relay option
        # config["ipv6"]["dhcp"] = {"relay": {"always_on": True}}
        # Set helper addresses
        svi["ipv6_dhcp_relay_destinations"] = []
        for helper in svi_ipv6_helpers:
            ipv6_helper = {
                "address": helper['helper_ip'],
                "vrf": helper.get("source_vrf")
            }
            if helper.get("local_interface", "").strip() != "":
                ipv6_helper["local_interface"] = helper["local_interface"]
            svi["ipv6_dhcp_relay_destinations"].append(ipv6_helper)

    # ospf
    if svi.get("ospf", {}).get("enabled", False) is True and vrf.get("ospf", {}).get("enabled", True) is True:
        # ospf area
        svi["ospf_area"] = default(svi["ospf"]["area"], "0")

        # ospf network point to point
        svi["ospf_network_point_to_point"] = default(svi["ospf"]["point_to_point"], True)

        # ospf cost
        if svi["ospf"].get("cost"):
            svi["ospf_cost"] = svi["ospf"]["cost"]

        # authentication
        if svi["ospf"].get("authentication", "") == "simple" and svi["ospf"].get("simple_auth_key", "") != "":
            svi["ospf_authentication"] = "simple"
            svi["ospf_authentication"] = svi["ospf"]["simple_auth_key"]

        elif svi["ospf"].get("authentication", "") == "message-digest" and svi["ospf"].get("message_digest_keys"):
            svi["ospf_authentication"] = "message-digest"
            svi["ospf_message_digest_keys"] = {}
            for key in svi["ospf"].get("message-message_digest_keys", []):
                if key.get("id") and key.get("key"):
                    svi["ospf_message_digest_keys"][key["id"]] = {
                        "hash_algorithm": default(key.get("hash_algorithm"), "sha512"),
                        "key": key.get("key")
                    }

    if svi.get("underlay_multicast", False) is True or get(svi, "pim.enabled"):
        assert (vrf['name'] == "default" and switch_facts["underlay_multicast"]) or get(vrf, "_multicast_enabled"), \
                f"PIM is enabled on SVI {svi['id']} in VRF {vrf['name']} but VRF {vrf['name']} does not have multicast enabled"
        svi["pim"] = {"ipv4": {"sparse_mode": True}}

    # raw eos cli
    if svi_raw_eos_cli is not None:
        svi["eos_cli"] = svi_raw_eos_cli  # May need to indent each line by 6 spaces when input type changes to extended string

    return svi


@ctx.benchmark
def router_ospf(switch_facts) -> dict | None:
    """
    return structured config for router_ospf

    If we have static_routes in default VRF and not EPVN, and underlay is OSPF
    Then add redistribute static to the underlay OSPF process.
    """

    if not switch_facts["network_services_l3"]:
        return None

    ospf_processes = []
    for tenant in switch_facts["filtered_tenants"]:
        for vrf in tenant["vrfs"]:
            if get(vrf, "ospf.enabled") is not True:
                continue

            if switch_facts["serial_number"] not in get(vrf, "ospf.nodes", default=[switch_facts["serial_number"]]):
                continue

            ospf_interfaces = []
            for l3_interface in vrf["l3_interfaces"]:
                if get(l3_interface, "ospf.enabled") is True:
                    for node_index, node in enumerate(l3_interface["nodes"]):
                        if node != switch_facts["serial_number"]:
                            continue

                        ospf_interfaces.append(l3_interface["interfaces"][node_index])

            for svi in vrf["svis"]:
                if get(svi, "ospf.enabled") is True:
                    interface_name = f"Vlan{svi['id']}"
                    ospf_interfaces.append(interface_name)

            if not get(vrf, "ospf.process_id") and vrf["name"] == "default" and switch_facts.get("underlay_ospf_process_id"):
                vrf["ospf"]["process_id"] = switch_facts["underlay_ospf_process_id"]
            process_id = default(get(vrf, "ospf.process_id"), vrf.get("vrf_id"))
            if not process_id:
                raise Error(f"'ospf.process_id' or 'vrf_id' under vrf '{vrf['name']}")

            process = {
                "id": process_id,
                "vrf": vrf["name"],
                "passive_interface_default": True,
                "router_id": default(get(vrf, "ospf.router_id"), switch_facts["router_id"]),
                "no_passive_interfaces": ospf_interfaces,
                "bfd_enable": get(vrf, "ospf.bfd"),
                "max_lsa": get(vrf, "ospf.max_lsa"),
                "eos_cli": get(vrf, "ospf.eos_cli")
            }

            process_redistribute = {}

            if get(vrf, "ospf.redistribute_bgp.enabled", default=True) is True:
                process_redistribute["bgp"] = {}
                if (route_map := get(vrf, "ospf.redistribute_bgp.route_map")) is not None:
                    process_redistribute["bgp"]["route_map"] = route_map

            if get(vrf, "ospf.redistribute_connected.enabled", default=False) is True:
                process_redistribute["connected"] = {}
                if (route_map := get(vrf, "ospf.redistribute_connected.route_map")) is not None:
                    process_redistribute["connected"]["route_map"] = route_map

            process["redistribute"] = process_redistribute or None

            # Strip None values from process before adding to list
            process = {key: value for key, value in process.items() if value is not None}

            append_if_not_duplicate(
                list_of_dicts=ospf_processes, primary_key="id", new_dict=process, context="OSPF Processes defined under network services", context_keys="id"
            )

    # If we have static_routes in default VRF and not EPVN, and underlay is OSPF
    # Then add redistribute static to the underlay OSPF process.
    # if self._vrf_default_ipv4_static_routes["redistribute_in_underlay"] and switch_facts["underlay_routing_protocol"] in ["ospf", "ospf-ldp"]:
    #     ospf_processes.append({"id": int(self.shared_utils.underlay_ospf_process_id), "redistribute": {"static": {}}})
    if ospf_processes:
        return {"process_ids": ospf_processes}

    return None


@ctx.benchmark
def _get_vlan_interface_config_for_mlag_peering(switch_facts, vrf) -> dict:
    vlan_interface_config = {
        "tenant": vrf["tenant"],
        "type": "underlay_peering",
        "shutdown": False,
        "description": f"MLAG_PEER_L3_iBGP: vrf {vrf['name']}",
        "vrf": vrf["name"],
        "mtu": switch_facts["p2p_uplinks_mtu"]
    }
    if get(vrf, "_evpn_l3_multicast_enabled") or get(vrf, "_multicast_enabled"):
        vlan_interface_config["pim"] = {"ipv4": {"sparse_mode": True}}
    if switch_facts.get("underlay_rfc5549") and switch_facts.get("overlay_mlag_rfc5549"):
        vlan_interface_config["ipv6_enable"] = True
    elif (mlag_ibgp_peering_ipv4_pool := vrf.get("mlag_ibgp_peering_ipv4_pool")) is not None:
        mlag_l3_ip = get_mlag_ip(switch_facts, mlag_ibgp_peering_ipv4_pool, switch_facts['mlag_peer_l3_subnet_mask'], switch_facts["mlag_role"])
        vlan_interface_config["ip_address"] = f"{mlag_l3_ip}/{switch_facts['mlag_peer_l3_subnet_mask']}"
    else:
        vlan_interface_config["ip_address"] = f"{switch_facts['mlag_l3_ip']}/{switch_facts['mlag_peer_l3_subnet_mask']}"
    return vlan_interface_config


@ctx.benchmark
def can_delete_bgp_vrf(vrf):
    # Remove vrf if vrf isn't necessary
    tmp_vrf = vrf.copy()
    tmp_vrf.pop("router_id")
    tmp_vrf.pop("rd")
    redistribute_routes = tmp_vrf.pop('redistribute_routes')
    tmp_vrf = strip_null_from_data(tmp_vrf, strip_values_tuple=(None, "", {}, []))
    if tmp_vrf == {} and len(redistribute_routes) == 1:
        return True
    return False

@ctx.benchmark
def set_network_services_config_vlans(config, switch_facts, network_services_data):
    # Enable dhcp smart relay
    config['ip_dhcp_relay'] = {"information_option": True}
    # Enable dhcp snooping
    ip_igmp_snooping = {}
    igmp_snooping_vlans = []
    igmp_snooping_enabled = get(switch_facts, "igmp_snooping_enabled", required=False)
    for tenant in network_services_data["tenants"]:
        tenant_igmp_snooping_querier = tenant.get("igmp_snooping_querier", {})
        # Set l3 vlan config
        for vrf in tenant.get('vrfs', []):
            # Create vlans
            for svi in vrf.get('svis', []):
                # Create L3 vlans
                config['vlans'][svi['id']] = {
                    "tenant": tenant,
                    "name": svi['name']
                }
            # Set vrf ibgp peering vlan params
            if switch_facts.get('mlag') and switch_facts['network_services_l3'] \
                    and vrf.get('enable_mlag_ibgp_peering_vrfs') \
                    and vrf.get("mlag_ibgp_peering_vlan"):
                ibgp_vlan = vrf['mlag_ibgp_peering_vlan']
                config['vlans'][ibgp_vlan] = {
                    "tenant": tenant['name'],
                    "name": f"MLAG_iBGP_{vrf['name']}",
                    "trunk_groups": ['MLAG_VRF_PEER']
                }

        # Set l2 vlan config
        for l2vlan in tenant.get('l2vlans', []):
            config['vlans'][l2vlan['id']] = {
                "tenant": tenant['name'],
                "name": l2vlan['name']
            }
            # Section commented out for now until more detail is found on which platforms
            # support dhcp snooping
            # Create L2 SVI with helper address pointing towards CVP
            # config['vlan_interfaces'][f"Vlan{l2vlan['id]}"]['ip_helpers'] = {
            #     "127.0.0.1": {}
            # }
            # # enable snooping on the vlan
            # config['ip_dhcp_snooping']['vlans'].append(l2vlan['id'])

            # igmp snooping
            ip_igmp_snooping_vlan = {}
            if igmp_snooping_enabled is not None:
                ip_igmp_snooping_vlan["enabled"] = igmp_snooping_enabled
            igmp_snooping_querier = l2vlan.get("igmp_snooping_querier", {})
            vlan_evpn_l2_multicast_enabled = default(get(l2vlan, "evpn_l2_multicast.enabled"), get(tenant, "evpn_l2_multicast.enabled"))
            if switch_facts.get("vtep") and vlan_evpn_l2_multicast_enabled:
                igmp_snooping_querier_enabled = True
                ip_igmp_snooping_vlan["id"] = l2vlan["id"]
                ip_igmp_snooping_vlan["querier"] = {"enabled": igmp_snooping_querier_enabled}
                address = default(igmp_snooping_querier.get("source_address"), tenant_igmp_snooping_querier.get("source_address"), switch_facts["router_id"])
                if address is not None:
                    ip_igmp_snooping_vlan["querier"]["address"] = address

                version = default(
                    igmp_snooping_querier.get("version"),
                    tenant_igmp_snooping_querier.get("version"),
                )
                if version is not None:
                    ip_igmp_snooping_vlan["querier"]["version"] = version

                igmp_snooping_vlans.append(ip_igmp_snooping_vlan)

        if igmp_snooping_enabled and igmp_snooping_vlans:
            config["ip_igmp_snooping"] = {
                "globally_enabled": True,
                "vlans": igmp_snooping_vlans
            }
    return config


@ctx.benchmark
def set_network_services_config_l3(config, switch_facts, network_services_data):
    ip_dhcp_snooping_vlans = []
    if switch_facts['network_services_l2'] and switch_facts['network_services_l3'] \
          and (cv_dhcp_snooping := get(advanced_services_settings, "cvFeatureSettings.dhcpSnoopingForClientId")):
        config['ip_dhcp_snooping'] = {
            "enabled": True,
            "information_option": {
                "enabled":True
            }
        }
    for tenant in network_services_data["tenants"]:
        for vrf in tenant.get('vrfs', []):
            # configure vrfs
            config['vrfs'][vrf['name']] = {
                "tenant": tenant['name'],
                "ip_routing": True
            }
            # multicast
            if get(vrf, "_evpn_l3_multicast_enabled") or get(vrf, "_multicast_enabled"):
                config["router_multicast"]["vrfs"].append({
                    "name": vrf['name'],
                    "ipv4": {
                        "routing": True
                    }
                })

                # pim rps
                vrf_rps = get(vrf, "_pim_rp_addresses")
                if vrf_rps:
                    config["router_pim_sparse_mode"]["vrfs"].append(
                        {
                            "name": vrf["name"],
                            "ipv4": {
                                "rp_addresses": vrf_rps,
                            }
                        }
                    )

            # configure static routes
            if vrf.get('static_routes') is not None:
                for static_route in vrf['static_routes']:
                    sr = {
                        "destination_address_prefix": static_route['destination_address_prefix']
                    }
                    if vrf['name'] != "default":
                        sr["vrf"] = vrf['name']
                    if static_route.get('gateway') and static_route['gateway'].strip() != "":
                        sr['gateway'] = static_route['gateway']
                    if static_route.get('distance'):
                        sr['distance'] = str(static_route['distance'])
                    if static_route.get('tag'):
                        sr['tag'] = str(static_route['tag'])
                    if static_route.get('name') and static_route['name'].strip() != "":
                        sr['name'] = static_route['name']
                    if static_route.get('metric'):
                        sr['metric'] = str(static_route['metric'])
                    if static_route.get('interface') and static_route['interface'].strip() != "":
                        sr['interface'] = static_route['interface']
                    config['static_routes'].append(sr)

            # configure ethernet interfaces
            if vrf.get('l3_interfaces') is not None:
                l3_interface_subif_parents = []
                for l3_iface in vrf['l3_interfaces']:
                    eth_iface = {}
                    l3_interface_subif_id = None
                    if "." in l3_iface['interfaces'][0]:
                        if l3_iface.get('encapsulation_dot1q_vlan'):
                            l3_interface_subif_id = l3_iface['encapsulation_dot1q_vlan']
                        else:
                            l3_interface_subif_id = l3_iface['interfaces'][0].split('.')[1]
                        l3_interface_subif_parents.append(l3_iface['interfaces'][0].split('.')[0])
                    if l3_interface_subif_id is not None:
                        eth_iface['type'] = "l3dot1q"
                        eth_iface['encapsulation_dot1q_vlan'] = l3_interface_subif_id
                    else:
                        eth_iface['type'] = "routed"
                        if l3_iface.get("speed"):
                            eth_iface["speed"] = l3_iface["speed"]
                    eth_iface['peer_type'] = "l3_interface"
                    if vrf['name'] != "default":
                        eth_iface['vrf'] = vrf['name']
                    eth_iface['ip_address'] = l3_iface['ip_addresses'][0]
                    if l3_iface.get('mtu'):
                        eth_iface['mtu'] = l3_iface['mtu'] if get(switch_facts, "platform_settings.per_interface_mtu", True) else None
                    if l3_iface.get('enabled') is not None:
                        eth_iface['shutdown'] = not l3_iface["enabled"]
                    if l3_iface.get('description') and l3_iface['description'].strip() != "":
                        eth_iface['description'] = l3_iface['description']
                    if l3_iface.get('raw_eos_cli'):
                        eth_iface['eos_cli'] = l3_iface['raw_eos_cli']

                    if vrf["name"] != "default":
                        eth_iface["vrf"] = vrf["name"]

                    if get(l3_iface, "ospf.enabled") is True and get(vrf, "ospf.enabled") is True:
                        eth_iface["ospf_area"] = l3_iface["ospf"].get("area", "0")
                        eth_iface["ospf_network_point_to_point"] = l3_iface["ospf"].get("point_to_point", False)
                        eth_iface["ospf_cost"] = l3_iface["ospf"].get("cost")
                        ospf_authentication = l3_iface["ospf"].get("authentication")
                        if ospf_authentication == "simple" and (ospf_simple_auth_key := l3_iface["ospf"].get("simple_auth_key")) is not None:
                            eth_iface["ospf_authentication"] = ospf_authentication
                            eth_iface["ospf_authentication_key"] = ospf_simple_auth_key
                        elif (
                            ospf_authentication == "message-digest"
                            and (ospf_message_digest_keys := l3_iface["ospf"].get("message_digest_keys")) is not None
                        ):
                            ospf_keys = []
                            for ospf_key in ospf_message_digest_keys:
                                if not ("id" in ospf_key and "key" in ospf_key):
                                    continue

                                ospf_keys.append(
                                    {
                                        "id": ospf_key["id"],
                                        "hash_algorithm": ospf_key.get("hash_algorithm", "sha512"),
                                        "key": ospf_key["key"],
                                    }
                                )

                            if ospf_keys:
                                eth_iface["ospf_authentication"] = ospf_authentication
                                eth_iface["ospf_message_digest_keys"] = ospf_keys

                    if get(l3_iface, "pim.enabled"):
                        assert vrf.get("_evpn_l3_multicast_enabled") or vrf.get("_multicast_enabled"), (f"'pim: enabled' set on l3_interface {l3_iface['interfaces'][0]} on {switch_facts['hostname']}"
                                                                                                        f" This requires 'multicast: enabled' true under VRF '{vrf['name']}'.")

                        # if not vrf.get("_pim_rp_addresses"):
                        #     raise Error(
                        #         f"'pim: enabled' set on l3_interface {interface_name} on {self.shared_utils.hostname} requires at least one RP defined"
                        #         f" in pim_rp_addresses under VRF '{vrf.name}' or Tenant '{tenant.name}'"
                        #     )

                        eth_iface["pim"] = {"ipv4": {"sparse_mode": True}}

                    # Strip None values from vlan before adding to list
                    eth_iface = {key: value for key, value in eth_iface.items() if value is not None}

                    config['ethernet_interfaces'][l3_iface['interfaces'][0]] = eth_iface
                for parent_iface in l3_interface_subif_parents:
                    config['ethernet_interfaces'][parent_iface] = {
                        "type": "routed",
                        "peer_type": "l3_interface",
                        "shutdown": False
                    }
                    if l3_iface.get("speed"):
                        config['ethernet_interfaces'][parent_iface]["speed"] = l3_iface["speed"]

            # configure route maps
            for peer in vrf.get("bgp_peers", []):
                if peer.get('set_ipv4_next_hop') or peer.get('set_ipv6_next_hop'):
                    config['route_maps'][f"RM-{vrf['name']}-{peer['ip_address']}-SET-NEXT-HOP-OUT"] = {
                        "sequence_numbers": {
                            10: {
                                "type": "permit",
                                "set": []
                            }
                        }
                    }
                    if peer.get('set_ipv4_next_hop'):
                        (config['route_maps'][f"RM-{vrf['name']}-{peer['ip_address']}-SET-NEXT-HOP-OUT"]
                        ['sequence_numbers'][10]['set']).append(f"ip next-hop {peer['set_ipv4_next_hop']}")
                    elif peer.get('set_ipv6_next_hop'):
                        (config['route_maps'][f"RM-{vrf['name']}-{peer['ip_address']}-SET-NEXT-HOP-OUT"]
                        ['sequence_numbers'][10]['set']).append(f"ipv6 next-hop {peer['set_ipv6_next_hop']}")

            # set and configure vtep diagnostic loopback interfaces
            if vrf.get('vtep_diagnostic'):
                loopback = vrf['vtep_diagnostic']['loopback']
                loopback_description = f"{vrf['name']}_VTEP_DIAGNOSTICS"
                loopback_ipv4_pool = vrf['vtep_diagnostic']['loopback_ip_range']
                if loopback_ipv4_pool:
                    loopback_ipv4_offset = 0
                    if switch_facts["type"] == "leaf" and ("vxlan" in switch_facts["campus_type"] or
                                                           "evpn" in switch_facts["campus_type"]):
                        # Offset is 2
                        loopback_ipv4_offset = 2
                    loopback_ip_host_addresses = list(ipaddress.ip_network(loopback_ipv4_pool).hosts())
                    loopback_ip = str(loopback_ip_host_addresses[int(switch_facts['id']) - 1 + loopback_ipv4_offset])
                    config['loopback_interfaces'][f"{loopback}"] = {
                        "description": loopback_description,
                        "shutdown": False,
                        "vrf": vrf['name'],
                        "ip_address": f"{loopback_ip}/32"
                    }
                    # Set virtual-source-nat-vrfs
                    config['virtual_source_nat_vrfs'][vrf['name']] = {
                        "ip_address": loopback_ip
                    }

            if switch_facts['network_services_l2'] and switch_facts['network_services_l3']:
                # configure svis
                for svi in vrf.get('svis', []):
                    svi["tenant"] = tenant["name"]
                    vlan_interface_config = _get_vlan_interface_config_for_svi(switch_facts, svi, vrf)
                    config["vlan_interfaces"][f"Vlan{svi['id']}"] = vlan_interface_config
                    if cv_dhcp_snooping:
                        ip_dhcp_snooping_vlans.append(svi['id'])

                # VLAN interface for iBGP peering in overlay VRFs
                if switch_facts.get("mlag_l3", False) is True:
                    configure_mlag_ibgp_peering = vrf.get("enable_mlag_ibgp_peering_vrfs", True)
                    if configure_mlag_ibgp_peering and vrf.get("mlag_ibgp_peering_vlan"):
                        vrf["tenant"] = tenant["name"]
                        vlan_interface_config = _get_vlan_interface_config_for_mlag_peering(switch_facts, vrf)
                        config["vlan_interfaces"][f"Vlan{vrf['mlag_ibgp_peering_vlan']}"] = vlan_interface_config

                        # Add trunk group to port-channel
                        assert switch_facts.get('mlag_port_channel_id'), \
                         f"Ensure sure a peer link is defined between {switch_facts['hostname']} " \
                         f"and its MLAG peer in the Inventory & Topology studio."
                        if "MLAG_VRF_PEER" not in (config['port_channel_interfaces']
                                                [f"Port-Channel{switch_facts['mlag_port_channel_id']}"]
                                                ['trunk_groups']):
                            (config['port_channel_interfaces']
                            [f"Port-Channel{switch_facts['mlag_port_channel_id']}"]
                            ['trunk_groups']).append("MLAG_VRF_PEER")

    # ospf
    if (switch_facts.get("router_id")) and (vrf_ospf := router_ospf(switch_facts)):
        if config["router_ospf"].get("process_ids"):
            config["router_ospf"]["process_ids"] += vrf_ospf["process_ids"]
        else:
            config["router_ospf"] = vrf_ospf

    # Clean ip_dhcp_snooping.vlan
    if ip_dhcp_snooping_vlans:
        config["ip_dhcp_snooping"]["vlan"] =  list_compress(ip_dhcp_snooping_vlans)

    return config


@ctx.benchmark
def set_network_services_config_vtep(config, switch_facts, network_services_data):
    @ctx.benchmark
    def prepare_vtep_tenant_L3(tenant, switch_facts):
        @ctx.benchmark
        def prepare_vtep_tenant_vrf_general(tenant, vrf, switch_facts):
            if switch_facts.get("underlay_routing_protocol"):
                # Set vrf rd
                vrf["route_distinguisher"] = get_vrf_rd(switch_facts, vrf)
                if switch_facts.get("overlay_routing_protocol"):
                    # Set vrf rt
                    vrf['route_target'] = get_vrf_rt(switch_facts, vrf)
                    # Set l3 multicast group
                    if vrf.get("_evpn_l3_multicast_enabled") and tenant.get("evpn_l3_multicast"):
                        mcast_pool = tenant["evpn_l3_multicast"]["evpn_underlay_l3_multicast_group_ipv4_pool"]
                        offset = vrf['vni'] - 1 + tenant["evpn_l3_multicast"].get("evpn_underlay_l3_multicast_group_ipv4_pool_offset", 0)
                        underlay_group_address = get_ip(mcast_pool, 32, offset, 0)
                        vrf["multicast_group"] = underlay_group_address

        @ctx.benchmark
        def prepare_vtep_tenant_vrf_svis(tenant, vrf, switch_facts):
            # Set L3 vlans
            for vlan in vrf.get("svis", []):
                if not vlan["vxlan"] or not switch_facts.get("vtep"):
                    continue
                # Set vlan rd
                vlan['route_distinguisher'] = get_vlan_rd(switch_facts, vlan, tenant)
                # Set vlan rts
                switch_rt = []  # For both import/export rt
                vlan['route_target'] = get_vlan_rt(switch_facts, vlan, tenant)

                if switch_facts.get('evpn_gateway_vxlan_l2'):
                    vlan['rd_evpn_domain'] = {
                        "domain": "remote",
                        "rd": vlan['route_distinguisher']
                    }
                    vlan['import_export_evpn_domains'] = [
                        {
                            "domain": "remote",
                            "route_target": vlan['route_target']
                        }
                    ]

        # Set vrfs
        for vrf in tenant.get("vrfs", []):
            if vrf["name"] != "default":
                prepare_vtep_tenant_vrf_general(tenant, vrf, switch_facts)
            prepare_vtep_tenant_vrf_svis(tenant, vrf, switch_facts)

    @ctx.benchmark
    def prepare_vtep_tenant_L2(tenant, switch_facts):
        # Set L2 vlans
        for vlan in tenant.get("l2vlans", []):
            if not vlan["vxlan"] or not switch_facts.get("vtep"):
                continue
            vlan_evpn_l2_multicast_enabled = default(get(vlan, "evpn_l2_multicast.enabled"), get(tenant, "evpn_l2_multicast.enabled"))
            if vlan_evpn_l2_multicast_enabled is True:
                mcast_pool = get(
                    tenant,
                    "evpn_l2_multicast.underlay_l2_multicast_group_ipv4_pool",
                    required=True,
                    org_key=f"'evpn_l2_multicast.underlay_l2_multicast_group_ipv4_pool' for Tenant: {tenant['name']}",
                )
                offset = vlan['id'] - 1 + get(tenant, "evpn_l2_multicast.underlay_l2_multicast_group_ipv4_pool_offset", default=0)
                underlay_group_address = get_ip(mcast_pool, 32, offset, 0)
                vlan["multicast_group"] = underlay_group_address

            # Set vlan rd
            vlan['route_distinguisher'] = get_vlan_rd(switch_facts, vlan, tenant)
            # Set vlan rt
            vlan['route_target'] = get_vlan_rt(switch_facts, vlan, tenant)
            if switch_facts.get('evpn_gateway_vxlan_l2'):
                vlan['rd_evpn_domain'] = {
                    "domain": "remote",
                    "rd": vlan['route_distinguisher']
                }
                vlan['import_export_evpn_domains'] = [
                    {
                        "domain": "remote",
                        "route_target": vlan['route_target']
                    }
                ]

    @ctx.benchmark
    def set_config_vtep_tenant_bgp_L3(tenant, config, switch_facts):
        if switch_facts.get("bgp_as"):
            # Set vrfs
            for vrf in tenant.get('vrfs', []):
                address_family_ipv4_neighbors = []
                address_family_ipv6_neighbors = []
                try:
                    if vrf['name'] == "default":
                        route_distinguisher = None
                        route_targets = None
                    else:
                        route_distinguisher = vrf['route_distinguisher']
                        route_targets = {}
                        if switch_facts["overlay_routing_protocol"] == "ebgp":
                            route_targets["import"] = {"evpn": [vrf['route_target']]}
                            route_targets["export"] = {"evpn": [vrf['route_target']]}

                        # additional route targets
                        if vrf.get('additional_route_targets'):
                            for rt in natural_sort(vrf['additional_route_targets']):
                                if rt.get('address_family') \
                                        and rt.get('route_target') \
                                        and rt.get('type'):
                                    if rt['address_family'] == "evpn" and switch_facts["overlay_routing_protocol"] != "ebgp":
                                        continue
                                    if rt['address_family'] in route_targets[rt['type']].keys():
                                        route_targets[rt['type']][rt['address_family']].append(rt['route_target'])
                                    else:
                                        route_targets[rt['type']].update({rt['address_family']: rt['route_target']})
                except Exception as e:
                    assert False, f"{switch_facts['hostname']} is having an issue with {vrf['name']} vrf: {e}"
                # initialize vrf
                config['router_bgp']['vrfs'][vrf['name']] = {
                    "router_id": switch_facts['router_id'],
                    "rd": route_distinguisher,
                    "route_targets": route_targets,
                    "neighbors": {},
                    "redistribute_routes": {
                        "connected": {}
                        # "attached-host": {}
                    },
                    "address_families": {
                        "ipv4": {"neighbors": {}, "networks": {}},
                        "ipv6": {"neighbors": {}, "networks": {}}
                    },
                    "eos_cli": []
                }
                if switch_facts["overlay_routing_protocol"] == "ebgp":
                    config['router_bgp']['vrfs'][vrf['name']]["evpn_multicast"] = get(vrf, "_evpn_l3_multicast_enabled")
                # set mlag peer config
                mlag_peer_sn = switch_facts.get('mlag_peer_serial_number')
                if switch_facts.get('mlag') and mlag_peer_sn \
                        and vrf.get('enable_mlag_ibgp_peering_vrfs') \
                        and vrf.get("mlag_ibgp_peering_vlan"):
                    mlag_peer_switch_facts = my_switch_facts_neighbors[mlag_peer_sn]
                    ibgp_vlan = vrf['mlag_ibgp_peering_vlan']
                    if (mlag_ibgp_peering_ipv4_pool := vrf.get("mlag_ibgp_peering_ipv4_pool")) is not None:
                        ibgp_peering_subnet = vrf['mlag_ibgp_peering_ipv4_pool']
                    else:
                        ibgp_peering_subnet = mlag_peer_switch_facts["mlag_peer_l3_ipv4_pool"]
                    ibgp_peering_subnet_mask = switch_facts['mlag_peer_l3_subnet_mask']
                    mlag_peer_ip = str(get_mlag_ip(
                            mlag_peer_switch_facts,
                            ibgp_peering_subnet,
                            ibgp_peering_subnet_mask,
                            mlag_peer_switch_facts['mlag_role']
                            )
                        )

                    # Add mlag_ip to nieghbors and address family
                    config['router_bgp']['vrfs'][vrf['name']]['neighbors'][mlag_peer_ip] = {
                        "remote_as": switch_facts['bgp_as'],
                        "description": mlag_peer_switch_facts['hostname'],
                        "send_community": "all",
                        "next_hop_self": True,
                    }
                    address_family_ipv4_neighbors.append(mlag_peer_ip)
                # set external bgp peers
                for peer in vrf.get("bgp_peers", []):
                    if validIPAddress(peer["ip_address"]) is True:
                        address_family_ipv4_neighbors.append(peer["ip_address"])
                    elif validIPAddress(peer) is False:
                        address_family_ipv6_neighbors.append(peer["ip_address"])
                    else:
                        continue
                    if peer.get('set_ipv4_next_hop') or peer.get('set_ipv6_next_hop'):
                        peer.update({"route_map_out": f"RM-{vrf['name']}-{peer['ip_address']}-SET-NEXT-HOP-OUT"})
                        if peer.get('default_originate'):
                            if not peer['default_originate'].get('route_map'):
                                peer['default_originate'].update(
                                    {"route_map": f"RM-{vrf['name']}-{peer['ip_address']}-SET-NEXT-HOP-OUT"}
                                )
                        if peer.get('set_ipv4_next_hop'):
                            peer.pop("set_ipv4_next_hop")
                        if peer.get('set_ipv6_next_hop'):
                            peer.pop("set_ipv6_next_hop")
                    config['router_bgp']['vrfs'][vrf['name']]['neighbors'][peer["ip_address"]] = peer
                # set general bgp
                if vrf.get('bgp') and vrf['bgp'].get('raw_eos_cli'):
                    config['router_bgp']['vrfs'][vrf['name']]['eos_cli'] = vrf['bgp']['raw_eos_cli']

                # redistribute static routes
                if vrf.get('redistribute_static'):
                    config['router_bgp']['vrfs'][vrf['name']]['redistribute_routes']['static'] = {}

                # redistribute static routes
                if get(vrf, "ospf.enabled") is True and vrf.get('redistribute_ospf'):
                    config['router_bgp']['vrfs'][vrf['name']]['redistribute_routes']['ospf'] = {}

                # activate neighbors for ipv4 address family
                if len(address_family_ipv4_neighbors) > 0:
                    for neighbor in address_family_ipv4_neighbors:
                        config['router_bgp']['vrfs'][vrf['name']]['address_families']['ipv4']['neighbors'][neighbor] = {
                            "activate": True
                        }
                else:
                    del(config['router_bgp']['vrfs'][vrf['name']]['address_families']['ipv4'])
                # activate neighbors for ipv6 address family
                if len(address_family_ipv6_neighbors) > 0:
                    for neighbor in address_family_ipv6_neighbors:
                        config['router_bgp']['vrfs'][vrf['name']]['address_families']['ipv6']['neighbors'][neighbor] = {
                            "activate": True
                        }
                else:
                    del(config['router_bgp']['vrfs'][vrf['name']]['address_families']['ipv6'])

                # multicast
                if switch_facts["overlay_routing_protocol"] == "ebgp":
                    evpn_multicast_transit_mode = get(vrf, "_evpn_l3_multicast_evpn_peg_transit")
                    if evpn_multicast_transit_mode is True:
                        config['router_bgp']['vrfs'][vrf['name']]["evpn_multicast_address_family"] = {"ipv4": {"transit": evpn_multicast_transit_mode}}

                # Set l3 vlans
                if switch_facts["overlay_routing_protocol"] == "ebgp" and switch_facts.get("vtep") and switch_facts["network_services_l2"]:
                    for svi in vrf.get('svis', []):
                        if not svi['vxlan']:
                            continue
                        vlan_in_bundle = False
                        for bundle in tenant.get('vlan_aware_bundles', []):
                            if svi['id'] in string_to_list(bundle['vlan_range']):
                                vlan_in_bundle = True
                                break
                        if vlan_in_bundle is True:
                            continue
                        config['router_bgp']['vlans'][svi['id']] = {
                            "tenant": tenant['name'],
                            "rd": svi['route_distinguisher'],
                            "route_targets": {},
                            "redistribute_routes": {
                                "learned": {}
                            }
                        }
                        if switch_facts.get("dot1x"):
                            config['router_bgp']['vlans'][svi['id']]['redistribute_routes']['dot1x'] = {}
                        if svi.get('rd_evpn_domain'):
                            config['router_bgp']['vlans'][svi['id']]['rd_evpn_domain'] = svi['rd_evpn_domain']
                        # Set route targets
                        config['router_bgp']['vlans'][svi['id']]['route_targets']['both'] = [svi['route_target']] if svi.get('route_target') else None
                        if svi.get('import_export_evpn_domains'):
                            config['router_bgp']['vlans'][svi['id']]['route_targets']['import_export_evpn_domains'] = svi['import_export_evpn_domains']

                # Remove vrf if vrf isn't necessary
                if can_delete_bgp_vrf(config['router_bgp']['vrfs'][vrf['name']]):
                    del(config['router_bgp']['vrfs'][vrf['name']])
                else:
                    if not config['router_bgp'].get("as") and switch_facts.get("bgp_as"):
                        config["router_bgp"]["as"] = switch_facts["bgp_as"]

    @ctx.benchmark
    def set_config_vtep_tenant_bgp_L2(tenant, config):
        if switch_facts["overlay_routing_protocol"] == "ebgp" and switch_facts.get("vtep") and switch_facts["network_services_l2"]:
            # Set l2 vlans
            for l2vlan in tenant.get('l2vlans', []):
                if not l2vlan['vxlan']:
                    continue
                vlan_in_bundle = False
                for bundle in tenant.get('vlan_aware_bundles', []):
                    if l2vlan['id'] in string_to_list(bundle['vlan_range']):
                        vlan_in_bundle = True
                        break
                if vlan_in_bundle is True:
                    continue
                config['router_bgp']['vlans'][l2vlan['id']] = {
                    "tenant": tenant['name'],
                    "rd": l2vlan['route_distinguisher'],
                    "route_targets": {},
                    "redistribute_routes": {
                        "learned": {}
                    }
                }
                if switch_facts.get("dot1x"):
                    config['router_bgp']['vlans'][l2vlan['id']]['redistribute_routes']['dot1x'] = {}
                if l2vlan.get('rd_evpn_domain'):
                    config['router_bgp']['vlans'][l2vlan['id']]['rd_evpn_domain'] = l2vlan['rd_evpn_domain']
                # Set route targets
                config['router_bgp']['vlans'][l2vlan['id']]['route_targets']['both'] = [l2vlan['route_target']] if l2vlan.get('route_target') else None
                if l2vlan.get('import_export_evpn_domains'):
                    config['router_bgp']['vlans'][l2vlan['id']]['route_targets']['import_export_evpn_domains'] = l2vlan['import_export_evpn_domains']

    @ctx.benchmark
    def set_config_vtep_tenant_vxlan_vrf(tenant, config):
        if switch_facts.get("vtep"):
            if switch_facts["network_services_l3"]:
                for vrf in tenant.get('vrfs', []):
                    if vrf['name'] != "default":
                        # map vrfs to vnis
                        config['vxlan_interface']['Vxlan1']['vxlan']['vrfs'][vrf['name']] = {
                            "vni": get_vrf_vni(vrf)
                        }
                        if vrf.get("multicast_group"):
                            config['vxlan_interface']['Vxlan1']['vxlan']['vrfs'][vrf['name']]["multicast_group"] = vrf["multicast_group"]
                    # map l3vlans to vnis
                    if switch_facts["network_services_l2"]:
                        for svi in vrf.get('svis', []):
                            if not svi['vxlan']:
                                continue
                            config['vxlan_interface']['Vxlan1']['vxlan']['vlans'][svi['id']] = {
                                "vni": get_vlan_mac_vrf_vni(svi, tenant)
                            }

    @ctx.benchmark
    def set_config_vtep_tenant_vxlan_L2(tenant, config):
        # map l2vlans to vnis
        if switch_facts.get("vtep") and switch_facts["network_services_l2"]:
            for l2vlan in tenant.get('l2vlans', []):
                if not l2vlan['vxlan']:
                    continue
                config['vxlan_interface']['Vxlan1']['vxlan']['vlans'][l2vlan['id']] = {
                    "vni": get_vlan_mac_vrf_vni(l2vlan, tenant)
                }
                if l2vlan.get("multicast_group"):
                    config['vxlan_interface']['Vxlan1']['vxlan']['vlans'][l2vlan['id']]["multicast_group"] = l2vlan["multicast_group"]

    # Start of set_network_services_config_vtep()
    #
    # Prepare tenants for config
    for tenant in network_services_data["tenants"]:
        prepare_vtep_tenant_L3(tenant, switch_facts)
        prepare_vtep_tenant_L2(tenant, switch_facts)
        # prepare_vtep_tenant_bundles(tenant)

    # Set bgp
    if switch_facts['network_services_l3']:
        config['router_bgp']['vrfs'] = {}
        config['router_bgp']['vlans'] = {}
        # config['router_bgp']['vlan_aware_bundles'] = {}
        for tenant in network_services_data["tenants"]:
            set_config_vtep_tenant_bgp_L3(tenant, config,
                                   switch_facts)
            set_config_vtep_tenant_bgp_L2(tenant, config)
            # set_config_vtep_tenant_bgp_bundles(tenant, config)

    # Set vxlan interface
    # config['vxlan_interface'] = {"Vxlan1": {"vxlan": {"vrfs": {}, "vlans": {}}}}
    for tenant in network_services_data["tenants"]:
        set_config_vtep_tenant_vxlan_vrf(tenant, config)
        set_config_vtep_tenant_vxlan_L2(tenant, config)

    return config

# Connected endpoints helper functions
@ctx.benchmark
def _filtered_connected_endpoints(switch_facts, avd_connected_endpoints) -> list:
    """
    Return list of endpoints defined under one of the keys in "connected_endpoints_keys"
    which are connected to this switch.

    Adapters are filtered to contain only the ones connected to this switch.
    """
    filtered_connected_endpoints = []
    for connected_endpoints_key, connected_endpoints in avd_connected_endpoints.items():
        # connected_endpoints is avd format connected_endpoints list of dictionaries
        for connected_endpoint in connected_endpoints:
            if "adapters" not in connected_endpoint:
                continue

            filtered_adapters = []
            for adapter_index, adapter in enumerate(connected_endpoint["adapters"]):
                adapter_settings = adapter

                # Match switch being connected to endpoints
                if switch_facts["serial_number"] not in adapter_settings.get("switches", []):
                    continue

                # Update Port-Channel MLAG setting
                if adapter_settings.get("port_channel") and get(adapter_settings, "port_channel.mlag") is None  \
                        and switch_facts.get("mlag_peer_serial_number") in adapter_settings["switches"]:
                    adapter_settings["port_channel"]["mlag"] = True
                # Update VLANs setting
                if adapter_settings.get("vlans", "") == "all":
                    adapter_settings.pop("vlans")
                else:
                    # Get services vlan ids
                    service_vlans = list(set(range_expand(switch_facts["vlans"])))
                    # add inband management vlan
                    if switch_facts.get("inband_management_vlan"):
                        service_vlans.append(switch_facts["inband_management_vlan"])
                    # Get transit vlan ids
                    transit_vlans = [svi['id'] for svi in avd_transit_svis]
                    if adapter_settings.get('vlans', '') == "services":
                        uplink_vlans = service_vlans
                    elif adapter_settings.get('vlans', '') == "transit":
                        uplink_vlans = transit_vlans
                    elif adapter_settings.get('vlans'):
                        uplink_vlans = list(set(range_expand(adapter_settings["vlans"])))
                    else:
                        uplink_vlans = service_vlans + transit_vlans
                    if adapter.get('allow_vlan_1'):
                        uplink_vlans.append(1)
                    adapter_settings["vlans"] = list_compress([int(vlan) for vlan in uplink_vlans])

                # Add adapter_settings
                filtered_adapters.append(adapter_settings)

            if filtered_adapters:
                filtered_connected_endpoints.append(
                    {
                        **connected_endpoint,
                        "adapters": filtered_adapters,
                        "type": connected_endpoints_key,
                    }
                )

    return filtered_connected_endpoints

@ctx.benchmark
def get_adapter_ptp(adapter: dict) -> Union[dict, None]:
    """
    Return ptp for one adapter
    """
    if get(adapter, "ptp.enabled") is not True:
        return None

    ptp_config = {}

    # Apply PTP profile config
    ptp_profile_name = get(adapter, "ptp.profile", default=ptp_profile)
    if ptp_profile_name:
        ptp_config.update(get_item(ptp_profiles, "profile", ptp_profile_name, default={}))

    ptp_config["enable"] = True

    if get(adapter, "ptp.endpoint_role") != "bmca":
        ptp_config["role"] = "master"

    ptp_config.pop("profile", None)

    return ptp_config

@ctx.benchmark
def get_ethernet_interface_cfg(adapter, node_index=None, connected_endpoint=None):
    """
    Return structured_config for one ethernet_interface
    """
    default_channel_group_id = int("".join(re.findall(r"\d", adapter["switch_ports"][0])))
    channel_group_id = get(adapter, "port_channel.channel_id", default=default_channel_group_id)
    # short_esi = self._get_short_esi(adapter, channel_group_id)

    # if 'descriptions' is set, it is preferred
    if (interface_descriptions := adapter.get("descriptions")) is not None:
        interface_description = interface_descriptions[node_index]
    else:
        interface_description = adapter.get("description")

    # Common ethernet_interface settings
    # TODO: avoid generating redundant structured config for port-channel members
    ethernet_interface = {
        # "peer": peer,
        # "peer_interface": peer_interface,
        "name": adapter["switch_ports"][node_index],
        "peer_type": connected_endpoint["type"],
        "port_profile": adapter.get("profile"),
        "description": interface_description,
        "speed": adapter.get("speed"),
        "mtu": adapter.get("mtu") if get(switch_facts, "platform_settings.per_interface_mtu", True) else None,
        "l2_mtu": adapter.get("l2_mtu"),
        "type": "switched",
        "shutdown": not adapter.get("enabled", True),
        "mode": adapter.get("mode"),
        "vlans": adapter.get("vlans"),
        "native_vlan_tag": adapter.get("native_vlan_tag"),
        "native_vlan": adapter.get("native_vlan"),
        "ptp": get_adapter_ptp(adapter),
        "eos_cli": adapter.get("raw_eos_cli"),
        "struct_cfg": adapter.get("structured_config"),
    }
    # Port-channel member
    port_channel_mode = get(adapter, "port_channel.mode")
    if port_channel_mode:
        ethernet_interface["channel_group"] = {
            "id": channel_group_id,
            "mode": port_channel_mode,
        }

    return strip_null_from_data(ethernet_interface, strip_values_tuple=(None, "", {}, []))

@ctx.benchmark
def ethernet_interfaces(switch_facts) -> Union[dict, None]:
    """
    Return structured config for ethernet_interfaces
    """
    ethernet_interfaces = []

    # List of ethernet_interfaces used for duplicate checks.
    non_overwritable_ethernet_interfaces = []

    for connected_endpoint in switch_facts["filtered_connected_endpoints"]:
        for adapter in connected_endpoint["adapters"]:
            for node_index, node_name in enumerate(adapter["switches"]):
                if node_name != switch_facts["serial_number"]:
                    continue

                ethernet_interface = get_ethernet_interface_cfg(adapter, node_index, connected_endpoint)
                ethernet_interfaces.append(ethernet_interface)

    if ethernet_interfaces:
        return ethernet_interfaces

    return []

@ctx.benchmark
def get_port_channel_interface_cfg(adapter: dict, port_channel_interface_name: str, channel_group_id: int, connected_endpoint: dict) -> dict:
    """
    Return structured_config for one port_channel_interface
    """

    peer = connected_endpoint["name"]
    adapter_port_channel_description = get(adapter, "port_channel.description")
    port_channel_type = "routed" if get(adapter, "port_channel.subinterfaces") else "switched"
    port_channel_mode = get(adapter, "port_channel.mode")
    node_index = my_switch_facts.get("node_id", 0) # adapter["switches"].index(self._hostname)

    # Common port_channel_interface settings
    port_channel_interface = {
        "name": port_channel_interface_name,
        "description": default(get(adapter, "port_channel.description"), adapter.get("description")),  # self.avd_interface_descriptions.connected_endpoints_port_channel_interfaces(peer, adapter_port_channel_description),
        "type": port_channel_type,
        "shutdown": not get(adapter, "port_channel.enabled", default=True),
        "mtu": adapter.get("mtu") if get(switch_facts, "platform_settings.per_interface_mtu", True) else None,
        "service_profile": adapter.get("qos_profile"),
        # "link_tracking_groups": get_adapter_link_tracking_groups(adapter),
        "eos_cli": get(adapter, "port_channel.raw_eos_cli"),
        "struct_cfg": get(adapter, "port_channel.structured_config"),
    }

    # Only switches interfaces
    if port_channel_type == "switched":
        port_channel_interface.update(
            {
                "mode": adapter.get("mode"),
                "l2_mtu": adapter.get("l2_mtu"),
                "vlans": adapter.get("vlans"),
                "native_vlan_tag": adapter.get("native_vlan_tag"),
                "native_vlan": adapter.get("native_vlan"),
                "ptp": get_adapter_ptp(adapter)
            }
        )

    # Set MLAG ID on port-channel if connection is multi-homed and this switch is running MLAG
    if get(adapter, "port_channel.mlag"):
        port_channel_interface["mlag"] = channel_group_id

    return strip_null_from_data(port_channel_interface)

@ctx.benchmark
def port_channel_interfaces(switch_facts) -> Union[dict, None]:
    """
    Return structured config for ethernet_interfaces
    """
    port_channel_interfaces = []

    for connected_endpoint in switch_facts["filtered_connected_endpoints"]:
        for adapter in connected_endpoint["adapters"]:
            if get(adapter, "port_channel.mode") is None:
                continue

            default_channel_group_id = int("".join(re.findall(r"\d", adapter["switch_ports"][0])))
            channel_group_id = get(adapter, "port_channel.channel_id", default=default_channel_group_id)

            port_channel_interface_name = f"Port-Channel{channel_group_id}"
            port_channel_config = get_port_channel_interface_cfg(adapter, port_channel_interface_name, channel_group_id, connected_endpoint)
            # append_if_not_duplicate(
            #     list_of_dicts=port_channel_interfaces,
            #     primary_key="name",
            #     new_dict=port_channel_config,
            #     context="Port-channel Interfaces defined under connected_endpoints",
            #     context_keys=["name"],
            # )
            port_channel_interfaces.append(port_channel_config)

    if port_channel_interfaces:
        return port_channel_interfaces

    return []


@ctx.benchmark
def set_network_services_config(config, switch_facts):
    # logic (Probably will be easier to break away from AVD logic)
    network_services_data = {}
    network_services_data["tenants"] = switch_facts["filtered_tenants"]
    # Configure vlans
    if switch_facts['network_services_l2']:
        config = set_network_services_config_vlans(config,
                     switch_facts, network_services_data)

    # Configure mlag
    # if switch_facts.get('mlag'):
    #     # Initialize mlag port-channel interface for ibgp trunk groups
    #     config['port_channel_interfaces'][f"Port-Channel{switch_facts['mlag_port_channel_id']}"] = {"trunk_groups": []}

    # Configure L3
    if switch_facts['network_services_l3']:
        config = set_network_services_config_l3(config, switch_facts, network_services_data)

        # Configure vtep
        config = set_network_services_config_vtep(config, switch_facts, network_services_data)

    return config


@ctx.benchmark
def set_connected_endpoints_config(config, switch_facts):
    if not switch_facts.get("network_services_l2"):
        return config

    switch_facts["filtered_connected_endpoints"] = _filtered_connected_endpoints(switch_facts, avd_connected_endpoints)

    # Get structured config for ethernet_interfaces
    my_switch_ethernet_interfaces = ethernet_interfaces(switch_facts)
    for ethernet_interface in ethernet_interfaces(switch_facts):
        interface_name = ethernet_interface.pop("name")
        if interface_name not in config["ethernet_interfaces"]:
            config["ethernet_interfaces"][interface_name] = ethernet_interface

    # Get structured config for port_channel_interfaces
    my_switch_port_channel_interfaces = port_channel_interfaces(switch_facts)
    for port_channel_interface in port_channel_interfaces(switch_facts):
        interface_name = port_channel_interface.pop("name")
        if interface_name not in config["port_channel_interfaces"]:
            config["port_channel_interfaces"][interface_name] = port_channel_interface

    return config


@ctx.benchmark
def set_inband_ztp_interfaces_config(config, switch_facts):
    # Determine whether or not boot ztp can be configured on this switch
    if switch_facts.get("advertise_inband_ztp_vlan") and switch_facts.get("inband_management_vlan"):
        for iface in switch_facts.get("inband_ztp_interfaces", []):
            if iface not in config["ethernet_interfaces"]:
                config["ethernet_interfaces"][iface] = {}
            if config["ethernet_interfaces"][iface].get("type", "") == "routed":
                continue
            config["ethernet_interfaces"][iface]["type"] = "switched"
            config["ethernet_interfaces"][iface]["shutdown"] = False
            config["ethernet_interfaces"][iface]["vlans"] = switch_facts["inband_management_vlan"]
            config["ethernet_interfaces"][iface]["mode"] = "access"
            # Used for print_ethernet function
            config["ethernet_interfaces"][iface]["ztp_interface"] = True
    return config


@ctx.benchmark
def _mlag_odd_id_based_offset(switch_facts) -> int:
    """
    Return the subnet offset for an MLAG pair based on odd id
    Requires a pair of odd and even IDs
    """
    if switch_facts.get("mlag"):
        # Verify a mix of odd and even IDs
        if (switch_facts["mlag_primary_id"] % 2) == (switch_facts["mlag_secondary_id"] % 2):
            raise Error("MLAG compact addressing mode requires all MLAG pairs to have a single odd and even ID")

        odd_id = switch_facts["mlag_primary_id"]
        if odd_id % 2 == 0:
            odd_id = switch_facts["mlag_secondary_id"]
    else:
        odd_id = switch_facts["id"]
    return int((odd_id - 1) / 2)


@ctx.benchmark
def set_custom_fabric_variables(custom_settings):
    if DEBUG_LEVEL > 2:
        ctx.info(f"{custom_settings}")
    # Inband ZTP settings
    fabric_variables["inband_ztp"] = {}
    fabric_variables["inband_ztp"]["lacp_fallback_mode"] = "individual"
    if get(custom_settings, "inbandZtp.lacpFallback.timeout"):
        fabric_variables["inband_ztp"]["lacp_fallback_timeout"] = custom_settings["inbandZtp"]["lacpFallback"]["timeout"]
    else:
        fabric_variables["inband_ztp"]["lacp_fallback_timeout"] = 30
    # Interface description settings
    if customDesc := get(custom_settings,
        "interfaceDescriptions.routerIdLoopbackInterface"):
        fabric_variables["interface_descriptions"][
            "router_id_interface"] = customDesc
    if customDesc := get(custom_settings,
        "interfaceDescriptions.vtepLoopbackInterface"):
        fabric_variables["interface_descriptions"][
            "vtep_source_interface"] = customDesc
    if customDesc := get(custom_settings,
        "interfaceDescriptions.underlayL3EthernetInterfaces"):
        fabric_variables["interface_descriptions"][
            "underlay_l3_ethernet_interfaces"] = customDesc
    if customDesc := get(custom_settings,
        "interfaceDescriptions.underlayL2EthernetInterfaces"):
        fabric_variables["interface_descriptions"][
            "underlay_l2_ethernet_interfaces"] = customDesc
    if customDesc := get(custom_settings,
        "interfaceDescriptions.underlayPortChannelInterfaces"):
        fabric_variables["interface_descriptions"][
            "underlay_port_channel_interfaces"] = customDesc
    if customDesc := get(custom_settings,
        "interfaceDescriptions.mlagPortChannelInterfaces"):
        fabric_variables["interface_descriptions"][
            "mlag_port_channel_interface"] = customDesc
    if customDesc := get(custom_settings,
        "interfaceDescriptions.mlagEthernetInterfaces"):
        fabric_variables["interface_descriptions"][
            "mlag_ethernet_interfaces"] = customDesc
    # peer group name settings
    if customName := get(custom_settings,
        "bgpPeerGroupSettings.ipv4UnderlayPeerGroup.name"):
        fabric_variables["bgp_peer_groups"][
            "IPv4_UNDERLAY_PEERS"]["name"] = customName
    if customName := get(custom_settings,
        "bgpPeerGroupSettings.mlagIPv4PeerGroup.name"):
        fabric_variables["bgp_peer_groups"][
            "MLAG_IPv4_UNDERLAY_PEER"]["name"] = customName
    if customName := get(custom_settings,
        "bgpPeerGroupSettings.evpnOverlayPeerGroup.name"):
        fabric_variables["bgp_peer_groups"][
            "EVPN_OVERLAY_PEERS"]["name"] = customName
    if DEBUG_LEVEL > 2:
        ctx.info(f"{fabric_variables}")


@ctx.benchmark
def _vlans(switch_facts) -> list[int]:
    """
    Return list of vlans after filtering network services.
    The filter is based on filter.tenants, filter.tags and filter.only_vlans_in_use

    Ex. [1, 2, 3 ,4 ,201, 3021]
    """
    if switch_facts.get("network_services_l2") or switch_facts.get("network_services_l3"):
        vlans = []
        match_tags = ["all"]  # self.shared_utils.filter_tags
        tenants = get(switch_facts, "network_services")
        # Support legacy data model by converting nested dict to list of dict
        tenants = convert_dicts(tenants, "name")
        for tenant in natural_sort(tenants, "name"):
            # if not set(self.shared_utils.filter_tenants).intersection([tenant["name"], "all"]):
            #     # Not matching tenant filters. Skipping this tenant.
            #     continue

            vrfs = tenant.get("vrfs", [])
            # Support legacy data model by converting nested dict to list of dict
            vrfs = convert_dicts(vrfs, "name")
            for vrf in natural_sort(vrfs, "name"):
                svis = vrf.get("svis", [])
                # Support legacy data model by converting nested dict to list of dict
                svis = convert_dicts(svis, "id")
                for svi in natural_sort(svis, "id"):
                    if switch_facts["serial_number"] in svi["devices"]:
                        vlans.append(int(svi["id"]))

            l2vlans = tenant.get("l2vlans", [])
            # Support legacy data model by converting nested dict to list of dict
            l2vlans = convert_dicts(l2vlans, "id")

            for l2vlan in natural_sort(l2vlans, "id"):
                if switch_facts["serial_number"] in l2vlan["devices"]:
                    vlans.append(int(l2vlan["id"]))

        switch_facts["vlans"] = list_compress(vlans)
        return switch_facts

    switch_facts["vlans"] = []
    return switch_facts


@ctx.benchmark
def _filtered_tenants(switch_facts) -> list[dict]:
    """
    Return sorted tenants list from all network_services_keys and filtered based on switch.filter_tenants
    Keys of Tenant data model will be converted to lists.
    All sub data models like vrfs and l2vlans are also converted and filtered.
    """
    filtered_tenants = []
    tenants = convert_dicts(switch_facts["network_services"])
    for tenant in tenants:
        tenant["l2vlans"] = _filtered_l2vlans(switch_facts, tenant)
        tenant["vrfs"] = _filtered_vrfs(switch_facts, tenant)
        filtered_tenants.append(tenant)

    return natural_sort(filtered_tenants, "name")


@ctx.benchmark
def _filtered_l2vlans(switch_facts, tenant: dict) -> list[dict]:
    """
    Return sorted and filtered l2vlan list from given tenant.
    Filtering based on l2vlan tags.
    """
    if "l2vlans" not in tenant:
        return []

    l2vlans: list[dict] = natural_sort(convert_dicts(tenant["l2vlans"], "id"), "id")
    l2vlans = [
        l2vlan
        for l2vlan in l2vlans
        if switch_facts['serial_number'] in l2vlan['devices']
    ]
    # Set tenant key on all l2vlans
    for l2vlan in l2vlans:
        l2vlan.update({"tenant": tenant["name"]})

    return l2vlans


@ctx.benchmark
def _filtered_vrfs(switch_facts, tenant: dict) -> list[dict]:
    """
    Return sorted and filtered vrf list from given tenant.
    Filtering based on svi tags, l3interfaces and filter.always_include_vrfs_in_tenants.
    Keys of VRF data model will be converted to lists.
    """
    filtered_vrfs = []

    # always_include_vrfs_in_tenants = get(self.shared_utils.switch_data_combined, "filter.always_include_vrfs_in_tenants", default=[])

    vrfs: list[dict] = natural_sort(convert_dicts(tenant.get("vrfs", []), "name"), "name")
    for vrf in vrfs:
        # Storing tenant on VRF for use by child objects like SVIs
        vrf["tenant"] = tenant["name"]
        bgp_peers = natural_sort(convert_dicts(vrf.get("bgp_peers"), "ip_address"), "ip_address")
        vrf["bgp_peers"] = [bgp_peer for bgp_peer in bgp_peers if switch_facts["serial_number"] in bgp_peer.get("nodes", [])]
        vrf["static_routes"] = [
            route
            for route in get(vrf, "static_routes", default=[])
            if switch_facts["serial_number"] in get(route, "nodes", [])
        ]
        # vrf["ipv6_static_routes"] = [
        #     route
        #     for route in get(vrf, "ipv6_static_routes", default=[])
        #     if self.shared_utils.hostname in get(route, "nodes", default=[self.shared_utils.hostname])
        # ]
        vrf["svis"] = _filtered_svis(switch_facts, vrf)
        vrf["l3_interfaces"] = [
            l3_interface
            for l3_interface in get(vrf, "l3_interfaces", default=[])
            if (
                switch_facts["serial_number"] in get(l3_interface, "nodes", default=[])
                and l3_interface.get("ip_addresses") is not None
                and l3_interface.get("interfaces") is not None
            )
        ]

        # non evpn multicast
        if switch_facts["underlay_multicast"] and get(vrf, "multicast_enabled"):
            vrf["_multicast_enabled"] = vrf["multicast_enabled"]
            # Format RPs
            rps = []
            for rp_address in default(get(vrf, "pim_rp_addresses"), get(tenant, "pim_rp_addresses"), []):
                if switch_facts["serial_number"] in get(rp_address, "nodes", default=[switch_facts["serial_number"]]):
                    for rp_ip in get(
                        rp_address,
                        "rps",
                        required=True,
                        org_key=f"pim_rp_addresses.rps under VRF '{vrf['name']}' in Tenant '{tenant['name']}'",
                    ):
                        if rp_groups := get(rp_address, "groups"):
                            rps.append({"address": rp_ip, "groups": rp_groups})
                        else:
                            rps.append({"address": rp_ip})
            if rps:
                vrf["_pim_rp_addresses"] = rps

        # if self.shared_utils.vtep is True:
        #     evpn_l3_multicast_enabled = default(get(vrf, "evpn_l3_multicast.enabled"), get(tenant, "evpn_l3_multicast.enabled"))
        #     if evpn_l3_multicast_enabled is True and self._evpn_multicast is not True:
        #         raise AristaAvdError(
        #             f"'evpn_l3_multicast: true' under VRF {vrf['name']} or Tenant {tenant['name']}; this requires 'evpn_multicast' to also be set to true."
        #         )

        #     if self._evpn_multicast:
        #         vrf["_evpn_l3_multicast_enabled"] = evpn_l3_multicast_enabled

        #         rps = []
        #         for rp_entry in default(get(vrf, "pim_rp_addresses"), get(tenant, "pim_rp_addresses"), []):
        #             if self.shared_utils.hostname in get(rp_entry, "nodes", default=[self.shared_utils.hostname]):
        #                 for rp_ip in get(
        #                     rp_entry,
        #                     "rps",
        #                     required=True,
        #                     org_key=f"pim_rp_addresses.rps under VRF '{vrf['name']}' in Tenant '{tenant['name']}'",
        #                 ):
        #                     rp_address = {"address": rp_ip}
        #                     if (rp_groups := get(rp_entry, "groups")) is not None:
        #                         if (acl := rp_entry.get("access_list_name")) is not None:
        #                             rp_address["access_lists"] = [acl]
        #                         else:
        #                             rp_address["groups"] = rp_groups

        #                     rps.append(rp_address)

        #         if rps:
        #             vrf["_pim_rp_addresses"] = rps

        #         for evpn_peg in default(get(vrf, "evpn_l3_multicast.evpn_peg"), get(tenant, "evpn_l3_multicast.evpn_peg"), []):
        #             if self.shared_utils.hostname in evpn_peg.get("nodes", [self.shared_utils.hostname]) and rps:
        #                 vrf["_evpn_l3_multicast_evpn_peg_transit"] = evpn_peg.get("transit")
        #                 break
        if vrf.get("svis") or vrf["l3_interfaces"]:  # or "all" in always_include_vrfs_in_tenants or tenant["name"] in always_include_vrfs_in_tenants:
            filtered_vrfs.append(vrf)

        vrf["additional_route_targets"] = [
            rt
            for rt in get(vrf, "additional_route_targets", default=[])
            if (
                switch_facts["serial_number"] in get(rt, "nodes", [])
                and rt.get("address_family") is not None
                and rt.get("route_target") is not None
                and rt.get("type") in ["import", "export"]
            )
        ]

    return filtered_vrfs


@ctx.benchmark
def _filtered_svis(switch_facts, vrf: dict) -> list[dict]:
    """
    Return sorted and filtered svi list from given tenant vrf.
    Filtering based on accepted vlans since eos_designs_facts already
    filtered that on tags and trunk_groups.
    """
    svis: list[dict] = natural_sort(convert_dicts(vrf.get("svis", []), "id"), "id")
    # svis = [svi for svi in svis if _is_accepted_vlan(switch_facts, svi)]

    # # Handle svi_profile inheritance
    # svis = [self._get_merged_svi_config(svi) for svi in svis]
    # Perform filtering on tags after merge of profiles, to support tags being set inside profiles.
    svis = [svi for svi in svis if switch_facts['serial_number'] in svi['devices']]

    # Set tenant key on all SVIs
    for svi in svis:
        svi.update({"tenant": vrf["tenant"]})

    return svis


@ctx.benchmark
def _is_accepted_vlan(switch_facts, vlan: dict) -> bool:
    """
    Check if vlan is in accepted_vlans list
    If filter.only_vlans_in_use is True also check if vlan id or trunk group is assigned to connected endpoint
    """
    vlan_id = int(vlan["id"])

    if vlan_id not in _accepted_vlans(switch_facts):
        return False

    return False


@ctx.benchmark
def _accepted_vlans(switch_facts) -> list[int]:
    """
    switch.vlans is a string representing a vlan range (ex. "1-200")
    For l2 switches return intersection of switch.vlans and switch.vlans from uplink switches
    For anything else return the expanded switch.vlans
    """
    switch_vlans = get(switch_facts, "vlans")
    if not switch_vlans:
        return []
    switch_vlans_list = range_expand(switch_vlans)
    accepted_vlans = [int(vlan) for vlan in switch_vlans_list]
    if switch_facts["uplink_type"] != "port-channel":
        return accepted_vlans

    uplink_switches = unique(switch_facts["uplink_switches_ids"])
    for uplink_switch in uplink_switches:
        uplink_switch_facts = my_switch_facts_neighbors.get(uplink_switch)
        if not uplink_switch_facts:
            continue
        uplink_switch_vlans = uplink_switch_facts.get("vlans", [])
        uplink_switch_vlans_list = range_expand(uplink_switch_vlans)
        uplink_switch_vlans_list = [int(vlan) for vlan in uplink_switch_vlans_list]
        accepted_vlans = [vlan for vlan in accepted_vlans if vlan in uplink_switch_vlans_list]

    return accepted_vlans


@ctx.benchmark
def set_inband_ztp_interfaces(switch_facts, key):
    interfaces = []
    for tag_matcher in get(advanced_fabric_settings, "inbandZtp.inbandZtpInterfaces.devices", default=[]):
        tag_query = tag_matcher['tagQuery']
        tag_match_nodes = tag_query.inputs['devices']
        if switch_facts["serial_number"] in tag_match_nodes:
            inband_ztp_interfaces = range_expand(tag_matcher["interfaces"].replace(" ", ""))
            interfaces += inband_ztp_interfaces
    interfaces = list(set(interfaces))
    if len(interfaces) > 0:
        return interfaces
    if switch_facts.get("platform"):
        for inband_ztp_interfaces_group in get(advanced_fabric_settings, f"inbandZtp.inbandZtpInterfaces.{key}", default=[]):
            if re.search(inband_ztp_interfaces_group['platform'], switch_facts['platform'], re.IGNORECASE):
                inband_ztp_interfaces = inband_ztp_interfaces_group["inbandZtpInterfaces"]
                return range_expand(inband_ztp_interfaces)
    return []


@ctx.benchmark
def get_switch_basics(device_id, id_checkers):
    dev = ctx.topology.getDevices(deviceIds=[device_id])[0]
    # Initialize switch_facts
    switch_facts = {}
    switch_facts['serial_number'] = device_id
    switch_facts['hostname'] = dev.hostName
    switch_facts['platform'] = dev.modelName
    switch_facts["campus"] = campus_pod_details["campus"]
    switch_facts["campus_pod"] = campus_pod_details["campus_pod"]
    # TBD - eos system tag won't be found, need topology field or user tag for it,
    #       else for checks utilize platform instead of eos version
    switch_facts["eos_version"] = "0"
    if tag := dev.getSingleTag(ctx, 'eos', required=False):
        switch_facts["eos_version"] = tag.value

    # set campus pod fabric name
    switch_facts["fabric_name"] = f"{switch_facts['campus']}-{switch_facts['campus_pod']}"

    # Get facts from inputs
    # Set switch node type and node id
    if device_matches_resolver_query(campus_pod_details["spines"], device_id):
        assert not device_matches_resolver_query(
            campus_pod_details["accessPods"], device_id), (
                f"{switch_facts['hostname']} is identified as both "+
                f"a Spine and a Leaf. It cannot be both.")
        switch_facts["type"] = "spine"
        if dev.getTags(ctx, 'Leaf-Domain'):
            switch_facts['dcLeaf-CampusSpine'] = True
        switch_facts["group"] = f"{switch_facts['campus']}_{switch_facts['campus_pod']}_Spines"
        node_id = campus_pod_details["spines"].resolve(device=device_id)["spinesInfo"].get("nodeId")
        if node_id:
            switch_facts['id'] =  node_id
        elif device_id == my_device.id:
            assert node_id, (f"Spine {switch_facts['hostname']} in Campus:{switch_facts['campus']} --> Campus-Pod:{switch_facts['campus_pod']} does not have an assigned Node Id.")
        else:
            return switch_facts
    elif device_matches_resolver_query(campus_pod_details["accessPods"], device_id):
        access_pod_details_resolved, access_pod_ctx = campus_pod_details["accessPods"].resolveWithContext(device=device_id)
        switch_facts["group"] = re.match(r"Access-Pod:(.*)", access_pod_ctx.query_str).group(1)
        access_pod_details = access_pod_details_resolved["accessPodFacts"]
        switch_facts["access_pod_details"] = access_pod_details
        if device_matches_resolver_query(access_pod_details["leafs"], device_id):
            assert not device_matches_resolver_query(
                access_pod_details["memberLeafs"], device_id), (
                    f"{switch_facts['hostname']} is identified as both "+
                    f"a Leaf and a Member-Leaf. It cannot be both.")
            switch_facts["type"] = "leaf"
            node_id = access_pod_details["leafs"].resolve(device=device_id)["leafsInfo"].get("nodeId")
            if node_id:
                switch_facts['id'] = node_id
            elif device_id == my_device.id:
                assert node_id, (f"Leaf {switch_facts['hostname']} in Campus:{switch_facts['campus']} --> Campus-Pod:{switch_facts['campus_pod']} -> Access-Pod:{switch_facts['group']} does not have an assigned Node Id.")
            else:
                return switch_facts
        elif device_matches_resolver_query(access_pod_details["memberLeafs"], device_id):
            switch_facts["type"] = "memberleaf"
            node_id = access_pod_details["memberLeafs"].resolve(device=device_id)["memberLeafsInfo"].get("nodeId")
            if node_id:
                switch_facts['id'] = node_id
            elif device_id == my_device.id:
                assert node_id, (f"Member-Leaf {switch_facts['hostname']} in Campus:{switch_facts['campus']} --> Campus-Pod:{switch_facts['campus_pod']} -> Access-Pod:{switch_facts['group']} does not have an assigned Node Id.")
            else:
                return switch_facts
        else:
            if device_id == my_device.id:
                ctx.warning(f"No role set for {switch_facts['hostname']} "
                            f"in Campus:{switch_facts['campus']} --> "
                            f"Campus-Pod:{switch_facts['campus_pod']} -> "
                            f"Access-Pod:{switch_facts['group']}")
            return switch_facts
    else:
        if device_id == my_device.id:
            ctx.warning(f"No role set for {switch_facts['hostname']} in "
                        f"Campus:{switch_facts['campus']} --> "
                        f"Campus-Pod:{switch_facts['campus_pod']}")
        return switch_facts

    # Check for duplicate nodeIds
    if switch_facts.get('id') and (
        id_checker := id_checkers.get(switch_facts.get("type"))):
        id_checker.allocate(
            switch_facts['id'],
            dev.hostName.strip() if dev.hostName.strip() else device_id)

    # Process topology interfaces
    switch_facts["interfaces"] = get_device_interfaces(switch_facts)

    # Set platform settings
    switch_facts = set_switch_facts_node_properties(switch_facts)

    return switch_facts


@ctx.benchmark
def get_switch_basics_for_third_party_devices(device_id, id_checkers):
    third_party_devices = {}
    # Set role and node id for switches
    for device_info in campus_pod_details.get('thirdPartyDevices', []):
        if ( not device_info.get("identifier") or
             not device_info.get("role") or
             not device_info.get("nodeId") ):
            continue
        if device_info.get("nodeId") and (
            id_checker := id_checkers.get(device_info.get("role"))):
            id_checker.allocate(
                device_info["nodeId"],
                device_info.get("hostname", "").strip() if device_info.get(
                    "hostname", "").strip() else device_info.get(
                    "identifier", "").strip())
        third_party_device = {
            "serial_number": device_info["identifier"].strip(),
            "hostname": device_info["hostname"].strip(),
            "type": device_info["role"],
            "id": device_info["nodeId"],
            "interfaces": [],
            "campus": campus_pod_details["campus"],
            "campus_pod": campus_pod_details["campus_pod"],
            "fabric_name": f"{campus_pod_details['campus']}-{campus_pod_details['campus_pod']}"
        }
        # Set group
        if third_party_device["type"] == "spine":
            third_party_device["group"] = f"{campus_pod_details['campus']}_{campus_pod_details['campus_pod']}_Spines"
        # Set up group setting for idf devices later
        # Get interface info for 3rd party devices by checking if this switch is a neighbor of other Arista switches in this campus
        for peer_switch_facts in my_switch_facts_neighbors.values():
            for peer_interface in peer_switch_facts.get("interfaces", {}):
                if third_party_device["serial_number"] == peer_interface["peer_serial_number"]:
                    third_party_device["interfaces"].append({
                        "interface_name": peer_interface["peer_interface_name"],
                        "peer_interface_name": peer_interface["interface_name"],
                        "peer_hostname": peer_switch_facts["hostname"],
                        "peer_serial_number": peer_switch_facts["serial_number"]
                    })

        third_party_device = set_switch_facts_node_properties(third_party_device)

        third_party_devices[third_party_device['serial_number']] = third_party_device

    return third_party_devices


@ctx.benchmark
def set_switch_facts_node_properties(switch_facts):
    # set device_id
    device_id = switch_facts["serial_number"]
    # Set campus type
    if campus_pod_details["design"]["campusType"].lower() == "l3":
        l2_or_l3 = "l3ls"
    elif campus_pod_details["design"]["campusType"].lower() == "l2":
        l2_or_l3 = "l2ls"
    elif campus_pod_details["design"]["campusType"].lower() == "l2 only":
        l2_or_l3 = "only-l2ls"
    else:
        return

    vxlan_enabled = campus_pod_details["design"]["vxlanOverlay"]
    evpn_enabled = campus_pod_details["campusPodRoutingProtocols"]["campusPodOverlayRoutingProtocol"] if campus_pod_details["campusPodRoutingProtocols"].get("campusPodOverlayRoutingProtocol") else None

    if l2_or_l3 != "only-l2ls":
        campus_design = l2_or_l3
        if vxlan_enabled and not evpn_enabled:
            campus_design += "-vxlan"
        elif vxlan_enabled and evpn_enabled:
            campus_design += "-evpn"
    else:
        campus_design = l2_or_l3

    switch_facts["campus_type"] = campus_design

    # Get custom node properties
    custom_node_properties = {
        "connected_endpoints": None,
        "default_evpn_role": None,
        "mlag_support": None,
        "vtep": None,
        "network_services_l2": None,
        "network_services_l3": None,
        "underlay_router": None,
        "uplink_type": None
    }
    if switch_facts["type"] == "spine":
        spine_defaults = campus_pod_details['nodeTypeProperties']['defaultSpineProperties']
        # Set custom EVPN role
        if spine_defaults.get('spineEvpnRoleDefault', '').strip() != "":
            custom_node_properties['default_evpn_role'] = spine_defaults['spineEvpnRoleDefault'].lower()
        # Set custom MLAG support role
        if spine_defaults.get('spineMlagSupportDefault', '').strip() != "":
            custom_node_properties['mlag_support'] = True if spine_defaults['spineMlagSupportDefault'] == "Yes" else False
        # Set custom Vtep role
        if spine_defaults.get('spineVtepDefault', '').strip() != "":
            custom_node_properties['vtep'] = True if spine_defaults['spineVtepDefault'] == "Yes" else False
        # Set custom Connnected Endpoints role
        if spine_defaults.get('spineConnectedEndpointsDefault', '').strip() != "":
            custom_node_properties['connected_endpoints'] = True if spine_defaults['spineConnectedEndpointsDefault'] == "Yes" else False
        # Set custom L2 Network Services role
        if spine_defaults.get('spineL2NetworkServicesDefault', '').strip() != "":
            custom_node_properties['network_services_l2'] = True if spine_defaults['spineL2NetworkServicesDefault'] == "Yes" else False
        # Set custom L3 Network Services role
        if spine_defaults.get('spineL3NetworkServicesDefault', '').strip() != "":
            custom_node_properties['network_services_l3'] = True if spine_defaults['spineL3NetworkServicesDefault'] == "Yes" else False
        # Set custom Underlay Router role
        if spine_defaults.get('spineUnderlayRouter', '').strip() != "":
            custom_node_properties['underlay_router'] = True if spine_defaults['spineUnderlayRouter'] == "Yes" else False
        # Set custom Underlay Router role
        if spine_defaults.get('spineUplinkType', '').strip() != "":
            custom_node_properties['uplink_type'] = spine_defaults['spineUplinkType'].lower()

        # Set inband ztp interfaces
        if inband_ztp_interfaces := set_inband_ztp_interfaces(switch_facts, "spinesInbandZtpInterfaces"):
            switch_facts["inband_ztp_interfaces"] = inband_ztp_interfaces

    elif switch_facts["type"] == "leaf":
        leaf_defaults = campus_pod_details['nodeTypeProperties']['defaultLeafProperties']
        # Set custom EVPN role
        if leaf_defaults.get('leafEvpnRoleDefault', '').strip() != "":
            custom_node_properties['default_evpn_role'] = leaf_defaults['leafEvpnRoleDefault'].lower()
        # Set custom MLAG support role
        if leaf_defaults.get('leafMlagSupportDefault', '').strip() != "":
            custom_node_properties['mlag_support'] = True if leaf_defaults['leafMlagSupportDefault'] == "Yes" else False
        # Set custom Vtep role
        if leaf_defaults.get('leafVtepDefault', '').strip() != "":
            custom_node_properties['vtep'] = True if leaf_defaults['leafVtepDefault'] == "Yes" else False
        # Set custom Connnected Endpoints role
        if leaf_defaults.get('leafConnectedEndpointsDefault', '').strip() != "":
            custom_node_properties['connected_endpoints'] = True if leaf_defaults['leafConnectedEndpointsDefault'] == "Yes" else False
        # Set custom L2 Network Services role
        if leaf_defaults.get('leafL2NetworkServicesDefault', '').strip() != "":
            custom_node_properties['network_services_l2'] = True if leaf_defaults['leafL2NetworkServicesDefault'] == "Yes" else False
        # Set custom L3 Network Services role
        if leaf_defaults.get('leafL3NetworkServicesDefault', '').strip() != "":
            custom_node_properties['network_services_l3'] = True if leaf_defaults['leafL3NetworkServicesDefault'] == "Yes" else False
        # Set custom Underlay Router role
        if leaf_defaults.get('leafUnderlayRouter', '').strip() != "":
            custom_node_properties['underlay_router'] = True if leaf_defaults['leafUnderlayRouter'] == "Yes" else False
        # Set custom Underlay Router role
        if leaf_defaults.get('leafUplinkType', '').strip() != "":
            custom_node_properties['uplink_type'] = leaf_defaults['leafUplinkType'].lower()

        # Set inband ztp interfaces
        if inband_ztp_interfaces := set_inband_ztp_interfaces(switch_facts, "leafsInbandZtpInterfaces"):
            switch_facts["inband_ztp_interfaces"] = inband_ztp_interfaces

    elif switch_facts["type"] == "memberleaf":
        member_leaf_defaults = campus_pod_details['nodeTypeProperties']['defaultMemberLeafProperties']
        # Set custom MLAG support role
        if member_leaf_defaults.get('memberLeafMlagSupportDefault', '').strip() != "":
            custom_node_properties['mlag_support'] = True if member_leaf_defaults['memberLeafMlagSupportDefault'] == "Yes" else False
        # Set inband ztp interfaces
        if inband_ztp_interfaces := set_inband_ztp_interfaces(switch_facts, "memberLeafsInbandZtpInterfaces"):
            switch_facts["inband_ztp_interfaces"] = inband_ztp_interfaces

    # Set node properties
    switch_facts["connected_endpoints"] = default(custom_node_properties.get("connected_endpoints"), node_type_defaults[switch_facts["campus_type"]][switch_facts["type"]]["connected_endpoints"])
    switch_facts["default_evpn_role"] = default(custom_node_properties.get("default_evpn_role"), node_type_defaults[switch_facts["campus_type"]][switch_facts["type"]]["default_evpn_role"])
    switch_facts["mlag_support"] = default(custom_node_properties.get("mlag_support"), node_type_defaults[switch_facts["campus_type"]][switch_facts["type"]]["mlag_support"])
    switch_facts["network_services_l2"] = default(custom_node_properties.get("network_services_l2"), node_type_defaults[switch_facts["campus_type"]][switch_facts["type"]]["network_services_l2"])
    switch_facts["network_services_l3"] = default(custom_node_properties.get("network_services_l3"), node_type_defaults[switch_facts["campus_type"]][switch_facts["type"]]["network_services_l3"])
    switch_facts["underlay_router"] = default(custom_node_properties.get("underlay_router"), node_type_defaults[switch_facts["campus_type"]][switch_facts["type"]]["underlay_router"])
    switch_facts["uplink_type"] = default(custom_node_properties.get("uplink_type"), node_type_defaults[switch_facts["campus_type"]][switch_facts["type"]]["uplink_type"])
    switch_facts["vtep"] = default(custom_node_properties.get('vtep'), node_type_defaults[switch_facts["campus_type"]][switch_facts["type"]]["vtep"])
    switch_facts["avd_type"] = node_type_defaults[switch_facts["campus_type"]][switch_facts["type"]]["avd_type"]
    # switch_facts["ip_addressing"] =
    # switch_facts["interface_descriptions"] =

    # Set platform settings
    if switch_facts.get("platform") and switch_facts.get('platform_settings') is None:
        for platform, settings in platform_settings.items():
            # Skip default as this will be applied at the end
            # to any switch that doesn't match any other platform
            if platform == "default":
                continue
            # check to see if any default platform regex is matched
            for regex in settings['regexes']:
                if re.search(regex, switch_facts['platform'], re.IGNORECASE):
                    switch_facts['platform_settings'] = settings

    # If no platform setting is matched, set to default
    if switch_facts.get('platform_settings') is None:
        switch_facts['platform_settings'] = platform_settings['default']

    return switch_facts


@ctx.benchmark
def get_switches_in_my_campus_pod(id_checkers):
    all_switch_facts = {}
    found_my_device = False
    # Get Spines
    spines_details = campus_pod_details["spines"].resolveAllWithContext(strict=True)
    for spine_dev, _, _ in spines_details:
        if my_device.id == spine_dev:
            found_my_device = True
        switch_facts_device = get_switch_basics(spine_dev, id_checkers)
        if not switch_facts_device or not switch_facts_device.get('type'):
            continue
        all_switch_facts[spine_dev] = switch_facts_device
    # Get Leaf and Member Leafs
    access_pods_details = campus_pod_details["accessPods"].resolveAllWithContext(strict=True)
    for access_pod_dev, _, _ in access_pods_details:
        if my_device.id == access_pod_dev:
            found_my_device = True
        switch_facts_device = get_switch_basics(access_pod_dev, id_checkers)
        if not switch_facts_device or not switch_facts_device.get('type'):
            continue
        all_switch_facts[access_pod_dev] = switch_facts_device
    if not found_my_device:
        ctx.warning(f"No role set for {my_device.hostName} in "
                    f"Campus:{campus_pod_details['campus']} --> "
                    f"Campus-Pod:{campus_pod_details['campus_pod']}")
    return all_switch_facts


@ctx.benchmark
def get_campus_pod_details(device_id, campus_resolver):
    # Used for logging
    dev = ctx.topology.getDevices(deviceIds=[device_id])[0]
    # Process Studio inputs
    campus_resolved, campus_ctx = campus_resolver.resolveWithContext(device=device_id)
    if not campus_resolved or not campus_ctx.query_str:
        return
    campus_name = re.match(r"Campus:(.*)", campus_ctx.query_str).group(1)
    campus_details = campus_resolved.get('campusDetails', None)
    if campus_details is None:
        ctx.warning(f"The AVD Campus Fabric studio is applied to "
                    f"{dev.hostName} but {dev.hostName} is not a member "
                    f"of any Campus.")
        return

    campus_pod_resolved, campus_pod_ctx = campus_details["campusPod"].resolveWithContext(device=device_id)
    if not campus_pod_resolved or not campus_pod_ctx.query_str:
        ctx.warning(f"The AVD Campus Fabric studio is applied to "
                    f"{dev.hostName} but {dev.hostName} in "
                    f"Campus:{campus_name} is not a member of any Campus-Pod.")
        return
    campus_pod_name = re.match(r"Campus-Pod:(.*)", campus_pod_ctx.query_str).group(1)
    campus_pod_details = campus_pod_resolved.get('campusPodFacts', None)
    if campus_pod_details is None:
        ctx.warning(f"The AVD Campus Fabric studio is applied to "
                    f"{dev.hostName} but {dev.hostName} in "
                    f"Campus:{campus_name} is not a member of any Campus-Pod.")
        return
    campus_pod_details["campus"] = campus_name
    campus_pod_details["campus_pod"] = campus_pod_name

    if campus_pod_details["design"]["campusType"].lower() == "l3":
        assert campus_pod_details["campusPodRoutingProtocols"]["campusPodUnderlayRoutingProtocol"],\
        f"For Campus: {campus_name}, Campus-Pod: {campus_pod_name}: In the L3 Campus Type setting, " \
        f"an underlying routing protocol needs to be selected."

    # Set MLAG and P2P Uplinks IP Addressing Algorithms
    campus_pod_details["fabric_ip_addressing"] = {
        "mlag": {},
        "p2p_uplinks": {}
    }
    campus_pod_advanced_fabric_settings = campus_pod_details["advancedFabricSettings"] if campus_pod_details.get("advancedFabricSettings") else {}
    # MLAG Algorithm
    campus_mlag_algorithm = get(advanced_fabric_settings, "fabricIpAddressing.mlag.ipAddressing")
    campus_pod_mlag_algorithm = get(campus_pod_advanced_fabric_settings, "fabricIpAddressing.mlag.mlagLocalInterfaceIpAddressing")
    fabric_variables["fabric_ip_addressing"]["mlag"]["algorithm"] = default(campus_pod_mlag_algorithm, campus_mlag_algorithm, "first_id")
    # MLAG IPv4 Prefix Length
    campus_mlag_prefix_length = get(advanced_fabric_settings, "fabricIpAddressing.mlag.ipv4PrefixLength")
    campus_pod_mlag_prefix_length = get(campus_pod_advanced_fabric_settings, "fabricIpAddressing.mlag.ipv4PrefixLength")
    fabric_variables["fabric_ip_addressing"]["mlag"]["ipv4_prefix_length"] = default(campus_pod_mlag_prefix_length, campus_mlag_prefix_length, 31)
    # MLAG BGP Numbering
    campus_mlag_bgp_numbering = get(advanced_fabric_settings, "fabricIpAddressing.mlag.bgpNumbering")
    campus_pod_mlag_bgp_numbering = get(campus_pod_advanced_fabric_settings, "fabricIpAddressing.mlag.bgpNumbering")
    fabric_variables["fabric_ip_addressing"]["mlag"]["bgp_numbering"] = default(campus_pod_mlag_bgp_numbering, campus_mlag_bgp_numbering, "first_id")
    # P2P Uplinks IPv4 Prefix Length
    # Get node defaults from user inputs
    campus_p2p_uplinks_prefix_length = get(advanced_fabric_settings, "fabricIpAddressing.p2pUplinks.ipv4PrefixLength")
    campus_pod_p2p_uplinks_prefix_length = get(campus_pod_advanced_fabric_settings, "fabricIpAddressing.p2pUplinks.ipv4PrefixLength")
    fabric_variables["fabric_ip_addressing"]["p2p_uplinks"]["ipv4_prefix_length"] = default(campus_pod_p2p_uplinks_prefix_length, campus_p2p_uplinks_prefix_length, 31)
    # Get EVPN defaults
    fabric_variables["evpn_ebgp_multihop"] = default(get(campus_pod_details, "fabricConfigurations.evpn.evpnEbgpMultihop"), 3)

    return campus_pod_details


@ctx.benchmark
def get_campus_services_details(device_id, campus_services_resolver):
    # Process Studio inputs
    campus_services_resolved = campus_services_resolver.resolve(device=device_id)
    if campus_services_resolved is None:
        return avd_tenants
    campus_services_details = campus_services_resolved["campusServicesGroup"]
    campus_pod_services_resolved = campus_services_details["campusPodsServices"].resolve(device=device_id)
    if campus_pod_services_resolved is None:
        return avd_tenants
    campus_pod_services_details = campus_pod_services_resolved["services"]
    return campus_services_details, campus_pod_services_details

@ctx.benchmark
def set_bgp_as(switch_facts, avd_bgp_peers):
    if switch_facts.get("underlay_routing_protocol", "") == "ebgp" \
            or switch_facts.get("overlay_routing_protocol", "") == "ebgp":
        return True
    for bgp_peer in avd_bgp_peers:
        if switch_facts["serial_number"] in bgp_peer.get("nodes", []):
            return True

    return False

@ctx.benchmark
def leaf_in_access_pod_check(my_switch_facts):
    access_pods_devices_list = []
    if "access_pod_details" in my_switch_facts:
        leafs_details = my_switch_facts['access_pod_details']['leafs'].resolveAllWithContext(strict=True)
        for leaf_dev, _, _ in  leafs_details:
            access_pods_devices_list.append(leaf_dev)
        assert len(access_pods_devices_list) <= 2,\
        f"For Campus: {my_switch_facts['campus']}, Campus-Pod: {my_switch_facts['campus_pod']}, " \
        f"Access-Pod: {my_switch_facts['group']}, the maximum number of leaf devices allowed is 2, " \
        f"but there are currently {len(access_pods_devices_list)} leaf devices."

@ctx.benchmark
def overlapping_networks_check(networks, msg):
    for i in range(len(networks)):
        if networks[i].strip() == "":
            continue
        network1 = ipaddress.ip_network(networks[i])
        j = i+1
        while j < len(networks):
            network2 = ipaddress.ip_network(networks[j])
            assert not network1.overlaps(network2), f"Overlapping {msg}: " \
                f"subnets {network1.exploded} {network2.exploded} overlap"
            j += 1

@ctx.benchmark
def reused_networks_check(pool_list, err_msg):
    pool_set = set()
    mapper = {
        "vtep_loopback_ipv4_pool": "VTEP Loopback IPv4 Pool",
        "loopback_ipv4_pool": "Router ID Pool",
        "uplink_ipv4_pool": "Uplink IPv4 Pool",
    }
    msg = ""
    count = 0
    for index, pool in enumerate(pool_list):
        if switch_facts.get(pool):
            count += 1
            pool_set.add(switch_facts[pool])
            msg += f"{mapper[pool]}"
            if index != len(pool_list) - 1:
              msg += "/"
    assert len(pool_set) == count, err_msg
    sorted_ip_list = sorted(list(pool_set), key=lambda ip: ipaddress.IPv4Network(ip))
    overlapping_networks_check(sorted_ip_list, msg)

@ctx.benchmark
def overlap_pool_check(my_switch_facts):
    if my_switch_facts["type"] == "spine":
        pool_list = ["vtep_loopback_ipv4_pool", "loopback_ipv4_pool"]
        err_msg = (
          f"For Campus: {my_switch_facts['campus']}, Campus-Pod: {my_switch_facts['campus_pod']}: " \
          f"VTEP Loopback IPv4 Pool and Router ID Pool need to be unique in " \
          f"Spine configuration."
        )
        reused_networks_check(pool_list, err_msg)
    else:
        pool_list = ["vtep_loopback_ipv4_pool", "loopback_ipv4_pool", "uplink_ipv4_pool"]
        err_msg = (
          f"For Campus: {my_switch_facts['campus']}, Campus-Pod: {my_switch_facts['campus_pod']}, " \
          f"Access-Pod: {my_switch_facts['group']}: VTEP Loopback IPv4 Pool, Router ID Pool " \
          f"and Uplink IPv4 Pool need to be unique in Access Pod Configuration."
        )
        reused_networks_check(pool_list, err_msg)

@ctx.benchmark
def check_inband_management_vlan_overlap(my_switch_facts):
    inband_management_vlan = my_switch_facts.get("inband_management_vlan")
    warning_msg = f"For Campus: {my_switch_facts['campus']}, Campus-Pod: {my_switch_facts['campus_pod']}, "
    if not inband_management_vlan:
        return
    if my_switch_facts.get("network_services"):
        for _, network_list in enumerate(my_switch_facts["network_services"]):
            for key, item in network_list.items():
                if key == "l2vlans":
                    for vlan in item:
                        if vlan.get("id") and vlan["id"] == inband_management_vlan:
                            warning_msg += f"Inband management vlan {vlan['id']} might be overridden by a user vlan."
                            ctx.warning(warning_msg)
                            return
                elif key == "vrfs":
                    for _, vrf_vlaue in enumerate(item):
                        if vrf_vlaue.get("svis"):
                            for vlan in vrf_vlaue["svis"]:
                                if vlan.get("id") and vlan["id"] == inband_management_vlan:
                                    warning_msg += f"Inband management vlan {vlan['id']} might be overridden by a user vlan."
                                    ctx.warning(warning_msg)
                                    return
# Template mainline start
#
# Check campus input is not None
if not campus:
    return

log_all_checkpoint_times = False

start_time = time.time()

if log_all_checkpoint_times:
    task_time = time.time()

# Get studio info from ctx
my_device = ctx.getDevice()
workspace_id = ctx.studio.workspaceId

# Initialize variables
advanced_fabric_settings = advancedFabricSettings if advancedFabricSettings else {}
advanced_services_settings = campusServicesSettings
my_switch_facts = {}
my_switch_facts_neighbors = {}
my_config = {}

# Set custom fabric settings
set_custom_fabric_variables(advanced_fabric_settings)

# Get campus pod inputs for build switch
campus_pod_details = get_campus_pod_details(my_device.id, campus)
if not campus_pod_details:
    return

# Check that the device is not used multiple times in the studio
_ = my_device.getSingleTag(ctx, campusLabel, required=False)
_ = my_device.getSingleTag(ctx, campusPodLabel, required=False)
_ = my_device.getSingleTag(ctx, accessPodLabel, required=False)

# Get campus services for build switch (used in get_campus_tenants())
campus_services_details, campus_pod_services_details = get_campus_services_details(my_device.id, campusServices)

# Use checkers to validate that nodeIds are allocated correctly
id_checkers = {}
id_checkers['spine'] = IdAllocator(idLabel='NodeID', groupLabel='Spines')
if 'l2' in campus_pod_details["design"]["campusType"].lower():
    id_checkers['leaf'] = IdAllocator(idLabel='NodeID', groupLabel='Leafs')
    id_checkers['memberleaf'] = id_checkers['leaf']
else:
    id_checkers['leaf'] = IdAllocator(idLabel='NodeID', groupLabel='Leafs')
    id_checkers['memberleaf'] = IdAllocator(idLabel='NodeID', groupLabel='Member-Leafs')

# Get all switches in same campus pod as build switch
my_switch_facts_neighbors = get_switches_in_my_campus_pod(id_checkers)
if not my_switch_facts_neighbors:
    return

# Check that build switch is in my_switch_facts_neighbors
if my_device.id in my_switch_facts_neighbors:
    my_switch_facts = my_switch_facts_neighbors[my_device.id]
else:
    return

dump_my_switch_facts(1)

# Check to see if spines are l2 only devices (used for inband management ip address selection - specifically matters in l2 only spine designs)
spines_l2_only = False
for switch_facts in dict(my_switch_facts_neighbors).values():
    if switch_facts["type"] == "spine":
        if switch_facts.get("network_services_l2") and not switch_facts.get("network_services_l3"):
            spines_l2_only = True
        break

# Add 3rd party devices
third_party_devices = get_switch_basics_for_third_party_devices(my_device.id, id_checkers)
my_switch_facts_neighbors.update(third_party_devices)

# Remove devices that don't contain a node id
for sn, switch_facts in dict(my_switch_facts_neighbors).items():
    if "id" not in switch_facts:
        del my_switch_facts_neighbors[sn]

# Check to see if build switch is in my_switch_facts
if my_device.id not in my_switch_facts_neighbors:
    return

# Used when looking for device by hostname
my_switch_facts_neighbors_by_hostname = {}
for neighbor in my_switch_facts_neighbors.values():
    my_switch_facts_neighbors_by_hostname[neighbor['hostname']] = neighbor

avd_bgp_peers = []
# Get external neighbors with bgp peering (Used for determining whether or not to set ASN on switch)
if external_devices := get(campus_pod_details, "egressConnectivity.externalDevices"):
    _, _, avd_bgp_peers = get_external_devices(external_devices, no_assert=True)

dump_my_switch_facts(2)

# Get mlag_peer (need to do this before setting uplinks
# for untraditional member leaf topologies)
for switch_facts in my_switch_facts_neighbors.values():
    switch_facts = set_mlag_switch_facts(switch_facts)

# Set uplink info for all switch_facts in my_switch_facts_neighbors
for switch_facts in my_switch_facts_neighbors.values():
    switch_facts = set_switch_uplink_info(switch_facts)
dump_my_switch_facts(3)

# Set downlink info for all of my_switch_facts' neighbors
for switch_facts in my_switch_facts_neighbors.values():
    switch_facts = set_switch_downlink_info(switch_facts)
dump_my_switch_facts(4)

# Set switch_facts for all of my_switch_facts neighbors and my_switch_facts
for switch_facts in my_switch_facts_neighbors.values():
    switch_facts = set_switch_facts(switch_facts)
dump_my_switch_facts(5)

# Get tenant network services in AVD format
for switch_facts in my_switch_facts_neighbors.values():
    avd_tenants = get_tenants(tenants, switch_facts)
    switch_facts["network_services"] = avd_tenants
dump_my_switch_facts(6)

# Get campus network services in AVD format
for switch_facts in my_switch_facts_neighbors.values():
    avd_campus_tenants = get_campus_tenants(switch_facts)
    switch_facts["network_services"] += avd_campus_tenants
dump_my_switch_facts(7)

# Check if inband management vlan overlap with user vlans
check_inband_management_vlan_overlap(switch_facts)

# Add egress device network services
avd_egress_static_routes = []
if egress_static_routes := get(campus_pod_details, "egressConnectivity.staticRoutes"):
    avd_egress_static_routes = get_egress_static_routes(egress_static_routes)

# Add egress srs
for switch_facts in my_switch_facts_neighbors.values():
    switch_facts = add_egress_srs_to_network_services(avd_egress_static_routes, switch_facts)

# Get egress svi info in AVD format
avd_transit_svis = []  # network_services - svis
if egress_svis := get(campus_pod_details, "egressConnectivity.svis"):
    avd_transit_svis = get_egress_transit_svis(egress_svis)

for switch_facts in my_switch_facts_neighbors.values():
    switch_facts = add_egress_svis_to_network_services(avd_transit_svis, switch_facts)

# Get egress devices info in AVD format
avd_connected_endpoints = {}  # connected_endpoints
avd_l3_interfaces = []  # l3_edge/network_services-bgp_peers
avd_bgp_peers = []  # network_services-bgp_peers
if external_devices := get(campus_pod_details, "egressConnectivity.externalDevices"):
    avd_connected_endpoints, avd_l3_interfaces, avd_bgp_peers = get_external_devices(external_devices)
for switch_facts in my_switch_facts_neighbors.values():
    switch_facts = add_egress_l3_interfaces_to_network_services(avd_l3_interfaces, switch_facts)
for switch_facts in my_switch_facts_neighbors.values():
    switch_facts = add_egress_bgp_peers_to_network_services(avd_bgp_peers, switch_facts)

# Get network services applied to switch
for switch_facts in my_switch_facts_neighbors.values():
    switch_facts = _vlans(switch_facts)
    switch_facts["filtered_tenants"] = _filtered_tenants(switch_facts)
dump_my_switch_facts(8)

# Set topology facts ( in order to set transit p2p and port-channel links )
for switch_facts in my_switch_facts_neighbors.values():
    switch_facts = set_topology_facts(switch_facts)
dump_my_switch_facts(9)

# Get my_switch_facts from my_switch_facts_neighbors
my_switch_facts = my_switch_facts_neighbors[my_device.id]

# Check devices inside my access pods do not contain more than 2 Leafs.
leaf_in_access_pod_check(my_switch_facts)

# Set structured config
my_config = {
    "spanning_tree": {},
    "vlans": {},
    "vlan_interfaces": {},
    "port_channel_interfaces": {},
    "ethernet_interfaces": {},
    "loopback_interfaces": {},
    "prefix_lists": {},
    "route_maps": {},
    ## "router_bfd": {},
    "router_multicast": {},
    "router_bgp": {
        "peer_groups": {},
        "address_family_ipv4": {
            "peer_groups": {}
        },
        "address_family_evpn": {
            "peer_groups": {}
        },
        "neighbor_interfaces": {},
        "neighbors": {},
        "redistribute_routes": {
            "connected": {}
        }
    },
    "router_ospf": {
        "process_ids": []
    },
    "vrfs": {},
    "virtual_source_nat_vrfs": {},
    "static_routes": []
}

my_config = set_base_config(my_config, my_switch_facts)
dump_my_config(1)
my_config = set_mlag_config(my_config, my_switch_facts)
dump_my_config(2)
my_config = set_underlay_config(my_config, my_switch_facts)
dump_my_config(3)
my_config = set_overlay_config(my_config, my_switch_facts)
dump_my_config(4)
my_config = set_vxlan_config(my_config, my_switch_facts)
dump_my_config(5)
my_config = set_inband_management_config(my_config, my_switch_facts)
dump_my_config(6)
my_config = set_network_services_config(my_config, my_switch_facts)
dump_my_config(7)
my_config = set_connected_endpoints_config(my_config, my_switch_facts)
dump_my_config(8)
my_config = set_inband_ztp_interfaces_config(my_config, my_switch_facts)
dump_my_config(9)

config = my_config

set_uplinks_downlinks(my_switch_facts)
dump_my_switch_facts(10)
set_studio_outputs(my_switch_facts, avd_l3_interfaces, avd_connected_endpoints)

ctx.benchmarkDump()
%>
% if config.get("address_locking"):
address locking
%     for dhcp_server in config["address_locking"].get("dhcp_servers", []):
   dhcp server ipv4 ${dhcp_server}
%     endfor
%     if config["address_locking"].get("local_interface"):
   local-interface ${ config["address_locking"]["local_interface"] }
%     endif
%     if config["address_locking"].get("locked_address"):
%         if config["address_locking"]["locked_address"].get("ipv4"):
%             if config["address_locking"]["locked_address"]["ipv4"]["enforcement"].get("disabled", False) is True:
   locked-address ipv4 enforcement disabled
%              endif
%         endif
%         if config["address_locking"]["locked_address"].get("ipv6"):
%             if config["address_locking"]["locked_address"]["ipv6"]["enforcement"].get("disabled", False) is True:
   locked-address ipv6 enforcement disabled
%             endif
%         endif
%         if get(config, "address_locking.locked_address.expiration_mac.enforcement.disabled"):
   locked-address expiration mac disabled
%         endif
%     endif
!
% endif
% if config.get("ip_dhcp_relay"):
%     if config["ip_dhcp_relay"].get("information_option"):
ip dhcp relay information option
%     endif
!
## eos - ip dhcp snooping
% if get(config, "ip_dhcp_snooping.enabled"):
%     if get(config, "ip_dhcp_snooping.bridging"):
ip dhcp snooping bridging
%     else:
ip dhcp snooping
%     endif
%     if get(config, "ip_dhcp_snooping.information_option.enabled"):
ip dhcp snooping information option
%         if get(config, "ip_dhcp_snooping.information_option.circuit_id_type") and get(config, "ip_dhcp_snooping.information_option.circuit_id_format"):
ip dhcp snooping information option circuit-id type ${ get(config, "ip_dhcp_snooping.information_option.circuit_id_type") } format ${ get(config, "ip_dhcp_snooping.information_option.circuit_id_format") }
%         endif
%     endif
%     if get(config, "ip_dhcp_snooping.vlan"):
ip dhcp snooping vlan ${ config["ip_dhcp_snooping"]["vlan"] }
%     endif
!
% endif
% endif
## eos - interface defaults
% if config.get("interface_defaults"):
interface defaults
%     if config["interface_defaults"].get("mtu") is not None:
   mtu ${ config["interface_defaults"]["mtu"] }
%     endif
!
% endif
## eos - routing model
% if config.get("service_routing_protocols_model") is not None and config.get("service_routing_protocols_model") == "multi-agent":
service routing protocols model multi-agent
!
% endif
## hostname
hostname ${config["hostname"]}
!
## eos - ptp
% if config.get("ptp"):
%     if config["ptp"].get("clock_identity"):
ptp clock-identity ${ config["ptp"]["clock_identity"] }
%     endif
%     if config["ptp"].get("source", {}).get("ip"):
ptp source ip ${ config["ptp"]["source"]["ip"] }
%     endif
%     if config["ptp"].get("priority1"):
ptp priority1 ${ config["ptp"]["priority1"] }
%     endif
%     if config["ptp"].get("priority2"):
ptp priority2 ${ config["ptp"]["priority2"] }
%     endif
%     if config["ptp"].get("ttl"):
ptp ttl ${ config["ptp"]["ttl"] }
%     endif
%     if config["ptp"].get("domain"):
ptp domain ${ config["ptp"]["domain"] }
%     endif
%     if config["ptp"].get("message_type"):
%         if config["ptp"]["message_type"]["general"].get("dscp"):
ptp message-type general dscp ${ config["ptp"]["message_type"]["general"]["dscp"] } default
%         endif
%         if config["ptp"]["message_type"]["event"].get("dscp"):
ptp message-type event dscp ${ config["ptp"]["message_type"]["event"]["dscp"] } default
%         endif
%     endif
%     if config["ptp"].get("mode"):
ptp mode ${ config["ptp"]["mode"] }
%     endif
%     if config["ptp"].get("forward_unicast") is True:
ptp forward-unicast
%     endif
%     if config["ptp"].get("monitor", {}).get("enabled") is False:
no ptp monitor
%     elif config["ptp"].get("monitor"):
%         if config["ptp"]["monitor"].get("threshold", {}).get("offset_from_master"):
ptp monitor threshold offset-from-master ${ config["ptp"]["monitor"]["threshold"]["offset_from_master"] }
%         endif
%         if config["ptp"]["monitor"].get("threshold", {}).get("mean_path_delay"):
ptp monitor threshold mean-path-delay ${ config["ptp"]["monitor"]["threshold"]["mean_path_delay"] }
%         endif
%         if config["ptp"]["monitor"].get("threshold", {}).get("drop", {}).get("offset_from_master"):
ptp monitor threshold offset-from-master ${ config["ptp"]["monitor"]["threshold"]["drop"]["offset_from_master"] } nanoseconds drop
%         endif
%         if config["ptp"]["monitor"].get("threshold", {}).get("drop", {}).get("mean_path_delay"):
ptp monitor threshold mean-path-delay ${ config["ptp"]["monitor"]["threshold"]["drop"]["mean_path_delay"] } nanoseconds drop
%         endif
%         if config["ptp"]["monitor"].get("missing_message", {}).get("intervals"):
%             if config["ptp"]["monitor"]["missing_message"]["intervals"].get("announce"):
ptp monitor threshold missing-message announce ${ config["ptp"]["monitor"]["missing_message"]["intervals"]["announce"] } intervals
%             endif
%             if config["ptp"]["monitor"]["missing_message"]["intervals"].get("follow_up"):
ptp monitor threshold missing-message follow-up ${ config["ptp"]["monitor"]["missing_message"]["intervals"]["follow_up"] } intervals
%             endif
%             if config["ptp"]["monitor"]["missing_message"]["intervals"].get("sync"):
ptp monitor threshold missing-message sync ${ config["ptp"]["monitor"]["missing_message"]["intervals"]["sync"] } intervals
%             endif
%         endif
%         if config["ptp"]["monitor"].get("missing_message", {}).get("sequence_ids", {}).get("enabled", True) is False:
no ptp monitor sequence-id
%         elif config["ptp"]["monitor"].get("missing_message", {}).get("sequence_ids", {}).get("enabled", False) is True:
ptp monitor sequence-id
%             if config["ptp"]["monitor"]["missing_message"]["sequence_ids"].get("announce"):
ptp monitor threshold missing-message announce ${ config["ptp"]["monitor"]["missing_message"]["sequence_ids"]["announce"] } sequence-ids
%             endif
%             if config["ptp"]["monitor"]["missing_message"]["sequence_ids"].get("delay_resp"):
ptp monitor threshold missing-message delay-resp ${ config["ptp"]["monitor"]["missing_message"]["sequence_ids"]["delay_resp"] } sequence-ids
%             endif
%             if config["ptp"]["monitor"]["missing_message"]["sequence_ids"].get("follow_up"):
ptp monitor threshold missing-message follow-up ${ config["ptp"]["monitor"]["missing_message"]["sequence_ids"]["follow_up"] } sequence-ids
%             endif
%             if config["ptp"]["monitor"]["missing_message"]["sequence_ids"].get("sync"):
ptp monitor threshold missing-message sync ${ config["ptp"]["monitor"]["missing_message"]["sequence_ids"]["sync"] } sequence-ids
%             endif
%         endif
%     endif
!
% endif
## eos - radius server
% if config.get("radius_server"):
%     if config["radius_server"].get("dynamic_authorization"):
<%         dynamic_authorization_cli = "radius-server dynamic-authorization" %>
%         if config["radius_server"]["dynamic_authorization"].get("port"):
<%             dynamic_authorization_cli = dynamic_authorization_cli + " port " + str(config["radius_server"]["dynamic_authorization"]["port"]) %>
%         endif
${ dynamic_authorization_cli }
%     endif
!
% endif
## eos - spanning-tree
% if config.get("spanning_tree") is not None:
%     if config["spanning_tree"].get("mode") is not None:
spanning-tree mode ${ config["spanning_tree"].get("mode") }
%     endif
%     if config["spanning_tree"].get("no_spanning_tree_vlan") is not None:
no spanning-tree vlan-id ${ config["spanning_tree"].get("no_spanning_tree_vlan") }
%     endif
%     if config["spanning_tree"].get("mode", "") == "mstp":
%         for mst_instance_id in natural_sort(config["spanning_tree"].get("mst_instances", {}).keys()):
%             if config["spanning_tree"]["mst_instances"][mst_instance_id].get("priority"):
spanning-tree mst ${ mst_instance_id } priority ${ config["spanning_tree"]["mst_instances"][mst_instance_id]["priority"] }
%             endif
%         endfor
%     elif  config["spanning_tree"].get("mode", "") == "rapid-pvst":
%         for vlan_id in natural_sort(config["spanning_tree"].get("rapid_pvst_instances", {}).keys()):
%             if config["spanning_tree"]["rapid_pvst_instances"][vlan_id].get("priority"):
spanning-tree vlan-id ${ vlan_id } priority ${ config["spanning_tree"]["rapid_pvst_instances"][vlan_id]["priority"] }
%             endif
%         endfor
%     else:
%         if config["spanning_tree"].get("rstp_priority"):
spanning-tree priority ${ config["spanning_tree"]["rstp_priority"] }
%         endif
%     endif
%     if config['spanning_tree'].get('mst', {}).get('configuration'):
!
spanning-tree mst configuration
%         if config['spanning_tree']['mst']['configuration'].get('name'):
   name ${ config['spanning_tree']['mst']['configuration']['name'] }
%         endif
%         if config['spanning_tree']['mst']['configuration'].get('revision'):
   revision ${ config['spanning_tree']['mst']['configuration']['revision'] }
%         endif
%         for instance in natural_sort(config['spanning_tree']['mst']['configuration'].get('instances', {}).keys()):
%             if config['spanning_tree']['mst']['configuration']['instances'][instance].get('vlans'):
   instance ${ instance } vlan ${ config['spanning_tree']['mst']['configuration']['instances'][instance]['vlans'] }
%             endif
%         endfor
%     endif
!
% endif
## eos - VLANs
%if config.get("vlans") is not None:
%     for vlan in natural_sort(config.get("vlans")):
vlan ${ vlan }
%          if config.get("vlans")[vlan].get("name") is not None:
   name ${ config.get("vlans")[vlan].get("name") }
%          endif
%          if config.get("vlans")[vlan].get("state") is not None:
   state ${ config.get("vlans")[vlan].get("state") }
%          endif
%          if config.get("vlans")[vlan].get("trunk_groups") is not None:
%               for trunk_group in config.get("vlans")[vlan].get("trunk_groups"):
   trunk group ${ trunk_group }
%               endfor
%          endif
!
%    endfor %}
%endif
## vrfs
% if config.get("vrfs") is not None:
%   for vrf in natural_sort(config["vrfs"].keys()):
%     if vrf != "default":
vrf instance ${ vrf }
%       if config["vrfs"][vrf].get("description"):
   description ${ config["vrfs"][vrf]["description"] }
%       endif
%     endif
!
%   endfor
%endif
## eos- Port-Channel Interfaces
% if config.get("port_channel_interfaces") is not None:
%   for port_channel_interface in natural_sort(config["port_channel_interfaces"].keys()):
interface ${ port_channel_interface }
%     if config["port_channel_interfaces"][port_channel_interface].get("description") is not None:
   description ${ config["port_channel_interfaces"][port_channel_interface]["description"] }
%     endif
%     if config["port_channel_interfaces"][port_channel_interface].get("shutdown") == True:
   shutdown
%     elif config["port_channel_interfaces"][port_channel_interface].get("shutdown") == False:
   no shutdown
%     endif
%     if config["port_channel_interfaces"][port_channel_interface].get("mtu") is not None:
   mtu ${ config["port_channel_interfaces"][port_channel_interface]["mtu"] }
%     endif
%     if config["port_channel_interfaces"][port_channel_interface].get("type") is not None and config["port_channel_interfaces"][port_channel_interface].get("type") == "routed":
   no switchport
%     else:
   switchport
%     endif
%     if config["port_channel_interfaces"][port_channel_interface].get("mode") is not None and config["port_channel_interfaces"][port_channel_interface].get("mode") == "access":
   switchport access vlan ${ config["port_channel_interfaces"][port_channel_interface]["vlans"] }
%     endif
%     if config["port_channel_interfaces"][port_channel_interface].get("vlans") and config["port_channel_interfaces"][port_channel_interface]["mode"] == "trunk":
   switchport trunk allowed vlan ${ config["port_channel_interfaces"][port_channel_interface]["vlans"] }
%     endif
%     if config["port_channel_interfaces"][port_channel_interface].get("mode") is not None and config["port_channel_interfaces"][port_channel_interface].get("mode") == "trunk":
   switchport mode ${ config["port_channel_interfaces"][port_channel_interface]["mode"] }
%     endif
%     if config["port_channel_interfaces"][port_channel_interface].get("trunk_groups") is not None:
%       for trunk_group in config["port_channel_interfaces"][port_channel_interface]["trunk_groups"]:
   switchport trunk group ${ trunk_group }
%       endfor
%     endif
%     if config["port_channel_interfaces"][port_channel_interface].get("lacp_fallback_mode"):
   port-channel lacp fallback ${ config["port_channel_interfaces"][port_channel_interface]["lacp_fallback_mode"] }
%     endif
%     if config["port_channel_interfaces"][port_channel_interface].get("lacp_fallback_timeout"):
   port-channel lacp fallback timeout ${ config["port_channel_interfaces"][port_channel_interface]["lacp_fallback_timeout"] }
%     endif
%     if config["port_channel_interfaces"][port_channel_interface].get("mlag"):
   mlag ${ config["port_channel_interfaces"][port_channel_interface]["mlag"] }
%     endif
%     if config["port_channel_interfaces"][port_channel_interface].get("ptp"):
%         if config["port_channel_interfaces"][port_channel_interface]["ptp"].get("enable", False) is True:
   ptp enable
%         endif
%         if config["port_channel_interfaces"][port_channel_interface]["ptp"].get("sync_message", {}).get("interval") is not None:
   ptp sync-message interval ${ config["port_channel_interfaces"][port_channel_interface]["ptp"]["sync_message"]["interval"] }
%         endif
%         if config["port_channel_interfaces"][port_channel_interface]["ptp"].get("delay_mechanism") is not None:
   ptp delay-mechanism ${ config["port_channel_interfaces"][port_channel_interface]["ptp"]["delay_mechanism"] }
%         endif
%         if config["port_channel_interfaces"][port_channel_interface]["ptp"].get("announce", {}).get("interval") is not None:
   ptp announce interval ${ config["port_channel_interfaces"][port_channel_interface]["ptp"]["announce"]["interval"] }
%         endif
%         if config["port_channel_interfaces"][port_channel_interface]["ptp"].get("transport"):
   ptp transport ${ config["port_channel_interfaces"][port_channel_interface]["ptp"]["transport"] }
%         endif
%         if config["port_channel_interfaces"][port_channel_interface]["ptp"].get("announce", {}).get("timeout") is not None:
   ptp announce timeout ${ config["port_channel_interfaces"][port_channel_interface]["ptp"]["announce"]["timeout"] }
%         endif
%         if config["port_channel_interfaces"][port_channel_interface]["ptp"].get("delay_req") is not None:
   ptp delay-req interval ${ config["port_channel_interfaces"][port_channel_interface]["ptp"]["delay_req"] }
%         endif
%         if config["port_channel_interfaces"][port_channel_interface]["ptp"].get("role"):
   ptp role ${ config["port_channel_interfaces"][port_channel_interface]["ptp"].get("role") }
%         endif
%         if config["port_channel_interfaces"][port_channel_interface]["ptp"].get("vlan"):
   ptp vlan ${ config["port_channel_interfaces"][port_channel_interface]["ptp"]["vlan"] }
%         endif
%     endif
%     if config["port_channel_interfaces"][port_channel_interface].get("eos_cli"):
%         for cli_statement in config["port_channel_interfaces"][port_channel_interface]["eos_cli"].split("\n"):
   ${cli_statement}
%         endfor
%     endif
!
%   endfor
% endif
## eos - Ethernet Interfaces
%if config.get("ethernet_interfaces") is not None:
%for ethernet_interface in natural_sort(config["ethernet_interfaces"].keys()):
<%
print_ethernet = True
if config["ethernet_interfaces"][ethernet_interface].get("channel_group", {}).get("id") and config["ethernet_interfaces"][ethernet_interface].get("channel_group", {}).get("mode"):
    port_channel_interface_name = f"Port-Channel{config['ethernet_interfaces'][ethernet_interface]['channel_group']['id']}"
    port_channel_interface = None
    for port_channel in config.get("port_channel_interfaces", {}).keys():
        if port_channel == port_channel_interface_name:
            port_channel_interface = config["port_channel_interfaces"][port_channel]
            break
    if port_channel_interface:
        print_ethernet = False
        if port_channel_interface.get("lacp_fallback_mode", "") == "individual":
            print_ethernet = True
if config["ethernet_interfaces"][ethernet_interface].get('ztp_interface'):
    print_ethernet = True
%>
interface ${ethernet_interface }
%     if config["ethernet_interfaces"][ethernet_interface].get("description") is not None:
   description ${config["ethernet_interfaces"][ethernet_interface]["description"]}
%     endif
%     if config["ethernet_interfaces"][ethernet_interface].get("speed") and config["ethernet_interfaces"][ethernet_interface]["speed"].strip() not in ["", "auto"]:
   speed ${config["ethernet_interfaces"][ethernet_interface]["speed"]}
%     endif
%     if config["ethernet_interfaces"][ethernet_interface].get("lldp", {}).get("ztp_vlan"):
   lldp tlv transmit ztp vlan ${config["ethernet_interfaces"][ethernet_interface]["lldp"]["ztp_vlan"]}
%     endif
%     if config["ethernet_interfaces"][ethernet_interface].get("channel_group") is not None:
   channel-group ${ config["ethernet_interfaces"][ethernet_interface]["channel_group"]["id"] } mode ${ config["ethernet_interfaces"][ethernet_interface]["channel_group"]["mode"] }
%     endif
%     if print_ethernet:
%         if config["ethernet_interfaces"][ethernet_interface].get("mtu") is not None:
   mtu ${ config["ethernet_interfaces"][ethernet_interface]["mtu"] }
%         endif
%         if config["ethernet_interfaces"][ethernet_interface].get("type") is not None and config["ethernet_interfaces"][ethernet_interface].get("type") == "routed":
   no switchport
%         elif config["ethernet_interfaces"][ethernet_interface].get("type", "") in ["l2dot1q", "l3dot1q"]:
%             if config["ethernet_interfaces"][ethernet_interface].get("vlan_id") and config["ethernet_interfaces"][ethernet_interface]["type"] == 'l2dot1q':
   vlan id ${ config["ethernet_interfaces"][ethernet_interface]["vlan_id"] }
%             endif
%             if config["ethernet_interfaces"][ethernet_interface].get("encapsulation_dot1q_vlan"):
   encapsulation dot1q vlan ${ config["ethernet_interfaces"][ethernet_interface]["encapsulation_dot1q_vlan"] }
%             endif
%         else:
   switchport
%         endif
%         if config["ethernet_interfaces"][ethernet_interface].get("mode") is not None and config["ethernet_interfaces"][ethernet_interface].get("mode") == "access":
%             if config["ethernet_interfaces"][ethernet_interface].get("vlans") is not None:
   switchport access vlan ${ config["ethernet_interfaces"][ethernet_interface].get("vlans") }
%             endif
%         endif
%         if config["ethernet_interfaces"][ethernet_interface].get("mode") is not None and config["ethernet_interfaces"][ethernet_interface].get("mode") == "trunk":
%             if config["ethernet_interfaces"][ethernet_interface].get("vlans") is not None:
   switchport trunk allowed vlan ${ config["ethernet_interfaces"][ethernet_interface].get("vlans") }
%             endif
%             if config["ethernet_interfaces"][ethernet_interface].get("native_vlan") is not None:
   switchport trunk native vlan ${ config["ethernet_interfaces"][ethernet_interface].get("native_vlan") }
%             endif
%         endif
%         if config["ethernet_interfaces"][ethernet_interface].get("mode") is not None:
   switchport mode ${ config["ethernet_interfaces"][ethernet_interface].get("mode") }
%         endif
%         if config["ethernet_interfaces"][ethernet_interface].get("trunk_groups") is not None:
%             for trunk_group in config["ethernet_interfaces"][ethernet_interface].get("trunk_groups"):
   switchport trunk group ${ trunk_group }
%             endfor
%         endif
%         if config["ethernet_interfaces"][ethernet_interface].get("vrf") is not None:
   vrf ${ config["ethernet_interfaces"][ethernet_interface].get("vrf") }
%         endif
%         if config["ethernet_interfaces"][ethernet_interface].get("ip_address") is not None:
   ip address ${ config["ethernet_interfaces"][ethernet_interface].get("ip_address") }
%             if config["ethernet_interfaces"][ethernet_interface].get("ip_address_secondaries") is not None:
%                 for ip_address_secondary in config["ethernet_interfaces"][ethernet_interface].get("ip_address_secondaries"):
   ip address ${ ip_address_secondary } secondary
%                 endfor
%             endif
%         endif
%         if config["ethernet_interfaces"][ethernet_interface].get("ospf_network_point_to_point", False):
   ip ospf network point-to-point
%         endif
%         if config["ethernet_interfaces"][ethernet_interface].get("ospf_area"):
   ip ospf area ${ config["ethernet_interfaces"][ethernet_interface]["ospf_area"] }
%         endif
%         if config["ethernet_interfaces"][ethernet_interface].get("ospf_cost"):
   ip ospf cost ${ config["ethernet_interfaces"][ethernet_interface]["ospf_cost"] }
%         endif
%         if config["ethernet_interfaces"][ethernet_interface].get("ospf_authentication") is not None:
%           if config["ethernet_interfaces"][ethernet_interface]["ospf_authentication"] == "simple":
   ip ospf authentication
%           elif config["ethernet_interfaces"][ethernet_interface]["ospf_authentication"] == "message-digest":
   ip ospf authentication message-digest
%           endif
%         endif
%         if config["ethernet_interfaces"][ethernet_interface].get("ospf_authentication_key") is not None:
   ip ospf authentication-key 7 ${ config["ethernet_interfaces"][ethernet_interface]["ospf_authentication_key"] }
%         endif
%         for ospf_message_digest_key in natural_sort(config["ethernet_interfaces"][ethernet_interface].get("ospf_message_digest_keys", [])):
%           if ospf_message_digest_key.get("hash_algorithm") is not None and ospf_message_digest_key.get("key") is not None:
   ip ospf message-digest-key ${ ospf_message_digest_key["id"] } ${ ospf_message_digest_key["hash_algorithm"] } 7 ${ ospf_message_digest_key["key"] }
%           endif
%         endfor
%         if config["ethernet_interfaces"][ethernet_interface].get("ptp"):
%             if config["ethernet_interfaces"][ethernet_interface]["ptp"].get("enable", False) is True:
   ptp enable
%             endif
%             if config["ethernet_interfaces"][ethernet_interface]["ptp"].get("sync_message", {}).get("interval") is not None:
   ptp sync-message interval ${ config["ethernet_interfaces"][ethernet_interface]["ptp"]["sync_message"]["interval"] }
%             endif
%             if config["ethernet_interfaces"][ethernet_interface]["ptp"].get("delay_mechanism") is not None:
   ptp delay-mechanism ${ config["ethernet_interfaces"][ethernet_interface]["ptp"]["delay_mechanism"] }
%             endif
%             if config["ethernet_interfaces"][ethernet_interface]["ptp"].get("announce", {}).get("interval") is not None:
   ptp announce interval ${ config["ethernet_interfaces"][ethernet_interface]["ptp"]["announce"]["interval"] }
%             endif
%             if config["ethernet_interfaces"][ethernet_interface]["ptp"].get("transport"):
   ptp transport ${ config["ethernet_interfaces"][ethernet_interface]["ptp"]["transport"] }
%             endif
%             if config["ethernet_interfaces"][ethernet_interface]["ptp"].get("announce", {}).get("timeout") is not None:
   ptp announce timeout ${ config["ethernet_interfaces"][ethernet_interface]["ptp"]["announce"]["timeout"] }
%             endif
%             if config["ethernet_interfaces"][ethernet_interface]["ptp"].get("delay_req") is not None:
   ptp delay-req interval ${ config["ethernet_interfaces"][ethernet_interface]["ptp"]["delay_req"] }
%             endif
%             if config["ethernet_interfaces"][ethernet_interface]["ptp"].get("role"):
   ptp role ${ config["ethernet_interfaces"][ethernet_interface]["ptp"].get("role") }
%             endif
%             if config["ethernet_interfaces"][ethernet_interface]["ptp"].get("vlan"):
   ptp vlan ${ config["ethernet_interfaces"][ethernet_interface]["ptp"]["vlan"] }
%             endif
%         endif
%         if config["ethernet_interfaces"][ethernet_interface].get("pim"):
%           if config["ethernet_interfaces"][ethernet_interface]["pim"]["ipv4"].get("sparse_mode"):
   pim ipv4 sparse-mode
%           endif
%         endif
%     endif
%     if config["ethernet_interfaces"][ethernet_interface].get("eos_cli"):
%         for cli_statement in config["ethernet_interfaces"][ethernet_interface]["eos_cli"].split("\n"):
   ${cli_statement}
%         endfor
%     endif
!
%endfor
%endif
## eos - Loopback Interfaces
%if config.get("loopback_interfaces") is not None:
%   for loopback_interface in natural_sort(config.get("loopback_interfaces").keys()):
interface ${ loopback_interface }
%       if config["loopback_interfaces"][loopback_interface].get("description") is not None:
   description ${ config["loopback_interfaces"][loopback_interface].get("description") }
%       endif
%       if config["loopback_interfaces"][loopback_interface].get("shutdown") is not None and config["loopback_interfaces"][loopback_interface].get("shutdown") == True:
   shutdown
%       elif config["loopback_interfaces"][loopback_interface].get("shutdown") is not None and config["loopback_interfaces"][loopback_interface].get("shutdown") == False:
   no shutdown
%       endif
%       if config["loopback_interfaces"][loopback_interface].get("vrf") is not None:
   vrf ${ config["loopback_interfaces"][loopback_interface].get("vrf") }
%       endif
%       if config["loopback_interfaces"][loopback_interface].get("ip_address") is not None:
   ip address ${ config["loopback_interfaces"][loopback_interface].get("ip_address") }
%           if config["loopback_interfaces"][loopback_interface].get("ip_address_secondaries") is not None:
%               for ip_address_secondary in config["loopback_interfaces"][loopback_interface].get("ip_address_secondaries"):
   ip address ${ ip_address_secondary } secondary
%               endfor
%           endif
%       endif
%     if config["loopback_interfaces"][loopback_interface].get("ospf_network_point_to_point"):
   ip ospf network point-to-point
%     endif
%     if config["loopback_interfaces"][loopback_interface].get("ospf_area"):
   ip ospf area ${ config["loopback_interfaces"][loopback_interface]["ospf_area"] }
%     endif
!
%   endfor
%endif
## eos - Management Interfaces
% for management_interface in natural_sort( config.get("management_interfaces", {}).keys() ):
interface ${ management_interface }
%     if config["management_interfaces"][management_interface].get("description"):
   description ${ config["management_interfaces"][management_interface]["description"] }
%     endif
%     if config["management_interfaces"][management_interface].get("shutdown") and config["management_interfaces"][management_interface]["shutdown"] is True:
   shutdown
%     elif config["management_interfaces"][management_interface].get("shutdown") and config["management_interfaces"][management_interface]["shutdown"] is False:
   no shutdown
%     endif
%     if config["management_interfaces"][management_interface].get("vrf") and config["management_interfaces"][management_interface]["vrf"] != 'default':
   vrf ${ config["management_interfaces"][management_interface]["vrf"] }
%     endif
%     if config["management_interfaces"][management_interface].get("ip_address"):
   ip address ${ config["management_interfaces"][management_interface]["ip_address"] }
%     endif
%     if config["management_interfaces"][management_interface].get("ipv6_enable") is not None and config["management_interfaces"][management_interface]["ipv6_enable"] is True:
   ipv6 enable
%     endif
%     if config["management_interfaces"][management_interface].get("ipv6_address"):
   ipv6 address ${ config["management_interfaces"][management_interface]["ipv6_address"] }
%     endif
!
% endfor
## eos - VLAN Interfaces
% if config.get("vlan_interfaces") is not None:
%   for vlan_interface in natural_sort(config.get("vlan_interfaces").keys()):
interface ${ vlan_interface }
%     if config.get("vlan_interfaces")[vlan_interface].get("description") is not None:
   description ${ config.get("vlan_interfaces")[vlan_interface].get("description") }
%     endif
%     if config.get("vlan_interfaces")[vlan_interface].get("shutdown", False) == True:
   shutdown
%     elif config.get("vlan_interfaces")[vlan_interface].get("shutdown", True) == False:
   no shutdown
%     endif
%     if config.get("vlan_interfaces")[vlan_interface].get("mtu") is not None:
   mtu ${ config.get("vlan_interfaces")[vlan_interface].get("mtu") }
%     endif
%     if config.get("vlan_interfaces")[vlan_interface].get("no_autostate") == True:
   no autostate
%     endif
%     if config.get("vlan_interfaces")[vlan_interface].get("vrf") is not None and config.get("vlan_interfaces")[vlan_interface].get("vrf") != 'default':
   vrf ${ config.get("vlan_interfaces")[vlan_interface].get("vrf") }
%     endif
%     if config.get("vlan_interfaces")[vlan_interface].get("ip_address") is not None:
   ip address ${ config.get("vlan_interfaces")[vlan_interface].get("ip_address") }
%         if config.get("vlan_interfaces")[vlan_interface].get("ip_address_secondaries") is not None:
%             for ip_address_secondary in config.get("vlan_interfaces")[vlan_interface].get("ip_address_secondaries"):
   ip address ${ ip_address_secondary } secondary
%             endfor
%         endif
%     endif
%     for ip_virtual_router_address in config["vlan_interfaces"][vlan_interface].get("ip_virtual_router_addresses", []):
   ip virtual-router address ${ ip_virtual_router_address }
%     endfor
%     if config.get("vlan_interfaces")[vlan_interface].get("ip_address_virtual") is not None:
   ip address virtual ${ config.get("vlan_interfaces")[vlan_interface].get("ip_address_virtual") }
%     endif
%     if config["vlan_interfaces"][vlan_interface].get("ipv6_enable", False) is True:
   ipv6 enable
%     endif
%     if config["vlan_interfaces"][vlan_interface].get("ipv6_address"):
   ipv6 address ${ config["vlan_interfaces"][vlan_interface]["ipv6_address"] }
%     endif
%     if config["vlan_interfaces"][vlan_interface].get("ipv6_address_link_local"):
   ipv6 address ${ config["vlan_interfaces"][vlan_interface]["ipv6_address_link_local"] } link-local
%     endif
%     if config["vlan_interfaces"][vlan_interface].get("ipv6_address_virtual"):
   ipv6 address virtual ${ config["vlan_interfaces"][vlan_interface]["ipv6_address_virtual"] }
%     endif
%     for ipv6_address_virtual in natural_sort(config["vlan_interfaces"][vlan_interface].get("ipv6_address_virtuals", [])):
   ipv6 address virtual ${ ipv6_address_virtual }
%     endfor
%     for ipv6_virtual_router_address in natural_sort(config["vlan_interfaces"][vlan_interface].get("ipv6_virtual_router_addresses", [])):
   ipv6 virtual-router address ${ ipv6_virtual_router_address }
%     endfor
%     if config.get("vlan_interfaces")[vlan_interface].get("ip_helpers") is not None:
%       for ip_helper in config.get("vlan_interfaces")[vlan_interface].get("ip_helpers").keys():
<%        ip_helper_cli = "ip helper-address " + ip_helper %>
%         if config.get("vlan_interfaces")[vlan_interface]["ip_helpers"][ip_helper].get("vrf") is not None:
<%            ip_helper_cli = ip_helper_cli + " vrf " + config.get("vlan_interfaces")[vlan_interface]["ip_helpers"][ip_helper].get("vrf") %>
%         endif
%         if config.get("vlan_interfaces")[vlan_interface]["ip_helpers"][ip_helper].get("source_interface") is not None:
<%            ip_helper_cli = ip_helper_cli + " source-interface " + config.get("vlan_interfaces")[vlan_interface]["ip_helpers"][ip_helper]["source_interface"] %>
%         endif
   ${ ip_helper_cli }
%       endfor
%     endif
%     for ipv6_helper in config.get("vlan_interfaces")[vlan_interface].get("ipv6_dhcp_relay_destinations", []):
<%        ip_helper_cli = "ipv6 dhcp relay destination " + ipv6_helper["address"] %>
%         if ipv6_helper.get("vrf") is not None:
<%            ip_helper_cli = ip_helper_cli + " vrf " + ipv6_helper["vrf"] %>
%         endif
%         if ipv6_helper.get("local_interface") is not None:
<%            ip_helper_cli = ip_helper_cli + " local-interface " + ipv6_helper["local_interface"] %>
%         endif
   ${ ip_helper_cli }
%     endfor
%     if config.get("vlan_interfaces")[vlan_interface].get("ospf_network_point_to_point"):
   ip ospf network point-to-point
%     endif
%     if config.get("vlan_interfaces")[vlan_interface].get("ospf_area"):
   ip ospf area ${ config.get("vlan_interfaces")[vlan_interface]["ospf_area"] }
%     endif
%     if config["vlan_interfaces"][vlan_interface].get("ospf_cost"):
   ip ospf cost ${ config["vlan_interfaces"][vlan_interface]["ospf_cost"] }
%     endif
%     if config["vlan_interfaces"][vlan_interface].get("ospf_authentication") is not None:
%         if config["vlan_interfaces"][vlan_interface]["ospf_authentication"] == "simple":
   ip ospf authentication
%         elif config["vlan_interfaces"][vlan_interface]["ospf_authentication"] == "message-digest":
   ip ospf authentication message-digest
%         endif
%     endif
%     if config["vlan_interfaces"][vlan_interface].get("ospf_authentication_key") is not None:
   ip ospf authentication-key 7 ${ config["vlan_interfaces"][vlan_interface]["ospf_authentication_key"] }
%     endif
%     for ospf_message_digest_key in natural_sort(config["vlan_interfaces"][vlan_interface].get("ospf_message_digest_keys", [])):
%         if ospf_message_digest_key.get("hash_algorithm") is not None and ospf_message_digest_key.get("key") is not None:
   ip ospf message-digest-key ${ ospf_message_digest_key["id"] } ${ ospf_message_digest_key["hash_algorithm"] } 7 ${ ospf_message_digest_key["key"] }
%         endif
%     endfor
%     if config["vlan_interfaces"][vlan_interface].get("pim"):
%         if config["vlan_interfaces"][vlan_interface]["pim"]["ipv4"].get("sparse_mode", False) is True:
   pim ipv4 sparse-mode
%         endif
%     endif
%     if config["vlan_interfaces"][vlan_interface].get("eos_cli"):
%         for cli_statement in config["vlan_interfaces"][vlan_interface]["eos_cli"].split("\n"):
   ${cli_statement}
%         endfor
%     endif
!
%   endfor
% endif
## vxlan-interfaces
% if config.get("vxlan_interface"):
interface Vxlan1
%     if config["vxlan_interface"]["Vxlan1"]["vxlan"].get("source_interface"):
   vxlan source-interface ${ config["vxlan_interface"]["Vxlan1"]["vxlan"]["source_interface"] }
%     endif
%     if config["vxlan_interface"]["Vxlan1"].get("vxlan"):
%         if config["vxlan_interface"]["Vxlan1"]["vxlan"].get("virtual_router_encapsulation_mac_address"):
   vxlan virtual-router encapsulation mac-address ${ config["vxlan_interface"]["Vxlan1"]["vxlan"]["virtual_router_encapsulation_mac_address"] }
%         endif
%         if config["vxlan_interface"]["Vxlan1"].get("vxlan_udp_port"):
   vxlan udp-port ${ config["vxlan_interface"]["Vxlan1"]["vxlan_udp_port"] }
%         endif
%         if config["vxlan_interface"]["Vxlan1"]["vxlan"].get("vlans"):
%             for vlan in natural_sort(config["vxlan_interface"]["Vxlan1"]["vxlan"]["vlans"].keys()):
   vxlan vlan ${ vlan } vni ${ config["vxlan_interface"]["Vxlan1"]["vxlan"]["vlans"][vlan]["vni"] }
%               if config["vxlan_interface"]["Vxlan1"]["vxlan"]["vlans"][vlan].get("multicast_group"):
   vxlan vlan ${ vlan } multicast group ${config["vxlan_interface"]["Vxlan1"]["vxlan"]["vlans"][vlan]["multicast_group"]}
%               endif
%             endfor
%         endif
%         if config["vxlan_interface"]["Vxlan1"]["vxlan"].get("vrfs"):
%             for vrf in natural_sort(config["vxlan_interface"]["Vxlan1"]["vxlan"]["vrfs"].keys()):
   vxlan vrf ${ vrf } vni ${ config["vxlan_interface"]["Vxlan1"]["vxlan"]["vrfs"][vrf]["vni"] }
%               if config["vxlan_interface"]["Vxlan1"]["vxlan"]["vrfs"][vrf].get("multicast_group"):
   vxlan vrf ${ vrf } multicast group ${config["vxlan_interface"]["Vxlan1"]["vxlan"]["vrfs"][vrf]["multicast_group"]}
%               endif
%             endfor %}
%         endif
%     endif
!
% endif
## eos - tcam profile
% if config.get("tcam_profile") is not None:
hardware tcam
%     if config["tcam_profile"].get("system") is not None:
   system profile ${ config["tcam_profile"]["system"] }
%     endif
!
% endif
## eos - ip virtual router mac
% if config.get("ip_virtual_router_mac_address") is not None:
ip virtual-router mac-address ${ config["ip_virtual_router_mac_address"] }
!
% endif
## eos - IP Routing
% if config.get("ip_routing") == True:
ip routing
!
% elif config.get("ip_routing") == False:
no ip routing
!
% endif
## eos - VRFs
% if config.get('vrfs'):
%   for vrf in config["vrfs"]:
%       if config["vrfs"][vrf].get("ip_routing") is not None and config["vrfs"][vrf].get("ip_routing") == True  and vrf != 'default':
ip routing vrf ${ vrf }
%       elif config["vrfs"][vrf].get("ip_routing") is not None and config["vrfs"][vrf].get("ip_routing") == False  and vrf != 'default':
no ip routing vrf ${ vrf }
%       endif
%   endfor
!
% endif
## static routes
% for static_route in config.get("static_routes", []):
<%    static_route_cli = "ip route" %>
%     if static_route.get("vrf") and static_route["vrf"] != 'default':
<%        static_route_cli = static_route_cli + " vrf " + static_route["vrf"] %>
%     endif
%     if static_route.get("destination_address_prefix"):
<%        static_route_cli = static_route_cli + " " + static_route["destination_address_prefix"] %>
%     endif
%     if static_route.get("interface"):
<%        static_route_cli = static_route_cli + " " + static_route["interface"] %>
%     endif
%     if static_route.get("gateway"):
<%        static_route_cli = static_route_cli + " " + static_route["gateway"] %>
%     endif
%     if static_route.get("distance"):
<%        static_route_cli = static_route_cli + " " + static_route["distance"] %>
%     endif
%     if static_route.get("tag"):
<%        static_route_cli = static_route_cli + " tag " + static_route["tag"] %>
%     endif
%     if static_route.get("name"):
<%        static_route_cli = static_route_cli + " name " + static_route["name"] %>
%     endif
%     if static_route.get("metric"):
<%        static_route_cli = static_route_cli + " metric " + static_route["metric"] %>
%     endif
${ static_route_cli }
!
%    endfor %}
## eos - Router Multicast
% if config.get("router_multicast"):
router multicast
%     if config["router_multicast"].get("ipv4"):
   ipv4
%         if config["router_multicast"]["ipv4"].get("routing"):
      routing
%         endif
%         if config["router_multicast"]["ipv4"].get("multipath"):
      multipath ${ config["router_multicast"]["ipv4"]["multipath"] }
%         endif
%         if config["router_multicast"]["ipv4"].get("software_forwarding"):
      software-forwarding ${ config["router_multicast"]["ipv4"]["software_forwarding"] }
%         endif
%     endif
%     for vrf in natural_sort(config["router_multicast"].get("vrfs",[]), sort_key="name"):
%         if vrf["name"] != "default":
   vrf ${ vrf["name"] }
%             if vrf.get("ipv4"):
      ipv4
%             endif
%             if vrf["ipv4"].get("routing", False) is True:
         routing
%             endif
   !
%         endif
%     endfor
!
% endif
## eos - prefix-lists
% if config.get("prefix_lists") is not None:
%    for prefix_list in config["prefix_lists"].keys():
ip prefix-list ${ prefix_list }
%       for sequence in config["prefix_lists"][prefix_list]["sequence_numbers"].keys():
%         if config["prefix_lists"][prefix_list]["sequence_numbers"][sequence].get("action") is not None:
   seq ${ sequence } ${ config["prefix_lists"][prefix_list]["sequence_numbers"][sequence]["action"] }
%         endif
%       endfor
!
%    endfor
% endif
## eos - mlag configuration
% if config.get("mlag_configuration") is not None and config["mlag_configuration"].get("enabled") == True:
mlag configuration
%     if config["mlag_configuration"].get("domain_id") is not None:
   domain-id ${ config["mlag_configuration"]["domain_id"] }
%     endif
%     if config["mlag_configuration"].get("local_interface") is not None:
   local-interface ${ config["mlag_configuration"]["local_interface"] }
%     endif
%     if config["mlag_configuration"].get("peer_address") is not None:
   peer-address ${ config["mlag_configuration"]["peer_address"] }
%     endif
%     if config["mlag_configuration"].get("peer_address_heartbeat") is not None:
%       if config["mlag_configuration"]["peer_address_heartbeat"].get("peer_ip") is not None:
%           if config["mlag_configuration"]["peer_address_heartbeat"].get("vrf") is not None and config["mlag_configuration"]["peer_address_heartbeat"].get("vrf") != 'default':
   peer-address heartbeat ${ config["mlag_configuration"]["peer_address_heartbeat"]["peer_ip"] } vrf ${ config["mlag_configuration"]["peer_address_heartbeat"]["vrf"] }
## using the default VRF #}
%           else:
   peer-address heartbeat ${ config["mlag_configuration"]["peer_address_heartbeat"]["peer_ip"] }
%           endif
%       endif
%     endif
%     if config["mlag_configuration"].get("peer_link") is not None:
   peer-link ${ config["mlag_configuration"]["peer_link"] }
%     endif
%     if config["mlag_configuration"].get("dual_primary_detection_delay") is not None:
   dual-primary detection delay ${ config["mlag_configuration"]["dual_primary_detection_delay"] } action errdisable all-interfaces
%     endif
%     if config["mlag_configuration"].get("reload_delay_mlag") is not None:
   reload-delay mlag ${ config["mlag_configuration"]["reload_delay_mlag"] }
%     endif
%     if config["mlag_configuration"].get("reload_delay_non_mlag") is not None:
   reload-delay non-mlag ${ config["mlag_configuration"]["reload_delay_non_mlag"] }
%     endif
!
% endif
## eos - Route Maps
% if config.get("route_maps") is not None:
%   for route_map in config["route_maps"].keys():
%       for sequence in config["route_maps"][route_map]["sequence_numbers"].keys():
%           if config["route_maps"][route_map]["sequence_numbers"][sequence].get("type") is not None:
route-map ${ route_map } ${ config["route_maps"][route_map]["sequence_numbers"][sequence]["type"] } ${ sequence }
%               if config["route_maps"][route_map]["sequence_numbers"][sequence].get("description") is not None:
   description ${ config["route_maps"][route_map]["sequence_numbers"][sequence]["description"] }
%               endif
%               if config["route_maps"][route_map]["sequence_numbers"][sequence].get("match") is not None:
%                   for match_rule in config["route_maps"][route_map]["sequence_numbers"][sequence]["match"]:
   match ${ match_rule }
%                   endfor
%               endif
%               if config["route_maps"][route_map]["sequence_numbers"][sequence].get("set") is not None:
%                   for set_rule in config["route_maps"][route_map]["sequence_numbers"][sequence]["set"]:
   set ${ set_rule }
%                   endfor
%               endif
!
%           endif
%       endfor
%   endfor
% endif
## eos - peer-filters
% if config.get("peer_filters") is not None:
%   for peer_filter in config["peer_filters"].keys():
peer-filter ${ peer_filter }
%     for sequence in config["peer_filters"][peer_filter]["sequence_numbers"].keys():
%         if config["peer_filters"][peer_filter]["sequence_numbers"][sequence].get("match") is not None:
   ${ sequence } match ${ config["peer_filters"][peer_filter]["sequence_numbers"][sequence]["match"] }
%         endif
%     endfor
!
%   endfor
% endif
## eos - Router bfd
% if config.get("router_bfd") is not None and config.get("router_bfd") != {}:
router bfd
%   if config["router_bfd"].get("multihop") is not None:
%     if config["router_bfd"]["multihop"].get("interval") is not None and config["router_bfd"]["multihop"].get("min_rx") is not None and config["router_bfd"]["multihop"].get("multiplier") is not None:
   multihop interval ${ config["router_bfd"]["multihop"]["interval"] } min-rx ${ config["router_bfd"]["multihop"]["min_rx"] } multiplier ${ config["router_bfd"]["multihop"]["multiplier"] }
%     endif
%   endif
!
% endif
## eos - Router BGP
% if config.get("router_bgp") is not None:
% if config["router_bgp"].get("as") is not None:
router bgp ${ config["router_bgp"]["as"] }
%     if config["router_bgp"].get("router_id") is not None:
   router-id ${ config["router_bgp"]["router_id"] }
%     endif
%     if get(config, "router_bgp.distance.external_routes"):
<%        distance_cli = "distance bgp " + str(config["router_bgp"]["distance"]["external_routes"]) %>
%         if get(config, "router_bgp.distance.internal_routes") and get(config, "router_bgp.distance.local_routes"):
<%            distance_cli += " " + str(config["router_bgp"]["distance"]["internal_routes"]) + " " + str(config["router_bgp"]["distance"]["local_routes"]) %>
%         endif
   ${ distance_cli }
%     endif
%     if config["router_bgp"].get("graceful_restart"):
%         if config["router_bgp"]["graceful_restart"].get("enabled"):
%             if config["router_bgp"]["graceful_restart"].get("restart_time"):
   graceful-restart restart-time ${ config["router_bgp"]["graceful_restart"]["restart_time"] }
%             endif
   graceful-restart
%         endif
%     endif
%     if config["router_bgp"].get("maximum_paths"):
<% max_paths_cli = "maximum-paths {} ".format(config["router_bgp"]["maximum_paths"]) %>
%        if config["router_bgp"].get("ecmp"):
<% max_paths_cli += "ecmp {}".format(config["router_bgp"]["ecmp"]) %>
        % endif
   ${max_paths_cli}
%     endif
%    if config["router_bgp"].get("updates"):
%         if config["router_bgp"]["updates"].get("wait_for_convergence"):
   update wait-for-convergence
%         endif
%         if config["router_bgp"]["updates"].get("wait_install"):
   update wait-install
%         endif
%     endif
%     if config["router_bgp"].get("peer_groups") is not None:
%       for peer_group in config["router_bgp"]["peer_groups"].keys():
%         if config["router_bgp"]["peer_groups"][peer_group].get("bgp_listen_range_prefix") is not None and config["router_bgp"]["peer_groups"][peer_group].get("peer_filter") is not None:
   bgp listen range ${ config["router_bgp"]["peer_groups"][peer_group]["bgp_listen_range_prefix"] } peer-group ${ peer_group } peer-filter ${ config["router_bgp"]["peer_groups"][peer_group]["peer_filter"] }
%         endif
%       endfor
%     for peer_group in config["router_bgp"]["peer_groups"].keys():
%         if config["router_bgp"]["peer_groups"][peer_group].get("description") is not None:
   neighbor ${ peer_group } description ${ config["router_bgp"]["peer_groups"][peer_group]["description"] }
%         endif
%         if config["router_bgp"]["peer_groups"][peer_group].get("shutdown") == True:
   neighbor ${ peer_group } shutdown
%         endif
   neighbor ${ peer_group } peer group
%         if config["router_bgp"]["peer_groups"][peer_group].get("remote_as") is not None:
   neighbor ${ peer_group } remote-as ${ config["router_bgp"]["peer_groups"][peer_group]["remote_as"] }
%         endif
%         if config["router_bgp"]["peer_groups"][peer_group].get("local_as") is not None:
   neighbor ${ peer_group } local-as ${ config["router_bgp"]["peer_groups"][peer_group]["local_as"] } no-prepend replace-as
%         endif
%         if config["router_bgp"]["peer_groups"][peer_group].get("next_hop_self") == True:
   neighbor ${ peer_group } next-hop-self
%         endif
%         if config["router_bgp"]["peer_groups"][peer_group].get("next_hop_unchanged") == True:
   neighbor ${ peer_group } next-hop-unchanged
%         endif
%         if config["router_bgp"]["peer_groups"][peer_group].get("update_source") is not None:
   neighbor ${ peer_group } update-source ${ config["router_bgp"]["peer_groups"][peer_group]["update_source"] }
%         endif
%         if config["router_bgp"]["peer_groups"][peer_group].get("route_reflector_client") == True:
   neighbor ${ peer_group } route-reflector-client
%         endif
%         if config["router_bgp"]["peer_groups"][peer_group].get("bfd") == True:
   neighbor ${ peer_group } bfd
%         endif
%         if config["router_bgp"]["peer_groups"][peer_group].get("ebgp_multihop") is not None:
   neighbor ${ peer_group } ebgp-multihop ${ config["router_bgp"]["peer_groups"][peer_group]["ebgp_multihop"] }
%         endif
%         if config["router_bgp"]["peer_groups"][peer_group].get("password") is not None:
   neighbor ${ peer_group } password 7 ${ config["router_bgp"]["peer_groups"][peer_group]["password"] }
%         endif
%         if config["router_bgp"]["peer_groups"][peer_group].get("send_community") is not None and config["router_bgp"]["peer_groups"][peer_group]["send_community"] == "all":
   neighbor ${ peer_group } send-community
%         elif config["router_bgp"]["peer_groups"][peer_group].get("send_community") is not None:
   neighbor ${ peer_group } send-community ${ config["router_bgp"]["peer_groups"][peer_group]["send_community"] }
%         endif
%         if config["router_bgp"]["peer_groups"][peer_group].get("maximum_routes") is not None and config["router_bgp"]["peer_groups"][peer_group].get("warning_limit_routes") is not None:
   neighbor ${ peer_group } maximum-routes ${ config["router_bgp"]["peer_groups"][peer_group]["maximum_routes"] } warning-limit ${ config["router_bgp"]["peer_groups"][peer_group]["warning_limit_routes"] }
%         elif config["router_bgp"]["peer_groups"][peer_group].get("maximum_routes") is not None:
   neighbor ${ peer_group } maximum-routes ${ config["router_bgp"]["peer_groups"][peer_group]["maximum_routes"] }
%         endif
%         if config["router_bgp"]["peer_groups"][peer_group].get("weight") is not None:
   neighbor ${ peer_group } weight ${ config["router_bgp"]["peer_groups"][peer_group]["weight"] }
%         endif
%         if config["router_bgp"]["peer_groups"][peer_group].get("timers") is not None:
   neighbor ${ peer_group } timers ${ config["router_bgp"]["peer_groups"][peer_group]["timers"] }
%         endif
%         if config["router_bgp"]["peer_groups"][peer_group].get("route_map_in") is not None:
   neighbor ${ peer_group } route-map ${ config["router_bgp"]["peer_groups"][peer_group]["route_map_in"] } in
%         endif
%         if config["router_bgp"]["peer_groups"][peer_group].get("route_map_out") is not None:
   neighbor ${ peer_group } route-map ${ config["router_bgp"]["peer_groups"][peer_group]["route_map_out"] } out
%         endif
%       endfor
%     endif
## {%     for neighbor_interface in router_bgp.neighbor_interfaces | arista.avd.natural_sort %}
## {%         set neighbor_interface_cli = "neighbor interface " ~ neighbor_interface %}
## {%         if router_bgp.neighbor_interfaces[neighbor_interface].peer_group is arista.avd.defined %}
## {%             set neighbor_interface_cli = neighbor_interface_cli ~ " peer-group " ~ router_bgp.neighbor_interfaces[neighbor_interface].peer_group %}
## {%         endif %}
## {%         if router_bgp.neighbor_interfaces[neighbor_interface].remote_as is arista.avd.defined %}
## {%             set neighbor_interface_cli = neighbor_interface_cli ~ " remote-as " ~ router_bgp.neighbor_interfaces[neighbor_interface].remote_as %}
## {%         endif %}
## ##    {{ neighbor_interface_cli }}
## {%     endfor %}
%     if config["router_bgp"].get("neighbors") is not None:
%       for neighbor in natural_sort(config["router_bgp"]["neighbors"].keys()):
%         if config["router_bgp"]["neighbors"][neighbor].get("peer_group") is not None:
   neighbor ${ neighbor } peer group ${ config["router_bgp"]["neighbors"][neighbor]["peer_group"] }
%         endif
%         if config["router_bgp"]["neighbors"][neighbor].get("remote_as") is not None:
   neighbor ${ neighbor } remote-as ${ config["router_bgp"]["neighbors"][neighbor]["remote_as"] }
%         endif
%         if config["router_bgp"]["neighbors"][neighbor].get("next_hop_self") == True:
   neighbor ${ neighbor } next-hop-self
%         endif
%         if config["router_bgp"]["neighbors"][neighbor].get("shutdown") == True:
   neighbor ${ neighbor } shutdown
%         endif
%         if config["router_bgp"]["neighbors"][neighbor].get("local_as") is not None:
   neighbor ${ neighbor } local-as ${ config["router_bgp"]["neighbors"][neighbor]["local_as"] } no-prepend replace-as
%         endif
%         if config["router_bgp"]["neighbors"][neighbor].get("description") is not None:
   neighbor ${ neighbor } description ${ config["router_bgp"]["neighbors"][neighbor]["description"] }
%         endif
%         if config["router_bgp"]["neighbors"][neighbor].get("update_source") is not None:
   neighbor ${ neighbor } update-source ${ config["router_bgp"]["neighbors"][neighbor]["update_source"] }
%         endif
%         if config["router_bgp"]["neighbors"][neighbor].get("bfd") == True:
   neighbor ${ neighbor } bfd
%         endif
%         if config["router_bgp"]["neighbors"][neighbor].get("password") is not None:
   neighbor ${ neighbor } password 7 ${ config["router_bgp"]["neighbors"][neighbor]["password"] }
%         endif
%         if config["router_bgp"]["neighbors"][neighbor].get("weight") is not None:
   neighbor ${ neighbor } weight ${ config["router_bgp"]["neighbors"][neighbor]["weight"] }
%         endif
%         if config["router_bgp"]["neighbors"][neighbor].get("timers") is not None:
   neighbor ${ neighbor } timers ${ config["router_bgp"]["neighbors"][neighbor]["timers"] }
%         endif
%         if config["router_bgp"]["neighbors"][neighbor].get("route_map_in") is not None:
   neighbor ${ neighbor } route-map ${ config["router_bgp"]["neighbors"][neighbor]["route_map_in"] } in
%         endif
%         if config["router_bgp"]["neighbors"][neighbor].get("route_map_out") is not None:
   neighbor ${ neighbor } route-map ${ config["router_bgp"]["neighbors"][neighbor]["route_map_out"] } out
%         endif
%       endfor
%     endif
## {%     for aggregate_address in router_bgp.aggregate_addresses | arista.avd.natural_sort %}
## {%         set aggregate_address_cli = "aggregate-address " ~ aggregate_address %}
## {%         if router_bgp.aggregate_addresses[aggregate_address].as_set is arista.avd.defined(true) %}
## {%             set aggregate_address_cli = aggregate_address_cli ~ " as-set" %}
## {%         endif %}
## {%         if router_bgp.aggregate_addresses[aggregate_address].summary_only is arista.avd.defined(true) %}
## {%             set aggregate_address_cli = aggregate_address_cli ~ " summary-only" %}
## {%         endif %}
## {%         if router_bgp.aggregate_addresses[aggregate_address].attribute_map is arista.avd.defined %}
## {%             set aggregate_address_cli = aggregate_address_cli ~  " attribute-map " ~ router_bgp.aggregate_addresses[aggregate_address].attribute_map %}
## {%         endif %}
## {%         if router_bgp.aggregate_addresses[aggregate_address].match_map is arista.avd.defined %}
## {%             set aggregate_address_cli = aggregate_address_cli ~ " match-map " ~ router_bgp.aggregate_addresses[aggregate_address].match_map %}
## {%         endif %}
## {%         if router_bgp.aggregate_addresses[aggregate_address].advertise_only is arista.avd.defined(true) %}
## {%             set aggregate_address_cli = aggregate_address_cli ~ " advertise-only" %}
## {%         endif %}
##    {{ aggregate_address_cli }}
## {%     endfor %}
%     if config["router_bgp"].get("redistribute_routes") is not None:
%       for redistribute_route in config["router_bgp"]["redistribute_routes"].keys():
<%         redistribute_route_cli = "redistribute " + redistribute_route %>
%         if config["router_bgp"]["redistribute_routes"][redistribute_route].get("route_map") is not None:
<%             redistribute_route_cli = redistribute_route_cli + " route-map " + config["router_bgp"]["redistribute_routes"][redistribute_route]["route_map"] %>
%         endif
   ${ redistribute_route_cli }
%       endfor
%     endif
%     if config["router_bgp"].get("bgp_defaults"):
%       for bgp_default in config["router_bgp"]["bgp_defaults"].split("\n"):
   ${ bgp_default }
%       endfor
!
%     endif
## L2VPNs - (vxlan) vlan based
%     if config["router_bgp"].get("vlans") is not None:
%       for vlan in config["router_bgp"]["vlans"]:
!
   vlan ${ vlan }
%         if config["router_bgp"]["vlans"][vlan].get("rd") is not None:
      rd ${ config["router_bgp"]["vlans"][vlan]["rd"] }
%         endif
%         if config["router_bgp"]["vlans"][vlan].get("route_targets") is not None and config["router_bgp"]["vlans"][vlan]["route_targets"].get("both") is not None:
%             for route_target in config["router_bgp"]["vlans"][vlan]["route_targets"]["both"]:
      route-target both ${ route_target }
%             endfor
%         endif
%         if config["router_bgp"]["vlans"][vlan].get("route_targets") is not None and config["router_bgp"]["vlans"][vlan]["route_targets"].get("import") is not None:
%             for route_target in config["router_bgp"]["vlans"][vlan]["route_targets"]["import"]:
      route-target import ${ route_target }
%             endfor
%         endif
%         if config["router_bgp"]["vlans"][vlan].get("route_targets") is not None and config["router_bgp"]["vlans"][vlan]["route_targets"].get("export") is not None:
%             for route_target in config["router_bgp"]["vlans"][vlan]["route_targets"]["export"]:
      route-target export ${ route_target }
%             endfor
%         endif
%         if config["router_bgp"]["vlans"][vlan].get("redistribute_routes") is not None:
%           for redistribute_route in config["router_bgp"]["vlans"][vlan]["redistribute_routes"]:
      redistribute ${ redistribute_route }
%           endfor
%         endif
%       endfor
## vxlan vlan aware bundles
%       if config["router_bgp"].get("vlan_aware_bundles") is not None:
%         for vlan_aware_bundle in config["router_bgp"]["vlan_aware_bundles"].keys():
   !
   vlan-aware-bundle ${ vlan_aware_bundle }
%         if  config["router_bgp"]["vlan_aware_bundles"][vlan_aware_bundle].get("rd") is not None:
      rd ${  config["router_bgp"]["vlan_aware_bundles"][vlan_aware_bundle]["rd"] }
%         endif
%         if config["router_bgp"]["vlan_aware_bundles"][vlan_aware_bundle].get("route_targets") is not None and config["router_bgp"]["vlan_aware_bundles"][vlan_aware_bundle]["route_targets"].get("both") is not None:
%             for route_target in  config["router_bgp"]["vlan_aware_bundles"][vlan_aware_bundle]["route_targets"]["both"]:
      route-target both ${ route_target }
%             endfor
%         endif
%         if config["router_bgp"]["vlan_aware_bundles"][vlan_aware_bundle].get("route_targets") is not None and config["router_bgp"]["vlan_aware_bundles"][vlan_aware_bundle]["route_targets"].get("import") is not None:
%             for route_target in config["router_bgp"]["vlan_aware_bundles"][vlan_aware_bundle]["route_targets"]["import"]:
      route-target import ${ route_target }
%             endfor
%         endif
%         if config["router_bgp"]["vlan_aware_bundles"][vlan_aware_bundle].get("route_targets") is not None and config["router_bgp"]["vlan_aware_bundles"][vlan_aware_bundle]["route_targets"].get("export") is not None:
%             for route_target in  config["router_bgp"]["vlan_aware_bundles"][vlan_aware_bundle]["route_targets"]["export"]:
      route-target export ${ route_target }
%             endfor
%         endif
%         if config["router_bgp"]["vlan_aware_bundles"][vlan_aware_bundle].get("redistribute_routes") is not None:
%           for redistribute_route in config["router_bgp"]["vlan_aware_bundles"][vlan_aware_bundle]["redistribute_routes"]:
      redistribute ${ redistribute_route }
%           endfor %}
%         endif
%         if config["router_bgp"]["vlan_aware_bundles"][vlan_aware_bundle].get("vlan") is not None:
      vlan ${ config["router_bgp"]["vlan_aware_bundles"][vlan_aware_bundle]["vlan"] }
%         endif
%         endfor
%       endif
%     endif
## address families activation
## address family evpn activation ##
%     if config["router_bgp"].get("address_family_evpn") is not None:
   !
   address-family evpn
%         if config["router_bgp"]["address_family_evpn"].get("evpn_hostflap_detection") is not None and config["router_bgp"]["address_family_evpn"]["evpn_hostflap_detection"].get("enabled") == False:
      no host-flap detection
%         else:
%             if config["router_bgp"]["address_family_evpn"].get("evpn_hostflap_detection") is not None and config["router_bgp"]["address_family_evpn"]["evpn_hostflap_detection"].get("window") is not None:
      host-flap detection window ${ config["router_bgp"]["address_family_evpn"]["evpn_hostflap_detection"]["window"] }
%             endif
%             if config["router_bgp"]["address_family_evpn"].get("evpn_hostflap_detection") is not None and config["router_bgp"]["address_family_evpn"]["evpn_hostflap_detection"].get("threshold") is not None:
      host-flap detection threshold ${ config["router_bgp"]["address_family_evpn"]["evpn_hostflap_detection"]["threshold"] }
%             endif
%         endif
%         if config["router_bgp"]["address_family_evpn"].get("domain_identifier") is not None:
      domain identifier ${ config["router_bgp"]["address_family_evpn"]["domain_identifier"] }
%         endif
%         if config["router_bgp"]["address_family_evpn"].get("peer_groups") is not None:
%           for peer_group in config["router_bgp"]["address_family_evpn"]["peer_groups"].keys():
%             if config["router_bgp"]["address_family_evpn"]["peer_groups"][peer_group].get("route_map_in") is not None:
      neighbor ${ peer_group } route-map ${ config["router_bgp"]["address_family_evpn"]["peer_groups"][peer_group]["route_map_in"] } in
%             endif
%             if config["router_bgp"]["address_family_evpn"]["peer_groups"][peer_group].get("route_map_out") is not None:
      neighbor ${ peer_group } route-map ${ config["router_bgp"]["address_family_evpn"]["peer_groups"][peer_group]["route_map_out"] } out
%             endif
%             if config["router_bgp"]["address_family_evpn"]["peer_groups"][peer_group].get("activate") == True:
      neighbor ${ peer_group } activate
%             elif config["router_bgp"]["address_family_evpn"]["peer_groups"][peer_group].get("activate") == False:
      no neighbor ${ peer_group } activate
%             endif
%           endfor
%         endif
%     endif
## {# address family rt-membership activation #}
## {%     if router_bgp.address_family_rtc is arista.avd.defined %}
##    !
##    address-family rt-membership
## {%         for peer_group in router_bgp.address_family_rtc.peer_groups | arista.avd.natural_sort %}
## {%             if router_bgp.address_family_rtc.peer_groups[peer_group].activate is arista.avd.defined(true) %}
##       neighbor ${ peer_group } activate
## {%             elif router_bgp.address_family_rtc.peer_groups[peer_group].activate is arista.avd.defined(false) %}
##       no neighbor ${ peer_group } activate
## {%             endif %}
## {%             if router_bgp.address_family_rtc.peer_groups[peer_group].default_route_target is defined %}
## {%                 if router_bgp.address_family_rtc.peer_groups[peer_group].default_route_target.only is arista.avd.defined(true) %}
##       neighbor ${ peer_group } default-route-target only
## {%                 else %}
##       neighbor ${ peer_group } default-route-target
## {%                 endif %}
## {%             endif %}
## {%             if router_bgp.address_family_rtc.peer_groups[peer_group].default_route_target.encoding_origin_as_omit is defined %}
##       neighbor ${ peer_group } default-route-target encoding origin-as omit
## {%             endif %}
## {%         endfor %}
## {%     endif %}
## address family ipv4 activation
%     if config["router_bgp"].get("address_family_ipv4") is not None:
   !
   address-family ipv4
%       if config["router_bgp"]["address_family_ipv4"].get("networks") is not None:
%         for network in config["router_bgp"]["address_family_ipv4"]["networks"].keys():
%             if config["router_bgp"]["address_family_ipv4"]["networks"][network].get("route_map") is not None:
      network ${ network } route-map ${ config["router_bgp"]["address_family_ipv4"]["networks"][network]["route_map"] }
%             else:
      network ${ network }
%             endif
%         endfor
%       endif
%       if config["router_bgp"]["address_family_ipv4"].get("peer_groups") is not None:
%           for peer_group in config["router_bgp"]["address_family_ipv4"]["peer_groups"].keys():
%             if config["router_bgp"]["address_family_ipv4"]["peer_groups"][peer_group].get("route_map_in") is not None:
      neighbor ${ peer_group } route-map ${ config["router_bgp"]["address_family_ipv4"]["peer_groups"][peer_group]["route_map_in"] } in
%             endif
%             if config["router_bgp"]["address_family_ipv4"]["peer_groups"][peer_group].get("route_map_out") is not None:
      neighbor ${ peer_group } route-map ${ config["router_bgp"]["address_family_ipv4"]["peer_groups"][peer_group]["route_map_out"] } out
%             endif
%             if config["router_bgp"]["address_family_ipv4"]["peer_groups"][peer_group].get("prefix_list_in") is not None:
      neighbor ${ peer_group } prefix-list ${ config["router_bgp"]["address_family_ipv4"]["peer_groups"][peer_group]["prefix_list_in"] } in
%             endif
%             if config["router_bgp"]["address_family_ipv4"]["peer_groups"][peer_group].get("prefix_list_out") is not None:
      neighbor ${ peer_group } prefix-list ${ config["router_bgp"]["address_family_ipv4"]["peer_groups"][peer_group]["prefix_list_out"] } out
%             endif
%             if config["router_bgp"]["address_family_ipv4"]["peer_groups"][peer_group].get("activate") == True:
      neighbor ${ peer_group } activate
%             elif config["router_bgp"]["address_family_ipv4"]["peer_groups"][peer_group].get("activate") == False:
      no neighbor ${ peer_group } activate
%             endif
%           endfor
%       endif
%       if config["router_bgp"]["address_family_ipv4"].get("neighbors") is not None:
%           for neighbor in config["router_bgp"]["address_family_ipv4"]["neighbors"].keys():
%             if config["router_bgp"]["address_family_ipv4"]["neighbors"][neighbor].get("route_map_in") is not None:
      neighbor ${ neighbor } route-map ${ config["router_bgp"]["address_family_ipv4"]["neighbors"][neighbor]["route_map_in"] } in
%             endif
%             if config["router_bgp"]["address_family_ipv4"]["neighbors"][neighbor].get("route_map_out") is not None:
      neighbor ${ neighbor } route-map ${ config["router_bgp"]["address_family_ipv4"]["neighbors"][neighbor]["route_map_out"] } out
%             endif
%             if config["router_bgp"]["address_family_ipv4"]["neighbors"][neighbor].get("prefix_list_in") is not None:
      neighbor ${ neighbor } prefix-list ${ config["router_bgp"]["address_family_ipv4"]["neighbors"][neighbor]["prefix_list_in"] } in
%             endif
%             if config["router_bgp"]["address_family_ipv4"]["neighbors"][neighbor].get("prefix_list_out") is not None:
      neighbor ${ neighbor } prefix-list ${ config["router_bgp"]["address_family_ipv4"]["neighbors"][neighbor]["prefix_list_out"] } out
%             endif
%             if config["router_bgp"]["address_family_ipv4"]["neighbors"][neighbor].get("default_originate") is not None:
<%                 neighbor_default_originate_cli = "neighbor " + neighbor + " default-originate" %>
%                 if config["router_bgp"]["address_family_ipv4"]["neighbors"][neighbor]["default_originate"].get("route_map") is not None:
<%                     neighbor_default_originate_cli = neighbor_default_originate_cli + " route-map " + config["router_bgp"]["address_family_ipv4"]["neighbors"][neighbor]["default_originate"]["route_map"] %>
%                 endif
%                 if config["router_bgp"]["address_family_ipv4"]["neighbors"][neighbor]["default_originate"].get("always") == True:
<%                     neighbor_default_originate_cli = neighbor_default_originate_cli + " always" %>
%                 endif
      ${ neighbor_default_originate_cli }
%             endif
%             if config["router_bgp"]["address_family_ipv4"]["neighbors"][neighbor].get("activate") == True:
      neighbor ${ neighbor } activate
%             elif config["router_bgp"]["address_family_ipv4"]["neighbors"][neighbor].get("activate") == False:
      no neighbor ${ neighbor } activate
%             endif
%           endfor
%       endif
%     endif
## {# address family ipv4 multicast activation #}
## {%     if router_bgp.address_family_ipv4_multicast is arista.avd.defined %}
##    !
##    address-family ipv4 multicast
## {%         for peer_group in router_bgp.address_family_ipv4_multicast.peer_groups | arista.avd.natural_sort %}
## {%             if router_bgp.address_family_ipv4_multicast.peer_groups[peer_group].route_map_in is arista.avd.defined %}
##       neighbor ${ peer_group } route-map {{ router_bgp.address_family_ipv4_multicast.peer_groups[peer_group].route_map_in }} in
## {%             endif %}
## {%             if router_bgp.address_family_ipv4_multicast.peer_groups[peer_group].route_map_out is arista.avd.defined %}
##       neighbor ${ peer_group } route-map {{ router_bgp.address_family_ipv4_multicast.peer_groups[peer_group].route_map_out }} out
## {%             endif %}
## {%             if router_bgp.address_family_ipv4_multicast.peer_groups[peer_group].activate is arista.avd.defined(true) %}
##       neighbor ${ peer_group } activate
## {%             elif router_bgp.address_family_ipv4_multicast.peer_groups[peer_group].activate is arista.avd.defined(false) %}
##       no neighbor ${ peer_group } activate
## {%             endif %}
## {%         endfor %}
## {%         for neighbor in router_bgp.address_family_ipv4_multicast.neighbors | arista.avd.natural_sort %}
## {%             if router_bgp.address_family_ipv4_multicast.neighbors[neighbor].route_map_in is arista.avd.defined %}
##       neighbor {{ neighbor }} route-map {{ router_bgp.address_family_ipv4_multicast.neighbors[neighbor].route_map_in }} in
## {%             endif %}
## {%             if router_bgp.address_family_ipv4_multicast.neighbors[neighbor].route_map_out is arista.avd.defined %}
##       neighbor {{ neighbor }} route-map {{ router_bgp.address_family_ipv4_multicast.neighbors[neighbor].route_map_out }} out
## {%             endif %}
## {%             if router_bgp.address_family_ipv4_multicast.neighbors[neighbor].activate is arista.avd.defined(true) %}
##       neighbor {{ neighbor }} activate
## {%             elif router_bgp.address_family_ipv4_multicast.neighbors[neighbor].activate is arista.avd.defined(false) %}
##       no neighbor {{ neighbor }} activate
## {%             endif %}
## {%         endfor %}
## {%         for redistribute_route in router_bgp.address_family_ipv4_multicast.redistribute_routes | arista.avd.natural_sort %}
## {%             set redistribute_route_cli = "redistribute " ~ redistribute_route %}
## {%             if router_bgp.address_family_ipv4_multicast.redistribute_routes[redistribute_route].route_map is arista.avd.defined %}
## {%                 set redistribute_route_cli = redistribute_route_cli ~ " route-map " ~ router_bgp.address_family_ipv4_multicast.redistribute_routes[redistribute_route].route_map %}
## {%             endif %}
##       {{ redistribute_route_cli }}
## {%         endfor %}
## {%     endif %}
## {# address family ipv6 activation #}
## {%     if router_bgp.address_family_ipv6 is arista.avd.defined %}
##    !
##    address-family ipv6
## {%         for network in router_bgp.address_family_ipv6.networks | arista.avd.natural_sort %}
## {%             if router_bgp.address_family_ipv6.networks[network].route_map is arista.avd.defined %}
##       network {{ network }} route-map {{ router_bgp.address_family_ipv6.networks[network].route_map }}
## {%             else %}
##       network {{ network }}
## {%             endif %}
## {%         endfor %}
## {%         for peer_group in router_bgp.address_family_ipv6.peer_groups | arista.avd.natural_sort %}
## {%             if router_bgp.address_family_ipv6.peer_groups[peer_group].route_map_in is arista.avd.defined %}
##       neighbor ${ peer_group } route-map {{ router_bgp.address_family_ipv6.peer_groups[peer_group].route_map_in }} in
## {%             endif %}
## {%             if router_bgp.address_family_ipv6.peer_groups[peer_group].route_map_out is arista.avd.defined %}
##       neighbor ${ peer_group } route-map {{ router_bgp.address_family_ipv6.peer_groups[peer_group].route_map_out }} out
## {%             endif %}
## {%             if router_bgp.address_family_ipv6.peer_groups[peer_group].activate is arista.avd.defined(true) %}
##       neighbor ${ peer_group } activate
## {%             elif router_bgp.address_family_ipv6.peer_groups[peer_group].activate is arista.avd.defined(false) %}
##       no neighbor ${ peer_group } activate
## {%             endif %}
## {%         endfor %}
## {%         for neighbor in router_bgp.address_family_ipv6.neighbors | arista.avd.natural_sort %}
## {%             if router_bgp.address_family_ipv6.neighbors[neighbor].route_map_in is arista.avd.defined %}
##       neighbor {{ neighbor }} route-map {{ router_bgp.address_family_ipv6.neighbors[neighbor].route_map_in }} in
## {%             endif %}
## {%             if router_bgp.address_family_ipv6.neighbors[neighbor].route_map_out is arista.avd.defined %}
##       neighbor {{ neighbor }} route-map {{ router_bgp.address_family_ipv6.neighbors[neighbor].route_map_out }} out
## {%             endif %}
## {%             if router_bgp.address_family_ipv6.neighbors[neighbor].activate is arista.avd.defined(true) %}
##       neighbor {{ neighbor }} activate
## {%             elif router_bgp.address_family_ipv6.neighbors[neighbor].activate is arista.avd.defined(false) %}
##       no neighbor {{ neighbor }} activate
## {%             endif %}
## {%         endfor %}
## {%         for redistribute_route in router_bgp.address_family_ipv6.redistribute_routes | arista.avd.natural_sort %}
## {%             set redistribute_route_cli = "redistribute " ~ redistribute_route %}
## {%             if router_bgp.address_family_ipv6.redistribute_routes[redistribute_route].route_map is arista.avd.defined %}
## {%                 set redistribute_route_cli = redistribute_route_cl ~ " route-map " ~ router_bgp.address_family_ipv6.redistribute_routes[redistribute_route].route_map %}
## {%             endif %}
##       {{ redistribute_route_cli }}
## {%         endfor %}
## {%     endif %}
## {# address family vpn-ipv4 activation #}
## {%     if router_bgp.address_family_vpn_ipv4 is arista.avd.defined %}
##    !
##    address-family vpn-ipv4
## {%         if router_bgp.address_family_vpn_ipv4.domain_identifier is arista.avd.defined %}
##       domain identifier {{ router_bgp.address_family_vpn_ipv4.domain_identifier }}
## {%         endif %}
## {%         for peer_group in router_bgp.address_family_vpn_ipv4.peer_groups | arista.avd.natural_sort %}
## {%             if router_bgp.address_family_vpn_ipv4.peer_groups[peer_group].activate is arista.avd.defined(true) %}
##       neighbor ${ peer_group } activate
## {%             elif router_bgp.address_family_vpn_ipv4.peer_groups[peer_group].activate is arista.avd.defined(false) %}
##       no neighbor ${ peer_group } activate
## {%             endif %}
## {%         endfor %}
## {%         for neighbor in router_bgp.address_family_vpn_ipv4.neighbors | arista.avd.natural_sort %}
## {%             if router_bgp.address_family_vpn_ipv4.neighbors[neighbor].activate is arista.avd.defined(true) %}
##       neighbor {{ neighbor }} activate
## {%             elif router_bgp.address_family_vpn_ipv4.neighbors[neighbor].activate is arista.avd.defined(false) %}
##       no neighbor {{ neighbor }} activate
## {%             endif %}
## {%         endfor %}
## {%         if router_bgp.address_family_vpn_ipv4.neighbor_default_encapsulation_mpls_next_hop_self.source_interface is arista.avd.defined %}
##       neighbor default encapsulation mpls next-hop-self source-interface {{ router_bgp.address_family_vpn_ipv4.neighbor_default_encapsulation_mpls_next_hop_self.source_interface }}
## {%         endif %}
## {%     endif %}
## L3VPNs - (vxlan) VRFs
%     if config["router_bgp"].get("vrfs") is not None:
%       for vrf in config["router_bgp"]["vrfs"].keys():
   !
   vrf ${ vrf }
%         if config["router_bgp"]["vrfs"][vrf].get("rd") is not None:
      rd ${ config["router_bgp"]["vrfs"][vrf]["rd"] }
%         endif
%         if config["router_bgp"]["vrfs"][vrf].get("route_targets") is not None and config["router_bgp"]["vrfs"][vrf]["route_targets"].get("import") is not None:
%             for address_family in config["router_bgp"]["vrfs"][vrf]["route_targets"]["import"].keys():
%                 for route_target in config["router_bgp"]["vrfs"][vrf]["route_targets"]["import"][address_family]:
      route-target import ${ address_family } ${ route_target }
%                 endfor
%             endfor
%         endif
%         if config["router_bgp"]["vrfs"][vrf].get("route_targets") is not None and config["router_bgp"]["vrfs"][vrf]["route_targets"].get("export") is not None:
%             for address_family in config["router_bgp"]["vrfs"][vrf]["route_targets"]["export"].keys():
%                 for route_target in config["router_bgp"]["vrfs"][vrf]["route_targets"]["export"][address_family]:
      route-target export ${ address_family } ${ route_target }
%                 endfor
%             endfor
%         endif
%         if config["router_bgp"]["vrfs"][vrf].get("router_id") is not None:
      router-id ${ config["router_bgp"]["vrfs"][vrf]["router_id"] }
%         endif
%         if config["router_bgp"]["vrfs"][vrf].get("timers") is not None:
      timers bgp ${ config["router_bgp"]["vrfs"][vrf]["timers"] }
%         endif
%         if config["router_bgp"]["vrfs"][vrf].get("networks") is not None:
%           for network in config["router_bgp"]["vrfs"][vrf]["networks"].keys():
%             if config["router_bgp"]["vrfs"][vrf].networks[network].get("route_map") is not None:
      network ${ network } route-map ${ config["router_bgp"]["vrfs"][vrf]["networks"][network]["route_map"] }
%             else:
      network ${ network }
%             endif
%           endfor
%         endif
%         if config["router_bgp"]["vrfs"][vrf].get("neighbors") is not None:
%           for neighbor in config["router_bgp"]["vrfs"][vrf]["neighbors"].keys():
%             if config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor].get("remote_as") is not None:
      neighbor ${ neighbor } remote-as ${ config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor]["remote_as"] }
%             endif
%             if config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor].get("peer_group") is not None:
      neighbor ${ neighbor } peer group ${ config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor]["peer_group"] }
%             endif
%             if config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor].get("password") is not None:
      neighbor ${ neighbor } password 7 ${ config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor]["password"] }
%             endif
%             if config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor].get("local_as") is not None:
      neighbor ${ neighbor } local-as ${ config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor]["local_as"] } no-prepend replace-as
%             endif
%             if config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor].get("description") is not None:
      neighbor ${ neighbor } description ${ config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor]["description"] }
%             endif
%             if config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor].get("ebgp_multihop") is not None:
<%                 neighbor_ebgp_multihop_cli = "neighbor " + neighbor + " ebgp-multihop" %>
%                 if type(config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor]["ebgp_multihop"]) is int:
<%                     neighbor_ebgp_multihop_cli = neighbor_ebgp_multihop_cli + " " + str(config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor]["ebgp_multihop"]) %>
%                 endif
      ${ neighbor_ebgp_multihop_cli }
%             endif
%             if config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor].get("next_hop_self") == True:
      neighbor ${ neighbor } next-hop-self
%             endif
%             if config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor].get("timers") is not None:
      neighbor ${ neighbor } timers ${ config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor]["timers"] }
%             endif
%             if config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor].get("send_community") is not None and config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor]["send_community"] == "all":
      neighbor ${ neighbor } send-community
%             elif config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor].get("send_community") is not None:
      neighbor ${ neighbor } send-community ${ config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor]["send_community"] }
%             endif
%             if config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor].get("maximum_routes") is not None and config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor].get("warning_limit_routes") is not None:
      neighbor ${ neighbor } maximum-routes ${ config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor]["maximum_routes"] } warning-limit ${ config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor]["warning_limit_routes"] }
%             elif config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor].get("maximum_routes") is not None:
      neighbor ${ neighbor } maximum-routes ${ config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor]["maximum_routes"] }
%             endif
%             if config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor].get("default_originate") is not None:
<%                neighbor_default_originate_cli = "neighbor " + neighbor + " default-originate" %>
%                 if config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor]["default_originate"].get("route_map") is not None:
<%                    neighbor_default_originate_cli = neighbor_default_originate_cli + " route-map " + config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor]["default_originate"]["route_map"] %>
%                 endif
%                 if config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor]["default_originate"].get("always") == True:
<%                    neighbor_default_originate_cli = neighbor_default_originate_cli+ " always" %>
%                 endif
      ${ neighbor_default_originate_cli }
%             endif
%             if config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor].get("update_source") is not None:
      neighbor ${ neighbor } update-source ${ config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor]["update_source"] }
%             endif
%             if config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor].get("password") is not None:
      neighbor ${ neighbor } password 7 ${ config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor]["password"] }
%             endif
%             if config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor].get("weight") is not None:
      neighbor ${ neighbor } weight ${ config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor]["weight"] }
%             endif
%             if config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor].get("route_map_out") is not None:
      neighbor ${ neighbor } route-map ${ config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor]["route_map_out"] } out
%             endif
%             if config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor].get("route_map_in") is not None:
      neighbor ${ neighbor } route-map ${ config["router_bgp"]["vrfs"][vrf]["neighbors"][neighbor]["route_map_in"] } in
%             endif
%           endfor
%         endif
%         if config["router_bgp"]["vrfs"][vrf].get("redistribute_routes") is not None:
%           for redistribute_route in config["router_bgp"]["vrfs"][vrf]["redistribute_routes"].keys():
<%             redistribute_cli = "redistribute " + redistribute_route %>
%              if config["router_bgp"]["vrfs"][vrf]["redistribute_routes"][redistribute_route].get("route_map") is not None:
<%                 redistribute_cli = redistribute_cli + " route-map " + config["router_bgp"]["vrfs"][vrf]["redistribute_routes"][redistribute_route]["route_map"] %>
%              endif
      ${ redistribute_cli }
%           endfor
%         endif
%         if config["router_bgp"]["vrfs"][vrf].get("aggregate_addresses") is not None:
%           for aggregate_address in config["router_bgp"]["vrfs"][vrf]["aggregate_addresses"].keys():
<%             aggregate_address_cli = "aggregate-address " + aggregate_address %>
%             if config["router_bgp"]["vrfs"][vrf]["aggregate_addresses"][aggregate_address].get("as_set") == True:
<%                 aggregate_address_cli = aggregate_address_cli + " as-set" %>
%             endif
%             if config["router_bgp"]["vrfs"][vrf]["aggregate_addresses"][aggregate_address].get("summary_only") == True:
<%                  aggregate_address_cli = aggregate_address_cli + " summary-only" %>
%             endif
%             if config["router_bgp"]["vrfs"][vrf]["aggregate_addresses"][aggregate_address].get("attribute_map") is not None:
<%                  aggregate_address_cli = aggregate_address_cli + " attribute-map " + config["router_bgp"]["vrfs"][vrf]["aggregate_addresses"][aggregate_address]["attribute_map"] %>
%             endif
%             if config["router_bgp"]["vrfs"][vrf]["aggregate_addresses"][aggregate_address].get("match_map") is not None:
<%                  aggregate_address_cli = aggregate_address_cli + " match-map " + config["router_bgp"]["vrfs"][vrf]["aggregate_addresses"][aggregate_address]["match_map"] %>
%             endif
%             if config["router_bgp"]["vrfs"][vrf]["aggregate_addresses"][aggregate_address].get("advertise_only") == True:
<%                 aggregate_address_cli = aggregate_address_cli + " advertise-only" %>
%             endif
      ${ aggregate_address_cli }
%           endfor
%         endif
%         if config["router_bgp"]["vrfs"][vrf].get("eos_cli"):
%             for cli_statement in config["router_bgp"]["vrfs"][vrf]["eos_cli"].split("\n"):
      ${cli_statement}
%             endfor
%         endif
%         if config["router_bgp"]["vrfs"][vrf].get("address_families") is not None:
%           for  address_family in config["router_bgp"]["vrfs"][vrf]["address_families"].keys():
    !
    address-family ${ address_family }
%             for neighbor in config["router_bgp"]["vrfs"][vrf]["address_families"][address_family]["neighbors"].keys():
%                 if config["router_bgp"]["vrfs"][vrf]["address_families"][address_family]["neighbors"][neighbor].get("activate") == True:
      neighbor ${ neighbor } activate
%                 endif
%             endfor
%             for network in config["router_bgp"]["vrfs"][vrf]["address_families"][address_family]["networks"].keys():
<%                network_cli = "network " + network %>
%                 if config["router_bgp"]["vrfs"][vrf]["address_families"][address_family]["networks"][network].get("route_map") is not None:
<%                     network_cli = network_cli + " route-map " + config["router_bgp"]["vrfs"][vrf]["address_families"][address_family]["networks"][network]["route_map"] %>
%                 endif
      ${ network_cli }
%             endfor
%           endfor
%         endif
%       endfor
%     endif
   !
% endif
% endif
## virtual source nat
% if config.get("virtual_source_nat_vrfs"):
%     for vrf in natural_sort(config["virtual_source_nat_vrfs"].keys()):
%         if config["virtual_source_nat_vrfs"][vrf].get("ip_address"):
ip address virtual source-nat vrf ${ vrf } address ${ config["virtual_source_nat_vrfs"][vrf]["ip_address"] }
%         endif
%     endfor
!
% endif
## router-ospf
%if config.get("router_ospf") and config["router_ospf"].get("process_ids"):
%for process_id in config["router_ospf"]["process_ids"]:
%     if process_id.get("vrf"):
router ospf ${ process_id["id"] } vrf ${ process_id["vrf"] }
%     else:
router ospf ${ process_id["id"] }
%     endif
%     if process_id.get("log_adjacency_changes_detail"):
   log-adjacency-changes detail
%     endif
%     if process_id.get("router_id"):
   router-id ${ process_id["router_id"] }
%     endif
%     if process_id.get("auto_cost_reference_bandwidth"):
   auto-cost reference-bandwidth ${ process_id["auto_cost_reference_bandwidth"] }
%     endif
%     if process_id.get("bfd_enable"):
   bfd default
%     endif
%     if process_id.get("passive_interface_default"):
   passive-interface default
%     endif
%     if process_id.get("no_passive_interfaces"):
%         for interface in process_id["no_passive_interfaces"]:
   no passive-interface ${ interface }
%         endfor
%     endif
%     if process_id.get("network_prefixes"):
%         for network_prefix in natural_sort(process_id["network_prefixes"].keys()):
   network ${ network_prefix } area ${ process_id["network_prefixes"][network_prefix]["area"] }
%         endfor
%     endif
%     if process_id.get("bfd_enable"):
   bfd default
%     endif
%     if process_id.get("redistribute"):
%         if process_id["redistribute"].get("static"):
<%            redistribute_static_cli = "redistribute static" %>
%             if process_id["redistribute"]["static"].get("include_leaked"):
<%                   redistribute_static_cli = redistribute_static_cli + " include leaked" %>
%             endif
%             if process_id["redistribute"]["static"].get("route_map"):
<%                   redistribute_static_cli = redistribute_static_cli + " route-map " +  process_id["redistribute"]["static"]["route_map"] %>
%             endif
   ${ redistribute_static_cli }
%         endif
%         if process_id["redistribute"].get("connected"):
<%            redistribute_connected_cli = "redistribute connected" %>
%             if process_id["redistribute"]["connected"].get("include_leaked"):
<%                   redistribute_connected_cli = redistribute_connected_cli + " include leaked" %>
%             endif
%             if process_id["redistribute"]["connected"].get("route_map"):
<%                   redistribute_connected_cli = redistribute_connected_cli + " route-map " + process_id["redistribute"]["connected"]["route_map"] %>
%             endif
   ${ redistribute_connected_cli }
%         endif
%         if process_id["redistribute"].get("bgp"):
<%            redistribute_bgp_cli = "redistribute bgp" %>
%             if process_id["redistribute"]["bgp"].get("include_leaked"):
<%                    redistribute_bgp_cli = redistribute_bgp_cli + " include leaked" %>
%             endif
%             if process_id["redistribute"]["bgp"].get("route_map"):
<%                    redistribute_bgp_cli = redistribute_bgp_cli + " route-map " + process_id["redistribute"]["bgp"]["route_map"] %>
%             endif
   ${ redistribute_bgp_cli }
%         endif
%     endif
%     if process_id.get("graceful_restart"):
%         if process_id["graceful_restart"].get("enabled"):
<%            graceful_restart_cli = "graceful-restart" %>
%             if process_id["graceful_restart"].get("grace_period"):
<%                graceful_restart_cli += " grace-period " + str(process_id["graceful_restart"]["grace_period"]) %>
%             endif
   ${ graceful_restart_cli}
%         endif
%     endif
%     if process_id.get("eos_cli"):
%         for ospf_cli in process_id["eos_cli"].split("\n"):
   ${ospf_cli}
%         endfor
%     endif
!
%endfor
%endif
## router pim sparse mode
% if config.get('router_pim_sparse_mode'):
router pim sparse-mode
%     if config["router_pim_sparse_mode"].get("ipv4"):
   ipv4
%         if config["router_pim_sparse_mode"]["ipv4"].get("bfd", False) is True:
      bfd
%         endif
%         for rp_address in natural_sort(config["router_pim_sparse_mode"]["ipv4"].get("rp_addresses", {}).keys()):
%             if len(config["router_pim_sparse_mode"]["ipv4"]['rp_addresses'][rp_address].get("groups", {})) > 0 or len(config["router_pim_sparse_mode"]["ipv4"]['rp_addresses'][rp_address].get("access_lists", {})) > 0:
%                 if config["router_pim_sparse_mode"]["ipv4"]['rp_addresses'][rp_address].get("groups"):
%                     for group in natural_sort(config["router_pim_sparse_mode"]["ipv4"]['rp_addresses'][rp_address]["groups"]):
      rp address ${ rp_address } ${ group }
%                     endfor
%                 endif
%                 if config["router_pim_sparse_mode"]["ipv4"]['rp_addresses'][rp_address].get("access_lists"):
%                     for access_list in natural_sort(config["router_pim_sparse_mode"]["ipv4"]['rp_addresses'][rp_address]["access_lists"]):
      rp address ${ rp_address } access-list ${ access_list }
%                     endfor
%                 endif
%             else:
      rp address ${ rp_address }
%             endif
%         endfor
   !
%     endif
%     for vrf in natural_sort(config["router_pim_sparse_mode"].get("vrfs", []), sort_key="name"):
   vrf ${ vrf["name"] }
%         if vrf.get("ipv4"):
      ipv4
%             if vrf.get("bfd", False) is True:
         bfd
%             endif
%             for rp_address in natural_sort(vrf["ipv4"].get("rp_addresses", []), sort_key="address"):
%                 if len(rp_address.get("groups", [])) > 0 or len(rp_address.get("access_lists", [])) > 0:
%                     if rp_address.get("groups"):
%                         for group in natural_sort(rp_address["groups"]):
         rp address ${ rp_address["address"] } ${ group }
%                         endfor
%                     endif
%                     if rp_address.get("access_lists"):
%                         for access_list in natural_sort(rp_address["access_lists"]):
         rp address ${ rp_address["address"] } access-list ${ access_list }
%                         endfor
%                     endif
%                 else:
         rp address ${ rp_address["address"] }
%                 endif
%             endfor
%         endif
   !
%     endfor
% endif
## eos - dot1x
% if config.get("dot1x"):
%     if config["dot1x"].get("system_auth_control"):
dot1x system-auth-control
%     endif
%     if config["dot1x"].get("protocol_lldp_bypass"):
dot1x protocol lldp bypass
%     endif
%     if config["dot1x"].get("dynamic_authorization"):
dot1x dynamic-authorization
%     endif
%     if config["dot1x"].get("mac_based_authentication") or config["dot1x"].get("radius_av_pair") or config["dot1x"].get("radius_av_pair_username_format"):
dot1x
%         if config["dot1x"].get("mac_based_authentication"):
%             if config["dot1x"].get("mac_based_authentication", {}).get("delay"):
   mac based authentication delay ${ config["dot1x"]["mac_based_authentication"]["delay"] } seconds
%             endif
%             if config["dot1x"].get("mac_based_authentication", {}).get("hold_period"):
   mac based authentication hold period ${ config["dot1x"]["mac_based_authentication"]["hold_period"] } seconds
%             endif
%         endif
%         if get(config, "dot1x.radius_av_pair.service_type"):
   radius av-pair service-type
%         endif
%         if get(config, "dot1x.radius_av_pair.framed_mtu"):
   radius av-pair framed-mtu ${ config["dot1x"]["radius_av_pair"]["framed_mtu"] }
%         endif
%         if (delimiter := get(config, "dot1x.radius_av_pair_username_format.delimiter")) and (mac_string_case := get(config, "dot1x.radius_av_pair_username_format.mac_string_case")):
   mac-based-auth radius av-pair user-name delimiter ${ delimiter } ${ mac_string_case }
%         endif
%         if get(config, "dot1x.radius_av_pair.lldp.system_name.enabled"):
<%            av_pair_lldp = "radius av-pair lldp system-name" %>
%             if get(config, "dot1x.radius_av_pair.lldp.system_name.auth_only"):
<%                av_pair_lldp += " auth-only" %>
%             endif
   ${ av_pair_lldp }
%         endif
%         if get(config, "dot1x.radius_av_pair.lldp.system_description.enabled"):
<%            av_pair_lldp = "radius av-pair lldp system-description" %>
%             if get(config, "dot1x.radius_av_pair.lldp.system_description.auth_only"):
<%                av_pair_lldp += " auth-only" %>
%             endif
   ${ av_pair_lldp }
%         endif
%         if get(config, "dot1x.radius_av_pair.dhcp.hostname.enabled"):
<%            av_pair_dhcp = "radius av-pair dhcp hostname" %>
%             if get(config, "dot1x.radius_av_pair.dhcp.hostname.auth_only"):
<%                av_pair_dhcp += " auth-only" %>
%             endif
   ${ av_pair_dhcp }
%         endif
%         if get(config, "dot1x.radius_av_pair.dhcp.parameter_request_list.enabled"):
<%            av_pair_dhcp = "radius av-pair dhcp parameter-request-list" %>
%             if get(config, "dot1x.radius_av_pair.dhcp.parameter_request_list.auth_only"):
<%                av_pair_dhcp += " auth-only" %>
%             endif
   ${ av_pair_dhcp }
%         endif
%         if get(config, "dot1x.radius_av_pair.dhcp.vendor_class_id.enabled"):
<%            av_pair_dhcp = "radius av-pair dhcp vendor-class-id" %>
%             if get(config, "dot1x.radius_av_pair.dhcp.vendor_class_id.auth_only"):
<%                av_pair_dhcp += " auth-only" %>
%             endif
   ${ av_pair_dhcp }
%         endif
%     endif
!
% endif
<% ctx.info(f"Time taken to run studio: {time.time() - start_time} seconds") %>