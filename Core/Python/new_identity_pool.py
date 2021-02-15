#
# _author_ = Martin Flint <Martin.Flint@Dell.com>
# _author_ = Trevor Squillario <Trevor.Squillario@Dell.com>
# _author_ = Grant Curell <grant_curell@dell.com>
#
# Copyright (c) 2021 Dell EMC Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
#### Synopsis
Script to create identity pool in OpenManage Enterprise

#### Description
This script uses the OME REST API to create identity pools
For authentication X-Auth is used over Basic Authentication
Note that the credentials entered are not stored to disk.

*Must include header row with at least the rows in the example below
*Use get_identitypool.py to export CSV file
Example:
Name,EthernetSettings IdentityCount,EthernetSettings StartingMacAddress,IscsiSettings IdentityCount,IscsiSettings StartingMacAddress,IscsiSettings InitiatorConfig IqnPrefix,IscsiSettings InitiatorIpPoolSettings IpRange,IscsiSettings InitiatorIpPoolSettings SubnetMask,IscsiSettings InitiatorIpPoolSettings Gateway,IscsiSettings InitiatorIpPoolSettings PrimaryDnsServer,IscsiSettings InitiatorIpPoolSettings SecondaryDnsServer,FcoeSettings IdentityCount,FcoeSettings StartingMacAddress,FcSettings Wwnn IdentityCount,FcSettings Wwnn StartingAddress,FcSettings Wwpn IdentityCount,FcSettings Wwpn StartingAddress
TestPool01,30,04:00:00:00:01:00,30,04:00:00:00:02:00,iqn01,192.168.1.100/24,,,,,30,04:00:00:00:03:00,30,20:00:04:00:00:00:04:00,30,20:01:04:00:00:00:04:00

#### Example
`python .\new_identity_pool.py --ip "mx7000-chassis.example.com" --user admin --password 'password' --in-file "C:\Temp\IdentityPools_New.csv"`
"""

import sys
import time
import argparse
from argparse import RawTextHelpFormatter
import traceback
from pprint import pprint
import codecs
import binascii
import json
import requests
import urllib3
from datetime import datetime
import os
from os import path
import csv

try:
    import urllib3
    import requests
except ModuleNotFoundError:
    print("This program requires urllib3 and requests. To install them on most systems run `pip install requests"
          "urllib3`")
    sys.exit(0)

session_auth_token = {}


def authenticate(ome_ip_address: str, ome_username: str, ome_password: str) -> dict:
    """
    Authenticates with OME and creates a session

    Args:
        ome_ip_address: IP address of the OME server
        ome_username:  Username for OME
        ome_password: OME password

    Returns: A dictionary of HTTP headers

    Raises:
        Exception: A generic exception in the event of a failure to connect
    """

    authenticated_headers = {'content-type': 'application/json'}
    session_url = 'https://%s/api/SessionService/Sessions' % ome_ip_address
    user_details = {'UserName': ome_username,
                    'Password': ome_password,
                    'SessionType': 'API'}
    try:
        session_info = requests.post(session_url, verify=False,
                                     data=json.dumps(user_details),
                                     headers=authenticated_headers)
    except requests.exceptions.ConnectionError:
        print("Failed to connect to OME. This typically indicates a network connectivity problem. Can you ping OME?")
        sys.exit(0)

    if session_info.status_code == 201:
        authenticated_headers['X-Auth-Token'] = session_info.headers['X-Auth-Token']
        return authenticated_headers

    print("There was a problem authenticating with OME. Are you sure you have the right username, password, "
          "and IP?")
    raise Exception("There was a problem authenticating with OME. Are you sure you have the right username, "
                    "password, and IP?")


def mac_to_base64_conversion(mac_address):
    try:
        if mac_address:
            allowed_mac_separators = [':', '-', '.']
            for sep in allowed_mac_separators:
                if sep in mac_address:
                    b64_mac_address = codecs.encode(codecs.decode(
                        mac_address.replace(sep, ''), 'hex'), 'base64')
                    address = codecs.decode(b64_mac_address, 'utf-8').rstrip()
                    return address
    except binascii.Error:
        print('Encoding of MAC address {0} to base64 failed'.format(mac_address))


def create_id_pool(
        base_uri,
        headers,
        Name,
        EthernetSettings_IdentityCount,
        EthernetSettings_StartingMacAddress,
        IscsiSettings_IdentityCount,
        IscsiSettings_StartingMacAddress,
        IscsiSettings_InitiatorConfig_IqnPrefix,
        IscsiSettings_InitiatorIpPoolSettings_IpRange,
        IscsiSettings_InitiatorIpPoolSettings_SubnetMask,
        IscsiSettings_InitiatorIpPoolSettings_Gateway,
        IscsiSettings_InitiatorIpPoolSettings_PrimaryDnsServer,
        IscsiSettings_InitiatorIpPoolSettings_SecondaryDnsServer,
        FcoeSettings_IdentityCount,
        FcoeSettings_StartingMacAddress,
        FcSettings_Wwnn_IdentityCount,
        FcSettings_Wwnn_StartingAddress,
        FcSettings_Wwpn_IdentityCount,
        FcSettings_Wwpn_StartingAddress,
):

    # TODO - need to add the null settings
    identity_pool_payload = {
        "Name": Name,
        "EthernetSettings": {
            "Mac": {
                "IdentityCount": EthernetSettings_IdentityCount,
                "StartingMacAddress": EthernetSettings_StartingMacAddress
            }
        },
        "IscsiSettings": {
            "Mac": {
                "IdentityCount": IscsiSettings_IdentityCount,
                "StartingMacAddress": IscsiSettings_StartingMacAddress
            },
            'InitiatorConfig':
                {'IqnPrefix': ''},
                'InitiatorIpPoolSettings': {
                'IpRange': IscsiSettings_InitiatorIpPoolSettings_IpRange,
                'SubnetMask': IscsiSettings_InitiatorIpPoolSettings_SubnetMask,
                'Gateway': IscsiSettings_InitiatorIpPoolSettings_Gateway,
                'PrimaryDnsServer': IscsiSettings_InitiatorIpPoolSettings_PrimaryDnsServer,
                'SecondaryDnsServer': IscsiSettings_InitiatorIpPoolSettings_SecondaryDnsServer
            },
        },
        "FcoeSettings": {
            "Mac": {
                "IdentityCount": FcoeSettings_IdentityCount,
                "StartingMacAddress": FcoeSettings_StartingMacAddress
            }
        },
        "FcSettings": {
            "Wwnn": {
                "IdentityCount": FcSettings_Wwnn_IdentityCount,
                "StartingAddress": FcSettings_Wwnn_StartingAddress
            },
            "Wwpn": {
                "IdentityCount": FcSettings_Wwpn_IdentityCount,
                "StartingAddress": FcSettings_Wwpn_StartingAddress
            }
        }
    }

    id_pool_id = None
    if IscsiSettings_IdentityCount != '' \
            and (IscsiSettings_InitiatorConfig_IqnPrefix == ''
                 or IscsiSettings_InitiatorIpPoolSettings_IpRange == ''):
        print('Skipping creation of ID pool %s' % Name)
        print('When the iSCSI Initiator configuration is enabled, the IQN prefix and IP Range must be non-empty')
        id_pool_id = 'skip'
        exit()

    network_url = base_uri \
                  + '/api/IdentityPoolService/IdentityPools'
    network_response = requests.post(network_url, headers=headers,
                                     verify=False, data=json.dumps(identity_pool_payload))

    if network_response.status_code == 201 \
            or network_response.status_code == 200:
        network_data = network_response.json()
        id_pool_id = network_data['Id']
    elif network_response.status_code == 400 \
            or network_response.status_code == 500:
        print('Failed ID pool creation... ')
        print('Network Payload:')
        print(identity_pool_payload)
        print('')
        print('json dump...')
        print(json.dumps(network_response.json(), indent=4, sort_keys=False))

    return id_pool_id


def put_indentity_pool(base_uri, headers, outfile):
    if path.exists(outfile):
        with open(outfile) as f:
            records = csv.DictReader(f)
            for row in records:
                try:

                    pool_id = create_id_pool(
                        base_uri,
                        headers,
                        row['Name'],
                        row['EthernetSettings IdentityCount'],
                        mac_to_base64_conversion(row['EthernetSettings StartingMacAddress']),
                        row['IscsiSettings IdentityCount'],
                        mac_to_base64_conversion(row['IscsiSettings StartingMacAddress']),
                        row['IscsiSettings InitiatorConfig IqnPrefix'],
                        row['IscsiSettings InitiatorIpPoolSettings IpRange'
                        ],
                        row['IscsiSettings InitiatorIpPoolSettings SubnetMask'
                        ],
                        row['IscsiSettings InitiatorIpPoolSettings Gateway'
                        ],
                        row['IscsiSettings InitiatorIpPoolSettings PrimaryDnsServer'
                        ],
                        row['IscsiSettings InitiatorIpPoolSettings SecondaryDnsServer'
                        ],
                        row['FcoeSettings IdentityCount'],
                        mac_to_base64_conversion(row['FcoeSettings StartingMacAddress']),
                        row['FcSettings Wwnn IdentityCount'],
                        mac_to_base64_conversion(row['FcSettings Wwnn StartingAddress']),
                        row['FcSettings Wwpn IdentityCount'],
                        mac_to_base64_conversion(row['FcSettings Wwpn StartingAddress']),
                    )

                    if pool_id == None:
                        print('ERROR: Unable to create Pool %s' \
                              % row['Name'])
                    elif pool_id == 'skip':
                        print('Pool creation for %s skipped...' \
                              % row['Name'])
                        print('')
                    else:
                        print('Created new ID pool %s, ID = %s' \
                              % (row['Name'], pool_id))
                except KeyError:
                    print('Unexpected error:', sys.exc_info())
                    print('KeyError: Missing or improperly named columns.')
        f.close()


# MAIN

if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    PARSER = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=RawTextHelpFormatter)
    PARSER.add_argument('--ip', '-i', required=True,
                        help='OME Appliance IP')
    PARSER.add_argument('--user', '-u', required=False, help='Username for OME Appliance', default='admin')
    PARSER.add_argument('--password', '-p', required=True, help='Password for OME Appliance')
    PARSER.add_argument('--in-file', '-f', required=False, help="""Path to CSV file
*Must include header row with at least the rows in the example below
*Use get_identitypool.py to export CSV file
Example:
Name,EthernetSettings IdentityCount,EthernetSettings StartingMacAddress,IscsiSettings IdentityCount,IscsiSettings StartingMacAddress,IscsiSettings InitiatorConfig IqnPrefix,IscsiSettings InitiatorIpPoolSettings IpRange,IscsiSettings InitiatorIpPoolSettings SubnetMask,IscsiSettings InitiatorIpPoolSettings Gateway,IscsiSettings InitiatorIpPoolSettings PrimaryDnsServer,IscsiSettings InitiatorIpPoolSettings SecondaryDnsServer,FcoeSettings IdentityCount,FcoeSettings StartingMacAddress,FcSettings Wwnn IdentityCount,FcSettings Wwnn StartingAddress,FcSettings Wwpn IdentityCount,FcSettings Wwpn StartingAddress
TestPool01,30,04:00:00:00:01:00,30,04:00:00:00:02:00,iqn01,192.168.1.100/24,,,,,30,04:00:00:00:03:00,30,20:00:04:00:00:00:04:00,30,20:01:04:00:00:00:04:00""")

    args = PARSER.parse_args()
    base_uri = 'https://%s' % (args.ip)
    auth_token = authenticate(args.ip, args.user, args.password)
    headers = {'content-type': 'application/json'}
    if auth_token.get('token') != None:
        headers['X-Auth-Token'] = auth_token['token']
    else:
        print("Unable to create a session with appliance %s" % (base_uri))
        quit()

    try:
        if args.in_file:
            put_indentity_pool(base_uri, headers, args.in_file)
    except Exception as error:
        pprint(error)



