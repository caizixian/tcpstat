#!/usr/bin/python
# -*- coding: utf-8 -*-

# The MIT License (MIT)

# Copyright (c) 2014 Ivan Cai

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import absolute_import, division, print_function, with_statement
import os
import sys
import argparse
import logging
import datetime

__author__ = 'Ivan Cai'
__version__ = '0.0.1'

# The ConfigParser module has been renamed to configparser in Python 3.
try:
    import configparser
except ImportError:
    import ConfigParser as configparser

try:
    import pymongo
    import iptc
except ImportError:
    sys.exit("You don't have the required Python packages installed.")


def get_version():
    """Return a list which contains version number. Order is major, minor, micro."""
    return __version__.split()


def check_python():
    """Check whether user's Python version meets our requirements."""
    info = sys.version_info
    if info[0] == 2 and not info[1] >= 6:
        sys.exit("Python 2.6+ required'")
    elif info[0] == 3 and not info[1] >= 3:
        sys.exit("Python 3.3+ required")
    elif info[0] not in [2, 3]:
        sys.exit("Python version not supported")


def check_root():
    """Check whether user run our script using root privilege."""
    if not os.geteuid() == 0:
        sys.exit("You need to have root privileges to run this script.")


def init(group_list):
    """Create init iptables rules"""
    with open("/etc/tcpstat.sh", "w") as iptables_init_script:
        # Set shebang
        iptables_init_script.write("#!/bin/bash\n")
        # Create new chain for security reason
        iptables_init_script.write("/sbin/iptables -N ACCT\n")
        # Flush existing rules in our custom chain
        iptables_init_script.write("/sbin/iptables -F ACCT\n")
        # Attach new chain
        iptables_init_script.write("/sbin/iptables -A FORWARD -j ACCT\n")
        iptables_init_script.write("/sbin/iptables -A INPUT -j ACCT\n")
        iptables_init_script.write("/sbin/iptables -A OUTPUT -j ACCT\n")
        for group in group_list:
            for port in group["Port"]:
                iptables_init_script.write(
                    "/sbin/iptables -A ACCT -p tcp --dport " + str(port) + "\n")
                iptables_init_script.write(
                    "/sbin/iptables -A ACCT -p tcp --sport " + str(port) + "\n")
    os.system("chmod +x /etc/tcpstat.sh")


def find_config(args):
    """Find user's path of config file."""
    if args.config == None and os.path.exists("/etc/tcpstat/config"):
        return "/etc/tcpstat/config"
    elif os.path.exists(args.config):
        return args.config
    else:
        return None


def check_port_validity(port):
    """Check whether a port is valid."""
    if 0 <= int(port) <= 65535:
        return True
    else:
        return False


def read_config(path):
    """Check whether the path of config file is valid."""
    if path == None:
        sys.exit("Config file doesn't exist.")
    else:
        config = configparser.ConfigParser()
        config.read(path)

        logging.info("Config file loaded.")

        groupname_list = config.get("Groups", "Name").split(",")
        group_list = []
        for groups in groupname_list:
            # In config file
            # [Gp1]
            # Port:-1,2,65534-65537
            # Webhook:http://localhost/api/v1/tcpstats
            # To
            # {"Name": "Gp1", "Port": [2,65534,65535], "Webhook": "http://localhost/api/v1/tcpstats"}
            logging.debug("Loading Group " + groups)
            temp_dict = {"Name": groups}
            port_list = []
            logging.debug(config.get(groups, "Port"))
            logging.debug(config.get(groups, "Port").split(","))
            for port_str in config.get(groups, "Port").split(","):
                logging.debug("Catch a port str " + port_str)
                if '-' not in port_str:
                    if port_str.isdigit() and check_port_validity(port_str):
                        logging.debug("Appended a port " + port_str)
                        port_list.append(int(port_str))
                    else:
                        logging.error("You entered " + port_str +
                                      " which is not valid port number.")
                else:
                    logging.debug("Catch a port range " + port_str)
                    head = int(port_str.split('-')[0])
                    tail = int(port_str.split('-')[1])
                    map(port_list.append,
                        filter(check_port_validity, range(head, tail + 1)))
            temp_dict.update({"Port": port_list})
            temp_dict.update({"Webhook": config.get(groups, 'Webhook', '')})
            group_list.append(temp_dict)
        logging.debug("Final list of groups")
        logging.debug(group_list)
        return group_list


def update_db(group_list):
    table = iptc.Table(iptc.Table.FILTER)
    client = pymongo.MongoClient('mongodb://localhost:27017/')
    db = client['tcpstat']
    collection = db['accounting']
    today_str = str(datetime.date.today())

    logging.info("Connect to db")

    chain = iptc.Chain(table, 'ACCT')
    for group in group_list:
        for rule in chain.rules:
            for match in rule.matches:
                if not match.sport:
                    port_number = str(match.dport)
                    rule_type = "RX"
                else:
                    port_number = str(match.sport)
                    rule_type = "TX"
                entry = collection.find_one(
                    {"Name": group["Name"], "Time": today_str})
                if port_number in entry.keys():
                    # Counters in bytes
                    if rule_type == "TX":
                        # Fetch entries in db
                        entry = collection.find_one(
                            {"Name": group["Name"], "Time": today_str})
                        TX = rule.get_counters()[1] + entry[port_number]["TX"]
                        RX = entry[port_number]["RX"]
                        logging.debug(
                            "This record is TX " + str(TX) + " for " + port_number)
                        # Modify data in db
                        collection.update({"Name": group["Name"],
                                           "Time": today_str},
                                          {"$set":
                                           {port_number: {
                                               "TX": int(TX), "RX": int(RX)}}
                                           }
                                          )
                    else:
                        entry = collection.find_one(
                            {"Name": group["Name"], "Time": today_str})
                        # Fetch entries in db
                        RX = rule.get_counters()[1] + entry[port_number]["RX"]
                        TX = entry[port_number]["TX"]
                        logging.debug(
                            "This record is RX " + str(RX) + " for " + port_number)
                        collection.update({"Name": group["Name"],
                                           "Time": today_str},
                                          {"$set":
                                           {port_number: {
                                               "TX": int(TX), "RX": int(RX)}}
                                           }
                                          )

    chain.zero_counters()


def migrate_db(group_list):
    client = pymongo.MongoClient('mongodb://localhost:27017/')
    db = client['tcpstat']
    collection = db['accounting']
    today_str = str(datetime.date.today())
    for group in group_list:
        entry = collection.find_one({"Name": group["Name"], "Time": today_str})
        if entry:
            logging.info("Find an existing entry. Let's migrate it.")
            for port in group["Port"]:
                if str(port) not in entry.keys():
                    collection.update({"Name": group["Name"], "Time": today_str},
                                      {"$set": {str(port): {"TX": 0, "RX": 0}}})

        else:
            logging.info("Create a new entry with new schema.")
            temp_dict = {}
            temp_dict.update({"Name": group["Name"], "Time": today_str})
            for port in group["Port"]:
                temp_dict.update({str(port): {"TX": 0, "RX": 0}})
            collection.insert(temp_dict)


def main():
    # Check whether user run our script using root privilege.
    check_root()
    # Check whether user's Python version meets our requirements.
    check_python()

    # Setting up logging module.
    logging.basicConfig(filename='/var/log/tcpstat.log',
                        format='%(asctime)s %(levelname)s: %(message)s',
                        level=logging.DEBUG)

    logging.info(" ".join(("Started. Version:", __version__)))

    # Init command line argument.
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", type=str,
                        help="Path of config file. Default /etc/tcpstat/config")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-v", "--version", help="Show version.",
                       action="store_true")
    group.add_argument("-i", "--init", help="Init iptables rules.",
                       action="store_true")
    group.add_argument("-u", "--update", help="Update db with latest data.",
                       action="store_true")
    group.add_argument("-m", "--migrate", help="Migrate db with new config.",
                       action="store_true")

    # Parse command line argument.
    args = parser.parse_args()

    # Do when accept -v
    if args.version:
        print(" ".join(("Tcpstat\nVersion:", __version__)))

    # Do when accept -i
    # Init rules in /etc/tcpstat.sh which will be included in /etc/rc.local
    if args.init:
        init(read_config(find_config(args)))

    if args.update:
        update_db(read_config(find_config(args)))

    if args.migrate:
        migrate_db(read_config(find_config(args)))

    logging.info("Exit.")

if __name__ == "__main__":
    main()
