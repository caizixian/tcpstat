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


def check_python():
    info = sys.version_info
    if info[0] == 2 and not info[1] >= 6:
        sys.exit('Python 2.6+ required')
    elif info[0] == 3 and not info[1] >= 3:
        sys.exit('Python 3.3+ required')
    elif info[0] not in [2, 3]:
        sys.exit('Python version not supported')


def check_root():
    if not os.geteuid() == 0:
        sys.exit("You need to have root privileges to run this script.")


def init():
    pass


def find_config(args):
    if args.config == None and os.path.exists("/etc/tcpstat/config"):
        return "/etc/tcpstat/config"
    elif os.path.exists(args.config):
        return args.config
    else:
        return None


def check_config(path):
    if path == None:
        sys.exit("Config file doesn't exist.")
    else:
        pass
        # TODO


def main():
    check_python()
    check_root()

    parser = argparse.ArgumentParser()

    parser.add_argument("-c", "--config", type=str,
                        help="Path of config file. Default /etc/tcpstat/config")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-v", "--version", help="Show version.",
                       action="store_true")
    group.add_argument("-i", "--init", help="Init iptables rules.",
                       action="store_true")

    args = parser.parse_args()

    if args.version:
        print(__version__)

    if args.init:
        check_config(find_config(args))
        init()

if __name__ == "__main__":
    main()
