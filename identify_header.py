#!/usr/bin/env python3
""" Script that parses Bro log files to determine what columns need parsing
    This can help when normalizing data, such as Logstash to Elasticsearch
    or just log file validation between Bro versions
"""
__author__ = "Jacolon Walker"
__email__ = "jay@stellersjay.pub"
__version__ = "0.1"

# pylint: disable=C0103
import csv

bro_files = [
    # network protocols
    'conn',
    'dhcp',
    'dnp3',
    'dns',
    'ftp',
    'http',
    'irc',
    'kerberos',
    'modbus',
    'modbus_register_change',
    'mysql',
    'radius',
    'rdp',
    'sip',
    'smtp',
    'snmp',
    'socks',
    'ssh',
    'ssl',
    'syslog',
    'tunnel',
    # files
    'files',
    'pe',
    'x509',
    # network observations
    'app_stats',
    'known_certs',
    'known_devices',
    'known_hosts',
    'known_modbus'
    'known_services',
    'software',
    ]

def identify_header(filename):
    """ Print the headers of bro log files if they exist on disk
    https://www.bro.org/sphinx/script-reference/log-files.html
    """

    try:
        with open(filename) as f:
            reader = csv.reader(f, delimiter='\t')
            for header_line in range(1, 8):
                header_row = next(reader)
            if '#fields' in header_row:
                del header_row[0]

            print("Bro_File: %s" %(filename))
            for column in header_row:
                print("\t" + column)
            print("-" * 20)
    except:
        pass

if __name__ == '__main__':
    file_type = '.log'
    for bro_file in bro_files:
        bro_file = bro_file + file_type
        identify_header(bro_file)
