#!/usr/bin/env python3
""" Script that parses Bro log files to determine what columns need parsing.
    Fields are converted to grok filters for logstash configuration
    This can help when normalizing data, such as Logstash to Elasticsearch
    or just log file validation between Bro versions. 
"""
__author__ = "Jacolon Walker"
__email__ = "jay@stellersjay.pub"
__version__ = "0.1"

# pylint: disable=C0103
import csv

# PATH of Bro logs and file extension type
# Change below to reflect your path
log_path = "/usr/local/bro/logs/current/"
file_type = '.log'

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
    # netcontrol
    'netcontrol',
    'netcontrol_drop',
    'netcontrol_shunt',
    'netcontrol_catch_release',
    'openflow',
    # detection
    'intel',
    'notice',
    'notice_alarm',
    'signatures',
    'traceroute',
    # network observations
    'known_certs',
    'known_devices',
    'known_hosts',
    'known_modbus'
    'known_services',
    'software',
    # misc
    'barnyard2',
    'dpd',
    'unified2',
    'weird',
    # Bro diag
    # Diagnostic files are a bit different and are not handle the same
    'capture_loss',
    'cluster',
    'communication',
    'loaded_scripts',
    'packet_filter',
    'prof',
    'reporter',
    'stats',
    ]

def identify_header(bro_file, filename):
    """ Print the headers of bro log files if they exist on disk
    https://www.bro.org/sphinx/script-reference/log-files.html
    """

    message = {}

    try:
        with open(filename) as f:
            reader = csv.reader(f, delimiter='\t')
            for header_line in range(1, 8):
                header_row = next(reader)
            if '#fields' in header_row:
                del header_row[0]

            fields = [column for column in header_row]

            print "Bro_File: %s" %(filename)
            for column in header_row:
                print "\t" + column
            print"-" * 20
            message[bro_file] = fields
    except:
        pass
    logstash_template(bro_file, message, filename)

def logstash_template(bro_file, message, bro_log):
    """
    Generate Grok filter template for logstash conf.
    Grok filter influenced by:
    http://www.appliednsm.com/parsing-bro-logs-with-logstash/
    """
    # Function logic can probably be improved
    begin_msg = "(?<"
    insert_msg = ">(.*?))\\t(?<"
    end_msg = ">(.*))"
    check = ">(.*?))\\t(?<>(.*))"
    period = "."
    final_msg = ""

    try:
        for field in message[bro_file]:
            if period in field:
                field = field.replace(period, "_")
            final_msg = final_msg + field + insert_msg
            buff = begin_msg + final_msg + end_msg

        if check in buff:
            buff = buff.replace(check, end_msg)
            print "###### %s" %(bro_file)
            print """
            file {
                type => "%s"
                path => "%s"
            }
            """ % (bro_file, bro_log)
            print """
              if [type] == "%s" {
                  grok {
                  match => [ "message", "%s" ]
                }
            }
            """ %(bro_file, buff)
            print "#" * 20
    except KeyError:
        pass

if __name__ == '__main__':
    for bro_file in bro_files:
        bro_log = log_path + bro_file + file_type
        bro_fields = identify_header(bro_file, bro_log)
