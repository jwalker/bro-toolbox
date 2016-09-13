## Bro NSM (https://www.bro.org/) Tools

These are a set of custom tools that I have created which should help
with Bro setups for different situations

#### logs2grok.py
This script helps identifies the headers from each bro log file

https://www.bro.org/sphinx/script-reference/log-files.html

then generates usable grok filters for logstash

Using the columns types found from the headers should help define normalization
usually defined by ETL standards
https://en.wikipedia.org/wiki/Extract,_transform,_load

#### example usage (sample snippet)
```
$ python logs2grok.py
Bro_File: /usr/local/bro/logs/current/conn.log
    ts
    uid
    id.orig_h
    id.orig_p
    id.resp_h
    id.resp_p
    proto
    service
    duration
    orig_bytes
    resp_bytes
    conn_state
    local_orig
    local_resp
    missed_bytes
    history
    orig_pkts
    orig_ip_bytes
    resp_pkts
    resp_ip_bytes
    tunnel_parents
--------------------
###### conn

            file {
                type => "conn"
                path => "/usr/local/bro/logs/current/conn.log"
            }


              if [type] == "conn" {
                  grok {
                  match => [ "message",
"(?<ts>(.*?))\t(?<uid>(.*?))\t(?<id_orig_h>(.*?))\t(?<id_orig_p>(.*?))\t(?<id_resp_h>(.*?))\t(?<id_resp_p>(.*?))\t(?<proto>(.*?))\t(?<service>(.*?))\t(?<duration>(.*?))\t(?<orig_bytes>(.*?))\t(?<resp_bytes>(.*?))\t(?<conn_state>(.*?))\t(?<local_orig>(.*?))\t(?<local_resp>(.*?))\t(?<missed_bytes>(.*?))\t(?<history>(.*?))\t(?<orig_pkts>(.*?))\t(?<orig_ip_bytes>(.*?))\t(?<resp_pkts>(.*?))\t(?<resp_ip_bytes>(.*?))\t(?<tunnel_parents>(.*))"
]
                }
            }

####################
Bro_File: /usr/local/bro/logs/current/dns.log
    ts
    uid
    id.orig_h
    id.orig_p
    id.resp_h
    id.resp_p
    proto
    trans_id
    rtt
    query
    qclass
    qclass_name
    qtype
    qtype_name
    rcode
    rcode_name
    AA
    TC
    RD
    RA
    Z
    answers
    TTLs
    rejected
--------------------
###### dns

            file {
                type => "dns"
                path => "/usr/local/bro/logs/current/dns.log"
            }


              if [type] == "dns" {
                  grok {
                  match => [ "message",
"(?<ts>(.*?))\t(?<uid>(.*?))\t(?<id_orig_h>(.*?))\t(?<id_orig_p>(.*?))\t(?<id_resp_h>(.*?))\t(?<id_resp_p>(.*?))\t(?<proto>(.*?))\t(?<trans_id>(.*?))\t(?<rtt>(.*?))\t(?<query>(.*?))\t(?<qclass>(.*?))\t(?<qclass_name>(.*?))\t(?<qtype>(.*?))\t(?<qtype_name>(.*?))\t(?<rcode>(.*?))\t(?<rcode_name>(.*?))\t(?<AA>(.*?))\t(?<TC>(.*?))\t(?<RD>(.*?))\t(?<RA>(.*?))\t(?<Z>(.*?))\t(?<answers>(.*?))\t(?<TTLs>(.*?))\t(?<rejected>(.*))"
]
                }
            }
```
