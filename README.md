## Bro NSM (https://www.bro.org/) Tools

These are a set of custom tools that I have created which should help
with Bro setups for different situations

### identify_header.py
This script helps identify the headers from each bro log file (defined in code)
https://www.bro.org/sphinx/script-reference/log-files.html

Using the columns types found from the headers should help define normalization
usually defined by ETL standards
https://en.wikipedia.org/wiki/Extract,_transform,_load

TO-DO: Add generic logstash transformation

#### example usage
```
$ ls
2016-07-07-traffic-analysis-exercise.pcap   identify_header.py
README.md                   packet_filter.log
conn.log                    pe.log
dhcp.log                    ssl.log
dns.log                     weird.log
files.log                   x509.log
http.log

$ python identify_header.py
Bro_File: conn.log
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
Bro_File: dhcp.log
    ts
    uid
    id.orig_h
    id.orig_p
    id.resp_h
    id.resp_p
    mac
    assigned_ip
    lease_time
    trans_id
--------------------
Bro_File: dns.log
    ts
    uid
    id.orig_h
    id.orig_p
    id.resp_h
    id.resp_p
    proto
    trans_id
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
Bro_File: http.log
    ts
    uid
    id.orig_h
    id.orig_p
    id.resp_h
    id.resp_p
    trans_depth
    method
    host
    uri
    referrer
    user_agent
    request_body_len
    response_body_len
    status_code
    status_msg
    info_code
    info_msg
    filename
    tags
    username
    password
    proxied
    orig_fuids
    orig_mime_types
    resp_fuids
    resp_mime_types
--------------------
Bro_File: ssl.log
    ts
    uid
    id.orig_h
    id.orig_p
    id.resp_h
    id.resp_p
    version
    cipher
    curve
    server_name
    resumed
    last_alert
    next_protocol
    established
    cert_chain_fuids
    client_cert_chain_fuids
    subject
    issuer
    client_subject
    client_issuer
--------------------
Bro_File: files.log
    ts
    fuid
    tx_hosts
    rx_hosts
    conn_uids
    source
    depth
    analyzers
    mime_type
    filename
    duration
    local_orig
    is_orig
    seen_bytes
    total_bytes
    missing_bytes
    overflow_bytes
    timedout
    parent_fuid
    md5
    sha1
    sha256
    extracted
--------------------
Bro_File: pe.log
    ts
    id
    machine
    compile_ts
    os
    subsystem
    is_exe
    is_64bit
    uses_aslr
    uses_dep
    uses_code_integrity
    uses_seh
    has_import_table
    has_export_table
    has_cert_table
    has_debug_data
    section_names
--------------------
Bro_File: x509.log
    ts
    id
    certificate.version
    certificate.serial
    certificate.subject
    certificate.issuer
    certificate.not_valid_before
    certificate.not_valid_after
    certificate.key_alg
    certificate.sig_alg
    certificate.key_type
    certificate.key_length
    certificate.exponent
    certificate.curve
    san.dns
    san.uri
    san.email
    san.ip
    basic_constraints.ca
    basic_constraints.path_len
--------------------
```
