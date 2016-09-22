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
####################
Bro_File: /Users/jwalker/git/bro-toolbox/x509.log
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
###### x509

                  grok {
                  match => [ "message",
"(?<ts>(.*?))\t(?<id>(.*?))\t(?<certificate_version>(.*?))\t(?<certificate_serial>(.*?))\t(?<certificate_subject>(.*?))\t(?<certificate_issuer>(.*?))\t(?<certificate_not_valid_before>(.*?))\t(?<certificate_not_valid_after>(.*?))\t(?<certificate_key_alg>(.*?))\t(?<certificate_sig_alg>(.*?))\t(?<certificate_key_type>(.*?))\t(?<certificate_key_length>(.*?))\t(?<certificate_exponent>(.*?))\t(?<certificate_curve>(.*?))\t(?<san_dns>(.*?))\t(?<san_uri>(.*?))\t(?<san_email>(.*?))\t(?<san_ip>(.*?))\t(?<basic_constraints_ca>(.*?))\t(?<basic_constraints_path_len>(.*))"
]
                }

####################
Bro_File: /Users/jwalker/git/bro-toolbox/weird.log
    ts
    uid
    id.orig_h
    id.orig_p
    id.resp_h
    id.resp_p
    name
    addl
    notice
    peer
--------------------
###### weird

                  grok {
                  match => [ "message",
"(?<ts>(.*?))\t(?<uid>(.*?))\t(?<id_orig_h>(.*?))\t(?<id_orig_p>(.*?))\t(?<id_resp_h>(.*?))\t(?<id_resp_p>(.*?))\t(?<name>(.*?))\t(?<addl>(.*?))\t(?<notice>(.*?))\t(?<peer>(.*))"
]
                }

####################
```
