# nsbcfg

Netscaler batch configuration based on YAML (or JSON) configuration files

## Supported configuration resources and bindings:

* Basic
  * Resources
    * server
    * service
    * servicegroup
  * Bindings
    * service -> lbmonitor
    * servicegroup -> lbmonitor
    * servicegroup -> servicegroupmember
* Content Switching
  * Resources
    * csaction
    * cspolicy
    * csvserver
  * Bindings
    * csvserver -> cspolicy
    * csvserver -> lbvserver
    * csvserver -> responderpolicy
    * csvserver -> rewritepolicy
    * csvserver -> transformpolicy
* Load Balancing
  * Resources
    * lbgroup
    * lbmonitor
    * lbvserver
  * Bindings
    * lbgroup -> lbvserver
    * lbvserver -> responderpolicy
    * lbvserver -> rewritepolicy
    * lbvserver -> service
    * lbvserver -> servicegroup
    * lbvserver -> transformpolicy
* Responder
  * Resources
    * responderaction
    * responderpolicy
* Rewrite
  * Resources
    * rewriteaction
    * rewritepolicy
* Transform
  * Resources
    * transformaction
    * transformpolicy
    * transformprofile
* SSL
  * Resources
    * sslprofile
    * sslservice
    * sslvserver
  * Bindings
    * sslvserver -> ecccurve
    * sslvserver -> sslcertkey
    * sslvserver -> sslcipher

Support for other resources and bindings can be easily added.

Resource and property names follow the ones used in [Netscaler NITRO API](http://docs.citrix.com/en-us/netscaler/11/nitro-api.html)

## Command line parameters

    Usage: nsbcfg.py [OPTIONS]
    -d,     --debug                     debug
    -h,     --help                      display help
    -i,     --ipaddr                    IP address of Netscaler
    -a,     --action                    create, c, update, u, delete, d
    -u,     --username                  username
    -p,     --password                  password, optional
    -c,     --cfgfile                   default nsconfig[.yml|.json]
    -t,     --filetype                  type of the config file (yaml - default, json),

## Usage rules

* All resource names must be unique, i.e resource name specified in one configuration must not be used in other configuration. Exception is server resource which contains property _shared_ set to _True_ or _'YES'_. Such resource name can be present in several configuration files
* All resource property names follow the naming scheme described in Netscaler NITRO API. The only exception is server property _shared_ which is not defined in NITRO and is solely used in this tool for purposes specified above
* If backupvserver is specified in lbvserver definition, the lbvserver definition of backup lbverver must be specified before lbvserver where the backupvserver is used.

```yaml
lbvserver:
- name: LBVS_TEST_BKP_HTTP
  servicetype: HTTP
- name: LBVS_TEST_HTTP
  servicetype: HTTP
  backupvserver: LBVS_TEST_BKP_HTTP
```

## Examples of use

### Create NS application environment

```text
PS C:nsbcfg> py -3 .\nsbcfg\nsbcfg.py -i 10.1.2.3 -u username -c .\config_examples\APP3\nsconfig.yml -a c
Password:
Successfuly created rewriteaction RWA_TEST_APP3_INS-X-FORW-FOR-IP
Successfuly created rewritepolicy RWP_TEST_APP3_INS-X-FORW-FOR-IP
Successfuly created csvserver CSVS_TEST_APP3_HTTP
Successfuly created lbvserver LBVS_TEST_APP3_HTTP
Successfuly created servicegroup SG_TEST_APP3_HTTP
Successfuly created server SVR_APP3-W1-CZP
Successfuly created server SVR_APP3-W2-CZP
Successfuly created server SVR_APP3-W3-CZP
Successfuly created server SVR_APP3-W4-CZP
Successfuly created lbmonitor MON_TEST_APP3
Successfuly binded SVR_APP3-W1-CZP to SG_TEST_APP3_HTTP
Successfuly binded SVR_APP3-W2-CZP to SG_TEST_APP3_HTTP
Successfuly binded SVR_APP3-W3-CZP to SG_TEST_APP3_HTTP
Successfuly binded SVR_APP3-W4-CZP to SG_TEST_APP3_HTTP
Successfuly binded MON_TEST_APP3 to SG_TEST_APP3_HTTP
Successfuly binded SG_TEST_APP3_HTTP to LBVS_TEST_APP3_HTTP
Successfuly binded LBVS_TEST_APP3_HTTP to CSVS_TEST_APP3_HTTP
Successfuly binded RWP_TEST_APP3_INS-X-FORW-FOR-IP to CSVS_TEST_APP3_HTTP
Finish
```

### Attempt to create already existing NS application environment

```text
PS C:nsbcfg> py -3 .\nsbcfg\nsbcfg.py -i 10.1.2.3 -u username -c .\config_examples\APP3\nsconfig.yml -a c
Password:
Option "create" is specified but some resources already exist !
```

### Update (delete and create again) NS application environment

```text
PS C:nsbcfg> py -3 .\nsbcfg\nsbcfg.py -i 10.1.2.3 -u username -c .\config_examples\APP3\nsconfig.yml -a u
Password:
Successfuly unbinded policyname RWP_TEST_APP3_INS-X-FORW-FOR-IP from CSVS_TEST_APP3_HTTP
Successfuly unbinded lbvserver LBVS_TEST_APP3_HTTP from CSVS_TEST_APP3_HTTP
Successfuly unbinded servicegroupname SG_TEST_APP3_HTTP from LBVS_TEST_APP3_HTTP
Successfuly unbinded monitor_name MON_TEST_APP3 from SG_TEST_APP3_HTTP
Successfuly unbinded servername SVR_APP3-W1-CZP from SG_TEST_APP3_HTTP
Successfuly unbinded servername SVR_APP3-W2-CZP from SG_TEST_APP3_HTTP
Successfuly unbinded servername SVR_APP3-W3-CZP from SG_TEST_APP3_HTTP
Successfuly unbinded servername SVR_APP3-W4-CZP from SG_TEST_APP3_HTTP
Successfuly deleted lbmonitor MON_TEST_APP3
Successfuly deleted server SVR_APP3-W1-CZP
Successfuly deleted server SVR_APP3-W2-CZP
Successfuly deleted server SVR_APP3-W3-CZP
Successfuly deleted server SVR_APP3-W4-CZP
Successfuly deleted servicegroup SG_TEST_APP3_HTTP
Successfuly deleted lbvserver LBVS_TEST_APP3_HTTP
Successfuly deleted csvserver CSVS_TEST_APP3_HTTP
Successfuly deleted rewritepolicy RWP_TEST_APP3_INS-X-FORW-FOR-IP
Successfuly deleted rewriteaction RWA_TEST_APP3_INS-X-FORW-FOR-IP
Successfuly created rewriteaction RWA_TEST_APP3_INS-X-FORW-FOR-IP
Successfuly created rewritepolicy RWP_TEST_APP3_INS-X-FORW-FOR-IP
Successfuly created csvserver CSVS_TEST_APP3_HTTP
Successfuly created lbvserver LBVS_TEST_APP3_HTTP
Successfuly created servicegroup SG_TEST_APP3_HTTP
Successfuly created server SVR_APP3-W1-CZP
Successfuly created server SVR_APP3-W2-CZP
Successfuly created server SVR_APP3-W3-CZP
Successfuly created server SVR_APP3-W4-CZP
Successfuly created lbmonitor MON_TEST_APP3
Successfuly binded SVR_APP3-W1-CZP to SG_TEST_APP3_HTTP
Successfuly binded SVR_APP3-W2-CZP to SG_TEST_APP3_HTTP
Successfuly binded SVR_APP3-W3-CZP to SG_TEST_APP3_HTTP
Successfuly binded SVR_APP3-W4-CZP to SG_TEST_APP3_HTTP
Successfuly binded MON_TEST_APP3 to SG_TEST_APP3_HTTP
Successfuly binded SG_TEST_APP3_HTTP to LBVS_TEST_APP3_HTTP
Successfuly binded LBVS_TEST_APP3_HTTP to CSVS_TEST_APP3_HTTP
Successfuly binded RWP_TEST_APP3_INS-X-FORW-FOR-IP to CSVS_TEST_APP3_HTTP
Finish
```

### Delete NS application environment

```text
PS C:nsbcfg> py -3 .\nsbcfg\nsbcfg.py -i 10.1.2.3 -u username -c .\config_examples\APP3\nsconfig.yml -a d
Password:
Successfuly unbinded policyname RWP_TEST_APP3_INS-X-FORW-FOR-IP from CSVS_TEST_APP3_HTTP
Successfuly unbinded lbvserver LBVS_TEST_APP3_HTTP from CSVS_TEST_APP3_HTTP
Successfuly unbinded servicegroupname SG_TEST_APP3_HTTP from LBVS_TEST_APP3_HTTP
Successfuly unbinded monitor_name MON_TEST_APP3 from SG_TEST_APP3_HTTP
Successfuly unbinded servername SVR_APP3-W1-CZP from SG_TEST_APP3_HTTP
Successfuly unbinded servername SVR_APP3-W2-CZP from SG_TEST_APP3_HTTP
Successfuly unbinded servername SVR_APP3-W3-CZP from SG_TEST_APP3_HTTP
Successfuly unbinded servername SVR_APP3-W4-CZP from SG_TEST_APP3_HTTP
Successfuly deleted lbmonitor MON_TEST_APP3
Successfuly deleted server SVR_APP3-W1-CZP
Successfuly deleted server SVR_APP3-W2-CZP
Successfuly deleted server SVR_APP3-W3-CZP
Successfuly deleted server SVR_APP3-W4-CZP
Successfuly deleted servicegroup SG_TEST_APP3_HTTP
Successfuly deleted lbvserver LBVS_TEST_APP3_HTTP
Successfuly deleted csvserver CSVS_TEST_APP3_HTTP
Successfuly deleted rewritepolicy RWP_TEST_APP3_INS-X-FORW-FOR-IP
Successfuly deleted rewriteaction RWA_TEST_APP3_INS-X-FORW-FOR-IP
Finish
```
