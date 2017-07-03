# nsbcfg
Netscaler batch configuration based on YAML (or JSON) configuration files

### Supportd configuration resources and bindings:

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
  * Responder
    * Resources
      * responderaction
      * responderpolicy
  * Rewrite
    * Resources
      * rewriteaction
      * rewritepolicy
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

Names follows the ones used in [Netscaler NITRO API](http://docs.citrix.com/en-us/netscaler/11/nitro-api.html)


### Command line parameters

    Usage: nsbcfg.py [OPTIONS]
    -d,     --debug                     debug
    -h,     --help                      display help
    -i,     --ipaddr                    IP address of Netscaler
    -a,     --action                    create, c, update, u, delete, d
    -u,     --username                  username
    -p,     --password                  password, optional
    -c,     --cfgfile                   default nsconfig[.yml|.json]
    -t,     --filetype                  type of the config file (yaml - default, json),








