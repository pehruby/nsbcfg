# pylint: disable=C0301, C0103

import sys
import getpass
import getopt

import nitrofn


def main():
    ''' Main
    '''

    
    config_file = ''

    argv = sys.argv[1:]
    username = ''
    pswd = ''
    debug = False
    vip_ip_port = ''

    #usage_str = 'Usage: nscfg.py -i <IP address> -a <action> -u <username> [ -d -p <password> -c <cfgfile>]'
    usage_str = '''
    Usage: nsstat.py [OPTIONS]
    -d,     --debug                     debug
    -h,     --help                      display help
    -i,     --ipaddr                    IP address of Netscaler
    -u,     --username                  username
    -p,     --password                  password, optional
    -c,     --cfgfile                   default nsconfig.json
    -v,     --vip                       ip[:port] of the VIP
    '''

    try:
        opts, args = getopt.getopt(argv, "dhpu:i:c:v:", ["debug", "help", "password=", "username=", "ipaddr=", "cfgfile=", "vip="])
    except getopt.GetoptError:
        print(usage_str)
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print(usage_str)
            sys.exit()
        elif opt in ("-d", "--debug"):
            debug = True
        elif opt in ("-u", "--username"):
            username = arg
        elif opt in ("-i", "--ipaddr"):
            ns_ip = arg
        elif opt in ("-p", "--password"):
            pswd = arg
        elif opt in ("-c", "--cfgfile"):
            config_file = arg
        elif opt in ("-v", "--vip"):
            vip_ip_port = arg



    if username == '':
        print("No username entered")
        sys.exit(2)

    if not nitrofn.is_ip_valid(ns_ip):
        print("Invalid IP address", ns_ip)
        sys.exit(2)


    #print("Username=", username)
    #print("IP addr=", ns_ip)
    #print("CFG file=", config_file)
    if config_file == '' and vip_ip_port == '':
        print("Config file or VIP must be specified")
        sys.exit(2)
    if config_file and vip_ip_port:
        print("Config file and VIP cannot be specified both")
        sys.exit(2)
    if pswd == '':
        pswd = getpass.getpass('Password:')


    nitrofn.init_nitrofn(ns_ip, debug)

    if not nitrofn.get_cookie(username, pswd):
        print("Authentication failed for username", username)
        sys.exit(2)

    if config_file:
        nitrofn.load_json_cfgs2(config_file)
        nitrofn.get_and_print_stat_all_cfgfile_simple()

#    nitrofn.get_stat_one_resource('service', 'SVC_PH-TEST-S01_HTTP')
#    nitrofn.get_stat_all_cfgfile_resource()
#    nitrofn.print_stat_all_simple()

#    nitrofn.get_nitro_resources('csvserver', 'filter=ipv46:10.25.50.21')

#    csvslist = nitrofn.get_vs_list_by_ip_address_port('csvserver', '10.25.50.11')
#    lbvslist = nitrofn.get_vs_list_by_ip_address_port('lbvserver', '10.25.50.14')
#    lbvslist = nitrofn.get_lbvs_list_under_csvs('CSVS_PROD_PRTG-NET_SSL')
#    svclist = nitrofn.get_svc_list_under_lbvs('LBVS_PROD_PRTGDC1-NET_SSL')
#    sglist = nitrofn.get_sg_list_under_lbvs('LBVS_TEST_HUGO-ST-CPAS_SSL')

 #   tmpdict = nitrofn.load_resource_name_tree_under_ip_port('10.25.50.11')
 #   stat = nitrofn.get_stat_all_dict(tmpdict)
 #   nitrofn.print_stat_all_simple(stat)

    if vip_ip_port:
        if nitrofn.is_ip_port_valid(vip_ip_port):
            [vipip, vipport] = nitrofn.get_ip_and_port_from_string(vip_ip_port)
        else:
            print("VIP IP or port is not valid:", vip_ip_port)
            sys.exit(2)
        nitrofn.get_and_print_stat_under_ip_port_simple(vipip, vipport)
    print("Finish")


if __name__ == "__main__":

    main()
