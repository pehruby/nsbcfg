# pylint: disable=C0301, C0103

import sys
import getpass
import getopt

import nitrofn


def main():
    ''' Main
    '''

    paction = ''               # create, update, delete
    config_file = ''
    conf_file_type = ''

    argv = sys.argv[1:]
    username = ''
    pswd = ''
    debug = False

    #usage_str = 'Usage: nscfg.py -i <IP address> -a <action> -u <username> [ -d -p <password> -c <cfgfile>]'
    usage_str = '''
    Usage: nsbcfg.py [OPTIONS]
    -d,     --debug                     debug
    -h,     --help                      display help
    -i,     --ipaddr                    IP address of Netscaler
    -a,     --action                    create, c, update, u, delete, d
    -u,     --username                  username
    -p,     --password                  password, optional
    -c,     --cfgfile                   default nsconfig[.yml|.json]
    -t,     --filetype                  type of the config file (yaml - default, json),
    '''

    try:
        opts, args = getopt.getopt(argv, "dhpu:i:a:c:t:", ["debug", "help", "password=", "username=", "ipaddr=", "action=", "cfgfile=", "filetype="])
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
        elif opt in ("-a", "--action"):
            paction = arg
        elif opt in ("-t", "--filetype"):
            conf_file_type = arg


    if paction not in ['create', 'update', 'delete', 'c', 'u', 'd']:
        print("Wrong action argument", paction)
        print(usage_str)
        sys.exit(2)

    if not conf_file_type:
        conf_file_type = 'YAML'

    conf_file_type.upper()
    if conf_file_type not in ('JSON', 'YAML'):
        print("Wrong filetype specified ", conf_file_type)
        print(usage_str)
        sys.exit(2)
    if not config_file:
        if conf_file_type == 'YAML':
            config_file = 'nsconfig.yml'
        elif conf_file_type == 'JSON':
            config_file = 'nsconfig.json'

    if username == '':
        print("No username entered")
        sys.exit(2)

    if not nitrofn.is_ip_valid(ns_ip):
        print("Invalid IP address", ns_ip)
        sys.exit(2)


    #print("Username=", username)
    #print("IP addr=", ns_ip)
    #print("CFG file=", config_file)

    if pswd == '':
        pswd = getpass.getpass('Password:')


    nitrofn.init_nitrofn(ns_ip, debug)
    if not nitrofn.get_cookie(username, pswd):
        print("Authentication failed for username", username)
        sys.exit(2)


    nitrofn.load_cfgs2(config_file, conf_file_type)

    if paction in ['create', 'c']:
        if nitrofn.check_if_items_exist():
            print("Option \"create\" is specified but some resources already exist !")
            sys.exit(2)


    if paction in ['create', 'update', 'c', 'u']:

        #nitrofn.unbind_all_from_sslvs()
        nitrofn.unbind_general("sslvserver")
        # nitrofn.unbind_all_from_csvs()
        nitrofn.unbind_general("csvserver")
        # nitrofn.unbind_all_from_lbvs()
        nitrofn.unbind_general("lbvserver")
        # nitrofn.unbind_all_from_lbsvc()
        nitrofn.unbind_general("service")
        #nitrofn.unbind_all_from_lbsg()
        nitrofn.unbind_general("servicegroup")
        nitrofn.unbind_general("lbgroup")

        nitrofn.process_json_cfgs()

        nitrofn.bind_general("lbgroup")
        #nitrofn.bind_all_lbsg()
        nitrofn.bind_general("servicegroup")
        #nitrofn.bind_all_lbsvc()
        nitrofn.bind_general("service")
        #nitrofn.bind_all_lbvs()
        nitrofn.bind_general("lbvserver")
        #nitrofn.bind_all_csvs()
        nitrofn.bind_general("csvserver")
        #nitrofn.bind_all_sslvs()
        nitrofn.bind_general("csvserver")
        nitrofn.process_one_item_from_cfgs('lbgroup', 'update')
        nitrofn.process_one_item_from_cfgs('sslservice', 'update')  # sslservice doesn't have Create, just Update method. Updates lbsvc item of type SSL.

    elif paction in ['delete', 'd']:

        #nitrofn.unbind_all_from_sslvs()
        nitrofn.unbind_general("sslvserver")
        #nitrofn.unbind_all_from_csvs()
        nitrofn.unbind_general("csvserver")
        #nitrofn.unbind_all_from_lbvs()
        nitrofn.unbind_general("lbvserver")
        #nitrofn.unbind_all_from_lbsvc()
        nitrofn.unbind_general("service")
        #nitrofn.unbind_all_from_lbsg()
        nitrofn.unbind_general("servicegroup")
        nitrofn.unbind_general("lbgroup")
        nitrofn.process_json_cfgs('delete')



    print("Finish")


if __name__ == "__main__":

    main()

