# pylint: disable=C0301, C0103

import sys
import getpass
import getopt

import nitrofn


def main():
    ''' Main
    '''

    paction = ''               # create, update, delete
    config_file = 'nsconfig.json'

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
    -c,     --cfgfile                   default nsconfig.json
    '''

    try:
        opts, args = getopt.getopt(argv, "dhpu:i:c:a:", ["debug", "help", "password=", "username=", "ipaddr=", "cfgfile=", "action="])
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


    if paction not in ['create', 'update', 'delete', 'c', 'u', 'd']:
        print("Wrong action argument", paction)
        print(usage_str)
        sys.exit(2)

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


    nitrofn.load_json_cfgs2(config_file)

    if paction in ['create', 'c']:
        if nitrofn.check_if_items_exist():
            print("Option \"create\" is specified but some resources already exist !")
            sys.exit(2)


    if paction in ['create', 'update', 'c', 'u']:

        nitrofn.unbind_all_from_sslvs()
        nitrofn.unbind_all_from_csvs()
        nitrofn.unbind_all_from_lbvs()
        nitrofn.unbind_all_from_lbsvc()
        nitrofn.unbind_all_from_lbsg()
        nitrofn.unbind_general("lbgroup")

        nitrofn.process_json_cfgs()

        nitrofn.bind_general("lbgroup")
        nitrofn.bind_all_lbsg()
        nitrofn.bind_all_lbsvc()
        nitrofn.bind_all_lbvs()
        nitrofn.bind_all_csvs()
        nitrofn.bind_all_sslvs()
        nitrofn.process_one_item_from_cfgs('lbgroup', 'update')
        nitrofn.process_one_item_from_cfgs('sslservice', 'update')  # this item doesn't have Create, just Update method. Updates lbsvc item of type SSL.

    elif paction in ['delete', 'd']:

        nitrofn.unbind_all_from_sslvs()
        nitrofn.unbind_all_from_csvs()
        nitrofn.unbind_all_from_lbvs()
        nitrofn.unbind_all_from_lbsvc()
        nitrofn.unbind_all_from_lbsg()
        nitrofn.unbind_general("lbgroup")
        nitrofn.process_json_cfgs('delete')



    print("Finish")


if __name__ == "__main__":

    main()

