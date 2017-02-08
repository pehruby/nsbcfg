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


    if paction not in ['all', 'a']:
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

#    nitrofn.get_stat_one_resource('service', 'SVC_PH-TEST-S01_HTTP')
    nitrofn.get_stat_all_cfgfile_resource()
    nitrofn.print_stat_all_simple()

    print("Finish")


if __name__ == "__main__":

    main()
