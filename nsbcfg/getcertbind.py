# pylint: disable=C0301, C0103

import sys
import getpass
import getopt

import nitrofn


def main():
    ''' Main
    '''


    argv = sys.argv[1:]
    username = ''
    pswd = ''
    debug = False
    zeroip = False
    cert_name = ''
    cert_list = []
    cert_exp_dict = {}

    #usage_str = 'Usage: nscfg.py -i <IP address> -a <action> -u <username> [ -d -p <password> -c <cfgfile>]'
    usage_str = '''
    Prints vservers (with IP addresses) binded to SSL certificate(s)
    Usage: getcertbin.py [OPTIONS]
    -d,     --debug                     debug (opt.)
    -h,     --help                      display help (opt.)
    -z,     --zeroip                    print servers with IP 0.0.0.0 (opt.)
    -i,     --ipaddr                    IP address of Netscaler
    -u,     --username                  username
    -c,     --certname                  certificate name (opt.)
    '''

    try:
        opts, args = getopt.getopt(argv, "dhzp:u:i:c:", ["debug", "help", "zeroip" "password=", "username=", "ipaddr=", "certname="]) # : require argument 
    except getopt.GetoptError:
        print(usage_str)
        sys.exit(2)
    if not opts:                    # no arguments
        print(usage_str)
        sys.exit()  
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print(usage_str)
            sys.exit()
        elif opt in ("-d", "--debug"):
            debug = True
        elif opt in ("-z", "--zeroip"):
            zeroip = True
        elif opt in ("-u", "--username"):
            username = arg
        elif opt in ("-i", "--ipaddr"):
            ns_ip = arg
        elif opt in ("-p", "--password"):
            pswd = arg
        elif opt in ("-c", "--certname"):
            cert_name = arg




    if username == '':
        print("No username entered")
        sys.exit(2)

    if not nitrofn.is_ip_valid(ns_ip):
        print("Invalid IP address", ns_ip)
        sys.exit(2)


    if pswd == '':
        pswd = getpass.getpass('Password:')


    nitrofn.init_nitrofn(ns_ip, debug)

    if not nitrofn.get_cookie(username, pswd):
        print("Authentication failed for username", username)
        sys.exit(2)

    if not cert_name:
        certs = nitrofn.get_nitro_resources('sslcertkey')               # certificate name was not specified, process all certificates
    else:
        certs = nitrofn.get_nitro_resources('sslcertkey', cert_name)     # process only one certificat which was specified

    for item in certs:
        cert_list.append(item['certkey'])               # list of all certificates, which should be processed
        cert_exp_dict[item['certkey']] = item['daystoexpiration']       # days to expiration for all certificates

    print_format = '{:10}{:50}{:4}{:15}'
    for cert in cert_list:
        # print("---------------------------------------")
        print("")
        print("Certificate", cert, "(expire in", cert_exp_dict[cert], "days) is binded to:")
        cert_bind = nitrofn.get_nitro_resources('sslcertkey_sslvserver_binding', cert)       # get vservers binded to specific certificate
        isone = False
        for binding in cert_bind:
            if nitrofn.resource_exist("csvserver", binding['servername']):           # is it csvserver?
                vserver = nitrofn.get_nitro_resources('csvserver', binding['servername'])
                if (vserver[0]['ipv46'] == '0.0.0.0' and zeroip) or vserver[0]['ipv46'] != '0.0.0.0':
                    print(print_format.format('csvserver', nitrofn.trim_string(vserver[0]['name'], 50, 'right'), 'IP:', vserver[0]['ipv46']))
                    isone = True
            elif nitrofn.resource_exist("lbvserver", binding['servername']):
                vserver = nitrofn.get_nitro_resources('lbvserver', binding['servername'])     # is it lbvserver?
                if (vserver[0]['ipv46'] == '0.0.0.0' and zeroip) or vserver[0]['ipv46'] != '0.0.0.0':
                    print(print_format.format('lbvserver', nitrofn.trim_string(vserver[0]['name'], 50, 'right'), 'IP:', vserver[0]['ipv46']))
                    isone = True
        if not isone:
            print("... nothing")




    print("")
    print("End")


if __name__ == "__main__":

    main()
