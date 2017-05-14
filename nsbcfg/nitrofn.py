# pylint: disable=C0301, C0103

import requests
import json
import os
import sys

requests.packages.urllib3.disable_warnings()
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

nitro_config_url = ""
nitro_stat_url = ""
ns_ip = ""
nitro_config_path = '/nitro/v1/config/'
nitro_stat_path = '/nitro/v1/stat/'
cookie = {}
json_header = {'Content-type': 'application/json'}
# config_file = 'nsconfig.json'
cfg_all_list = []        # list
cfg_all_set = {}       # set
cfg_bind = {}
# pswd = ''

debug = False

# the following variables are arrays/lists containing json configuration from several files, each array entry contains configuration
# from one configuration file
# this will replace cfg_all_list, cfg_all_set, cfg_bind
cfg_big_all_list = []       # list of lists, based on files contained in "items" configuration file section
cfg_big_all_set = []        # list of sets, based on files contained in "items" configuration file section
cfg_big_bind = []           # list of sets, based on files contained in "bindings" configuration file section


stat_all_cfgfiles_dict = {}          # statistics of items configured in configuration file

resourcetype_name_dict = {'server':'name', \
                            'servicegroup':'servicegroupname', \
                            'lbmonitor':'monitorname', \
                            'lbvserver':"name", \
                            "csvserver":"name", \
                            "cspolicy":"policyname", \
                            "csaction":"name",\
                            "rewritepolicy":"name", \
                            "rewriteaction":"name", \
                            "responderpolicy":"name", \
                            "responderaction":"name", \
                            "sslprofile":"name",\
                            "service":"name",\
                            "lbgroup":"name",\
                            "sslservice":"servicename"}    # name of item which contains name of specific type
resourcetype_list = ["rewriteaction", "rewritepolicy", "responderaction", "responderpolicy", "sslprofile", "csvserver", \
                    "lbvserver", "servicegroup", "server", "lbmonitor", "csaction", "cspolicy", "service", "lbgroup", "sslservice"]  #order in which resource types are created, i.e rewriteaction must be created before rewritepolicy

dont_process_at_beg_list = ["lbgroup", "sslservice"]      # don't create this resources at the beginning
update_body_del_dict = {"servicegroup":["servicetype", "td"], "lbvserver":["servicetype", "port", "td"], \
                        "csvserver":["port", "td", "servicetype", "range"]}                          # ktere polozky je treba odstranit pri update daneho typu
sg_parametr_name_dict = {"servicegroup_lbmonitor_binding":"monitor_name", "servicegroup_servicegroupmember_binding":"servername"}
svc_parametr_name_dict = {"service_lbmonitor_binding":"monitor_name"}
vs_parametr_name_dict = {"lbvserver_servicegroup_binding":"servicegroupname", \
                        "lbvserver_responderpolicy_binding":"policyname"}
cs_parametr_name_dict = {"csvserver_lbvserver_binding":"lbvserver", "csvserver_cspolicy_binding":"policyname", \
                         "csvserver_rewritepolicy_binding":"policyname"}           # name of binded item in CSVS
sslvs_parametr_name_dict = {"sslvserver_ecccurve_binding":"ecccurvename", "sslvserver_sslcertkey_binding":"certkeyname"}
general_parametr_name_dict = {"servicegroup_lbmonitor_binding":"monitor_name",\
                                "servicegroup_servicegroupmember_binding":"servername",\
                                "service_lbmonitor_binding":"monitor_name",\
                                "lbvserver_servicegroup_binding":"servicegroupname",\
                                "csvserver_lbvserver_binding":"lbvserver",\
                                "csvserver_cspolicy_binding":"policyname",\
                                "csvserver_rewritepolicy_binding":"policyname",\
                                "sslvserver_ecccurve_binding":"ecccurvename",\
                                "sslvserver_sslcertkey_binding":"certkeyname",\
                                "lbgroup_lbvserver_binding":"vservername"}
stat_name_list = ["service", "servicegroup", "lbvserver", "csvserver"]      # name of items which are we going to get statistics for



def get_nitro_resources(restype, resname='', parameters=''):
    ''' Get resources od specified type, parametrs could by filter, view, ... see NITRO docs
    '''
    if parameters:
        parameters = '?'+ parameters

    if resname:
        wholeurl = nitro_config_url + restype + '/' + resname + parameters      # name is specifies
    else:
        wholeurl = nitro_config_url + restype + parameters
    try:
        response = requests.get(wholeurl, headers=json_header, verify=False, cookies=cookie)
    except (requests.ConnectionError, requests.ConnectTimeout):
        print("Connection error")
        exit(1)
    if response.status_code != 200:
        print("Error during get_nitro_resources", "http status kod:", response.status_code)
        print("Response text", response.text)
        return False
    # else:
        # print("Successfuly binded", item['vservername'], "to", item['ecccurvename'])
    body_json = json.loads(response.text)
    if restype in body_json:
        retjson = body_json[restype]
        return retjson
    return []


def get_vs_list_by_ip_address_port(vstype, vsip, port=0):
    ''' Get list of vservers with specified IP address and port configured
        vstype is csvserver or lbvserver
    '''

    vs_list = []
    param = 'filter=ipv46:'+ vsip
    if port:
        param = param + ",port:" + port

    resp = get_nitro_resources(vstype, '', param)
    for vs in resp:
        vs_list.append(vs['name'])
    return vs_list

def get_lbvs_list_under_csvs(csvs):
    ''' Get list of lbvservers configured under specific csvserver
    '''

    lbvslist = []
    resp = get_nitro_resources('csvserver_binding', csvs)

    for csvsbind in resp:           # go through bindings of all csvserver
        if 'csvserver_lbvserver_binding' in csvsbind:     # does this key exist?
            cont_bind = csvsbind['csvserver_lbvserver_binding']
            for onelbvsbin in cont_bind:
                lbvs = onelbvsbin['lbvserver']
                lbvslist.append(lbvs)
        if 'csvserver_cspolicy_binding' in csvsbind:     # does this key exist?
            cont_bind = csvsbind['csvserver_cspolicy_binding']
            for onecspolicybind in cont_bind:           # go through all cspolicy bindings
                lbvs = onecspolicybind['targetlbvserver']  ## !!! POZOR, muze se stat, ze targetlbvserver neni definovan, ale s policy je svazana action, kde je specifikovan lbvserver !!!!
                if lbvs == '':
                    print("Target LB Vserver not specified in CSP, action must be checked !!")
                else:
                    lbvslist.append(lbvs)

    return lbvslist

def get_svc_list_under_lbvs(lbvs):
    ''' Get list of services configured under specific lbvserver
    '''

    svclist = []
    resp = get_nitro_resources('lbvserver_binding', lbvs)

    for lbvsbind in resp:           # go through bindings of all lbvserver () probably just one lbvs ...)
        if 'lbvserver_service_binding' in lbvsbind:     # does this key exist?
            cont_bind = lbvsbind['lbvserver_service_binding']
            for onelbvsbin in cont_bind:
                svc = onelbvsbin['servicename']
                svclist.append(svc)
    return svclist

def get_sg_list_under_lbvs(lbvs):
    ''' Get list of service groups configured under specific lbvserver
    '''

    sglist = []
    resp = get_nitro_resources('lbvserver_binding', lbvs)

    for lbvsbind in resp:           # go through bindings of all lbvserver () probably just one lbvs ...)
        if 'lbvserver_servicegroup_binding' in lbvsbind:     # does this key exist?
            cont_bind = lbvsbind['lbvserver_servicegroup_binding']
            for onelbvsbin in cont_bind:
                sg = onelbvsbin['servicegroupname']
                sglist.append(sg)
    return sglist

def load_resource_name_tree_under_ip_port(ip, port=0, tecky=False):
    ''' Loads names of resources "under" specific IP addres (and port). If tecky, points are printed to stdout
    '''
    resourcesdict = {'csvserver':[], 'lbvserver':[], 'service':[], 'servicegroup':[]}

    if tecky:
        print('.', end='', flush=True)
    csvslist = get_vs_list_by_ip_address_port('csvserver', ip, port)
    for csvservername in csvslist:              # go thoug all csvserver names contained in csvslist
        #if not 'csvserver' in resourcesdict:     # csvserver in dictionaty ?
         #   resourcesdict['csvserver'] = []     # no, create empty list
        resourcesdict['csvserver'].append(csvservername)    # add csvs name to list
    if tecky:
        print('.', end='', flush=True)
    lbvslist = get_vs_list_by_ip_address_port('lbvserver', ip, port)
    for lbvservername in lbvslist:              # go thoug all lbvserver names contained in lbvslist
        #if not 'lbvserver' in resourcesdict:     # lbvserver in dictionaty ?
        #    resourcesdict['lbvserver'] = []     # no, create empty list
        resourcesdict['lbvserver'].append(lbvservername)    # add lbvs name to list

    for csvsname in resourcesdict['csvserver']:
        if tecky:
            print('.', end='', flush=True)
        lbvslist = get_lbvs_list_under_csvs(csvsname)
        for lbvservername in lbvslist:
            resourcesdict['lbvserver'].append(lbvservername)

    for lbvsname in resourcesdict['lbvserver']:
        if tecky:
            print('.', end='', flush=True)
        svclist = get_svc_list_under_lbvs(lbvsname)
        for svcname in svclist:
            resourcesdict['service'].append(svcname)
        if tecky:
            print('.', end='', flush=True)
        sglist = get_sg_list_under_lbvs(lbvsname)
        for sgname in sglist:
            resourcesdict['servicegroup'].append(sgname)

    if tecky:
        print('.', end='', flush=True)
    return resourcesdict




def get_stat_one_resource(restype, name, args=''):
    ''' Get statistics for one resource
    '''
    if args:
        args = '?args=' + args
    try:
        response = requests.get(nitro_stat_url + restype + '/' + name + args, headers=json_header, verify=False, cookies=cookie)
    except (requests.ConnectionError, requests.ConnectTimeout):
        print("Unable to connect to the server")
        exit(1)
    if response.status_code != 200:
        print("Unexpected http response :", restype, name)
        return None
    body_json = json.loads(response.text)
    retjson = body_json[restype]
    return retjson

def get_stat_all_cfgfile_resource():
    ''' Get statistics for resources configured in configuration file
    '''

    for onecfg in cfg_big_all_set:      # go through all items cfg files
        for item_type in stat_name_list:     # go through all item types
            if item_type in onecfg.keys():   # does item type exist in cfg?
                body = onecfg[item_type]     # body contains configuration of specific type

#                item_name = body[restype_name]
                for item in body:
                    # print('.', end='')
                    res_type_name = resourcetype_name_dict[item_type]   # what is the name of "name" field in this type ?
                    name = str(item[res_type_name])          #  resource name
                    if resource_exist(item_type, name):
                        if not stat_all_cfgfiles_dict.get(item_type):    # is this item type in dictionary ?
                            stat_all_cfgfiles_dict[item_type] = []       # no, create empty list for item type
                        if item_type == 'servicegroup':         # proces servicegroup_servicegroupmember_binding
                            more_stat = get_stat_cfgfile_servicegroupmember(name)   # get statistics for members of specific servicegroup
                            for one_sgmember in more_stat:
                                if not stat_all_cfgfiles_dict.get('servicegroupmember'):    # is servicegroupmember type in dictionary ?
                                    stat_all_cfgfiles_dict['servicegroupmember'] = []       # no, create empty list for servicegroupmember
                                stat_all_cfgfiles_dict['servicegroupmember'].append(one_sgmember[0])
                        one_stat = get_stat_one_resource(item_type, name)   # stats for one item of specific item_type
                        if one_stat:
                            stat_all_cfgfiles_dict[item_type].append(one_stat[0])   # add item statistics to list of apropriate item type, statistics dict is first (and only one) item in list, that's why [0]
                    else:
                        print("Resource", name, "doesn't exist")
    # print("")


def get_stat_all_dict(resdict):
    ''' Get statistics for resources specified in resdict dictionary
    '''
    stat_all_dict = {}
    for item_type in resdict:           # go through all item types }lbvserver, csvserver, servicegroup,...)
        namelist = resdict[item_type]   # go through all names of specific type
        for name in namelist:
            if item_type == 'servicegroup':
                resp = get_nitro_resources('servicegroup_binding', name)    # get config of specific servicegroup
                respitem = resp[0]
                if 'servicegroup_servicegroupmember_binding' in respitem:   # is sg member binding configured ?
                    for sg_member in respitem['servicegroup_servicegroupmember_binding']:   # go through of member servers
                        one_stat = get_stat_one_resource('servicegroupmember', sg_member['servicegroupname'], 'servername:'+sg_member['servername']+',port:'+str(sg_member['port']))
                        if one_stat:            # statistics for one member server
                            if 'servicegroupmember' not in stat_all_dict:
                                stat_all_dict['servicegroupmember'] = []
                            stat_all_dict['servicegroupmember'].append(one_stat[0])
            one_stat = get_stat_one_resource(item_type, name)   # statistics for specific resource
            if one_stat:
                if not item_type in stat_all_dict:
                    stat_all_dict[item_type] = []
                stat_all_dict[item_type].append(one_stat[0])    # append to all statistics dictionary

    return stat_all_dict






def get_stat_cfgfile_servicegroupmember(servicegroup):
    ''' Get statistics for members of specifig servicegroup defined in configuration file
    '''
    response = []
    for cfg_bind in cfg_big_bind:                   # proces cfgs from all binding cfg files
        if 'servicegroup_binding' in cfg_bind:      # is servicegroup_binding presented ?
            for sgitem in cfg_bind['servicegroup_binding']:   # process all bindings defined in cfg
                if sgitem['servicegroupname'] == servicegroup:
                    if 'servicegroup_servicegroupmember_binding' in sgitem:
                        for item in sgitem['servicegroup_servicegroupmember_binding']:     # go through all bindings in this servicegroup
                            one_stat = get_stat_one_resource('servicegroupmember', servicegroup, 'servername:'+item['servername']+',port:'+str(item['port']))
                            if one_stat:
                                response.append(one_stat)

    return response

def get_and_print_stat_all_cfgfile_simple():
    ''' Get and print statistics for resources configured in cfgfile
    '''
    get_stat_all_cfgfile_resource()
    print_stat_all_simple(stat_all_cfgfiles_dict)       # dirty, redesign ... !!!

def get_and_print_stat_under_ip_port_simple(ip, port=0):
    ''' Get and print statistics for resources configured under specific IP and port
    '''
    tmpdict = load_resource_name_tree_under_ip_port(ip, port, True)
    stat = get_stat_all_dict(tmpdict)
    print_stat_all_simple(stat)


def print_stat_all_simple(stat_dict):
    ''' Prints statistics collected in stat_dict
    '''

    print("")
    if 'csvserver' in stat_dict.keys():
        print_stat_csvserver_list(stat_dict['csvserver'])
        print("\n")
    if 'lbvserver' in stat_dict.keys():
        print_stat_lbvserver_list(stat_dict['lbvserver'])
        print("\n")
    if 'service' in stat_dict.keys():
        print_stat_services_list(stat_dict['service'])
        print("\n")
    if 'servicegroup' in stat_dict.keys():
        print_stat_sg_list(stat_dict['servicegroup'])
        print("\n")
    if 'servicegroupmember' in stat_dict.keys():
        print_stat_sgmember_list(stat_dict['servicegroupmember'])
        print("\n")

def print_stat_csvserver_list(vserver_list):
    ''' Prints statistics collected in list of csvservers
    '''

    outformat = '{:50}{:20}{:>6} {:10}{:10}{:>12}'
    print('{:-<109}'.format(''))
    print("CS VSERVERS")
    print(outformat.format('Name', 'IP', 'Port', 'Type', 'State', 'Hits'))
    print('{:-<109}'.format(''))
    for one_server in vserver_list:
        print(outformat.format(one_server['name'], one_server['primaryipaddress'], one_server['primaryport'], one_server['type'], one_server['state'], one_server['tothits']))
    print('{:-<109}'.format(''))

def print_stat_lbvserver_list(vserver_list):
    ''' Prints statistics collected in list of lbvservers
    '''

    outformat = '{:50}{:20}{:>6} {:10}{:10}{:>12}'
    print('{:-<109}'.format(''))
    print("LB VSERVERS")
    print(outformat.format('Name', 'IP', 'Port', 'Type', 'State', 'Hits'))
    print('{:-<109}'.format(''))
    for one_server in vserver_list:
        print(outformat.format(one_server['name'], one_server['primaryipaddress'], one_server['primaryport'], one_server['type'], one_server['state'], one_server['tothits']))
    print('{:-<109}'.format(''))

def print_stat_services_list(services_list):
    ''' Prints statistics collected in list of services
    '''

    outformat = '{:50}{:16}{:>6} {:10}{:10}{:>12}{:>12}{:>10}'
    print('{:-<132}'.format(''))
    print("SERVICES")
    print(outformat.format('Name', 'IP', 'Port', 'Type', 'State', 'Request B', 'Response B', 'Act conn'))
    print('{:-<132}'.format(''))
    for service in services_list:
        print(outformat.format(service['name'], service['primaryipaddress'], service['primaryport'], service['servicetype'], service['state'], trim_string(service['totalrequestbytes'], 10), trim_string(service['totalresponsebytes'], 10), service['curclntconnections']))
    print('{:-<132}'.format(''))

def print_stat_sg_list(sg_list):
    ''' Prints statistics collected in list of service groups
    '''

    outformat = '{:50}{:20}{:10}'
    print('{:-<102}'.format(''))
    print("SERVICE GROUPS")
    print(outformat.format('Name', 'Type', 'State'))
    print('{:-<102}'.format(''))
    for one_sg in sg_list:
        print(outformat.format(one_sg['servicegroupname'], one_sg['servicetype'], one_sg['state']))
    print('{:-<102}'.format(''))

def print_stat_sgmember_list(sg_members_list):
    ''' Prints statistics collected in list of service group members
    '''

    outformat = '{:70}{:16}{:>6} {:10}{:10}{:>12}{:>12}{:>10}'
    print('{:-<147}'.format(''))
    print("SERVICES")
    print(outformat.format('Name', 'IP', 'Port', 'Type', 'State', 'Request B', 'Response B', 'Act conn'))
    print('{:-<147}'.format(''))
    for sgm in sg_members_list:
        print(outformat.format(sgm['servicegroupname'].replace('?', '|'), sgm['primaryipaddress'], sgm['primaryport'], sgm['servicetype'], sgm['state'], trim_string(sgm['totalrequestbytes'], 10), trim_string(sgm['totalresponsebytes'], 10), sgm['curclntconnections']))
    print('{:-<147}'.format(''))


def trim_string(string, length, where='left'):
    ''' Trim string to specific length
    '''
    tmplen = length-1
    if len(string) > tmplen:
        if where == 'left':
            string = '>' + string[-tmplen:]
        if where == 'right':
            string = string[:tmplen] + '>'
    return string



def init_nitrofn(ns_ip, deb):
    ''' Initialize some variables
    '''

    global nitro_config_url
    global nitro_stat_url
    global debug

    nitro_config_url = "https://"+ns_ip+nitro_config_path
    nitro_stat_url = "https://"+ns_ip+nitro_stat_path
    debug = deb

def resource_exist(restype, name):
    ''' Check if resource already exists
    '''

    try:
        response = requests.get(nitro_config_url + restype + '/' + name, headers=json_header, verify=False, cookies=cookie)
    except (requests.ConnectionError, requests.ConnectTimeout):
        print("Unable to connect to the server")
        exit(1)
    if response.status_code != 200:
        return False
    return True

def create_update_delete_resource(restype, name, body, action='delete'):
    ''' Performes create/update/delete HTTP action
    '''

    urlarg = ''
    try:
        if action == 'create':
            debug_print("Creating", restype, name)
            response = requests.post(nitro_config_url + '/' + restype + '/' + name, headers=json_header, data=json.dumps(body), verify=False, cookies=cookie)
        elif action == 'update':
            debug_print("Updating", restype, name)
            # modify_body_for_update(body)        # delete items not allowed in update message
            response = requests.put(nitro_config_url + '/' + restype + '/'+name, headers=json_header, data=json.dumps(body), verify=False, cookies=cookie)
        elif action == 'delete':
            debug_print("Deleting", restype, name)
            if restype == 'lbmonitor':      #monitor needs "type" args in delete method
                urlarg = "?args=type:"+str(body['lbmonitor']['type'])
            response = requests.delete(nitro_config_url + '/' + restype + '/'+ name + urlarg, headers=json_header, verify=False, cookies=cookie)
    except (requests.ConnectionError, requests.ConnectTimeout):
        print("Connection error")
        exit(1)
    if (response.status_code != 200) and (response.status_code != 201):
        print("Chyba pri create/update/delete", restype, name, "http status kod:", response.status_code)
        print("Response text", response.text)
        return False
    else:
        print("Successfuly", action+"d", restype, name)

    return True

def get_cookie(username, password):
    ''' Get Cookie for HTTP session
    '''

    global cookie
    payload = {"login":{"username":username, "password":password}}
    try:
        response = requests.post(nitro_config_url+'login', data=json.dumps(payload), headers=json_header, verify=False)
    except (requests.ConnectionError, requests.ConnectTimeout):
        print("Unable to conect to the server")
        exit(1)
    if response.status_code != 201:
        return False
    r_json = response.json()
    cookie = {'NITRO_AUTH_TOKEN': r_json["sessionid"]}
    return True

def load_json_cfgs(config_file):
    ''' Loads all configuration files into appropriates data structures
    '''

    global cfg_all_list
    global cfg_all_set
    global cfg_bind
    # server
    if os.path.isfile(config_file):        #zpracovani souboru nsconfig.json
        try:
            with open(config_file) as data_file:
                config_json = json.loads(data_file.read())
        except IOError:
            print("Unable to read the file", config_file)
            exit(1)
    else:
        print("Cannot find the file", config_file)
        exit(1)
    for files in config_json:              # projdi vsechny polozky z nsconfig.json
        try:
            filename = str((config_json[files]['filename']))      # nacti konfiguracni .json soubor pro danou polozku, napr. server.json
            with open(filename) as data_file:
                resource_json = json.loads(data_file.read())
        except ValueError:
            print("Unable to process the file", filename, ", syntax error?")
            exit(1)
        except IOError:
            print("Unable to read the file", filename)
            exit(1)

        if files == 'bindings':
            for key in list(resource_json.keys()):
                cfg_bind[key] = resource_json[key]    # binding descriptions in special dict variable
        else:
            for restype in resourcetype_list:
                if restype in resource_json.keys():
                    a = {restype:resource_json[restype]}
                    cfg_all_list.append(dict(a))
                    #                  cfg_all_list.append(dict(key, resource_json[key]))   # vsechny nactene konfigurace pridej do jedne promenne
                    cfg_all_set[restype] = resource_json[restype]      # elements description
    return True

def load_json_cfgs2(config_file):
    ''' Loads all configuration files into appropriates data structures
    '''

    global cfg_big_all_list
    global cfg_big_all_set
    global cfg_big_bind

    cfg_tmp_list = []
    cfg_tmp_set = {}
    # server
    if os.path.isfile(config_file):        #zpracovani souboru nsconfig.json
        try:
            with open(config_file) as data_file:
                config_json = json.loads(data_file.read())
        except IOError:
            print("Unable to read the file", config_file)
            exit(1)
    else:
        print("Cannot find the file", config_file)
        exit(1)

    for section in config_json:              # projdi vsechny sekce (items, bindings) z nsconfig.json
        for files in config_json[section]['filename']:
            filename = str(files)
            cfg_tmp_list = []
            cfg_tmp_set = {}
            try:
                with open(filename) as data_file:
                    resource_json = json.loads(data_file.read())
            except ValueError:
                print("Unable to process the file", filename, ", syntax error?")
                exit(1)
            except IOError:
                print("Unable to read the file", filename)
                exit(1)
            if section == 'bindings':
                for key in list(resource_json.keys()):
                    cfg_tmp_set[key] = resource_json[key]    # binding descriptions in special dict variable
                cfg_big_bind.append(cfg_tmp_set)
            else:
                for restype in resourcetype_list:
                    if restype in resource_json.keys():
                        a = {restype:resource_json[restype]}
                        cfg_tmp_list.append(dict(a))
                        #                  cfg_all_list.append(dict(key, resource_json[key]))   # vsechny nactene konfigurace pridej do jedne promenne
                        cfg_tmp_set[restype] = resource_json[restype]      # elements description
                cfg_big_all_list.append(cfg_tmp_list)
                cfg_big_all_set.append(cfg_tmp_set)




def create_update(body, action='create'):                  # it creates/updates or deletes items defined in nsconfig.json
    ''' Creates/updates/deletes one item (server, monitor,..)
    '''

    # typ=str(body.keys()[0])              # type (server,...) Python 2
    typ = list(body.keys())[0]
    res_type_name = resourcetype_name_dict[typ]   # what is the name of "name" field in this type ?
    for item in body[typ]:             # go through every item of specific type
        # name=str(body[typ][0]['name'])          #  resource name
        name = str(item[res_type_name])          #  resource name
        action_body = {}
        action_body[typ] = item                   #body with one item
        debug_print("Processing", typ, name)
        exists = False
        if resource_exist(typ, name):
            debug_print(typ, name, "exists")
            exists = True
        else:
            debug_print(typ, name, "doesn't exist")
       # try:
        if action == 'create' and not exists:
            #print("Creating", typ, name)
            create_update_delete_resource(typ, name, action_body, 'create')
            # response = requests.post(nitro_config_url + '/' + typ + '/' + name, headers=json_header, data=json.dumps(action_body), verify=False, cookies=cookie)
        elif (action == 'create' or action == 'update') and exists:
            #print("Updating", typ, name)
            modify_body_for_update(action_body)        # delete items not allowed in update message
            create_update_delete_resource(typ, name, action_body, 'update')
            # response = requests.put(nitro_config_url + '/' + typ + '/'+name, headers=json_header, data=json.dumps(action_body), verify=False, cookies=cookie)
        elif action == 'delete' and exists:
            # print("Deleting", typ, name)
            create_update_delete_resource(typ, name, action_body)
    #    except:
    #        print("Connection error")
    #        exit(1)
    #    if (response.status_code != 200) and (response.status_code != 201):
    #        print("Chyba pri create/update", typ, name, "http status kod:", response.status_code)
    #        print("Response text", response.text)
    #        return False
    #    else:
    #        print(typ, name, "successfuly created/updated")
    return True


def process_json_cfgs(action='update'):
    ''' Process (create/update/delete) configuration of all items (servers,monitors,..).
    '''
    for cfg_list in cfg_big_all_list:               # process config from all config files
        for item in reversed(cfg_list):
            if list(item.keys())[0] not in dont_process_at_beg_list:        # don't process certain specific items
                create_update(item, 'delete')
        if action == 'update' or action == 'create':
            for item in cfg_list:
                if list(item.keys())[0] not in dont_process_at_beg_list:        # don't process certain specific items
                    create_update(item)

def process_one_item_from_cfgs(item_type, action):
    ''' Process (create/update/delete) one item type (servers,monitors,..) from config file.
    '''
    for cfg_set in cfg_big_all_set:                  # process config from all config files
        if item_type in cfg_set.keys():                    # does item type exist in cfg?
            body = {item_type : cfg_set[item_type]}
            create_update(body, action)



def check_if_items_exist():
    ''' Check if items in cfg file (servers,monitors,..) already exist.
    '''
    exists = False
    for cfg_list in cfg_big_all_list:
        for item in cfg_list:
            typ = list(item.keys())[0]
            res_type_name = resourcetype_name_dict[typ]   # what is the name of "name" field in this type ?
            for subitem in item[typ]:             # go through every item of specific type
                # name=str(body[typ][0]['name'])          #  resource name
                name = str(subitem[res_type_name])          #  resource name
                action_body = {}
                action_body[typ] = item                   #body with one item
                if resource_exist(typ, name):
                    debug_print("Resource type:", typ, "name:", name, "exists")
                    exists = True
    return exists


def modify_body_for_update(telo):                      # delete items in body not allowed in update message
    ''' Deletes specific items, which are not allowed in update message, from body
    '''
    restyp = list(telo.keys())[0]
    if restyp in update_body_del_dict:                 # je tento typ v tabulce, tj. je treba potencialne neco odstranovat ?
        for polozka in update_body_del_dict[restyp]:   # projed vsechny polozky, ktere je treba odstranit
            if polozka in telo[restyp]:                # je tato polozka v tele ?
                del telo[restyp][polozka]                       # odstran ji

def bind_all_sslvs():
    ''' Binds all SSL parametrers to CSVSs
    '''

    #global cfg_bind
    for cfg_bind in cfg_big_bind:                       # process bindings from all config files
        if 'sslvserver_binding' in cfg_bind:
            for item in cfg_bind['sslvserver_binding']:
                bind_one_sslvs(item)

def bind_one_sslvs(onesslvs):
    ''' Binds all SSL objects to one CS VSs
    '''
    if 'sslvserver_ecccurve_binding' in onesslvs:
        for item in onesslvs['sslvserver_ecccurve_binding']:     # bind default LBVS to CSVS
            body = {'sslvserver_ecccurve_binding' : item}
            try:
                debug_print("Binding", item['vservername'], "to", item['ecccurvename'])
                response = requests.put(nitro_config_url + 'sslvserver_ecccurve_binding', headers=json_header, data=json.dumps(body), verify=False, cookies=cookie)
            except (requests.ConnectionError, requests.ConnectTimeout):
                print("Connection error")
                exit(1)
            if response.status_code != 200:
                print("Chyba pri bindingu ECC curve na CSVS", "http status kod:", response.status_code)
                print("Response text", response.text)
                return False
            else:
                print("Successfuly binded", item['vservername'], "to", item['ecccurvename'])

    if 'sslvserver_sslcertkey_binding' in onesslvs:
        for item in onesslvs['sslvserver_sslcertkey_binding']:     # bind default LBVS to CSVS
            body = {'sslvserver_sslcertkey_binding' : item}
            try:
                debug_print("Binding", item['vservername'], "to", item['certkeyname'])
                response = requests.put(nitro_config_url + 'sslvserver_sslcertkey_binding', headers=json_header, data=json.dumps(body), verify=False, cookies=cookie)
            except (requests.ConnectionError, requests.ConnectTimeout):
                print("Connection error")
                exit(1)
            if response.status_code != 200:
                print("Chyba pri bindingu certkey na CSVS", "http status kod:", response.status_code)
                print("Response text", response.text)
                return False
            else:
                print("Successfuly binded", item['vservername'], "to", item['certkeyname'])



def unbind_all_from_sslvs():
    ''' Unbinds all objects from all CS VSs
    '''
    for cfg_set in cfg_big_all_set:
        if 'csvserver' in cfg_set:              # is item 'csvserver' in current cfg_set (i.e config file)?
            for csvs in cfg_set['csvserver']:
                if resource_exist('csvserver', csvs['name']):     # does specific CSVS already exist ?
                    debug_print("SSLVS unbind:", csvs['name'])
                    response = requests.get(nitro_config_url + 'sslvserver_binding/' + csvs['name'], headers=json_header, verify=False, cookies=cookie)
                    if response.status_code == 200:
                        body_json = json.loads(response.text)
                        ssl_bindings = body_json['sslvserver_binding']
                        for key, value in dict.items(ssl_bindings[0]):
                            if sslvs_parametr_name_dict.get(key) != None: # pouze polozky definovane ve slovniku
                                for subitem in ssl_bindings[0][key]:     # projed vsechny cleny dane polozky
                                    subitem_name = subitem[sslvs_parametr_name_dict[key]]    # jmeno konkretni polozky
                                    add_param = ''
                                    debug_print("Unbinding", key, subitem_name)      # a unbinduje je ze CSVS
                                    response = requests.delete(nitro_config_url + key + '/' + csvs['name'] + '?args=' + sslvs_parametr_name_dict[key] + ':' + subitem_name + add_param, headers=json_header, verify=False, cookies=cookie)
                                    if response.status_code != 200:
                                        print("Chyba pri SSLVS unbind", key, subitem_name, "http status kod:", response.status_code)
                                        print("Response text", response.text)
                                        return False
                                    else:
                                        print("SSLVS unbind:", sslvs_parametr_name_dict[key], subitem_name, "successfuly unbinded from", csvs['name'])
                    else:
                        None
                        #print("Chyba pri GET csvserver_binding", csvs['csvserver'])
                        #return False
                debug_print("Konec SSLVS unbind:", csvs['name'])


def unbind_all_from_csvs():
    ''' Unbinds all objects from all CS VSs
    '''
    for cfg_set in cfg_big_all_set:
        if 'csvserver' in cfg_set:
            for csvs in cfg_set['csvserver']:
                if resource_exist('csvserver', csvs['name']):     # does specific CSVS already exist ?
                    debug_print("CSVS unbind:", csvs['name'])
                    response = requests.get(nitro_config_url + 'csvserver_binding/' + csvs['name'], headers=json_header, verify=False, cookies=cookie)
                    if response.status_code != 200:
                        print("Chyba pri GET csvserver_binding", csvs['csvserver'])
                        return False
                    body_json = json.loads(response.text)
                    cs_bindings = body_json['csvserver_binding']
                    for key, value in dict.items(cs_bindings[0]):
                        if cs_parametr_name_dict.get(key) != None: # pouze polozky definovane ve slovniku
                            for subitem in cs_bindings[0][key]:     # projed vsechny cleny dane polozky
                                subitem_name = subitem[cs_parametr_name_dict[key]]    # jmeno konkretni polozky
                                add_param = ''
                                debug_print("Unbinding", key, subitem_name)      # a unbinduje je ze CSVS
                                response = requests.delete(nitro_config_url + key + '/' + csvs['name'] + '?args=' + cs_parametr_name_dict[key] + ':' + subitem_name + add_param, headers=json_header, verify=False, cookies=cookie)
                                if response.status_code != 200:
                                    print("Chyba pri CSVS unbind", key, subitem_name, "http status kod:", response.status_code)
                                    print("Response text", response.text)
                                    return False
                                else:
                                    print("CSVS unbind:", cs_parametr_name_dict[key], subitem_name, "successfuly unbinded from", csvs['name'])
                debug_print("Konec CSVS unbind:", csvs['name'])

def bind_all_csvs():
    ''' Binds all objects to all CS VSs
    '''

    #global cfg_bind
    for cfg_bind in cfg_big_bind:
        if 'csvserver_binding' in cfg_bind:
            for item in cfg_bind['csvserver_binding']:
                bind_one_csvs(item)

def bind_one_csvs(onecsvs):
    ''' Binds all objects to one CS VS
    '''

    if 'csvserver_lbvserver_binding' in onecsvs:
        for item in onecsvs['csvserver_lbvserver_binding']:     # bind default LBVS to CSVS
            body = {'csvserver_lbvserver_binding' : item}
            try:
                debug_print("Binding", item['lbvserver'], "to", item['name'])
                response = requests.put(nitro_config_url + 'csvserver_lbvserver_binding', headers=json_header, data=json.dumps(body), verify=False, cookies=cookie)
            except (requests.ConnectionError, requests.ConnectTimeout):
                print("Connection error")
                exit(1)
            if response.status_code != 200:
                print("Chyba pri bindingu default LBVS na CSVS", "http status kod:", response.status_code)
                print("Response text", response.text)
                return False
            else:
                print("Successfuly binded", item['lbvserver'], "to", item['name'])

    if 'csvserver_cspolicy_binding' in onecsvs:
        for item in onecsvs['csvserver_cspolicy_binding']:     # bind CS policies to CSVS
            body = {'csvserver_cspolicy_binding' : item}
            try:
                debug_print("Binding", item['policyname'], "to", item['name'])
                response = requests.put(nitro_config_url + 'csvserver_cspolicy_binding', headers=json_header, data=json.dumps(body), verify=False, cookies=cookie)
            except (requests.ConnectionError, requests.ConnectTimeout):
                print("Connection error")
                exit(1)
            if response.status_code != 200:
                print("Chyba pri bindingu policy na CSVS", "http status kod:", response.status_code)
                print("Response text", response.text)
                return False
            else:
                print("Successfuly binded", item['policyname'], "to", item['name'])

    if 'csvserver_rewritepolicy_binding' in onecsvs:
        for item in onecsvs['csvserver_rewritepolicy_binding']:     # bind rewrite policies to CSVS
            body = {'csvserver_rewritepolicy_binding' : item}
            try:
                debug_print("Binding", item['policyname'], "to", item['name'])
                response = requests.put(nitro_config_url + 'csvserver_rewritepolicy_binding', headers=json_header, data=json.dumps(body), verify=False, cookies=cookie)
            except (requests.ConnectionError, requests.ConnectTimeout):
                print("Connection error")
                exit(1)
            if response.status_code != 200:
                print("Chyba pri bindingu rewrite policy na CSVS", "http status kod:", response.status_code)
                print("Response text", response.text)
                return False
            else:
                print("Successfuly binded", item['policyname'], "to", item['name'])
    return True


def unbind_all_from_lbvs():
    ''' Unbinds all objects from all LB VSs
    '''
    for cfg_set in cfg_big_all_set:
        if 'lbvserver' in cfg_set:
            for lbvs in cfg_set['lbvserver']:
                if resource_exist('lbvserver', lbvs['name']):     # does specific LBVS already exist ?
                    debug_print("LBVS unbind:", lbvs['name'])
                    response = requests.get(nitro_config_url + 'lbvserver_binding/' + lbvs['name'], headers=json_header, verify=False, cookies=cookie)
                    if response.status_code != 200:
                        print("Chyba pri GET lbvserver_binding", lbvs['lbvserver'])
                        return False
                    body_json = json.loads(response.text)
                    vs_bindings = body_json['lbvserver_binding']
                    for key, value in dict.items(vs_bindings[0]):
                        if vs_parametr_name_dict.get(key) != None: # pouze polozky definovane ve slovniku
                            for subitem in vs_bindings[0][key]:     # projed vsechny cleny dane polozky
                                subitem_name = subitem[vs_parametr_name_dict[key]]    # jmeno konkretni polozky
                                add_param = ''
                                debug_print("Unbinding", key, subitem_name)      # a unbinduje je ze LB service groupy
                                response = requests.delete(nitro_config_url + key + '/' + lbvs['name'] + '?args=' + vs_parametr_name_dict[key] + ':' + subitem_name + add_param, headers=json_header, verify=False, cookies=cookie)
                                if response.status_code != 200:
                                    print("Chyba pri unbind", key, subitem_name, "http status kod:", response.status_code)
                                    print("Response text", response.text)
                                    return False
                                else:
                                    print("LBVS unbind:", vs_parametr_name_dict[key], subitem_name, "successfuly unbinded from", lbvs['name'])
                debug_print("Konec LBVS unbind:", lbvs['name'])

def bind_all_lbvs():
    ''' Binds all objects to all LB VSs
    '''

    # global cfg_bind
    for cfg_bind in cfg_big_bind:
        if 'lbvserver_binding' in cfg_bind:
            for item in cfg_bind['lbvserver_binding']:
                bind_one_lbvs(item)

def bind_one_lbvs(onelbvs):
    ''' Binds all objects to on LB VS
    '''

    if 'lbvserver_servicegroup_binding' in onelbvs:
        for item in onelbvs['lbvserver_servicegroup_binding']:     # bind all servergroups to LBVS
            body = {'lbvserver_servicegroup_binding' : item}
            try:
                debug_print("Binding", item['servicegroupname'], "to", item['name'])
                response = requests.put(nitro_config_url + 'lbvserver_servicegroup_binding', headers=json_header, data=json.dumps(body), verify=False, cookies=cookie)
            except requests.exceptions.ConnectionError:
                print("Connection error")
                exit(1)
            except KeyError as e:
                print("Keyerror", e)
                exit(1)
            if response.status_code != 200:
                print("Service binding errorgroup", "http status kod:", response.status_code)
                print("Response text", response.text)
                return False
            else:
                print("Successfuly binded", item['servicegroupname'], "to", item['name'])

    if 'lbvserver_service_binding' in onelbvs:
        for item in onelbvs['lbvserver_service_binding']:     # bind all services to LBVS
            body = {'lbvserver_service_binding' : item}
            try:
                debug_print("Binding", item['servicename'], "to", item['name'])
                response = requests.put(nitro_config_url + 'lbvserver_service_binding', headers=json_header, data=json.dumps(body), verify=False, cookies=cookie)
            except requests.exceptions.ConnectionError:
                print("Connection error")
                exit(1)
            except KeyError as e:
                print("Keyerror", e)
                exit(1)
            if response.status_code != 200:
                print("Service binding error", "http status kod:", response.status_code)
                print("Response text", response.text)
                return False
            else:
                print("Successfuly binded", item['servicename'], "to", item['name'])

    if 'lbvserver_responderpolicy_binding' in onelbvs:
        for item in onelbvs['lbvserver_responderpolicy_binding']:     # bind all services to LBVS
            body = {'lbvserver_responderpolicy_binding' : item}
            try:
                debug_print("Binding", item['policyname'], "to", item['name'])
                response = requests.put(nitro_config_url + 'lbvserver_responderpolicy_binding', headers=json_header, data=json.dumps(body), verify=False, cookies=cookie)
            except requests.exceptions.ConnectionError:
                print("Connection error")
                exit(1)
            except KeyError as e:
                print("Keyerror", e)
                exit(1)
            if response.status_code != 200:
                print("Service binding error", "http status kod:", response.status_code)
                print("Response text", response.text)
                return False
            else:
                print("Successfuly binded", item['policyname'], "to", item['name'])

    return True


def unbind_all_from_lbsg():                            # unbind all items (monitors, servers) binded to LB service groups
    ''' Unbinds all objects from all LB SGs
    '''
    for cfg_set in cfg_big_all_set:
        if 'servicegroup' in cfg_set:
            for lbsg in cfg_set['servicegroup']:
                if resource_exist('servicegroup', lbsg['servicegroupname']):     # does specific LBSG already exist ?
                    debug_print("LBSG unbind:", lbsg['servicegroupname'])
                    response = requests.get(nitro_config_url + 'servicegroup_binding/' + lbsg['servicegroupname'], headers=json_header, verify=False, cookies=cookie)
                    if response.status_code != 200:
                        print("Chyba pri GET servicegroupbindings", lbsg['servicegroupname'])
                        return False
                    body_json = json.loads(response.text)
                    sg_bindings = body_json['servicegroup_binding']
                    for key, value in dict.items(sg_bindings[0]):
                        # index=list(item.keys())[0]
                        if sg_parametr_name_dict.get(key) != None: # pouze polozky definovane ve slovniku (monitory, server membery)
                        #if key != 'servicegroupname' :    # preskoc polozku "servicegroupname"
                            for subitem in sg_bindings[0][key]:     # projed vsechny cleny dane polozky (monitory, membery)
                                subitem_name = subitem[sg_parametr_name_dict[key]]    # jmeno konkretni polozky (monitor, server)
                                add_param = ''
                                if key == 'servicegroup_servicegroupmember_binding':   # server member?
                                    add_param = ',port:' + str(subitem['port'])         # jeste pridat parametr 'port' do URL
                                debug_print("Unbinding", key, subitem_name)      # a unbinduje je ze LB service groupy
                                response = requests.delete(nitro_config_url + key + '/' + lbsg['servicegroupname'] + '?args=' + sg_parametr_name_dict[key] + ':' + subitem_name + add_param, headers=json_header, verify=False, cookies=cookie)
                                if response.status_code != 200:
                                    print("Chyba pri unbind", key, subitem_name, "http status kod:", response.status_code)
                                    print("Response text", response.text)
                                    return False
                                else:
                                    print("LBSG unbind:", sg_parametr_name_dict[key], subitem_name, "successfuly unbinded from", lbsg['servicegroupname'])
                debug_print("Konec LBSG unbind:", lbsg['servicegroupname'])

def bind_all_lbsg():
    ''' Binds all objects to all LB SGs
    '''

    # global cfg_bind
    for cfg_bind in cfg_big_bind:
        if 'servicegroup_binding' in cfg_bind:
            for item in cfg_bind['servicegroup_binding']:
                bind_one_lbsg(item)

def bind_one_lbsg(onelbsg):
    ''' Binds one objects to all LB SGs
    '''

    if 'servicegroup_servicegroupmember_binding' in onelbsg:
        for item in onelbsg['servicegroup_servicegroupmember_binding']:     # bind all servers to LBSG
            body = {'servicegroup_servicegroupmember_binding' : item}
            try:
                debug_print("Binding", item['servername'], "to", item['servicegroupname'])
                response = requests.put(nitro_config_url + 'servicegroup_servicegroupmember_binding', headers=json_header, data=json.dumps(body), verify=False, cookies=cookie)
            except (requests.ConnectionError, requests.ConnectTimeout):
                print("Connection error")
                exit(1)
            if response.status_code != 200:
                print("Chyba pri bindingu serveru", "http status kod:", response.status_code)
                print("Response text", response.text)
                return False
            else:
                print("Successfuly binded", item['servername'], "to", item['servicegroupname'])

    if 'servicegroup_lbmonitor_binding' in onelbsg:
        for item in onelbsg['servicegroup_lbmonitor_binding']:     # bind all monitors to LBSG
            body = {'servicegroup_lbmonitor_binding' : item}
            try:
                debug_print("Binding", item['monitor_name'], "to", item['servicegroupname'])
                response = requests.put(nitro_config_url + 'servicegroup_lbmonitor_binding', headers=json_header, data=json.dumps(body), verify=False, cookies=cookie)
            except (requests.ConnectionError, requests.ConnectTimeout):
                print("Connection error")
                exit(1)
            if response.status_code != 200:
                print("Chyba pri bindingu monitoru", "http status kod:", response.status_code)
                print("Response text", response.text)
                return False
            else:
                print("Successfuly binded", item['monitor_name'], "to", item['servicegroupname'])
    return True

def bind_all_lbsvc():
    ''' Binds all objects to all LB Services
    '''

    # global cfg_bind
    for cfg_bind in cfg_big_bind:
        if 'service_binding' in cfg_bind:
            for item in cfg_bind['service_binding']:
                bind_one_lbsvc(item)

def bind_one_lbsvc(onelbsg):
    ''' Binds one objects to all LB Services
    '''

    if 'service_lbmonitor_binding' in onelbsg:
        for item in onelbsg['service_lbmonitor_binding']:
            body = {'service_lbmonitor_binding' : item}
            try:
                debug_print("Binding", item['monitor_name'], "to", item['name'])
                response = requests.put(nitro_config_url + 'service_lbmonitor_binding', headers=json_header, data=json.dumps(body), verify=False, cookies=cookie)
            except (requests.ConnectionError, requests.ConnectTimeout):
                print("Connection error")
                exit(1)
            if response.status_code != 200:
                print("Chyba pri bindingu serveru", "http status kod:", response.status_code)
                print("Response text", response.text)
                return False
            else:
                print("Successfuly binded", item['monitor_name'], "to", item['name'])
    return True

def unbind_all_from_lbsvc():                            # unbind all items (monitors, servers) binded to LB service
    ''' Unbinds all objects from all LB SVCs
    '''
    for cfg_set in cfg_big_all_set:
        if 'service' in cfg_set:
            for lbsvc in cfg_set['service']:
                if resource_exist('service', lbsvc['name']):     # does specific LBSG already exist ?
                    debug_print("LBSVC unbind:", lbsvc['name'])
                    response = requests.get(nitro_config_url + 'service_binding/' + lbsvc['name'], headers=json_header, verify=False, cookies=cookie)
                    if response.status_code != 200:
                        print("Chyba pri GET service_bindings", lbsvc['name'])
                        return False
                    body_json = json.loads(response.text)
                    svc_bindings = body_json['service_binding']
                    for key, value in dict.items(svc_bindings[0]):
                        if svc_parametr_name_dict.get(key) != None: # pouze polozky definovane ve slovniku (monitory, server membery)
                            for subitem in svc_bindings[0][key]:     # projed vsechny cleny dane polozky (monitory, membery)
                                subitem_name = subitem[svc_parametr_name_dict[key]]    # jmeno konkretni polozky (monitor, server)
                                add_param = ''
                                debug_print("Unbinding", key, subitem_name)      # a unbinduje je ze LB service
                                response = requests.delete(nitro_config_url + key + '/' + lbsvc['name'] + '?args=' + svc_parametr_name_dict[key] + ':' + subitem_name + add_param, headers=json_header, verify=False, cookies=cookie)
                                if response.status_code != 200:
                                    print("Chyba pri unbind", key, subitem_name, "http status kod:", response.status_code)
                                    print("Response text", response.text)
                                    return False
                                else:
                                    print("LBSVC unbind:", svc_parametr_name_dict[key], subitem_name, "successfuly unbinded from", lbsvc['name'])
                debug_print("Konec LBSVC unbind:", lbsvc['name'])

def bind_general(name):
    ''' Process binding for specified item (i.e. name lbgroup process lbgroup_binding subtree)
    '''

    # global cfg_bind
    for cfg_bind in cfg_big_bind:
        subtree_name = name + '_binding'
        if subtree_name in cfg_bind:
            for subtree in cfg_bind[subtree_name]:      # go through each item of specified subtree, i.e through all lbgroup
                actname = subtree.get("name")
                for (key, value) in subtree.items():           # key is name of "binding function" with exception of "name"
                    if key == "name":
                        continue            # process next key
                    for cfgbody in value:            # go through each json body which will be binded
                        body = {key : cfgbody}         # create proper format of json body
                        try:
                            debug_print("Binding", cfgbody[general_parametr_name_dict[key]], "to", actname)
                            response = requests.put(nitro_config_url + key, headers=json_header, data=json.dumps(body), verify=False, cookies=cookie)
                        except (requests.ConnectionError, requests.ConnectTimeout):
                            print("Connection error")
                            exit(1)
                        if response.status_code != 200:
                            print("Chyba pri bindingu serveru", "http status kod:", response.status_code)
                            print("Response text", response.text)
                            return False
                        else:
                            print("Successfuly binded", cfgbody[general_parametr_name_dict[key]], "to", actname)

def unbind_general(unb_name):
    ''' Process unbinding for specified item (i.e. unb_name lbgroup process unbinding of lbgroup_binding subtree)
    '''

    subtree_name = unb_name + '_binding'
    for cfg_set in cfg_big_all_set:
        if unb_name in cfg_set:
            for item in cfg_set[unb_name]:
                if resource_exist(unb_name, item["name"]):       # resource type, name
                    debug_print(unb_name, "unbind:", item['name'])
                    response = requests.get(nitro_config_url + subtree_name + '/' + item['name'], headers=json_header, verify=False, cookies=cookie)
                    if response.status_code != 200:
                        print("Chyba pri GET service_bindings", item['name'])
                        return False
                    body_json = json.loads(response.text)
                    gen_bindings = body_json[subtree_name]
                    for key, value in gen_bindings[0].items():      # go through each item (section) of specific binding
                        if general_parametr_name_dict.get(key) != None: # only items defined in dictionary (monitory, server membery)
                            for subitem in gen_bindings[0][key]:     # projed vsechny cleny dane polozky (monitory, membery)
                                subitem_name = subitem[general_parametr_name_dict[key]]    # jmeno konkretni polozky (monitor, server)
                                add_param = ''
                                debug_print("Unbinding", key, subitem_name)
                                response = requests.delete(nitro_config_url + key + '/' + item['name'] + '?args=' + general_parametr_name_dict[key] + ':' + subitem_name + add_param, headers=json_header, verify=False, cookies=cookie)
                                if response.status_code != 200:
                                    print("Chyba pri unbind", key, subitem_name, "http status kod:", response.status_code)
                                    print("Response text", response.text)
                                    return False
                                else:
                                    print("unbind:", general_parametr_name_dict[key], subitem_name, "successfuly unbinded from", item['name'])
                    debug_print("Konec", unb_name, "unbind:", item['name'])

def is_ip_valid(testedip):
    ''' Test if string is valid IP address
    '''
    result = True
    list_ip = testedip.split('.')

    # dobra finta: convert octet from string to int
    for i, octet in enumerate(list_ip):

        # I haven't told you about exception handling yet (soon)
        # You could do without this, the script will just crash
        # on certain invalid input (for example, '1.1.1.')
        try:
            list_ip[i] = int(octet)
        except ValueError:
            # couldn't convert octet to an integer
            sys.exit("\n\nInvalid IP address: %s\n" % testedip)



    if len(list_ip) == 4:
        prvni, druhy, treti, ctvrty = list_ip
        if ((prvni >= 1) and (prvni <= 223)) and (prvni != 127) and ((prvni != 169) and (druhy != 254)):
            for item in list_ip[1:]:
                if (item < 0) or (item > 255):
                    result = result and False
        else:
            result = False
    else:
        result = False

    return result

def is_ip_port_valid(testedipport):
    ''' Is testedipport valid IP_addr:port string?
    '''
    if ':' in testedipport:
        res = testedipport.split(':')
        if len(res) > 2:
            return False
        if len(res) == 1:
            if is_ip_valid(res[0]):
                return True
        try:
            portn = int(res[1])
        except ValueError:
            return False
        if (portn <= 65535) and (portn > 0):
            return True
        return False
    return is_ip_valid(testedipport)


def get_ip_and_port_from_string(ipport):
    ''' Returns IP (and port) from IP_addr:port string
    '''
    #outlist = []
    if ':' in ipport:
        return ipport.split(':')
    #outlist.append(ipport)
    return [ipport, '']

    



def debug_print(*string):
    ''' Print debug info
    '''
    if debug:
        print("Debug: ", end='')
        for item in string:
            print(item, "", end='')
        print("")

