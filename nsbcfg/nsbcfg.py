# pylint: disable=C0301, C0103

import sys
import json
import getpass
import os
import getopt
import requests


requests.packages.urllib3.disable_warnings()

ns_ip = ""
nitro_config_path = '/nitro/v1/config/'
cookie = {}
json_header = {'Content-type': 'application/json'}
config_file = 'nsconfig.json'
cfg_all_list = []        # list
cfg_all_set = {}       # set
cfg_bind = {}
pswd = ''
paction = ''               # create, update, delete

# the following variables are arrays/lists containing json configuration from several files, each array entry contains configuration
# from one configuration file
# this will replace cfg_all_list, cfg_all_set, cfg_bind
cfg_big_all_list = []       # list of lists, based on files contained in "items" configuration file section
cfg_big_all_set = []        # list of sets, based on files contained in "items" configuration file section
cfg_big_bind = []           # list of sets, based on files contained in "bindings" configuration file section

resourcetype_name_dict = {'server':'name', \
                            'servicegroup':'servicegroupname', \
                            'lbmonitor':'monitorname', \
                            'lbvserver':"name", \
                            "csvserver":"name", \
                            "cspolicy":"policyname", \
                            "rewritepolicy":"name", \
                            "rewriteaction":"name", \
                            "sslprofile":"name",\
                            "service":"name",\
                            "lbgroup":"name"}    # jak se jmenuje polozka se jmenem u jednotlivych typu
resourcetype_list = ["rewriteaction", "rewritepolicy", "sslprofile", "cspolicy", "csvserver", \
                    "lbvserver", "servicegroup", "server", "lbmonitor", "service", "lbgroup"]  #order in which resource types are created, i.e rewriteaction must be created before rewritepolicy

dont_process_at_beg_list = ["lbgroup"]      # don't create this resources at the beginning
update_body_del_dict = {"servicegroup":["servicetype", "td"], "lbvserver":["servicetype", "port", "td"], \
                        "csvserver":["port", "td", "servicetype", "range"]}                          # ktere polozky je treba odstranit pri update daneho typu
sg_parametr_name_dict = {"servicegroup_lbmonitor_binding":"monitor_name", "servicegroup_servicegroupmember_binding":"servername"}
svc_parametr_name_dict = {"service_lbmonitor_binding":"monitor_name"}
vs_parametr_name_dict = {"lbvserver_servicegroup_binding":"servicegroupname"}
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
        print("Chyba pri pripojeni k serveru")
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

def load_json_cfgs():
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

def load_json_cfgs2():
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
    #        print("Chyba pri pripojeni k serveru")
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
                print("Chyba pri pripojeni k serveru")
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
                print("Chyba pri pripojeni k serveru")
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
                print("Chyba pri pripojeni k serveru")
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
                print("Chyba pri pripojeni k serveru")
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
                print("Chyba pri pripojeni k serveru")
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
            except (requests.ConnectionError, requests.ConnectTimeout):
                print("Chyba pri pripojeni k serveru")
                exit(1)
            if response.status_code != 200:
                print("Chyba pri bindingu servicegroup", "http status kod:", response.status_code)
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
            except (requests.ConnectionError, requests.ConnectTimeout):
                print("Chyba pri pripojeni k serveru")
                exit(1)
            if response.status_code != 200:
                print("Chyba pri bindingu service", "http status kod:", response.status_code)
                print("Response text", response.text)
                return False
            else:
                print("Successfuly binded", item['servicename'], "to", item['name'])

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
                print("Chyba pri pripojeni k serveru")
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
                print("Chyba pri pripojeni k serveru")
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
                print("Chyba pri pripojeni k serveru")
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
                            print("Chyba pri pripojeni k serveru")
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

def debug_print(*string):
    ''' Print debug info
    '''
    if debug:
        print("Debug: ", end='')
        for item in string:
            print(item, "", end='')
        print("")

argv = sys.argv[1:]
username = ''
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

if not is_ip_valid(ns_ip):
    print("Invalid IP address", ns_ip)
    sys.exit(2)


#print("Username=", username)
#print("IP addr=", ns_ip)
#print("CFG file=", config_file)

if pswd == '':
    pswd = getpass.getpass('Password:')

nitro_config_url = "https://"+ns_ip+nitro_config_path
if not get_cookie(username, pswd):
    print("Authentication failed for username", username)
    sys.exit(2)


load_json_cfgs2()

if paction in ['create', 'c']:
    if check_if_items_exist():
        print("Option \"create\" is specified but some resources already exist !")
        sys.exit(2)


if paction in ['create', 'update', 'c', 'u']:

    unbind_all_from_sslvs()
    unbind_all_from_csvs()
    unbind_all_from_lbvs()
    unbind_all_from_lbsvc()
    unbind_all_from_lbsg()
    unbind_general("lbgroup")

    process_json_cfgs()

    bind_general("lbgroup")
    bind_all_lbsg()
    bind_all_lbsvc()
    bind_all_lbvs()
    bind_all_csvs()
    bind_all_sslvs()
    process_one_item_from_cfgs('lbgroup', 'update')

elif paction in ['delete', 'd']:

    unbind_all_from_sslvs()
    unbind_all_from_csvs()
    unbind_all_from_lbvs()
    unbind_all_from_lbsvc()
    unbind_all_from_lbsg()
    unbind_general("lbgroup")
    process_json_cfgs('delete')



print("Finish")


# if __name__ == "__main__":

#    main(sys.argv[1:])
