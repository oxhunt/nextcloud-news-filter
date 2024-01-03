#!/usr/bin/env python3
#
# mark specific news items as read (so they don't show in the "unread" feed)
#
import base64
import sys
import logging
import os.path
import configparser
import re
from _datetime import datetime, timedelta
import requests
import os
import time


NAME_PROGRAM = "nextcloud-news-filter"
# CONFIG_FILE = os.path.expanduser(f"~/.config/{NAME_PROGRAM}/config.ini")
CONFIG_FILE = "/config.ini"






def get_matching_item_ids(items, one_filter):
    matching_ids = set()
    for t_item in items:
        # if the feed id matches
        if ('feedId' not in one_filter or one_filter['feedId'] in (None, t_item['feedId'])) and \
            ('folderId' not in one_filter or one_filter['folderId'] in (None, t_item['folderId'])):    
            if is_match(one_filter, t_item):
                matching_ids.add(t_item["id"])
                
    return matching_ids
    
    
def is_match(one_filter, t_item):
    if ('titleRegex' not in one_filter
                or one_filter['titleRegex'] is None
                or one_filter['titleRegex'].search(t_item['title'])) \
        and ('bodyRegex' not in one_filter
                or one_filter['bodyRegex'] is None
                or one_filter['bodyRegex'].search(t_item['body'])) \
        and ('fullRegex' not in one_filter
                or one_filter['fullRegex'] is None
                or one_filter['fullRegex'].search(t_item['title'] + "\n" + t_item['body'])) \
        and ('minPubDate' not in one_filter
                or one_filter['minPubDate'] is None
                or t_item['pubDate'] < one_filter['minPubDate']):
        return True
    return False
def check_config_existence():
    # Check if the directory exists and contains the file
    if not os.path.isfile(CONFIG_FILE):
        logging.info(f"No config file found: {CONFIG_FILE}")
        exit(1)
        
    else:
        print(f"File {CONFIG_FILE} found")

def parse_config():
    if not os.path.isfile(CONFIG_FILE):
        logging.error(f"{CONFIG_FILE} not found")
        exit(1)
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)

    if 'login' not in config:
        logging.log(logging.ERROR, 'configuration has to contain [login] section')
        exit(1)
    if 'address' not in config['login'] or config['login']['address'] == '':
        logging.log(logging.ERROR, 'configuration has to contain address in [login] section')
        exit(1)
    if 'username' not in config['login'] or config['login']['username'] == '' \
            or 'password' not in config['login'] or config['login']['password'] == '':
        logging.log(logging.ERROR, 'configuration has to contain username and password in [login] section')
        exit(1)
    return config

def print_unread_rss_structure(rss_structure):
    for f in rss_structure["folders"]:
        logging.debug(f"{f['name']}")
        for fd in rss_structure["feeds"]:
            if f["id"]==fd["folderId"]:
                logging.debug(f"    - {fd['title']}")
                for it in rss_structure["items"]:
                    if it["feedId"]==fd["id"]:
                        logging.debug(f"        - {it['title']}")

def get_folder_ids_matching_name(name_match, rss_structure):
    '''return all folder ids in the given structure which contain the name_match in their name'''
    matching_ids=[]
    for f in rss_structure["folders"]:
        if name_match.lower() in f["name"].lower():
            matching_ids.append(f["id"])
    return matching_ids

def get_feed_ids_matching_name(name_match, rss_structure):
    '''return all feed ids in the given structure which contain the name_match in their title'''
    matching_ids=[]
    for f in rss_structure["feeds"]:
        if (name_match).lower() in f["title"].lower():
            matching_ids.append(f["id"])
    return matching_ids

def is_supported_filter(f):
    if f["folderNameContains"] and f["folderId"]:
        logging.warning(f"Unsupported filter detected, you cannot filter both by folderid and foldername, ignoring: {f}")
        return False
    if f["feedNameContains"] and f["feedId"]:
        logging.warning(f"Unsupported filter detected, you cannot filter both by feedid and feedtitle, ignoring: {f}")
        return False
    return True

def clean_filters(filters, rss_structure):
    ''' takes the filters as inputs and converts folderNameContains and feedNameContains to the appropriate feedIds and folderIds'''
    new_filters = []
    
    # lets remove the filter types we do not support
    supported_filters = list(filter(lambda f: is_supported_filter(f), filters))
    
    # normal filters are the ones that do not use neither the  "folderNameContains" or "feedNameContains"
    normal_filters = list(filter(lambda f: not(f["folderNameContains"] or f["feedNameContains"]), supported_filters))
    
    # folder name filters are the ones using "folderNameContains" to filter
    folder_name_filters = list(filter(lambda f: f["folderNameContains"], supported_filters))
    
    # feed name filters are the ones using "feedrNameContains" to filter
    feed_name_filters = list(filter(lambda f: f["feedNameContains"], supported_filters))
    
    # creating new new normal filters depending on the number of matched folders/feeds using feedNameContains/folderNameContains
    normal_filters = []
    for f in folder_name_filters:
        matching_ids = get_folder_ids_matching_name(f["folderNameContains"], rss_structure)
        for m in matching_ids:
            f["folderId"]=m
            normal_filters.append(f)
    for f in feed_name_filters:
        matching_ids = get_feed_ids_matching_name(f["feedNameContains"], rss_structure)
        for m in matching_ids:
            f["feedId"]=m
            normal_filters.append(f)
    return normal_filters 
    
def parse_filters(config):
    filters = []
    for section in config:
        if section not in ['DEFAULT', 'login']:
            
            one_filter = {'name': section,
                          'folderNameContains': config[section]['folderNameContains'] if 'folderNameContains' in config[section] else None,
                          'feedNameContains': config[section]['feedNameContains'] if 'feedNameContains' in config[section] else None,
                          'folderId': int(config[section]['folderId']) if 'folderId' in config[section] else None,
                          'feedId': int(config[section]['feedId']) if 'feedId' in config[section] else None,
                          'titleRegex': re.compile(config[section]['titleRegex'], re.IGNORECASE) if 'titleRegex' in config[section] else None,
                          'bodyRegex': re.compile(config[section]['bodyRegex'], re.IGNORECASE) if 'bodyRegex' in config[section] else None,
                          'fullRegex': re.compile(config[section]['fullRegex'], re.IGNORECASE) if 'fullRegex' in config[section] else None,
                          'minPubDate': int((datetime.now() - timedelta(hours=int(config[section]['hoursAge']))).timestamp()) if 'hoursAge' in config[section] else None,
                          'isWhitelist': int(config[section]["isWhitelist"]) if 'isWhitelist' in config[section] else 0
                        }
            filters.append(one_filter)
    return filters

def add_folder_id_to_items(rss_structure):
    for i in rss_structure["items"]:
        for f in rss_structure["feeds"]:
            if f["id"]==i["feedId"]:
                i["folderId"]=f["folderId"]
                break

            
                

def get_rss_structure(config, token):
    rss_structure={}
    for i in ["items", "folders", "feeds"]:
        try:
            response = requests.get(url=config['login']['address'] + f'/index.php/apps/news/api/v1-3/{i}',
                                headers=dict(Authorization=f"Basic {token}"),
                                json=dict(batchSize=-1,
                                        offset=0,
                                        type=3,
                                        id=0,
                                        getRead='false'))    
            if response.status_code not in [200, 201]:
                logging.error(f"request to server failed with status: {response.status_code}")
                exit(1)
            rss_structure[i]=response.json()[i]
        except Exception as e:
            logging.fatal(f"exception occurred, {e}")
            exit(1)
    return rss_structure



if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        stream=sys.stdout)
    logging.debug('starting run')

    while True:
        check_config_existence()

        config = parse_config()
        
        token = base64.encodebytes((config['login']['username'] + ':' + config['login']['password'])
                                .encode(encoding='UTF-8')).decode(encoding='UTF-8').strip()
        
        
        rss_structure = get_rss_structure(config, token)
        
        # removing all feeds that are have already been marked as read
        rss_structure["items"] = list(filter(lambda i: i['unread'], rss_structure['items']))

        
        filters = parse_filters(config)
        # clean_filters is buggy, so I avoid using it
        # filters = clean_filters(parse_filters(config), rss_structure)
        
        for i in rss_structure["items"]:
            assert i['unread']==True
        #print(rss_structure["items"])

        # printing the folder, feed tree
        # print_unread_rss_structure(rss_structure)

        add_folder_id_to_items(rss_structure)
        # goes through the filters and collect the ids of the items to hide
        results = {
            "blacklist":{"matched":set(), "not_matched":set()},
            "whitelist": {"matched":set(), "not_matched":set()}
        }
        for f in filters:
            match_by_feedId = {'name': "", "feedId": f["feedId"], "folderId":f["folderId"]}
            f["matched_items"] = get_matching_item_ids(rss_structure["items"], f)
            f["considered_items"] = get_matching_item_ids(rss_structure["items"], match_by_feedId )
            f["not_matched"] = f["considered_items"]-f["matched_items"]
        
        # transforming all the blacklist filter results to whitelist mode
        def translate_blacklist_filter(f):
            if not f["isWhitelist"]:
                # import copy
                # m = copy.deepcopy(f["matched_items"])
                nm=f["not_matched"]
                m=f["matched_items"]
                f["not_matched"]=m
                f["matched_items"]=nm
            return f
        filters = list(map(lambda f: translate_blacklist_filter(f), filters))
        
        # we now have only results expressed as whitelists
        # between filters with same priority, the resulting set is the intersection of the sets  
        
        all_unread_item_ids = set(map(lambda i: i["id"], rss_structure["items"]))
        
        # we calculate, for each item, if there is at least a filter regarding it which deemed it as unworthy
        values_to_set_as_read = []
        for id in all_unread_item_ids:
            mark_as_read = False
            for f in filters:
                if id in f["considered_items"]:
                    if id in f["not_matched"]:
                        values_to_set_as_read.append(id)
                        break
                        
        
        if values_to_set_as_read:
            logging.log(logging.INFO, f"marking as read: {len(values_to_set_as_read)} items")
            requests.post(url=config['login']['address'] + '/index.php/apps/news/api/v1-3/items/read/multiple',
                        headers=dict(Authorization=f"Basic {token}"),
                        json=dict(itemIds=values_to_set_as_read))
        
        logging.debug('rerunning in 30 minutes')
        time.sleep(30*60) # repeat every 30 minutes
        logging.debug('finished sleep, starting to run')
