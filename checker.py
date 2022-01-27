from urllib.parse import urlparse
import sys
import os
import json
from mysql.connector import (connection)
import mysql.connector
import numpy as np
import glob

def geturlhash():
    with open("./urlhashes.json") as data_file:
        data = json.load(data_file)
    return data

def getpageurl(urlhash):
    data = geturlhash()
    for pageurl, pagehash in data.items():
        if pagehash == urlhash:
            return pageurl

def hundreddomain():
    validurl = []
    conn = connection.MySQLConnection(user='root', password='root', port="3306",
                                      host='127.0.0.1',
                                      database='webprintdb', auth_plugin='mysql_native_password')

    query = """SELECT id_mainpage, url FROM websites"""
    cursor = conn.cursor()
    cursor.execute(query)
    for id_mainpage, url in cursor:
        validurl.append(id_mainpage)
        validurl.append(urlparse(url).netloc)
        # validurl.append(urlparse(url[0]).netloc)
    conn.close()
    validurl = np.array(validurl)
    validurl = np.reshape(validurl, (len(validurl) // 2, 2))
    return validurl

def filelist(pathdir, filetype):
    hashesu = []
    for root, dirs, files in os.walk(f"./{pathdir}/"):
        for file in files:
            if file.endswith(".csv") and filetype in file:
                print(file)
                items = file.split('_')
                urlhash = items[2]
                hashesu.append(urlhash)
                # pageurl = getpageurl(urlhash)
    hashesu = list(set(hashesu))
    return hashesu

# hashlist = filelist("includeOLfeature", "TLS")

def validlist(filetype):
    print(filetype.center(60, '-'))
    print('Searching feature files for experiment... ')
    torhash = filelist('includeOLfeature', filetype)       # fingerprints generated from Tor cell traces
    available = []
    for th in torhash:
        files = glob.glob(rf"./includeOLfeature/feature_{filetype}traces_{th}_to_trace_*")
        print(files)
        if len(files) >= 15:
            # print(f"The total number of fingerprints per page {th} is: ", len(files))
            available.append(files)
        else:
            pass
    return available        # return arrays with feature files

def featurelist():
    torlist = []
    for root, dir, files in os.walk('./includeOLfeature/'):
        for file in files:
            if file.endswith('.csv') and 'TOR' in file:
                torlist.append(file)
    return torlist

def create_label():
    target_label=[]
    validurl = hundreddomain()
    filelist = featurelist()
    for x in range(len(filelist)):
        data = geturlhash()
        filehash = filelist[x].split('_')[2]
        for url, savedhash in data.items():
            if filehash == savedhash:
                domain = urlparse(url).netloc
                for y in range(len(validurl)):
                    if domain == validurl[y][1]:
                        target_label.append(validurl[y][0])
                    else:
                        pass
    return target_label

# labels = create_label()
# print(labels)
# validurl = hundreddomain()
# print(len(validurl))
# #
# validurl = hundreddomain()
# print(validurl)
# validurl = np.array(validurl)

# validurl = np.reshape(validurl, (len(validurl)//2, 2))
# print(validurl.shape)
#
# for x in range(len(validurl)):
#     # print(validurl[x][1])       # getting only url: validurl[x][1]
#     print(validurl[x][0])         # getting only id_mainpage