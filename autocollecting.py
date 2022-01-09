import shutil
import zipfile
import pyshark
import asyncio
import os
import json
import glob
from mysql.connector import (connection)
import mysql.connector
import mergetraces

conn = connection.MySQLConnection(user='root', password='root', port="3306",
                                  host='127.0.0.1',
                                  database='webprintdb', auth_plugin='mysql_native_password')

def geturlhash():
    with open("./hashes.json") as data_file:
        data = json.load(data_file)
    return data

def getpageurl(urlhash):
    data = geturlhash()
    for urlvalue, key in data.items():
        if key == urlhash:
            pageurl = urlvalue
            return pageurl

def cleanunzipped():
    for dirname, dirnames, filenames in os.walk('./LOGS'):
        for subdirname in dirnames:
            print(dirname, "dirnme")
            print(subdirname, "subdir")
            print(os.path.join(dirname, subdirname))
            path = os.path.join(dirname, subdirname)
            if subdirname == "LOGS":
                shutil.rmtree(path)

def tlscollection():
    StartTime = ""
    EntryIP = ""

    for root, dirs, files in os.walk("./LOGS"):
        for file in files:
            if file.endswith(".zip"):
                print(os.path.join(root, file))  # dir
                pathtocap = os.path.join(root, file)
                items = file.split('_')
                print("urlhash ", items[0])
                urlhash = items[0]
                pageurl = getpageurl(urlhash)
                circid = (items[2].split('.'))[0]
                print("circuit id", circid)

                    # get file time

                query = """SELECT start_time, finish_time, load_time FROM timelogs WHERE url = '%s' and circuit_id = '%s' """ % (pageurl, circid)
                print(query)
                cursor = conn.cursor()
                cursor.execute(query)

                for (start_time, finish_time, load_time) in cursor:
                    StartTime = start_time
                    FinishTime = finish_time
                    LoadTime = load_time

                print('Number of rows in the result  for time search is', cursor.rowcount)
                if cursor.rowcount < 1:
                    print("TIME RECORDS NOT FOUND")
                    print("trace will be deleted")
                    # delete here the trace
                    os.remove(pathtocap)
                    cursor.close()
                    continue

                cursor.close()

                # get entry node

                query = """SELECT entry_node, entry_node_ip FROM torlogs WHERE url = '%s' and circuit_id = '%s' """ % (
                pageurl, circid)
                print(query)
                cursor = conn.cursor()

                # forget assigning, just execute
                cursor.execute(query)

                for (entry_node, entry_node_ip) in cursor:
                    EntryIP = entry_node_ip

                print('Number of rows in the result  for entry search is', cursor.rowcount)
                if cursor.rowcount < 1:
                    print("TOR RECORDS NOT FOUND")
                    print("trace will be deleted")
                                # delete here the trace
                    os.remove(pathtocap)
                    cursor.close()
                    continue
                cursor.close()

                fileToWriteforTLS = open(rf"./TRACES/TLS_{urlhash}_{circid}.txt", "w")
                fileToWriteforTLS.write(rf"URL :{pageurl}" + '\t' + rf"START TIMESTAMP: {StartTime}" + '\n')
                with zipfile.ZipFile(pathtocap, 'r') as zip_ref:
                    zip_ref.extractall(root)
                pcapf = root + "/" + root + "/" + urlhash + rf"_pkts_{circid}.cap"
                print("path to unzip", pcapf)

                cap = pyshark.FileCapture(rf"{pcapf}", display_filter='tls')
                for pkt in cap:
                    try:
                        if (pkt.highest_layer == 'TLS') and pkt.sniff_timestamp >= start_time and pkt.sniff_timestamp <= finish_time and pkt.eth.src == '70:2c:1f:11:2e:93' and pkt.ip.dst == rf'{EntryIP}':
                            print("Timestamp: " + str(
                                            pkt.sniff_timestamp) + "--Entry IP: " + EntryIP + "--Destination: OUTGOING--Source IP: " + str(
                                            pkt.ip.src) + "--Destination IP: " + str(pkt.ip.dst) + "-- size:" + str(pkt.length))
                            fileToWriteforTLS.write(rf"Timestamp: {pkt.sniff_timestamp}--Entry IP: {EntryIP} --Destination: OUTGOING--Source IP: {pkt.ip.src}--Destination IP: {pkt.ip.dst}-- size:{pkt.length}"+'\n')


                        elif pkt.highest_layer == 'TLS' and pkt.sniff_timestamp >= start_time and pkt.sniff_timestamp <= finish_time and pkt.eth.src != '70:2c:1f:11:2e:93' and pkt.ip.src == rf'{EntryIP}':
                            print("Timestamp: " + str(pkt.sniff_timestamp)+"--Entry IP: " + EntryIP + "--Destination: INCOMING--Source IP: " + str(pkt.ip.src) + "--Destination IP: " + str(pkt.ip.dst) + "-- size:" + str(pkt.length))
                            fileToWriteforTLS.write(rf"Timestamp: {pkt.sniff_timestamp}--Entry IP: {EntryIP}--Destination: INCOMING--Source IP: {pkt.ip.src}--Destination IP: {pkt.ip.dst}-- size:{pkt.length}"+'\n')

                    except AttributeError():
                        pass
                cap.close()
                fileToWriteforTLS.close()

    #CLEANS THE UNCOMPRESED FILES
    cleanunzipped()

def tcpcollection():
    StartTime = ""
    EntryIP = ""

    for root, dirs, files in os.walk("./LOGS"):
        for file in files:
            if file.endswith(".zip"):
                print(os.path.join(root, file))  # dir
                pathtocap = os.path.join(root, file)

                items = file.split('_')
                print("urlhash ", items[0])
                urlhash = items[0]
                pageurl = getpageurl(urlhash)
                circid = (items[2].split('.'))[0]
                print("circuit id", circid)

                # get file time
                query = """SELECT start_time, finish_time, load_time FROM timelogs WHERE url = '%s' and circuit_id = '%s' """ % (
                pageurl, circid)
                print(query)
                cursor = conn.cursor()

                # forget assigning, just execute
                cursor.execute(query)

                for (start_time, finish_time, load_time) in cursor:
                    StartTime = start_time
                    FinishTime = finish_time
                    LoadTime = load_time

                print('Number of rows in the result  for time search is', cursor.rowcount)
                if cursor.rowcount < 1:
                    print("TIME RECORDS NOT FOUND")
                    print("trace will be deleted")
                    # delete here the trace
                    os.remove(pathtocap)
                    cursor.close()
                    continue

                cursor.close()

                # get entry node

                query = """SELECT entry_node, entry_node_ip FROM torlogs WHERE url = '%s' and circuit_id = '%s' """ % (
                pageurl, circid)
                cursor = conn.cursor()

                # forget assigning, just execute
                cursor.execute(query)

                for (entry_node, entry_node_ip) in cursor:
                    EntryIP = entry_node_ip

                print('Number of rows in the result  for entry search is', cursor.rowcount)

                if cursor.rowcount<1:
                    print("TOR RECORDS NOT FOUND")
                    print("trace will be deleted")
                    # delete here the trace
                    os.remove(pathtocap)
                    cursor.close()
                    continue
                cursor.close()

                fileToWriteforTCP = open(rf"./TRACES/TCP_{urlhash}_{circid}.txt", "w")
                fileToWriteforTCP.write(rf"URL :{pageurl}" + '\t' + rf"START TIMESTAMP: {StartTime}" + '\n')
                print("URL: ", pageurl, '\t', ''"--START TIME", StartTime)

                with zipfile.ZipFile(pathtocap, 'r') as zip_ref:
                    zip_ref.extractall(root)
                pcapf=root+"/"+root+"/"+urlhash+rf"_pkts_{circid}.cap"

                print("path to unzip", pcapf)

                # TCP AND OUTGOING
                cap = pyshark.FileCapture(rf"{pcapf}", display_filter='tcp')

                for pkt in cap:
                    try:
                        if (pkt.highest_layer=='TCP') and pkt.sniff_timestamp>=start_time and pkt.sniff_timestamp<=finish_time and pkt.eth.src == '70:2c:1f:11:2e:93' and pkt.ip.dst == EntryIP:
                            print ("Timestamp: " + str(pkt.sniff_timestamp)+ "--Entry IP: " + EntryIP+"--Destination: OUTGOING--Source IP: " +  str(pkt.ip.src) + "--Destination IP: " + str(pkt.ip.dst)+ "-- size:" + str(pkt.length))
                            fileToWriteforTCP.write("Timestamp: " + str(pkt.sniff_timestamp)+ "--Entry IP: " + EntryIP +"--Destination: OUTGOING--Source IP: " +  str(pkt.ip.src) + "--Destination IP: " + str(pkt.ip.dst)+ "-- size:" + str(pkt.length)+'\n')

                        elif (pkt.highest_layer == 'TCP') and pkt.sniff_timestamp>=start_time and pkt.sniff_timestamp<=finish_time and pkt.eth.src != '70:2c:1f:11:2e:93' and pkt.ip.src == EntryIP:
                            print("Timestamp: " + str(pkt.sniff_timestamp) + "--Entry IP: " + EntryIP+"--Destination: INCOMING--Source IP: " + str(pkt.ip.src) + "--Destination IP: " + str(pkt.ip.dst) + "-- size:" + str(pkt.length))
                            fileToWriteforTCP.write("Timestamp: " + str(pkt.sniff_timestamp) + "--Entry IP: " + EntryIP + "--Destination: INCOMING--Source IP: " +str(pkt.ip.src) + "--Destination IP: " + str(pkt.ip.dst) + "-- size:" + str(pkt.length)+'\n')

                    except AttributeError():
                        pass
                cap.close()
                fileToWriteforTCP.close()

    #CLEANS THE UNCOMPRESED FILES
    cleanunzipped()


def torcellcollection():
    for root, dirs, files in os.walk("./LOGS"):
        for file in files:
            if file.endswith(".zip"):
                pathtocap = os.path.join(root, file)
                print(pathtocap)
                items = file.split('_')
                print("urlhash ", items[0])
                urlhash = items[0]
                circid = (items[2].split('.'))[0]
                print("circuit id", circid)
                pageurl = getpageurl(urlhash)

                query = """SELECT start_time, finish_time, load_time FROM timelogs WHERE url = '%s' and circuit_id = '%s' """ % (
                            pageurl, circid)
                print(query)
                cursor = conn.cursor()

                            # forget assigning, just execute
                cursor.execute(query)

                for (start_time, finish_time, load_time) in cursor:
                    StartTime = start_time
                    FinishTime = finish_time
                    LoadTime = load_time

                print('Number of rows in the result  for time search is', cursor.rowcount)
                if cursor.rowcount < 1:
                    print("TIME RECORDS NOT FOUND")
                    print("trace will be deleted")
                                # delete here the trace
                    os.remove(pathtocap)
                    cursor.close()
                    continue
                cursor.close()

                            # get entry node

                query = """SELECT entry_node, entry_node_ip FROM torlogs WHERE url = '%s' and circuit_id = '%s' """ % (pageurl, circid)
                print(query)
                cursor = conn.cursor()

                cursor.execute(query)

                for (entry_node, entry_node_ip) in cursor:
                    EntryIP = entry_node_ip

                print('Number of rows in the result  for entry search is', cursor.rowcount)

                if cursor.rowcount < 1:
                    print("TOR RECORDS NOT FOUND")
                    print("trace will be deleted")
                                # delete here the trace
                    os.remove(pathtocap)
                    cursor.close()

                cursor.close()

                with open(rf"./TRACES/TOR_{urlhash}_{circid}.txt", "w") as fileToWriteforTOR:
                    fileToWriteforTOR.write(rf"URL :{pageurl}" + '\t' + rf"START TIMESTAMP: {StartTime}" + '\n')
                    print("URL: ", pageurl, "--START TIME", StartTime)

                                # end get entry node

                    with zipfile.ZipFile(pathtocap, 'r') as zip_ref:
                        zip_ref.extractall(root)
                    pcapf = root + "/" + root + "/" + urlhash + rf"_pkts_{circid}.cap"

                    print("path to unzip", pcapf)

                                # TOR AND INCOMING
                    cap = pyshark.FileCapture(rf"{pcapf}", display_filter="tls")
                    for pkt in cap:
                        if pkt.highest_layer=='TLS' and pkt.ip.src== EntryIP and pkt.sniff_timestamp>=start_time and pkt.sniff_timestamp<=finish_time:
                            if ('record_content_type' in pkt.tls.field_names) and int(pkt.tls.record_length) >= 512:
                                try:
                                    length = pkt.tls.record_length
                                    print ("Timestamp: " + str(pkt.sniff_timestamp)+ "--Entry IP: " + EntryIP + "--Destination: INCOMING--Source IP: " +  str(pkt.ip.src) + "--Destination IP: " +str(pkt.ip.dst)+ "-- size:" + str(length))
                                    fileToWriteforTOR.write(rf"Timestamp: {pkt.sniff_timestamp}--Entry IP: {EntryIP}--Destination: INCOMING--Source IP: {pkt.ip.src}--Destination IP: {pkt.ip.dst}-- size:{length}"+'\n')
                                except AttributeError as e:
                                    print("Attribute error", e)

                        elif pkt.highest_layer=='TLS' and pkt.ip.dst==EntryIP and pkt.sniff_timestamp>=start_time and pkt.sniff_timestamp<=finish_time:
                            if ('record_content_type' in pkt.tls.field_names) and int(pkt.tls.record_length) >= 512:
                                try:
                                    length = pkt.tls.record_length
                                    print("Timestamp: " + str(pkt.sniff_timestamp)+ "--Entry IP: " + EntryIP + "--Destination: OUTGOING--Source IP: " + str(pkt.ip.src) + "--Destination IP: " + str(pkt.ip.dst)+ "-- size:" + str(length))
                                    fileToWriteforTOR.write(rf"Timestamp: {pkt.sniff_timestamp}--Entry IP: {EntryIP}--Destination: OUTGOING--Source IP: {pkt.ip.src}--Destination IP: {pkt.ip.dst}-- size:{length}"+'\n')
                                except AttributeError as e:
                                    print("Attribute error", e)
                    cap.close()
                fileToWriteforTOR.close()

    cleanunzipped()


def verification():

    with open('./LOGS/brokenpages.txt') as file:
        lines = file.readlines()
        lines = [line.rstrip() for line in lines]

    print(lines)

    for line in lines:

        filestodelete = glob.glob(rf"./TRACES/*{line}.txt")
        print("URLs files to delete", filestodelete)

        for fname in filestodelete:

            file_path = fname

            try:

                os.remove(file_path)
            except OSError as e:
                print("Error: %s : %s" % (file_path, e.strerror))




def main():
    torcellcollection()
    tlscollection()
    tcpcollection()
    mergetraces.main()


if __name__ == '__main__':
    main()
    conn.close()



