import shutil
import zipfile

import pyshark

import os
import json
import glob
from mysql.connector import (connection)
import mysql.connector
#READ THE DICTIONARY
#GET ONE URL AND HASH
# ASK IF THERE IS FOLDER WITH THOSE HASHES
# GET THE NETWORK TRACES FILES PER CIRCUIT
#PRINT URL

conn = connection.MySQLConnection(user='root', password='@Studyproject1', port="3306",
                                  host='127.0.0.1',
                                  database='webprintdb', auth_plugin='mysql_native_password')


def getmac(interface):

  try:
    mac = open('/sys/class/net/'+interface+'/address').readline()
  except:
    mac = "00:00:00:00:00:00"

  return mac[0:17]



def cleanunzipped():
    for dirname, dirnames, filenames in os.walk('./LOGS'):
        # print path to all subdirectories first.
        for subdirname in dirnames:
            print(dirname, "dirnme")
            print(subdirname, "subdir")
            print(os.path.join(dirname, subdirname))
            path = os.path.join(dirname, subdirname)
            if subdirname == "LOGS":
                shutil.rmtree(path)



def tlscollection(listoftraces):

    StartTime=""
    EntryIP=""
    with open("./urlhashes.json") as data_file:
        data = json.load(data_file)

    for root, dirs, files in os.walk("./LOGS"):
        for file in files:

            if file.endswith(".zip"):
                print(os.path.join(root, file))  # dir
                pathtocap = os.path.join(root, file)
                items = file.split('_')
                print("urlhash ", items[0])
                urlhash = items[0]

                for key, urlvalue in data.items():
                    if key == urlhash:
                        print(key, urlvalue)
                        pageurl=urlvalue


                circid = (items[2].split('.'))[0]
                print("circuit id", circid)

                # get file time


                query= """SELECT start_time, finish_time, load_time FROM timelogs WHERE url = '%s' and circuit_id = '%s' """ % (pageurl, circid)
                print(query)
                cursor = conn.cursor()

                # forget assigning, just execute
                cursor.execute(query)

                for (start_time, finish_time, load_time) in cursor:

                        StartTime = start_time
                        FinishTime = finish_time
                        LoadTime = load_time



                print('Number of rows in the result  for time search is', cursor.rowcount)
                if cursor.rowcount<1:
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


                # end get entry node




                fileToWriteforTLS = open(rf"./TRACES/TLS_{urlhash}_{circid}.txt", "w")
                fileToWriteforTLS.write(rf"URL :{pageurl}" + rf"START TIMESTAMP: {StartTime}" + '\n')

                print("URL: ", pageurl, "--START TIME", StartTime)


                # TLS AND OUTGOING

                with zipfile.ZipFile(pathtocap, 'r') as zip_ref:
                    zip_ref.extractall(root)
                pcapf=root+"/"+root+"/"+urlhash+rf"_pkts_{circid}.cap"

                #with zipfile.ZipFile(pathtocap, 'r') as zfile:
                 #   unpacked = open(rf"./LOGS/{value}/{urlhash}/SNIFFS/{urlhash}_pkts_{circid}.cap", 'w')
                  #  unpacked.write(zfile.read(rf"./LOGS/{value}/{urlhash}/SNIFFS/{urlhash}_pkts_{circid}.cap"))
                   # unpacked.close()

                print("path to unzip", pcapf)

                cap = pyshark.FileCapture(rf"{pcapf}", display_filter=rf'tls and eth.src == 00:0c:29:c5:51:6e and ip.dst=={EntryIP}')

                #for pkt in cap:
                    #print(pkt.tls)
                 #   print("size", pkt.length)
                    #write this to file  with format

                for pkt in cap:
                    try:
                        if (pkt.highest_layer=='TLS') and pkt.sniff_timestamp>start_time and pkt.sniff_timestamp<finish_time:
                            #print("TCP  Trace")
                            print ("Timestamp: " + str(pkt.sniff_timestamp)+ " Entry IP: " + EntryIP + "--Destination: " + " OUTGOING" + "--Source IP: " +  str(pkt.ip.src) + "--Destination IP: " +str(pkt.ip.dst)+ "-- size:" + str (pkt.length))
                            fileToWriteforTLS.write("Timestamp: " + str(pkt.sniff_timestamp)+ "Entry IP: " + EntryIP +"--Destination: " + " OUTGOING" + "--Source IP: " +  str(pkt.ip.src) + "--Destination IP: " +str(pkt.ip.dst)+ "-- size:" + str (pkt.length))

                    except AttributeError():
                        pass

                # TLS INCOMING

                cap2 = pyshark.FileCapture(rf"{pcapf}", display_filter=rf'tls and eth.src != 00:0c:29:c5:51:6e and ip.src=={EntryIP}')

                #for pkt in cap2:
                    #print(pkt.tls)
                 #   print("size", pkt.length)
                    #write this to same file with format

                for pkt2 in cap2:
                    try:
                        if (pkt2.highest_layer == 'TLS') and pkt.sniff_timestamp>=start_time and pkt.sniff_timestamp<=finish_time:
                            # print("TCP  Trace")
                            print("Timestamp: " + str(pkt2.sniff_timestamp) + "--Destination: " + " INCOMING" + "--Source IP: " + str(pkt2.ip.src) + "--Destination IP: " + str(pkt2.ip.dst) + "-- size:" + str(pkt2.length))
                            fileToWriteforTLS.write("Timestamp: " + str(pkt2.sniff_timestamp) + "--Destination: " + " INCOMING" + "--Source IP: " + str(pkt2.ip.src) + "--Destination IP: " + str(pkt2.ip.dst) + "-- size:" + str(pkt2.length))
                    except AttributeError():
                        pass
                fileToWriteforTLS.close()


            #close  the trace file

    #CLEANS THE UNCOMPRESED FILES
    cleanunzipped()


def tcpcollection(listoftraces):

    StartTime = ""
    EntryIP = ""
    with open("./urlhashes.json") as data_file:
        data = json.load(data_file)

    for root, dirs, files in os.walk("./LOGS"):
        for file in files:
            if file.endswith(".zip"):
                print(os.path.join(root, file))  # dir
                pathtocap = os.path.join(root, file)

                items = file.split('_')
                print("urlhash ", items[0])
                urlhash = items[0]

                for key, urlvalue in data.items():
                    if key == urlhash:
                        print(key, urlvalue)
                        pageurl = urlvalue

                circid = (items[2].split('.'))[0]
                print("circuit id", circid)

                # get file time

                query = """SELECT start_time, finish_time, load_time FROM timelogs WHERE url = '%s' and circuit_id = '%s' """ % (pageurl, circid)
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



                #get entry node

                query = """SELECT entry_node, entry_node_ip FROM torlogs WHERE url = '%s' and circuit_id = '%s' """ % (pageurl, circid)
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

                #end get entry node

                fileToWriteforTCP = open(rf"./TRACES/TCP_{urlhash}_{circid}.txt", "w")
                fileToWriteforTCP.write(rf"URL :{pageurl}" + rf"START TIMESTAMP: {StartTime}" + '\n')

                print("URL: ", pageurl, "--START TIME", StartTime)


                with zipfile.ZipFile(pathtocap, 'r') as zip_ref:
                    zip_ref.extractall(root)
                pcapf=root+"/"+root+"/"+urlhash+rf"_pkts_{circid}.cap"


                print("path to unzip", pcapf)

                # TCP AND OUTGOING

                cap = pyshark.FileCapture(rf"{pcapf}", display_filter=rf'tcp and eth.src == 00:0c:29:c5:51:6e and ip.dst=={EntryIP}')

                for pkt in cap:
                    try:
                        if (pkt.highest_layer=='TCP') and pkt.sniff_timestamp>=start_time and pkt.sniff_timestamp<=finish_time:
                            #print("TCP  Trace")
                            print ("Timestamp: " + str(pkt.sniff_timestamp)+ "Entry IP: " + EntryIP+"--Destination: " + " OUTGOING" + "--Source IP: " +  str(pkt.ip.src) + "--Destination IP: " +str(pkt.ip.dst)+ "-- size:" + str (pkt.length) )
                            fileToWriteforTCP.write("Timestamp: " + str(pkt.sniff_timestamp)+ "Entry IP: " + EntryIP +"--Destination: " + " OUTGOING" + "--Source IP: " +  str(pkt.ip.src) + "--Destination IP: " +str(pkt.ip.dst)+ "-- size:" + str (pkt.length))
                    except AttributeError():
                        pass

                    #print(pkt.tcp)
                    #pkt.tcp.pretty_print()


                # TCP INCOMING

                cap2 = pyshark.FileCapture(rf"{pcapf}", display_filter=rf'tcp and eth.src != 00:0c:29:c5:51:6e and ip.src=={EntryIP}')

                for pkt2 in cap2:
                    try:
                        if (pkt2.highest_layer == 'TCP') and pkt.sniff_timestamp>=start_time and pkt.sniff_timestamp<=finish_time:
                            #print("TCP  Trace")
                            print("Timestamp: " + str(pkt2.sniff_timestamp) + "Entry IP: " + EntryIP+"--Destination: " + " INCOMING" + "--Source IP: " + str(pkt2.ip.src) + "--Destination IP: " + str(pkt2.ip.dst) + "-- size:" + str(pkt2.length))
                            fileToWriteforTCP.write("Timestamp: " + str(pkt2.sniff_timestamp) + "Entry IP: " + EntryIP + "--Destination: " + " INCOMING" + "--Source IP: " + str(pkt2.ip.src) + "--Destination IP: " + str(pkt2.ip.dst) + "-- size:" + str(pkt2.length))

                    except AttributeError():
                        pass
                fileToWriteforTCP.close()
                    #print(pkt.tcp)
                    #pkt.tcp.pretty_print()

    #CLEANS THE UNCOMPRESED FILES
    cleanunzipped()



def torcellcollection(listoftraces):
    with open("./urlhashes.json") as data_file:
        data = json.load(data_file)

    for root, dirs, files in os.walk("./LOGS"):
        for file in files:
            if file.endswith(".zip"):
                print(os.path.join(root, file))  # dir
                pathtocap = os.path.join(root, file)

                items = file.split('_')
                print("urlhash ", items[0])
                urlhash = items[0]

                for key, urlvalue in data.items():
                    if key == urlhash:
                        print(key, urlvalue)
                        pageurl = urlvalue


                circid = (items[2].split('.'))[0]
                print("circuit id", circid)

                # get time


                query = """SELECT start_time, finish_time, load_time FROM timelogs WHERE url = '%s' and circuit_id = '%s' """ % (pageurl, circid)
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

                fileToWriteforTOR = open(rf"./TRACES/TOR_{urlhash}_{circid}.txt", "w")
                fileToWriteforTOR.write(rf"URL :{pageurl}" + rf"START TIMESTAMP: {StartTime}" + '\n')

                print("URL: ", pageurl, "--START TIME", StartTime)

                # end get entry node

                with zipfile.ZipFile(pathtocap, 'r') as zip_ref:
                    zip_ref.extractall(root)
                pcapf = root + "/" + root + "/" + urlhash + rf"_pkts_{circid}.cap"

                print("path to unzip", pcapf)

                # TOR AND INCOMING


                cap = pyshark.FileCapture(rf"{pcapf}", display_filter="tls ")#include_raw=True, use_json=True

                for pkt in cap:
                    #print(pkt) #pkt.tcp
                    #print("packet lenght1", pkt.length)
                    #print("Size of TCP layer", pkt['tcp'].len)
                    #packettime = pkt.sniff_time
                    #payload= pkt.payload
                    #print("payload", payload)
                    #print("time ", packettime)
                    #print(pkt)
                    #print(dir(pkt))
                    #laye=pkt.layers
                    #print(laye)
                    #print(dir(pkt.tcp))

                    if pkt.ip.src==EntryIP and int(pkt.tcp.len)>=512 and pkt.sniff_timestamp>=start_time and pkt.sniff_timestamp<=finish_time:

                        try:
                            print ("Timestamp: " + str(pkt.sniff_timestamp)+ " Entry IP: " + EntryIP + "--Destination: " + " INCOMING" + "--Source IP: " +  str(pkt.ip.src) + "--Destination IP: " +str(pkt.ip.dst)+ "-- size:" + str (pkt.length))
                            fileToWriteforTOR.write("Timestamp: " + str(pkt.sniff_timestamp)+ " Entry IP: " + EntryIP + "--Destination: " + " INCOMING" + "--Source IP: " +  str(pkt.ip.src) + "--Destination IP: " +str(pkt.ip.dst)+ "-- size:" + str (pkt.length))

                            #print(pkt.tcp)
                        except AttributeError as e:
                            print("Attribute error",e)


                # TOR OUTGOING

                    if pkt.ip.dst==EntryIP and int(pkt.tcp.len)>=512 and pkt.sniff_timestamp>=start_time and pkt.sniff_timestamp<=finish_time:

                        try:
                            print ("Timestamp: " + str(pkt.sniff_timestamp)+ " Entry IP: " + EntryIP + "--Destination: " + " OUTGOING" + "--Source IP: " +  str(pkt.ip.src) + "--Destination IP: " +str(pkt.ip.dst)+ "-- size:" + str (pkt.length))
                            fileToWriteforTOR.write("Timestamp: " + str(pkt.sniff_timestamp)+ " Entry IP: " + EntryIP + "--Destination: " + " OUTGOING" + "--Source IP: " +  str(pkt.ip.src) + "--Destination IP: " +str(pkt.ip.dst)+ "-- size:" + str (pkt.length))


                            #print(pkt.tcp)
                        except AttributeError as e:
                            print("Attribute error",e)
                #cap2 = pyshark.FileCapture(rf"{pathtocap}", display_filter=' ip.dst == 192.166.245.119 and tcp.len>=512') #include_raw=True, use_json=True

                #for pkt2 in cap2:
                    #print(pkt2)
                    #print("packet lenght2", pkt2.length)
                 #   print("Size of TCP layer", pkt2['tcp'].len)
                  #  packettime = pkt2.sniff_time
                   # print("time ", packettime)
                    #print(pkt2)

                fileToWriteforTOR.close()


    #CLEANS UNCOMPRESSSED
    cleanunzipped()



def getentrynode(pathtocap):

    #pcapfile = sys.argv[1]
    pcapfile=str(pathtocap)
    print("pcap file to get entry: ", pcapfile)
    #nodefile = './nodes.txt'
    torports = ["9001","9002","9030","9031","9040","9050","9051","9150"]

    flpt = open('./nodelist', 'r')


    print(' 1- Detecting TOR nodes')

    cmd= 'tshark -2 -r ' + pcapfile + ' -T fields -e ip.dst | sort -u'
    ipdst = os.popen(cmd).readlines()

    cmd= 'tshark -2 -r ' + pcapfile + ' -T fields -e ip.src | sort -u'
    ipsrc = os.popen(cmd).readlines()

    ips = dict([(a,1) for a in ipdst+ipsrc]).keys()

    nodosidentificados = []
    for lnpt in flpt:
        if lnpt in ips:
            print(' TOR node detected in the following IP: ' + lnpt.rstrip('\n'))
            nodo=lnpt.rstrip('\n')
            nodosidentificados.append(lnpt)

    flpt.close

    print(nodo)
    return nodo


def getnetworktraces():
    traceslist = []
    with open("./urlhashes.json") as data_file:
        data = json.load(data_file)

    for root, dirs, files in os.walk("./LOGS"):
        for file in files:
            if file.endswith(".cap"):
                print(os.path.join(root, file))  # dir
                pathtocap = os.path.join(root, file)
                traceslist.append(pathtocap)

    return traceslist


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




def menu():
    ##### MENU
    ans=True
    while ans:
        print ("""
        1.Collect TCP traces
        2.Collect TLS traces
        3.Collect TOR traces
        4.Verification of Broken Pages
        5.Exit
        """)
        ans=input("What would you like to do? ")
        if ans=="1":
          print("\n Collecting TCP traces...")
          listoftraces=getnetworktraces()
          tcpcollection(listoftraces)
        elif ans=="2":
          print("\n Collecting TLS traces")
          listoftraces = getnetworktraces()
          tlscollection(listoftraces)
        elif ans=="3":
          print("\n Collecting TOR traces")
          listoftraces = getnetworktraces()
          torcellcollection(listoftraces)
        elif ans=="4":
          print("\n Verificacion of broken pages")
          verification()
        elif ans=="5":
          break
        elif ans !="":
          print("\n Not Valid Choice Try again")







menu()
conn.close()



