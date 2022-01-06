import json
import os
import re
import pandas as pd
import numpy as np
import statistics
from collections import Counter

def geturlhash():
    with open("./urlhashes.json") as data_file:
        data = json.load(data_file)
    return data

def findfile():
    data = geturlhash()
    filelist = []
    for root, dirs, files in os.walk("./outlierfree"):
        for file in files:
            # path = os.path.join(root, file)  # dir
            filelist.append(file)
            filehash = file[13:]
            for key, url in data.items():
                if key == filehash:
                    furl = url
                    # print(url)
    return filelist

def funcA(newtrace):     # count the number of total/incoming/outgoing packet
    print ('Function A'.center(80, '-'))
    pkt = 0
    incomingpkt = 0
    outgoingpkt = 0
    for j in range(len(newtrace)):
        if 'Timestamp' in newtrace[j]:  # start of the line for each packet
            pkt += 1
        elif 'INCOMING' in newtrace[j]:
            incomingpkt += 1
        elif 'OUTGOING' in newtrace[j]:
            outgoingpkt += 1
        else:
            pass

    if outgoingpkt == 0 or incomingpkt == 0:               # for normal communication, incomingpkt = outcomingpkt or has similar number
        print("You need to consider this trace again. ")
        tpkt = pkt
        ipart = incomingpkt
        opart = outgoingpkt
    elif incomingpkt + outgoingpkt == pkt:
        print('INCOMING Nr + OUTGOING Nr = total number of packets ')
        print(pkt, incomingpkt/pkt, outgoingpkt/pkt)
        tpkt = pkt
        ipart = incomingpkt/pkt
        opart = outgoingpkt/pkt
    else:                           # if incomingpkt + outgoingpkt != pkt?
        print("else case")
        print(pkt, incomingpkt, outgoingpkt)
        tpkt = pkt
        ipart = incomingpkt / pkt
        opart = outgoingpkt / pkt
    return tpkt, ipart, opart

def funcB(newtrace):
    print ('Function B'.center(80, '-'))
    pkt = 0
    outorderinglist = []
    inorderinglist = []
    for j in range(len(newtrace)):
        if 'Timestamp' in newtrace[j]:
            pkt += 1
            if j + 9 != len(newtrace) and 'OUTGOING' in newtrace[j + 4]:
                if j + 19 <= len(newtrace) and 'OUTGOING' in newtrace[j + 14]:
                    # print("just found continuous outgoing packet " + str(pkt))
                    outorderinglist.append(pkt)
            elif j + 9 != len(newtrace) and 'INCOMING' in newtrace[j + 4]:
                if j + 19 <= len(newtrace) and 'INCOMING' in newtrace[j + 14]:
                    # print('just found continuous incoming packet ' + str(pkt))
                    inorderinglist.append(pkt)
    if len(inorderinglist) > 1 and len(outorderinglist) > 1:
        binstd = statistics.stdev(inorderinglist)
        print('INCOMING STD: ' + str(binstd))
        binav = sum(inorderinglist) / len(inorderinglist)
        print('INCOMING AVERAGE: ' + str(binav))
        boutstd = statistics.stdev(outorderinglist)
        print('OUTGOING STD: ' + str(boutstd))
        boutav = sum(outorderinglist) / len(outorderinglist)
        print('OUTGOING AVERAGE: ' + str(boutav))
        return binstd, binav, boutstd, boutav
    elif len(inorderinglist) > 1 and len(outorderinglist) <= 1:
        binstd = statistics.stdev(inorderinglist)
        print('INCOMING STD: ' + str(binstd))
        binav = sum(inorderinglist) / len(inorderinglist)
        print('INCOMING AVERAGE: ' + str(binav))
        print(rf'There is {len(outorderinglist)} for successive OUTGOING packets. We cannot get statistic values. ')
        return binstd, binav, None, None
    elif len(inorderinglist) <= 1 and len(outorderinglist) > 1:
        boutstd = statistics.stdev(outorderinglist)
        print('OUTGOING STD: ' + str(boutstd))
        boutav = sum(outorderinglist) / len(outorderinglist)
        print('OUTGOING AVERAGE: ' + str(boutav))
        print(rf'There is {len(inorderinglist)} for successive INCOMING packets. We cannot get statistic values. ')
        return None, None, boutstd, boutav
    else:
        print(rf'Since there is {len(inorderinglist)} and {len(outorderinglist)}, we cannot compute statistical values.')
        return None, None, None, None


def incomingtime(newtrace):
    timelist = []
    for j in range(len(newtrace)):              # consider all possibilities
        if j != 0 and 'INCOMING' in newtrace[j]:
            if newtrace[j-3] == 'Entry':
                timelist.append(str(newtrace[j-4]).split('--')[0])
            elif newtrace[j-3]!= 'Entry' and 'Entry' in newtrace[j-3]:
                if '--' in newtrace[j-3]:
                    timelist.append(str(newtrace[j-3]).split('--')[0])
                elif '\'' in newtrace[j-4]:
                    timelist.append(str(newtrace[j - 4]).split('\'')[1])
                else:
                    timelist.append(newtrace[j-3][:-5])
            else:
                timelist.append(str(newtrace[j-1]).split('--')[0])
    return timelist

def outgoingtime(newtrace):
    timelist = []
    for j in range(len(newtrace)):              # consider all possibilities
        if j != 0 and 'OUTGOING' in newtrace[j]:
            if newtrace[j-3] == 'Entry':
                timelist.append(str(newtrace[j-4]).split('--')[0])
            elif newtrace[j-3]!= 'Entry' and 'Entry' in newtrace[j-3]:
                if '--' in newtrace[j-3]:
                    timelist.append(str(newtrace[j-3]).split('--')[0])
                elif '\'' in newtrace[j-4]:
                    timelist.append(str(newtrace[j - 4]).split('\'')[1])
                else:
                    timelist.append(newtrace[j-3][:-5])
            else:
                timelist.append(str(newtrace[j-1]).split('--')[0])
    return timelist

def funcG(newtrace):
    print ('Function G'.center(80, '-'))
    intransmission = []
    outtransmission = []
    intimelist = incomingtime(newtrace)
    outtimelist = outgoingtime(newtrace)
    intransmission.append(float(intimelist[len(intimelist) - 1]) - float(intimelist[0]))
    outtransmission.append(float(outtimelist[len(outtimelist) - 1]) - float(outtimelist[0]))
    iq1 = np.percentile(intransmission, 25)
    iq2 = np.percentile(intransmission, 50)
    iq3 = np.percentile(intransmission, 75)
    oq1 = np.percentile(outtransmission, 25)
    oq2 = np.percentile(outtransmission, 50)
    oq3 = np.percentile(outtransmission, 75)

    return iq1, iq2, iq3, oq1, oq2, oq3

def chunk(lst, n):
    for w in range(0, len(lst), n):
        yield lst[w:w+n]

def funcC(newtrace):
    print ('Function C'.center(80, '-'))
    pkt = 0
    traceline = []
    for j in range(len(newtrace)):
        if 'Timestamp' in newtrace[j] and 'size' in newtrace[j + 9]:  # the start and end of the line
            pkt += 1
            pktline = newtrace[j] + newtrace[j + 1] + newtrace[j + 2] + newtrace[
                j + 3] + newtrace[j + 4] + newtrace[j + 5] + newtrace[j + 6] + newtrace[j + 7] + newtrace[
                          j + 8] + newtrace[j + 9]
            traceline.append(pktline)
        else:
            pass
    traceline.append(newtrace[len(newtrace)-1])

    twenty = chunk(traceline, 20)
    twenty = list(twenty)
    lipkt = []
    print(rf'There are {len(twenty)} chunks in the trace. ')
    print(' ** In each chunk, there are 20 packets. ** ')

    for m in range(len(twenty)):
        ipkt = 0
        for element in twenty[m]:
            if 'INCOMING' in element:
                ipkt += 1
            else:
                pass
        lipkt.append(ipkt)

    if len(twenty) > 1:
        stdlipkt = statistics.stdev(lipkt)
        print('STD: ' + str(stdlipkt))
        meanlipkt = statistics.mean(lipkt)
        print('MEAN: ' + str(meanlipkt))
        medianlipkt = statistics.median(lipkt)
        print('MEDIAN: ' + str(medianlipkt))
        maxlipkt = max(lipkt)
        print('MAX: ' + str(maxlipkt))
        return stdlipkt, meanlipkt, medianlipkt, maxlipkt
    else:
        print(rf'Since there is {len(twenty)}, we cannot compute statistical values from chunk. ')
        return None, None, None, None


def funcD(newtrace):
    print ('Function D'.center(80, '-'))

    pkt = 0
    first = []
    for j in range(len(newtrace)):
        if 'Timestamp' in newtrace[j] and 'size' in newtrace[j + 9]:  # start of the line for each packet
            pkt += 1
            if pkt <= 30:
                pktline = newtrace[j] + newtrace[j + 1] + newtrace[j + 2] + newtrace[
                    j + 3] + newtrace[j + 4] + newtrace[j + 5] + newtrace[j + 6] + newtrace[j + 7] + newtrace[
                              j + 8] + newtrace[j + 9]
                first.append(pktline)
            else:
                pass
    ipkt = 0
    opkt = 0
    for x in range(len(first)):
        if 'INCOMING' in first[x]:
            ipkt += 1
        elif 'OUTGOING' in first[x]:
            opkt += 1
        else:
            pass

    lpkt = 0
    last = []
    for m in reversed(range(len(newtrace))):
        if 'Timestamp' in newtrace[m] and 'size' in newtrace[m + 9]:
            lpkt += 1
            if lpkt <= 30:
                lpktline = newtrace[m] + newtrace[m+ 1] + newtrace[m+ 2] + newtrace[
                    m+ 3] + newtrace[m+ 4] + newtrace[m+ 5] + newtrace[m+ 6] + newtrace[m+ 7] + newtrace[m+8] + newtrace[m+9]
                last.append(lpktline)
            else:
                pass
    lipkt = 0
    lopkt = 0
    for y in range(len(last)):
        if 'INCOMING' in last[y]:
            lipkt += 1
        elif 'OUTGOING' in last[y]:
            lopkt += 1
        else:
            pass
    print(rf'In first 30 packets, there are {ipkt} INCOMING packets. ')
    print(rf'In first 30 packets, there are {opkt} OUTGOING packets. ')
    print(rf'In last 30 packets, there are {lipkt} INCOMING packets. ')
    print(rf'In last 30 packets, there are {lopkt} OUTGOING packets. ')
    return ipkt, opkt, lipkt, lopkt         # get the value in main part and attach into csv at once

def funcF(newtrace):
    itstamp = []
    otstamp = []
    for j in range(len(newtrace)):
        if 'INCOMING' in newtrace[j]:
            iptime = str(newtrace[j - 3]).strip('\'')[:-8]
            itstamp.append(float(iptime))
        elif 'OUTGOING' in newtrace[j]:
            optime = str(newtrace[j - 3]).strip('\'')[:-8]
            otstamp.append(float(optime))
        else:
            pass

    outintertime = []
    for k in range(len(otstamp)):
        if k > 0:
            outintertime.append(otstamp[k] - otstamp[k - 1])
    inintertime = []
    for l in range(len(itstamp)):
        if l > 0:
            inintertime.append(itstamp[l] - itstamp[l - 1])

    if len(inintertime) > 1 and len(outintertime) > 1:
        inintermax = max(inintertime)
        print('INCOMING MAX: ' + str(inintermax))
        inintermean = statistics.mean(inintertime)
        print('INCOMING MEAN: ' + str(inintermean))
        ininterstd = statistics.stdev(inintertime)
        print('INCOMING STD: ' + str(ininterstd))
        ininterq3 = np.percentile(inintertime, 75)
        print('INCOMING 3rd QUARTILE: ' + str(ininterq3))

        outintermax = max(outintertime)
        print('OUTGOING MAX: ' + str(outintermax))
        outintermean = statistics.mean(outintertime)
        print('OUTGOING MEAN: ' + str(outintermean))
        outinterstd = statistics.stdev(outintertime)
        print('OUTGOING STD: ' + str(outinterstd))
        outinterq3 = np.percentile(outintertime, 75)
        print('OUTGOING 3rd QUARTILE: ' + str(outinterq3))
        return inintermax, inintermean, ininterstd, ininterq3, outintermax, outintermean, outinterstd, outinterq3

    elif len(inintertime) > 1 and len(outintertime) <= 1:
        inintermax = max(inintertime)
        print('INCOMING MAX: ' + str(inintermax))
        inintermean = statistics.mean(inintertime)
        print('INCOMING MEAN: ' + str(inintermean))
        ininterstd = statistics.stdev(inintertime)
        print('INCOMING STD: ' + str(ininterstd))
        ininterq3 = np.percentile(inintertime, 75)
        print('INCOMING 3rd QUARTILE: ' + str(ininterq3))
        print(rf'There is {len(outintertime)}. We cannot compute statistical values. ')
        return inintermax, inintermean, ininterstd, ininterq3, None, None, None, None

    elif len(inintertime) <= 1 and len(outintertime) > 1:
        outintermax = max(outintertime)
        print('OUTGOING MAX: ' + str(outintermax))
        outintermean = statistics.mean(outintertime)
        print('OUTGOING MEAN: ' + str(outintermean))
        outinterstd = statistics.stdev(outintertime)
        print('OUTGOING STD: ' + str(outinterstd))
        outinterq3 = np.percentile(outintertime, 75)
        print('OUTGOING 3rd QUARTILE: ' + str(outinterq3))
        print(rf'There is {len(inintertime)}. We cannot compute statistical values. ')
        return None, None, None, None, outintermax, outintermean, outinterstd, outinterq3

def uniquevalue(list):
    arr = np.array(list)
    return np.unique(arr)

def sizepercentage(list, ulist):       # to get percentage of each unique value
    count = Counter(list)           # list with size of packet
    pc = []
    for v in range(len(ulist)):
        for size1, value in count.items():
            if ulist[v] == size1:
                present = '%.3f' % (value * 100 / len(list))
                # print(f'{size1}: {present}%')
                pc.append(f'{size1}: {present}%')
    if len(pc) != 0:
        comparison = []
        for percent in pc:
            comparison.append(percent.split(':')[1])

        for idx in pc:
            if max(comparison) == idx.split(':')[1]:
                index = idx.split(':')[0]
                maxpercent = max(comparison)
                print('UNIQUE SIZE: ', index, maxpercent)  # size that has been sent mostly
                return index, maxpercent
    else:
        print('There is not enough data to get unique size of packet. ')
        return None, None


def findip(newtrace):
    srclist = []
    dstlist = []
    for j in range(len(newtrace)):
        if 'Source' in newtrace[j]:
            srclist.append(str(newtrace[j + 2]).split('--')[0])
            dstlist.append(str(newtrace[j + 4]).strip('--'))
    return srclist, dstlist

def dominatingip(list, ulist):
    count = Counter(list)  # list with size of packet
    pcent = []
    for v in range(len(ulist)):
        for ip, value in count.items():
            if ulist[v] == ip:
                present = '%.3f' % (value * 100 / len(list))
                # print(f'{size1}: {present}%')
                pcent.append(f'{ip}: {present}%')

    if len(pcent) != 0:
        comparison = []
        for srip in pcent:
            comparison.append(srip.split(':')[1])

        for idx in pcent:
            if max(comparison) == idx.split(':')[1]:
                index = idx.split(':')[0]
                maxpercent = max(comparison)
                return index, maxpercent
    else:
        print('There is not enough data to get unique IP address of packet. ')
        return None, None

def ofunc2(newtrace):
    srclist, dstlist = findip(newtrace)
    uniqsrc = uniquevalue(srclist)
    print(f'There are total {len(srclist)} source IP addresses and {len(uniqsrc)} of unique IP addresses in the trace. ')
    uniqdst = uniquevalue(dstlist)
    print(f'There are total {len(dstlist)} destination IP addresses and {len(uniqdst)} of unique IP address in the trace ')
    sip, srcpercent = dominatingip(srclist, uniqsrc)
    print('DOMINATED SRC IP: ', sip, srcpercent)  # size that has been sent mostly
    dip, dstpercent = dominatingip(dstlist, uniqdst)
    print('DOMINATED DST IP: ', dip, dstpercent)  # size that has been sent mostly
    return sip, srcpercent, dip, dstpercent

def ofunc1(newtrace):       # mean, max, std of incoming/outgoing packet sizes,
    print('-------------------------------------------------------------------------------')
    itotalsize = []         # total bytes of incoming/outgoing packets
    ototalsize = []         # unique bytes
    isize = 0
    osize = 0
    itstamp = []
    otstamp = []
    # for j in range(len(newtrace)):
    #     if 'INCOMING' in newtrace[j] and '--Entry' not in newtrace[j - 3]:
    #         pass
    #     elif 'INCOMING' in newtrace[j] and '--Entry' not in newtrace[j - 3]:
    #         iptime = str(newtrace[j - 3]).split('--')[0]
    #         print(iptime)
    #         # iptime = str(newtrace[j - 4]).strip('\'')[:-2]
    #         # iptime = str(newtrace[j-3]).strip('\'')[:-7]
    #     elif 'OUTGOING' in newtrace[j] and '--Entry' not in newtrace[j - 3]:
    #         pass
    #     elif 'OUTGOING' in newtrace[j] and '--Entry' in newtrace[j - 3]:
    #         optime = str(newtrace[j - 3]).split('--')[0]
    #         print(optime)
    #         # optime = str(newtrace[j - 4]).strip('\'')[:-2]
    #         # optime = str(newtrace[j-3]).strip('\'')[:-7]
    #     else:
    #         pass

    ############## depending on dataset, after extracting more data, here should be fixed ####################
    itotalsize = []  # total bytes of incoming/outgoing packets
    ototalsize = []
    isize = 0
    osize = 0
    for j in range(len(newtrace)):
        if 'INCOMING' in newtrace[j]:
            size = str(newtrace[j + 6]).split(':')[1].strip(',')
            # size = str(newtrace[j + 5]).split(':')[1]
            itotalsize.append(int(size))
            isize += int(size)
        elif 'INCOMING' in newtrace[j] and 'Timestamp' in newtrace[j + 5]:
            size = str(newtrace[j + 5]).split(':')[1][:-9]
            itotalsize.append(int(size))
            isize += int(size)
        elif 'OUTGOING' in newtrace[j]:
            size = str(newtrace[j + 6]).split(':')[1].strip(',')
            ototalsize.append(int(size))
            osize += int(size)
        elif 'OUTGOING' in newtrace[j] and 'Timestamp' in newtrace[j + 5]:
            size = str(newtrace[j + 5]).split(':')[1][:-9]
            ototalsize.append(int(size))
            osize += int(size)
        else:
            pass
    print('TOTAL INCOMING BYTES: ' + str(isize))
    print('TOTAL OUTGOING BYTES: ' + str(osize))
    iunq = uniquevalue(itotalsize)
    # print('UNIQUE BYTES: ', iunq)
    ounq = uniquevalue(ototalsize)
    # print('UNIQUE BYTES: ', ounq)

    iIndex, iPercent = sizepercentage(itotalsize, iunq)
    oIndex, oPercent = sizepercentage(ototalsize, ounq)

    if len(itotalsize) > 1 and len(ototalsize) > 1:
        imeansize = statistics.mean(itotalsize)
        print('INCOMING MEAN: ' + str(imeansize))
        omeansize = statistics.mean(ototalsize)
        print('OUTGOING MEAN: ' + str(omeansize))
        imin = min(itotalsize)
        print('INCOMING MIN: ' + str(imin))
        omin = min(ototalsize)
        print('OUTGOING MIN: ' + str(omin))
        imaxsize = max(itotalsize)
        print('INCOMING MAX: ' + str(imaxsize))
        omaxsize = max(ototalsize)
        print('OUTGOING MAX: ' + str(omaxsize))
        istdsize = statistics.stdev(itotalsize)
        print('INCOMING STD: ' + str(istdsize))
        ostdsize = statistics.stdev(ototalsize)
        print('OUTGOING STD: ' + str(ostdsize))
        return imeansize, imin, imaxsize, istdsize, omin, omeansize, omaxsize, ostdsize, isize, osize
    elif len(itotalsize) > 1 and len(ototalsize) <= 1:
        imeansize = statistics.mean(itotalsize)
        print('INCOMING MEAN: ' + str(imeansize))
        imin = min(itotalsize)
        print('INCOMING MIN: ' + str(imin))
        imaxsize = max(itotalsize)
        print('INCOMING MAX: ' + str(imaxsize))
        istdsize = statistics.stdev(itotalsize)
        print('INCOMING STD: ' + str(istdsize))
        print(rf'There is {len(ototalsize)}. We cannot compute statistical values. ')
        return imeansize, imin, imaxsize, istdsize, None, None, None, None, isize, osize

    elif len(itotalsize) <= 1 and len(ototalsize) > 1:
        omeansize = statistics.mean(ototalsize)
        print('OUTGOING MEAN: ' + str(omeansize))
        omin = min(ototalsize)
        print('OUTGOING MIN: ' + str(omin))
        omaxsize = max(ototalsize)
        print('OUTGOING MAX: ' + str(omaxsize))
        ostdsize = statistics.stdev(ototalsize)
        print('OUTGOING STD: ' + str(ostdsize))
        print(rf'There is {len(itotalsize)}. We cannot compute statistical values. ')
        return None, None, None, None, omin, omeansize, omaxsize, ostdsize, isize, osize

    else:
        print(rf'There is only {len(itotalsize)} and {len(ototalsize)}. We cannot compute statistical values. ')
        return None, None, None, None, None, None, None, None, isize, osize

if __name__ == '__main__':

    filelist = findfile()
    for i in range(len(filelist)):
        filename = filelist[i]
        ftype = filename.split('_')[0][6:-6]  # type of trace
        urlhash = filename.split('_')[1]
        if ftype == 'TCP' or ftype == 'TLS':        # read only TCP or TLS traces
            with open(rf'./outlierfree/{filename}', 'r') as f:
                print('\n' + rf'Reading {filename}...')
                trace = []
                tempo = []
                lines = f.read()
                for i, part in enumerate(lines.split('https')):  # split traces from merged file
                    line = part.split()
                    tempo.append(line)
                for string in tempo:
                    if len(string) > 4:  # remove empty entities
                        trace.append(string)
                print('There are ' + str(len(trace)) + ' traces in the file')
                urlregex = re.compile('www.')
                startregex = re.compile('START')
                timeregex = re.compile('TIMESTAMP')
                falschregex = re.compile('StartTime')
                delimregex = re.compile(r'\\n')
                sumlist = []

                for k in range(len(trace)):
                    print('\nReading ' + str(k+1) + 'th trace in the file...')
                    newtrace = []
                    totalsize = 0
                    for item in trace[k]:
                        urlgrep = urlregex.search(item)
                        startgrep = startregex.search(item)
                        timegrep = timeregex.search(item)
                        falschgrep = falschregex.search(item)
                        delimgrep = delimregex.search(item)
                        if urlgrep or startgrep or timegrep or falschgrep or delimgrep:   # pass the line including url
                                pass
                        else:
                            newtrace.append(item)       # newtrace includes parsed items of trace[k]
                    if len(newtrace) > 4:
                        ofunc1(newtrace)
                        # sip, srcpercent, dip, dstpercent = ofunc2(newtrace)
                        # tpkt, ipart, opart = funcA(newtrace)
                        # binstd, binav, boutstd, boutav = funcB(newtrace)
                        # cstd, cmean, cmedian, cmax = funcC(newtrace)
                        # dipkt, dopkt, dlipkt, dlopkt = funcD(newtrace)
                        # funcF(newtrace)
                        # srclist, dstlist = findip(newtrace)
                        # uniqsrc = uniquevalue(srclist)
                        # uniqdst = uniquevalue(dstlist)
                        # sip, srcpercent = dominatingip(srclist, uniqsrc)
                        # print('DOMINATED SRC IP: ', sip, srcpercent)  # size that has been sent mostly
                        # dip, dstpercent = dominatingip(dstlist, uniqdst)
                        # print('DOMINATED DST IP: ', dip, dstpercent)  # size that has been sent mostly
                        # imeansize, imin, imaxsize, istdsize, omin, omeansize, omaxsize, ostdsize, isize, osize = ofunc1(newtrace)
                        # df = pd.DataFrame([tpkt, ipart, opart, cstd, cmean, cmedian, cmax],
                        #                   index=['TOTAL', 'INCOMING', 'OUTGOING', 'IinCHUNK_STD', 'IinCHUNK_MEAN', 'IinCHUNK_MEDIAN', 'IinCHUNK_MAX']).T
                        # df.to_csv('./feature/feature_%s_to_trace_%s.csv' % (filename, k+1))
                        # print("Saved in csv file.")

            print('End of the operation'.center(80, '+'))
        else:
            pass



# OLFreeTCPtraces_fc183b0eb5105052d2ca22e662691faf << 요주의 대상