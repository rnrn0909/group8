import os
import re
import pandas as pd
import numpy as np
import statistics
from collections import Counter         # to count hashable object
import math


def findfile():
    filelist = []
    for root, dirs, files in os.walk("./outlierfree"):
        for file in files:
            filelist.append(file)
            # filehash = file[13:]

    return filelist

def funcA(newtrace):     # count the number of total/incoming/outgoing packet
    print('Function A'.center(80, '-'))
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
    # for normal communication, incomingpkt = outcomingpkt or has similar number
    if outgoingpkt == 0 or incomingpkt == 0:
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

def funcB(newtrace):                                            # packet ordering
    print('Function B'.center(80, '-'))
    pkt = 0
    outorderinglist = []
    inorderinglist = []
    for j in range(len(newtrace)):
        if 'Timestamp' in newtrace[j]:
            pkt += 1
            if 'OUTGOING' in newtrace[j + 4] and j + 14 < len(newtrace):  # EOL = newtrace[j+9]
                if 'OUTGOING' in newtrace[j + 14]:
                    outorderinglist.append(pkt)
                else:
                    pass
            elif 'OUTGOING' in newtrace[j + 5] and j + 22 < len(newtrace):
                if 'size' in newtrace[j + 10]:  # EOL = newtrace[j+10]
                    if 'OUTGOING' in newtrace[j + 16]:
                        outorderinglist.append(pkt)
                    else:
                        pass
                elif 'size' in newtrace[j + 11]:  # EOL = newtrace[j+11]
                    if 'OUTGOING' in newtrace[j + 17]:
                        outorderinglist.append(pkt)  # j+16: INCOMING
                    else:
                        pass
                else:
                    pass
            elif 'INCOMING' in newtrace[j + 4] and 'Source' in newtrace[j + 4] and j + 14 < len(newtrace):
                if 'INCOMING' in newtrace[j + 14]:
                    inorderinglist.append(pkt)
                else:
                    pass
            elif 'INCOMING' in newtrace[j + 4] and 'Source' not in newtrace[j + 4] and j + 14 < len(
                    newtrace):
                if 'INCOMING' in newtrace[j + 15]:
                    inorderinglist.append(pkt)
                else:
                    pass
            else:
                pass

    if len(inorderinglist) > 1 and len(outorderinglist) > 1:
        binstd = statistics.stdev(inorderinglist)
        print('INCOMING STD:', binstd)
        binav = sum(inorderinglist) / len(inorderinglist)
        print('INCOMING AVERAGE:', binav)
        boutstd = statistics.stdev(outorderinglist)
        print('OUTGOING STD:', boutstd)
        boutav = sum(outorderinglist) / len(outorderinglist)
        print('OUTGOING AVERAGE:', boutav)
        return binstd, binav, boutstd, boutav

    elif len(inorderinglist) > 1 and len(outorderinglist) <= 1:
        binstd = statistics.stdev(inorderinglist)
        print('INCOMING STD:', binstd)
        binav = sum(inorderinglist) / len(inorderinglist)
        print('INCOMING AVERAGE:', binav)
        boutstd = 'None'
        print('OUTGOING STD:', boutstd)
        boutav = 'None'
        print('OUTGOING AVERAGE:', boutav)
        print(
            rf'There is {len(outorderinglist)} for order of successive OUTGOING packets. We cannot get statistic values. ')
        return binstd, binav, boutstd, boutav

    elif len(inorderinglist) <= 1 and len(outorderinglist) > 1:
        binstd = 'None'
        print('INCOMING STD:', binstd)
        binav = 'None'
        print('INCOMING AVERAGE:', binav)
        boutstd = statistics.stdev(outorderinglist)
        print('OUTGOING STD:', boutstd)
        boutav = sum(outorderinglist) / len(outorderinglist)
        print('OUTGOING AVERAGE:', boutav)
        print(
            rf'There is {len(inorderinglist)} for order of successive INCOMING packets. We cannot get statistic values. ')
        return binstd, binav, boutstd, boutav
    else:
        print(
            rf'Since there is {len(inorderinglist)} and {len(outorderinglist)}, we cannot compute statistical values.')
        binstd = 'None'
        binav = 'None'
        boutstd = 'None'
        boutav = 'None'
        return binstd, binav, boutstd, boutav

def incomingtime(newtrace):
    timelist = []
    for j in range(len(newtrace)):
        if 'INCOMING' in newtrace[j]:
            stamp = str(newtrace[j - 3]).strip(',')  # ',' can exist at the end of the element
            if '--Entry' in newtrace[j - 3]:
                stamp = stamp.split('--')[0]
                timelist.append(float(stamp))
            elif 'Entry' in newtrace[j - 3]:
                stamp = stamp[:-5]
                timelist.append(float(stamp))
            else:
                pass
    return timelist

def outgoingtime(newtrace):
    timelist = []
    for j in range(len(newtrace)):
        if 'OUTGOING' in newtrace[j]:
            stamp = str(newtrace[j - 3]).strip(',')  # ',' can exist at the end of the element
            if '--Entry' in newtrace[j - 3]:
                stamp = stamp.split('--')[0]
                timelist.append(float(stamp))
            elif 'IP' in newtrace[j - 3]:
                stamp = str(newtrace[j - 4]).split('--')[0]
                timelist.append(float(stamp))
            elif 'Entry' in newtrace[j - 3]:
                stamp = stamp[:-5]
                timelist.append(float(stamp))
            else:
                pass
    return timelist

def funcG(newtrace):                                    # transmission time
    print('Function G'.center(80, '-'))
    intransmission = []
    outtransmission = []
    intimelist = incomingtime(newtrace)
    outtimelist = outgoingtime(newtrace)

    if len(intimelist) > 1 and len(outtimelist) > 1:
        intotaltime = intimelist[len(intimelist) - 1] - intimelist[0]
        print('TOTAL TRANSMISSION TIME(INCOMING):', intotaltime)
        outtotaltime = outtimelist[len(outtimelist) - 1] - outtimelist[0]
        print('TOTAL TRANSMISSION TIME(OUTGOING):', outtotaltime)
        intransmission.append(float(intimelist[len(intimelist) - 1]) - float(intimelist[0]))
        outtransmission.append(float(outtimelist[len(outtimelist) - 1]) - float(outtimelist[0]))
        iq1 = np.percentile(intransmission, 25)
        iq2 = np.percentile(intransmission, 50)
        iq3 = np.percentile(intransmission, 75)
        oq1 = np.percentile(outtransmission, 25)
        oq2 = np.percentile(outtransmission, 50)
        oq3 = np.percentile(outtransmission, 75)
        print(iq1, iq2, iq3, oq1, oq2, oq3)
        return iq1, iq2, iq3, oq1, oq2, oq3, intotaltime, outtotaltime

    else:
        print('Not available to compute statistical values. There are only ', len(intimelist), len(outtimelist))
        iq1 = 'None'
        iq2 = 'None'
        iq3 = 'None'
        oq1 = 'None'
        oq2 = 'None'
        oq3 = 'None'
        intotaltime = 'None'
        outtotaltime = 'None'
        return iq1, iq2, iq3, oq1, oq2, oq3, intotaltime, outtotaltime

def chunk(lst, n):
    for w in range(0, len(lst), n):
        yield lst[w:w+n]

def funcC(newtrace):                                            # concentration of incoming packets
    print('Function C'.center(80, '-'))
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
        print('STD:' + str(stdlipkt))
        meanlipkt = statistics.mean(lipkt)
        print('MEAN:' + str(meanlipkt))
        medianlipkt = statistics.median(lipkt)
        print('MEDIAN:' + str(medianlipkt))
        maxlipkt = max(lipkt)
        print('MAX:' + str(maxlipkt))
        return stdlipkt, meanlipkt, medianlipkt, maxlipkt
    else:
        print(rf'Since there is {len(twenty)}, we cannot compute statistical values from chunk. ')
        stdlipkt = 'None'
        meanlipkt = 'None'
        medianlipkt = 'None'
        maxlipkt = 'None'
        return stdlipkt, meanlipkt, medianlipkt, maxlipkt

def funcD(newtrace):                                    # concentration in first & last 30 packets
    print('Function D'.center(80, '-'))
    pkt = 0
    first = []
    for j in range(len(newtrace)):
        if 'Timestamp' in newtrace[j] and 'size' in newtrace[j + 9]:  # start of the line for each packet
            pkt += 1
            if pkt <= 30:
                pktline = newtrace[j] + newtrace[j + 1] + newtrace[j + 2] + newtrace[
                    j + 3] + newtrace[j + 4] + newtrace[j + 5] + newtrace[j + 6] + newtrace[j + 7] + \
                          newtrace[
                              j + 8] + newtrace[j + 9]
                first.append(pktline)
            else:
                pass
        elif 'Timestamp' in newtrace[j] and 'size' in newtrace[j + 10]:
            pkt += 1
            if pkt <= 30:
                pktline = newtrace[j] + newtrace[j + 1] + newtrace[j + 2] + newtrace[
                    j + 3] + newtrace[j + 4] + newtrace[j + 5] + newtrace[j + 6] + newtrace[j + 7] + \
                          newtrace[
                              j + 8] + newtrace[j + 9] + newtrace[j + 10]
                first.append(pktline)
            else:
                pass
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
                lpktline = newtrace[m] + newtrace[m + 1] + newtrace[m + 2] + newtrace[
                    m + 3] + newtrace[m + 4] + newtrace[m + 5] + newtrace[m + 6] + newtrace[m + 7] + \
                           newtrace[m + 8] + newtrace[m + 9]
                last.append(lpktline)
            else:
                pass
        elif 'Timestamp' in newtrace[m] and 'size' in newtrace[m + 10]:
            lpkt += 1
            if lpkt <= 30:
                lpktline = newtrace[m] + newtrace[m + 1] + newtrace[m + 2] + newtrace[
                    m + 3] + newtrace[m + 4] + newtrace[m + 5] + newtrace[m + 6] + newtrace[m + 7] + \
                           newtrace[m + 8] + newtrace[m + 9] + newtrace[m + 10]
                last.append(lpktline)
    lipkt = 0
    lopkt = 0
    for y in range(len(last)):
        if 'INCOMING' in last[y]:
            lipkt += 1
        elif 'OUTGOING' in last[y]:
            lopkt += 1
        else:
            pass
    print(rf'In first {len(first)} packets, there are {ipkt} INCOMING packets. ')
    print(rf'In first {len(first)} packets, there are {opkt} OUTGOING packets. ')
    print(rf'In last {len(last)} packets, there are {lipkt} INCOMING packets. ')
    print(rf'In last {len(last)} packets, there are {lopkt} OUTGOING packets. ')
    return ipkt, opkt, lipkt, lopkt         # get the value in main part and attach into csv at once

def funcF(newtrace):                                # packet inter-arrival
    print('Function F'.center(80, '-'))
    itstamp = []
    otstamp = []
    for j in range(len(newtrace)):
        if 'Timestamp' in newtrace[j] and 'INCOMING' in newtrace[j + 4]:
            iptime = str(newtrace[j + 1]).split('--')[0]
            itstamp.append(float(iptime))
        elif 'Timestamp' in newtrace[j] and 'OUTGOING' in newtrace[j + 4]:
            optime = str(newtrace[j + 1]).split('--')[0]
            otstamp.append(float(optime))
        elif 'Timestamp' in newtrace[j] and 'OUTGOING' in newtrace[j + 5]:
            optime = str(newtrace[j + 1]).split('--')[0]
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
        print('INCOMING MAX:', inintermax)
        inintermean = statistics.mean(inintertime)
        print('INCOMING MEAN:', inintermean)
        ininterstd = statistics.stdev(inintertime)
        print('INCOMING STD:', ininterstd)
        ininterq3 = np.percentile(inintertime, 75)
        print('INCOMING 3rd QUARTILE:', ininterq3)

        outintermax = max(outintertime)
        print('OUTGOING MAX:', outintermax)
        outintermean = statistics.mean(outintertime)
        print('OUTGOING MEAN:', outintermean)
        outinterstd = statistics.stdev(outintertime)
        print('OUTGOING STD:', outinterstd)
        outinterq3 = np.percentile(outintertime, 75)
        print('OUTGOING 3rd QUARTILE:', outinterq3)
        return inintermax, inintermean, ininterstd, ininterq3, outintermax, outintermean, outinterstd, outinterq3


    elif len(inintertime) > 1 and len(outintertime) <= 1:
        inintermax = max(inintertime)
        print('INCOMING MAX:', inintermax)
        inintermean = statistics.mean(inintertime)
        print('INCOMING MEAN:', inintermean)
        ininterstd = statistics.stdev(inintertime)
        print('INCOMING STD:', ininterstd)
        ininterq3 = np.percentile(inintertime, 75)
        print('INCOMING 3rd QUARTILE:', ininterq3)
        outintermax = 'None'
        outintermean = 'None'
        outinterstd = 'None'
        outinterq3 = 'None'
        print(rf'There is {len(outintertime)} of inter-arrival time value. We cannot compute statistical values. ')
        return inintermax, inintermean, ininterstd, ininterq3, outintermax, outintermean, outinterstd, outinterq3


    elif len(inintertime) <= 1 and len(outintertime) > 1:
        inintermax = 'None'
        inintermean = 'None'
        ininterstd = 'None'
        ininterq3 = 'None'
        outintermax = max(outintertime)
        print('OUTGOING MAX:' + str(outintermax))
        outintermean = statistics.mean(outintertime)
        print('OUTGOING MEAN:' + str(outintermean))
        outinterstd = statistics.stdev(outintertime)
        print('OUTGOING STD:' + str(outinterstd))
        outinterq3 = np.percentile(outintertime, 75)
        print('OUTGOING 3rd QUARTILE:' + str(outinterq3))
        print(

            rf'There is {len(inintertime)} of inter-arrival time value. We cannot compute statistical values. ')
        return inintermax, inintermean, ininterstd, ininterq3, outintermax, outintermean, outinterstd, outinterq3
    else:
        inintermax = 'None'
        inintermean = 'None'
        ininterstd = 'None'
        ininterq3 = 'None'
        outintermax = 'None'
        outintermean = 'None'
        outinterstd = 'None'
        outinterq3 = 'None'
        print(rf'There is {len(inintertime)} and {len(outintertime)} of inter-arrival time value. We cannot compute statistical values. ')
        return inintermax, inintermean, ininterstd, ininterq3, outintermax, outintermean, outinterstd, outinterq3


def uniquevalue(list):              # get a unique value in the list
    arr = np.array(list)
    return np.unique(arr)

def sizepercentage(list, ulist):        # to get percentage of each unique value
    count = Counter(list)               # list with size of packet
    pc = []
    for v in range(len(ulist)):
        for size1, value in count.items():
            if ulist[v] == size1:
                present = '%.3f' % (value * 100 / len(list))
                # print(f'{size1}: {present}%')
                pc.append(f'{size1}: {present}')
    if len(pc) != 0:
        comparison = []
        for percent in pc:
            comparison.append(percent.split(':')[1])

        for idx in pc:
            if max(comparison) == idx.split(':')[1]:
                index = idx.split(':')[0]
                maxpercent = max(comparison)
                print('UNIQUE SIZE:', index, maxpercent)  # size that has been sent mostly
                return index, maxpercent
    else:
        print('There is not enough data to get unique size of packet. ')
        index = 'None'
        maxpercent = 'None'
        return index, maxpercent


def findip(newtrace):
    srclist = []
    dstlist = []
    for j in range(len(newtrace)):
        if 'Source' in newtrace[j]:
            srclist.append(str(newtrace[j + 2]).split('--')[0])         # list of src ip
            dstlist.append(str(newtrace[j + 4]).split('--')[0])         # list of dst ip
    return srclist, dstlist

def dominatingip(list, ulist):
    count = Counter(list)  # list with size of packet
    pcent = []
    for v in range(len(ulist)):
        for ip, value in count.items():
            if ulist[v] == ip:
                present = '%.3f' % (value * 100 / len(list))
                # print(f'{size1}: {present}%')
                pcent.append(f'{ip}: {present}')

    if len(pcent) != 0:
        comparison = []
        for srip in pcent:
            comparison.append(srip.split(':')[1])

        for idx in pcent:
            if max(comparison) == idx.split(':')[1]:
                index = idx.split(':')[0]
                maxIPpercent = max(comparison)
                print('IP:', index, ':', maxIPpercent)
                return index, maxIPpercent
    else:
        print('There is not enough data to get unique IP address of packet. ')
        index = 'None'
        maxIPpercent = 'None'
        return index, maxIPpercent

def ofunc2(newtrace):                   # the ip seen in the trace most often
    print('Dominated IP Address'.center(80, '-'))       # ownfeature5
    srclist, dstlist = findip(newtrace)
    uniqsrc = uniquevalue(srclist)
    print(f'There are total {len(srclist)} source IP addresses and {len(uniqsrc)} of unique IP addresses in the trace. ')
    uniqdst = uniquevalue(dstlist)
    print(f'There are total {len(dstlist)} destination IP addresses and {len(uniqdst)} of unique IP address in the trace ')
    sip, srcpercent = dominatingip(srclist, uniqsrc)
    print('DOMINATED SRC IP:', sip, srcpercent)  # size that has been sent mostly
    dip, dstpercent = dominatingip(dstlist, uniqdst)
    print('DOMINATED DST IP:', dip, dstpercent)  # size that has been sent mostly
    return sip, srcpercent, dip, dstpercent

def ofunc1(newtrace):       # totalbytes / mean, max, std of incoming/outgoing packet sizes,
    print('Feature 1'.center(80, '-'))
    print('To get statistical values from packet sizes... ')
    itotalsize = []  # total bytes of incoming/outgoing packets
    ototalsize = []
    isize = 0
    osize = 0
    for j in range(len(newtrace)):
        if 'INCOMING' in newtrace[j] and 'Source' not in newtrace[j]:
            isize = str(newtrace[j + 6]).strip(',')
            if 'Timestamp' in isize:  # XXXTimestamp
                isize = isize.split(':')[1][:-9]
                itotalsize.append(int(isize))
            elif 'URL' in isize:  # XXXURL
                isize = isize.split(':')[1][:-3]
                itotalsize.append(int(isize))
            elif 'size' in isize:  # size:XXX, or size:XXX
                isize = isize.split(':')[1]
                itotalsize.append(int(isize))
            else:
                pass

        elif 'INCOMING' in newtrace[j] and 'Source' in newtrace[j]:
            isize = str(newtrace[j + 5]).strip(',')
            if 'Timestamp' in isize:
                isize = isize.split(':')[1][:-9]
                itotalsize.append(int(isize))
            elif 'URL' in isize:
                isize = isize.split(':')[1][:-3]
                itotalsize.append(int(isize))
            elif 'size' in isize:
                isize = isize.split(':')[1]
                itotalsize.append(int(isize))
            else:
                itotalsize.append(int(isize))
        elif 'OUTGOING' in newtrace[j] and 'Source' not in newtrace[j]:
            osize = str(newtrace[j + 6]).strip(',')
            if 'Timestamp' in osize:  # XXXTimestamp
                osize = osize.split(':')[1][:-9]
                ototalsize.append(int(osize))
            elif 'URL' in osize:  # XXXURL
                osize = osize.split(':')[1][:-3]
                ototalsize.append(int(osize))
            elif 'size' in osize:  # size:XXX, or size:XXX
                osize = osize.split(':')[1]
                ototalsize.append(int(osize))
            else:
                pass
        elif 'OUTGOING' in newtrace[j] and 'Source' in newtrace[j]:
            osize = str(newtrace[j + 5]).strip(',')
            if 'Timestamp' in osize:  # XXXTimestamp
                osize = osize.split(':')[1][:-9]
                ototalsize.append(int(osize))
            elif 'URL' in osize:  # XXXURL
                osize = osize.split(':')[1][:-3]
                ototalsize.append(int(osize))
            elif 'size' in osize:  # size:XXX, or size:XXX
                osize = osize.split(':')[1]
                ototalsize.append(int(osize))
            else:
                ototalsize.append(int(osize))

        else:
            pass

    print('TOTAL INCOMING BYTES:', isize)           # ownfeature4
    print('TOTAL OUTGOING BYTES:', osize)
    if isize == 0 and osize != 0:
        print('No INCOMING bytes. ')
        ounq = uniquevalue(ototalsize)
        oIndex, oPercent = sizepercentage(ototalsize, ounq)     # ownfeature3
        if len(ototalsize) > 1:
            imeansize = 'None'
            imin = isize
            imaxsize = isize
            istdsize = 'None'
            omeansize = statistics.mean(ototalsize)
            iIndex = 'None'
            iPercent = 'None'
            print('OUTGOING MEAN:', omeansize)
            omaxsize = max(ototalsize)
            print('OUTGOING MAX:', omaxsize)
            omin = min(ototalsize)
            print('OUTGOING MIN:', omin)
            ostdsize = statistics.stdev(ototalsize)
            print('OUTGOING STD:', ostdsize)
            return imeansize, imin, imaxsize, istdsize, omin, omeansize, omaxsize, ostdsize, isize, osize, iIndex, iPercent, oIndex, oPercent
            # ownfeature1

        else:       # if len(ototalsize) == 1
            print(rf'There is only {len(ototalsize)} OUTGOING bytes. We cannot compute statistical values. ')
            imeansize = 'None'
            imin = isize
            imaxsize = isize
            istdsize = 'None'
            iIndex = 'None'
            iPercent = 'None'
            omin = osize
            omeansize = 'None'
            omaxsize = osize
            ostdsize = 'None'
            oIndex = 'None'
            oPercent = 'None'
            return imeansize, imin, imaxsize, istdsize, omin, omeansize, omaxsize, ostdsize, isize, osize, iIndex, iPercent, oIndex, oPercent
    elif isize != 0 and osize == 0:
        print('No OUTGOING bytes. ')
        iunq = uniquevalue(itotalsize)
        iIndex, iPercent = sizepercentage(itotalsize, iunq)
        if len(itotalsize) > 1:
            imeansize = statistics.mean(itotalsize)
            print('INCOMING MEAN:', imeansize)
            imin = min(itotalsize)
            print('INCOMING MIN:', imin)
            imaxsize = max(itotalsize)
            print('INCOMING MAX:', imaxsize)
            istdsize = statistics.stdev(itotalsize)
            print('INCOMING STD:', istdsize)
            omin = osize
            omeansize = 'None'
            omaxsize = osize
            ostdsize = 'None'
            oIndex = 'None'
            oPercent = 'None'
            return imeansize, imin, imaxsize, istdsize, omin, omeansize, omaxsize, ostdsize, isize, osize, iIndex, iPercent, oIndex, oPercent

        else:   # len(itotalsize) == 1
            print(rf'There is only {len(itotalsize)} OUTGOING bytes. We cannot compute statistical values. ')
            imeansize = 'None'
            imin = isize
            imaxsize = isize
            istdsize = 'None'
            iIndex = 'None'
            iPercent = 'None'
            omin = osize
            omeansize = 'None'
            omaxsize = osize
            ostdsize = 'None'
            oIndex = 'None'
            oPercent = 'None'
            return imeansize, imin, imaxsize, istdsize, omin, omeansize, omaxsize, ostdsize, isize, osize, iIndex, iPercent, oIndex, oPercent


    else:       #  <=> len(itotalsize) != 0 or len(ototalsize) != 0
        iunq = uniquevalue(itotalsize)
        ounq = uniquevalue(ototalsize)
        iIndex, iPercent = sizepercentage(itotalsize, iunq)
        oIndex, oPercent = sizepercentage(ototalsize, ounq)

        if len(itotalsize) > 1 and len(ototalsize) > 1:
            imeansize = statistics.mean(itotalsize)
            print('INCOMING MEAN:', imeansize)
            omeansize = statistics.mean(ototalsize)
            print('OUTGOING MEAN:', omeansize)
            imin = min(itotalsize)
            print('INCOMING MIN:', imin)
            omin = min(ototalsize)
            print('OUTGOING MIN:', omin)
            imaxsize = max(itotalsize)
            print('INCOMING MAX:', imaxsize)
            omaxsize = max(ototalsize)
            print('OUTGOING MAX:', omaxsize)
            istdsize = statistics.stdev(itotalsize)
            print('INCOMING STD:', istdsize)
            ostdsize = statistics.stdev(ototalsize)
            print('OUTGOING STD:', ostdsize)
            return imeansize, imin, imaxsize, istdsize, omin, omeansize, omaxsize, ostdsize, isize, osize, iIndex, iPercent, oIndex, oPercent
        elif len(itotalsize) > 1 and len(ototalsize) <= 1:
            imeansize = statistics.mean(itotalsize)
            print('INCOMING MEAN:', imeansize)
            imin = min(itotalsize)
            print('INCOMING MIN:', imin)
            imaxsize = max(itotalsize)
            print('INCOMING MAX:', imaxsize)
            istdsize = statistics.stdev(itotalsize)
            print('INCOMING STD:', istdsize)
            omeansize = 'None'
            print('OUTGOING MEAN:', omeansize)
            omin = ototalsize
            print('OUTGOING MIN:',omin)
            omaxsize = ototalsize
            print('OUTGOING MAX:', omaxsize)
            ostdsize = 'None'
            print('OUTGOING STD:', ostdsize)
            print(rf'There is {len(ototalsize)} of outgoing bytes. We cannot compute statistical values. ')
            print('Instead of finding max, min value of outgoing bytes, use the original value. ')
            return imeansize, imin, imaxsize, istdsize, omeansize, omin, omaxsize, ostdsize, isize, osize, iIndex, iPercent, oIndex, oPercent

        elif len(itotalsize) <= 1 and len(ototalsize) > 1:
            imeansize = 'None'
            print('INCOMING MEAN:', imeansize)
            imin = itotalsize
            print('INCOMING MIN:', imin)
            imaxsize = itotalsize
            print('INCOMING MAX:', imaxsize)
            istdsize = 'None'
            print('INCOMING STD:', istdsize)
            omeansize = statistics.mean(ototalsize)
            print('OUTGOING MEAN:', omeansize)
            omin = min(ototalsize)
            print('OUTGOING MIN:',omin)
            omaxsize = max(ototalsize)
            print('OUTGOING MAX:',omaxsize)
            ostdsize = statistics.stdev(ototalsize)
            print('OUTGOING STD:', ostdsize)
            print(rf'There is {len(itotalsize)} of incoming bytes. We cannot compute statistical values. ')
            print('Instead of finding max, min value of incoming bytes, use the original value. ')
            return imeansize, imin, imaxsize, istdsize, omeansize, omin, omaxsize, ostdsize, isize, osize, iIndex, iPercent, oIndex, oPercent

        else:
            print(rf'There is only {len(itotalsize)} of incoming and {len(ototalsize)} of outgoing bytes.')
            print('We cannot compute statistical values. ')
            imeansize = 'None'
            imin = 'None'
            imaxsize = 'None'
            istdsize = 'None'
            omeansize = 'None'
            omin = 'None'
            omaxsize = 'None'
            ostdsize = 'None'
            return imeansize, imin, imaxsize, istdsize, omeansize, omin, omaxsize, ostdsize, isize, osize, iIndex, iPercent, oIndex, oPercent


def max_data_ip(newtrace):              # the ip who sent most bytes
    print('Feature 2'.center(80, '-'))          # ownfeature6
    print('To find IP address who sent most bytes ... ')
    ipbyte = []
    for j in range(len(newtrace)):  # INCOMING: s -> c
        if 'INCOMING' in newtrace[j] and 'Source' not in newtrace[j]:
            addr = str(newtrace[j + 3]).strip(',')  # newtrace[j+5] = dst
            addr = addr.split('--')[0]  # newtrace[j+3] = src
            ipbyte.append(addr)
            if 'size' in newtrace[j + 6]:
                size = str(newtrace[j + 6]).strip(',')
                size = size.split(':')[1]
                ipbyte.append(int(size))
            else:
                pass
        elif 'INCOMING' in newtrace[j] and 'Source' in newtrace[j]:
            addr = str(newtrace[j + 2]).strip(',')
            addr = addr.split('--')[0]
            ipbyte.append(addr)
            if 'size' in newtrace[j + 5]:
                size = str(newtrace[j + 5]).strip(',')
                size = size.split(':')[1]
                if 'Timestamp' in size:
                    size = size[:-9]
                    ipbyte.append(int(size))
                else:
                    ipbyte.append(int(size))
        else:
            pass
    ipbyte = np.array(ipbyte)
    ipbyte = np.reshape(ipbyte, (len(ipbyte) // 2, 2))
    srclist = []
    for x in range(len(ipbyte)):
        srclist.append(ipbyte[x][0])
    uniqsrc = uniquevalue(srclist)
    iplist = []
    sizelist = []
    for z in range(len(uniqsrc)):
        size = 0
        ip = uniqsrc[z]
        for y in range(len(ipbyte)):
            if ipbyte[y][0] == ip:
                size += int(ipbyte[y][1])
        iplist.append(ip)
        sizelist.append(size)
    # ## len(iplist) must be same with len(sizelist)
    if len(sizelist) == len(iplist) and len(sizelist) >= 1 and len(iplist) >= 1:
        maxdata = max(sizelist)
        for w in range(len(sizelist)):
            if maxdata == sizelist[w]:
                print('MAX DATA IP:', iplist[w], 'SENT:', maxdata)
                return iplist[w], maxdata
    else:
        print(f'There is {len(sizelist)} value for bytes. We cannot find max_data_ip. ')
        return 'None', 'None'               # string should be returned always (to save in csv)


def ofunc3(hash):       # samplecode rdd.py
    print('Feature 3'.center(80, '-'))              # ownfeature2
    print(rf'Number of packets for each protocol in {hash} ... ')
    print("\nReading TCP file ... ")
    with open(rf'./outlierfree/OLFreeTCPtraces_{hash}', 'r') as tcpf:
        tcptrace = []
        tcptempo = []
        tcplines = tcpf.read()
        if 'URL' in tcplines:
            for i, tcppart in enumerate(tcplines.split('URL :')):  # split traces from merged file
                tcpline = tcppart.split()
                tcptempo.append(tcpline)
            for tcpstring in tcptempo:
                if len(tcpstring) > 4:  # remove empty entities
                    tcptrace.append(tcpstring)
                else:
                    pass
        else:
            for i, tcppart in enumerate(tcplines.split('https://')):  # split traces from merged file
                tcpline = tcppart.split()
                tcptempo.append(tcpline)
            for tcpstring in tcptempo:
                if len(tcpstring) > 4:  # remove empty entities
                    tcptrace.append(tcpstring)
                else:
                    pass
        print('There are ' + str(len(tcptrace)) + ' traces in the file')
        urlregex = re.compile('https.')
        startregex = re.compile('START')
        timeregex = re.compile('TIMESTAMP')
        delimregex = re.compile(r'\\n')
        tcpnr = []

        for k in range(len(tcptrace)):
            newtcptrace = []
            for item in tcptrace[k]:
                urlgrep = urlregex.search(item)
                startgrep = startregex.search(item)
                timegrep = timeregex.search(item)
                delimgrep = delimregex.search(item)
                if urlgrep or startgrep or timegrep or delimgrep:  # pass the line including url
                    pass
                else:
                    newtcptrace.append(item)  # newtrace includes parsed items of trace[k]
            pkt = 0
            for j in range(len(newtcptrace)):
                if 'Timestamp' in newtcptrace[j]:  # start of the line for each packet
                    pkt += 1
            # print(rf'TOTAL PACKET IN TCP {hash} trace {k}: ' + str(pkt))
            tcpnr.append(pkt)
        if len(tcpnr) > 1:
            print(rf'[ OLFreeTCPtraces_{hash} ] ')
            tcpmean = statistics.mean(tcpnr)
            print('TCP MEAN:', tcpmean)
            tcpstd = statistics.stdev(tcpnr)
            print('TCP STD:', tcpstd)
            tcpmax = max(tcpnr)
            print('TCP MAX:', tcpmax)
            print('** For feature files with same hash, those all files will get this values. ')

        else:
            print('There is not enough trace in the file. ')
            tcpmean = 'None'
            tcpstd = 'None'
            tcpmax = 'None'

    ### 근데 이미 각 트레이스 별 총 패킷 합을 구하는데 프로토콜 별 통계값을 갖는게 의미가 있나? 중복처럼 보임

    print("\nReading TLS file ... ")
    with open(rf'./outlierfree/OLFreeTLStraces_{hash}', 'r') as tlsf:
        tlstrace = []
        tlstempo = []
        tlslines = tlsf.read()
        if 'URL' in tlslines:
            for i, tlspart in enumerate(tlslines.split('URL :')):  # split traces from merged file
                tlsline = tlspart.split()
                tlstempo.append(tlsline)
            for tlsstring in tlstempo:
                if len(tlsstring) > 4:  # remove empty entities
                    tlstrace.append(tlsstring)
                else:
                    pass
        else:
            for i, tlspart in enumerate(tlslines.split('https://')):  # split traces from merged file
                tlsline = tlspart.split()
                tlstempo.append(tlsline)
            for tlsstring in tlstempo:
                if len(tlsstring) > 4:  # remove empty entities
                    tlstrace.append(tlsstring)
                else:
                    pass
        print('There are ' + str(len(tlstrace)) + ' traces in the file')
        urlregex = re.compile('https.')
        startregex = re.compile('START')
        timeregex = re.compile('TIMESTAMP')
        delimregex = re.compile(r'\\n')
        tlsnr = []
        for l in range(len(tlstrace)):
            newtlstrace = []
            for item in tlstrace[l]:
                urlgrep = urlregex.search(item)
                startgrep = startregex.search(item)
                timegrep = timeregex.search(item)
                delimgrep = delimregex.search(item)
                if urlgrep or startgrep or timegrep or delimgrep:  # pass the line including url
                    pass
                else:
                    newtlstrace.append(item)  # newtrace includes parsed items of trace[k]
            tlspkt = 0

            for m in range(len(newtlstrace)):
                if 'Timestamp' in newtlstrace[m]:  # start of the line for each packet
                    tlspkt += 1
            tlsnr.append(tlspkt)
        if len(tlsnr) > 1:
            print(rf'[ OLFreeTLStraces_{hash} ] ')
            tlsmean = statistics.mean(tlsnr)
            print('TLS MEAN:' , tlsmean)
            tlsstd = statistics.stdev(tlsnr)
            print('TLS STD:', tlsstd)
            tlsmax = max(tlsnr)
            print('TLS MAX:', tlsmax)
            print('** For feature files with same hash, those all files will get this values. ')

        else:
            print('There is not enough trace in the file. ')
            tlsmean = 'None'
            tlsstd = 'None'
            tlsmax = 'None'
    return tcpmean, tcpstd, tcpmax, tlsmean, tlsstd, tlsmax


def funcE(tempocountlist):
    countlist = []
    for nr in tempocountlist:
        if nr != 0:  # 0 = initial value
            countlist.append(nr)  # countlist = [11, 11,..., 11, ... 14, 14, 14, 20, 20, 20, ... ]
    uniqcount = uniquevalue(countlist)  # remain only unique values

    if len(uniqcount) > 1:
        print("")
        Emean = statistics.mean(uniqcount)
        print('MEAN:', Emean)
        Estd = statistics.stdev(uniqcount)
        print('STD:', Estd)
        Emedian = statistics.median(uniqcount)
        print('MEDIAN:', Emedian)
        Emin = min(uniqcount)
        print('MIN:', Emin)
        Emax = max(uniqcount)
        print('MAX:', Emax)
        return Emean, Estd, Emedian, Emin, Emax
    else:
        print('There is only', uniqcount, 'value. Not able to compute. ')
        return 'None', 'None', 'None', 'None', 'None'



if __name__ == '__main__':
    filelist = findfile()
    for i in range(len(filelist)):
        filename = filelist[i]
        ftype = filename.split('_')[0][6:-6]  # type of trace
        urlhash = filename.split('_')[1]
        if ftype == 'TOR':        # read only TOR cell traces
            print('Start of the operation'.center(80, '+'))
            # -------------------------------------------------------------#
    #         urlhash = '062c59c1e4c6e7a36b438d3decb654ac'
            tcpmean, tcpstd, tcpmax, tlsmean, tlsstd, tlsmax = ofunc3(urlhash)
    #         # -------------------------------------------------------------#
            with open(rf'./outlierfree/{filename}', 'r') as f:
                print('\n' + rf'Reading {filename}...')
                trace = []
                tempo = []
                lines = f.read()
                if 'URL' in lines:
                    for i, part in enumerate(lines.split('URL :')):  # split traces from merged file
                        line = part.split()
                        tempo.append(line)
                    for string in tempo:
                        if len(string) > 4:  # remove empty entities
                            trace.append(string)
                        else:
                            pass
                else:
                    for i, part in enumerate(lines.split('https://')):  # split traces from merged file
                        line = part.split()
                        tempo.append(line)
                    for string in tempo:
                        if len(string) > 4:  # remove empty entities
                            trace.append(string)
                        else:
                            pass
                print('There are ' + str(len(trace)) + ' of traces in the file')
                urlregex = re.compile('www.')
                startregex = re.compile('START')
                timeregex = re.compile('TIMESTAMP')
                falschregex = re.compile('StartTime')
                delimregex = re.compile(r'\\n')

                for k in range(len(trace)):
                    print('\nReading ' + str(k+1) + 'th trace in the ' + f'{filename}...')
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


                    featuredata = {}
                    ################# extract feature from here ####################
                    Apkt, A_IN_part, A_OUT_part = funcA(newtrace)
                    featuredata.update({'TOTAL_PKT' : Apkt})
                    featuredata.update({'INCOMING_PKT' : A_IN_part})
                    featuredata.update({'OUTGOING_PKT' : A_OUT_part})
                    # -------------------------------------------------------------#
                    B_IN_std, B_IN_av, B_OUT_std, B_OUT_av = funcB(newtrace)
                    featuredata.update({'PKTORDER_IN_STD': B_IN_std})
                    featuredata.update({'PKTORDER_IN_AVER': B_IN_av})
                    featuredata.update({'PKTORDER_OUT_STD': B_OUT_std})
                    featuredata.update({'PKTORDER_OUT_AVER': B_OUT_av})
                    # -------------------------------------------------------------#
                    Cstd, Cmean, Cmedian, Cmax = funcC(newtrace)
                    featuredata.update({'CHUNK20_STD': Cstd})
                    featuredata.update({'CHUNK20_MEAN': Cmean})
                    featuredata.update({'CHUNK20_MEDIAN': Cmedian})
                    featuredata.update({'CHUNK20_MAX': Cmax})
                    # -------------------------------------------------------------#
                    D_INpkt, D_OUTpkt, D_L_INpkt, D_L_OUTpkt = funcD(newtrace)
                    featuredata.update({'FIRST30_IN': D_INpkt})
                    featuredata.update({'FIRST30_OUT': D_OUTpkt})
                    featuredata.update({'LAST30_IN': D_L_INpkt})
                    featuredata.update({'LAST30_OUT': D_L_OUTpkt})
                    # -------------------------------------------------------------#
                    # GOAL: packet per second (e)
                    print('Function E'.center(80, '-'))
                    print(' ** This work can take some seconds **')

                    timelist = []
                    tempocountlist = []
                    attach = 0
                    for a in range(len(newtrace)):
                        if 'Timestamp' in newtrace[a]:
                            standard = str(newtrace[a + 1]).split('--')[0]
                            timelist.append(float(standard))
                            frac, whole = math.modf(float(standard))
                            counter = 0
                            for g in range(len(newtrace)):
                                if 'Timestamp' in newtrace[g]:
                                    comparetime = str(newtrace[g + 1]).split('--')[0]
                                    if float(comparetime) <= whole + 1:     # 1 sec in epoch time = 1
                                        counter += 1
                            # print('BETWEEN', standard, 'AND', whole+1, ':', counter)
                            attach = counter
                        tempocountlist.append(attach)
                    Emean, Estd, Emedian, Emin, Emax = funcE(tempocountlist)
                    featuredata.update({'PKT/S_MEAN': Emean})
                    featuredata.update({'PKT/S STD': Estd})
                    featuredata.update({'PKT/S MEDIAN': Emedian})
                    featuredata.update({'PKT/S MIN': Emin})
                    featuredata.update({'PKT/S MAX': Emax})
                    # -------------------------------------------------------------#
                    F_INmax, F_INmean, F_INstd, F_INq3, F_OUTmax, F_OUTmean, F_OUTstd, F_OUTq3 = funcF(newtrace)
                    featuredata.update({'INTER_IN_MAX': F_INmax})
                    featuredata.update({'INTER_IN_MEAN': F_INmean})
                    featuredata.update({'INTER_IN_STD': F_INstd})
                    featuredata.update({'INTER_IN_Q3': F_INq3})
                    featuredata.update({'INTER_OUT_MAX': F_OUTmax})
                    featuredata.update({'INTER_OUT_MEAN': F_OUTmean})
                    featuredata.update({'INTER_OUT_STD': F_OUTstd})
                    featuredata.update({'INTER_OUT_Q3': F_OUTq3})
                    # -------------------------------------------------------------#
                    G_INq1, G_INq2, G_INq3, G_OUTq1, G_OUTq2, G_OUTq3, G_total_IN, G_total_OUT = funcG(newtrace)
                    featuredata.update({'IN_Q1': G_INq1})
                    featuredata.update({'IN_Q2': G_INq2})
                    featuredata.update({'IN_Q3': G_INq3})
                    featuredata.update({'IN_TOTALTIME': G_total_IN})
                    featuredata.update({'OUT_Q1': G_OUTq1})
                    featuredata.update({'OUT_Q2': G_OUTq2})
                    featuredata.update({'OUT_Q3': G_OUTq3})
                    featuredata.update({'OUT_TOTALTIME': G_total_OUT})
                    # -------------------------------------------------------------#
                    INSIZE_mean, INSIZE_min, INSIZE_max, INSIZE_std, OUTSIZE_min, OUTSIZE_mean, OUTSIZE_max, OUTSIZE_std, totalincome, totaloutgo, iIndex, iPercent, oIndex, oPercent = ofunc1(newtrace)
                    featuredata.update({'SIZE_IN_MEAN': INSIZE_mean})
                    featuredata.update({'SIZE_IN_MIN': INSIZE_min})
                    featuredata.update({'SIZE_IN_MAX': INSIZE_max})
                    featuredata.update({'SIZE_IN_STD': INSIZE_std})
                    featuredata.update({'SIZE_OUT_MEAN': OUTSIZE_mean})
                    featuredata.update({'SIZE_OUT_MIN': OUTSIZE_min})
                    featuredata.update({'SIZE_OUT_MAX': OUTSIZE_max})
                    featuredata.update({'SIZE_OUT_STD': OUTSIZE_std})
                    featuredata.update({'SIZE_IN_TOTAL': totalincome})
                    featuredata.update({'SIZE_OUT_TOTAL': totaloutgo})
                    featuredata.update({'MOST_IN_IP': iIndex})
                    featuredata.update({'IN_IP_%': iPercent})
                    featuredata.update({'MOST_OUT_IP': oIndex})
                    featuredata.update({'OUT_IP_%': oPercent})
                    # -------------------------------------------------------------#
                    sip, srcpercent, dip, dstpercent = ofunc2(newtrace)
                    featuredata.update({'MOST_SRC': sip})
                    featuredata.update({'SRC_%': srcpercent})
                    featuredata.update({'MOST_DST': dip})
                    featuredata.update({'DST_%': dstpercent})
                    # -------------------------------------------------------------#
                    idxip, maxdata = max_data_ip(newtrace)
                    featuredata.update({'MOST_SENT_BYTES_IP': idxip})
                    featuredata.update({'SENT_BYTES_BY_IP': maxdata})
                    # -------------------------------------------------------------#
                    featuredata.update({'TCP_MEAN': tcpmean})
                    featuredata.update({'TCP_STD': tcpstd})
                    featuredata.update({'TCP_MAX': tcpmax})
                    featuredata.update({'TLS_MEAN': tlsmean})
                    featuredata.update({'TLS_STD': tlsstd})
                    featuredata.update({'TLS_MAX': tlsmax})
                    print("")

                    print(featuredata)
                    # save data from each trace
                    df = pd.DataFrame(featuredata, index=[0])
                    print(df)
                    outputname = 'TORtraces_'+urlhash
                    df.to_csv('./torcell_feature/feature_%s_to_trace_%s.csv' % (outputname, k+1))
                    print("Saved in csv file.")

            print('End of the operation'.center(80, '+'))
            print('')



# reference: Effect of Feature Selection on Performance of Internet Traffic Classification on NIMS Multi-Class dataset
# Evaluation of machine learning classifiers for mobile malware detection (Fairuz Amalina Narudin et al.)
# A machine learning approach for feature selection traffic classification using security analysis (Muhammad Shafiq et al.)

#----------- implemented function (ownfeature#)------------#
# 1) packet length: mean, max, min, std
# 2) mean, max, std of number of packets of each protocol per url
# 3) percentage of packets with certain sizes(unique sizes)
# 4) total pkt length
# 5) IP address who sent most often & the frequency
# 6) IP address who sent most bytes