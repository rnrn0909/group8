import re
import numpy as np
import json
import os
import statistics
import shutil
import scipy.stats as stats


def findfile():
    filelist = []
    for root, dirs, files in os.walk("./alltraces"):
        for file in files:
            # path = os.path.join(root, file)
            filelist.append(file)

    return filelist

def create_of(ftype, furlhash, refhash, newapproach):
    with open(rf'./alltraces/all{ftype}traces_{furlhash}', 'r') as tf:
        print(rf'Reading all{ftype}traces_{furlhash} and removing outliers...' + '\n')
        ctrace = []
        ctempo = []
        clines = tf.read()
        if 'URL' in clines:
            for i, cpart in enumerate(clines.split('URL')):  # split traces from merged file
                cline = cpart.split()
                ctempo.append(cline)
            for cstring in ctempo:
                if len(cstring) > 4:  # remove empty entities
                    ctrace.append(cstring)
                else:
                    pass
        else:
            for i, cpart in enumerate(clines.split('https://')):  # split traces from merged file
                cline = cpart.split()
                ctempo.append(cline)
            for cstring in ctempo:
                if len(cstring) > 4:  # remove empty entities
                    ctrace.append(cstring)
                else:
                    pass
        xurlregex = re.compile('www.')
        xstartregex = re.compile('START')
        xtimeregex = re.compile('TIMESTAMP')  # target of removal from trace
        xdelimregex = re.compile(r'\\n')  # elements in first line of the trace
        xfalschregex = re.compile('StartTime')

        for k in range(len(ctrace)):
            cnewtrace = []
            for xitem in ctrace[k]:
                xurlgrep = xurlregex.search(xitem)
                xstartgrep = xstartregex.search(xitem)
                xtimegrep = xtimeregex.search(xitem)
                xdelimgrep = xdelimregex.search(xitem)
                xfalschgrep = xfalschregex.search(xitem)
                if xurlgrep or xstartgrep or xtimegrep or xfalschgrep or xdelimgrep:  # pass the line including url, START TIMESTAMP\n
                    pass
                else:
                    cnewtrace.append(xitem)
        if len(ctrace) == len(newapproach):
            print('No need to remove outlier. Copying the original... \n')
            shutil.copyfile(rf'./alltraces/all{ftype}traces_{furlhash}',
                            rf'./outlierfree/OLFree{ftype}traces_{refhash}')
        else:
            print('Removing outliers... ')
            if len(newapproach) != 0:
                vtrace = []
                for k in range(len(ctrace)):
                    for n in range(len(newapproach)):
                        if k == newapproach[n][0]:
                            vtrace.append(ctrace[k])
                            print(str(newapproach[n][0] + 1) + "th Trace is a valid trace. ")
                        else:
                            pass
                print(rf"There is {len(vtrace)}" + rf" valid traces in {ftype} file. ")
                if os.path.exists(
                        rf'./outlierfree/OLFree{ftype}traces_{refhash}'):  # check whether OLFree already exists or not
                    append_write = 'a'
                else:
                    append_write = 'w'
                if len(vtrace) != 0:
                    with open(rf'./outlierfree/OLFree{ftype}traces_{refhash}', append_write) as rmf:
                        for i in range(len(vtrace)):
                            element = str(vtrace[i]).strip('[').strip(']')
                            for x in element:
                                newelement = x.strip('\'')
                                rmf.write(newelement)
                else:
                    print('There is no available trace. ')
            print("Finished to remove outliers. \n")

    return True

def rmtrace(userchoice, refhash, newapproach):
    # from reference traces got a valid trace and write into file
    filelist = findfile()
    print('Start to get other types of traces...')
    if userchoice == 'TCP':
        for i in range(len(filelist)):
            filename = filelist[i]
            ftype = filename.split('_')[0][3:-6]  # type of trace
            furlhash = filename.split('_')[1]
            if furlhash == refhash and (ftype == 'TLS' or ftype == 'TOR'):
                create_of(ftype, furlhash, refhash, newapproach)
    elif userchoice == 'TLS':
        for i in range(len(filelist)):
            filename = filelist[i]
            ftype = filename.split('_')[0][3:-6]  # type of trace
            furlhash = filename.split('_')[1]
            if furlhash == refhash and (ftype == 'TCP' or ftype == 'TOR'):
                create_of(ftype, furlhash, refhash, newapproach)
    elif userchoice == 'TOR':
        for i in range(len(filelist)):
            filename = filelist[i]
            ftype = filename.split('_')[0][3:-6]  # type of trace
            furlhash = filename.split('_')[1]
            if furlhash == refhash and (ftype == 'TCP' or ftype == 'TLS'):
                create_of(ftype, furlhash, refhash, newapproach)
    else:
        pass

    return True

def firstapproach(sumlist, of):
    print("First Approach".center(50, '_'))
    mediansum = statistics.median(sumlist)
    approach1 = []
    print('\n' + rf"The median value of total size of incoming packets in this trace: {mediansum}")
    for m in range(len(of)):
        if sumlist[of[m][0]] < 0.85 * mediansum or sumlist[of[m][0]] > 1.85 * mediansum: # of[m][0] : index of valid trace
            print(rf'The sum from ' + str(of[m][0]+1) +'th trace is considered outlier.')
        else:
            print(rf'The sum from ' + str(of[m][0]+1) +'th trace is still valid.')
            approach1.append(of[m])
    return approach1

def secondapproach(sumlist, of):
    print("Second Approach".center(50, '_'))
    print("")
    approach2 = []
    q1 = np.percentile(sumlist, 25)
    q2 = np.percentile(sumlist, 50)         # if unnecessary, comment
    q3 = np.percentile(sumlist, 75)
    for t in range(len(of)):
        if sumlist[of[t][0]] > q1 - 1.5 * (q3 - q1) and sumlist[of[t][0]] < q3 + 1.5 * (q3 - q1):
            print(str(of[t][0]+1) + 'th trace is valid again.')
            approach2.append(of[t])                         # error occurs when len(of) is less than len(sumlist)
        else:                                               # why it does not occur in first approach?
            print(str(of[t][0]+1) + 'th trace is also outlier.')
    return approach2

def thirdapproach(sumlist, of):
    # Sample mean, variance, and standard deviation are sensitive to outliers
    # Z score is a number of standard deviations away from the mean that a certain data point is.
    print("Third Approach".center(50, '_'))
    print("")
    validsum = []
    for x in range(len(of)):
        validsum.append(of[x][0])
        validsum.append(sumlist[of[x][0]])
    validsum = np.array(validsum)
    validsum = np.reshape(validsum, (len(validsum) // 2, 2))

    listforscore = []
    for q in range(len(validsum)):
        listforscore.append(validsum[q][1])

    z = stats.zscore(listforscore)          # get Z score
    approach3 = []
    for p in range(len(z)):
        if np.abs(z[p]) > 1:                # threshold = 1 (temporary)
            if listforscore[p] in validsum:
                print(str(validsum[p][0]) + 'th trace is considered outlier')
        else:
            print(str(validsum[p][0]) + "th trace is still valid")
            approach3.append(of[p])
    return approach3


def ref(userchoice, min, approach):
    filelist = findfile()
    for i in range(len(filelist)):
        print('\nStart to search reference trace...')
        filename = filelist[i]
        reference = filename.split('_')[0][3:-6]        # type of trace
        refhash = filename.split('_')[1]                # hash of url in filename
        if userchoice == reference:
            with open(rf'./alltraces/all{reference}traces_{refhash}', 'r') as f:
                outlierfree = []
                trace = []
                tempo = []
                print(rf'Reading our reference trace : all{reference}traces_{refhash}...'+'\n')
                lines = f.read()
                for i, part in enumerate(lines.split('URL :')):   # split traces from merged trace file
                    line = part.split()
                    tempo.append(line)

                for string in tempo:  # remove empty entities
                    if len(string) > 4:  # due to spliting, empty entities can appear
                        trace.append(string)
                    else:
                        pass
                urlregex = re.compile('https.')
                startregex = re.compile('START')
                timeregex = re.compile('TIMESTAMP')  # target of removal from trace
                falschregex = re.compile('StartTime')
                delimregex = re.compile(r'\\n')  # elements in first line of the trace
                sumlist = []                                            # the list of total size of incoming packets
                for k in range(len(trace)):
                    print('Reading ' + str(k+1) + 'th trace in the file...')        # k+1: understandable for human
                    newtrace = []
                    pkt = 0
                    totalsize = 0           # initialization

                    for item in trace[k]:
                        urlgrep = urlregex.search(item)
                        startgrep = startregex.search(item)
                        timegrep = timeregex.search(item)
                        falschgrep = falschregex.search(item)
                        delimgrep = delimregex.search(item)
                        if urlgrep or startgrep or timegrep or falschgrep or delimgrep:   # pass the line including url, START TIMESTAMP\n
                            pass
                        else:
                            newtrace.append(item)
                    for j in range(len(newtrace)):
                        if 'Timestamp' in newtrace[j]:  # start of the line for each packet
                            pkt += 1  # count the total number of packets(whatever destination is)
                        if 'INCOMING' and 'Source' in newtrace[j]:
                            size = str(newtrace[j + 5]).strip(',')
                            if 'size' in size and 'Timestamp' in size:  # XXXTimestamp
                                size = size.split(':')[1][:-9]
                                totalsize += int(size)
                            elif 'URL' in size:                 # XXXURL
                                size = size.split(':')[1][:-3]
                                totalsize += int(size)
                            elif 'size' in size:                # size:XXX, or size:XXX
                                size = size.split(':')[1]
                                totalsize += int(size)
                            else:
                                pass                            # sometimes it grabs timestamps

                        elif 'INCOMING' in newtrace[j] and 'Source' not in newtrace[j]:
                            size = str(newtrace[j + 6]).strip(',')
                            if 'Timestamp' in size:
                                size = size.split(':')[1][:-9]
                                totalsize += int(size)
                            elif 'URL' in size:
                                size = size.split(':')[1][:-3]
                                totalsize += int(size)
                            elif 'size' in size:
                                size = size.split(':')[1]
                                totalsize += int(size)
                            else:
                                pass

                    print('\tThe sum of INCOMING packet sizes: ' + str(totalsize))
                    sumlist.append(totalsize)           # Whether the trace is valid or not, just get sum of incoming packet sizes
                    print('\tThe number of packet in this trace: ' + str(pkt))
                    if totalsize > 1045:
                        print('>> Trace ' + str(k+1) + ' is a valid trace.\n')
                        outlierfree.append(k)           # index of the trace
                        outlierfree.append(trace[k])
                    else:
                        print('>> The ' rf'{k+1}th trace should be removed. ' + '\n')

                outlierfree = np.array(outlierfree)
                of = np.reshape(outlierfree, (len(outlierfree) // 2, 2))                # (1, trace1), (2, trace2), ...
                print(f'The number of valid traces is in all{reference}traces_{refhash} is {len(of)}'+'\n')
                if len(of) == 0:
                    print(f'The number of valid traces in all{reference}traces_{refhash} is 0.')
                    print('There is no available traces. Calling crawling function again...\n')
                else:
                    pass
                ####################### 1st approach #################################
                if approach == '1':
                    newapproach = firstapproach(sumlist, of)
                    print(rf"After checking median, there are {len(newapproach)} traces.")

                ####################### 2nd approach #################################
                elif approach == '2':
                    newapproach = secondapproach(sumlist, of)
                    print(rf"After checking quartiles, there are {len(newapproach)} traces.")

                ####################### 3rd approach #################################
                elif approach == '3':
                    newapproach = thirdapproach(sumlist, of)
                    print(rf"After checking Z score, there are {len(newapproach)} traces. ")

                elif approach == '4':                           # No more removal
                    print("Keep processing ... ")
                    newapproach = of

                else:
                    print("Please put the valid option! \n")
                    break
            print('Getting reference traces is done.')
            # only when user selects further removal
            if len(newapproach) < int(min) and (approach == '1' or approach == '2' or approach == '3'):
                print("After removing outliers, the number of valid trace is less than minimum number. Do you want to revoke the previous process?")
                revoke = input("Do you want to revoke your choice? Y/N ")
                if revoke == "y" or "Y":
                    newapproach = of
                elif revoke == "n" or "N":      # return key also available
                    pass
                else:
                    print("Please put the valid option! Or it will not be revoked. \n")
                    pass

            if len(trace) == len(newapproach):
                print('>> No need to remove outlier.')
                if len(newapproach) < int(min):
                    print(rf'The number of valid traces is in all{reference}traces_{refhash} is {len(newapproach)}')
                    print("---> But You need to collect more dataset.")     # Then call visiturl/tracecollection to collect trace from corresponding url
                    noOfTraces = int(min)-len(newapproach)
                    chosenhash = refhash
                    print('The number of trace that you will collect from now ', noOfTraces)
                    print("Calling crawling function again...\n")
                else:
                    print("---> Enough dataset. Copying the original... \n")
                    shutil.copyfile(rf'./alltraces/all{reference}traces_{refhash}', rf'./outlierfree/OLFree{reference}traces_{refhash}')
                    # copy reference to ./outlierfree if there's no outliers in reference.

            else:
                if len(newapproach) < int(min):
                    print(rf'The number of valid traces is in all{reference}traces_{refhash} is {len(newapproach)}')
                    print("---> But You need to collect more dataset. \n")
                    noOfTraces = min - len(newapproach)
                    print('The number of trace that you will collect from now ', noOfTraces)
                    # Then call visiturl/tracecollection to collect trace from corresponding url
                    if os.path.exists(rf'./outlierfree/OLFree{reference}traces_{refhash}'):         # here should be changed.
                        append_write = 'a'
                    else:
                        append_write = 'w'

                    with open(rf'./outlierfree/OLFree{reference}traces_{refhash}', append_write) as nrf:
                        for i in range(len(newapproach)):           # 고치기
                            element = str(newapproach[i][1])        # to attach all traces in newapproach
                            nrf.write(element)

                else:
                    print("---> Enough dataset.")
                    print("Writing valid traces in OFtraces... \n")
                    if os.path.exists(rf'./outlierfree/OLFree{reference}traces_{refhash}'):         # check whether OLFree already exists or not
                        append_write = 'a'
                    else:
                        append_write = 'w'

                    with open(rf'./outlierfree/OLFree{reference}traces_{refhash}', append_write) as nrf:
                        for y in range(len(newapproach)):
                            element = str(newapproach[y][1]).strip('[').strip(']')       # to attach all traces in newapproach
                            for x in element:
                                newelement = x.strip('\'').strip(',')
                                nrf.write(newelement)

                    print('End of reading file'.center(50, '*'))
            rmtrace(userchoice, refhash, newapproach)
        else:
            print('Searching the reference files...')

    return True


if __name__ == '__main__':
    while True:
        print("""Which trace do you want to use as reference trace? \n
            1. TCP trace
            2. TLS trace
            3. TOR trace
            4. EXIT \n """)
        choice = input('Please enter the valid option: ')

        if choice == '1':
            print("""Give us the minimum number of the traces. (1~15)""")
            min = input("The number of minimum traces? ")
            if int(min) <= 15 and int(min) >= 1:
                print("""Do you need to remove more outliers?\n
            1. First approach: Using Median
            2. Second approach: Using Quartiles
            3. Third approach: Using Z Score
            4. No more removal \n""")
                approach = input("Please insert 1~4 : ")
                ref('TCP', min, approach)
            else:
                print("!!! Insert valid number !!! (Minimum number: 1~15, Approach: 1~4) \n")
                pass
        elif choice == '2':
            print("""Give us the minimum number of the traces. (1~15)""")
            min = input("The number of minimum traces? ")
            if int(min) <= 15 and int(min) >= 1:
                print("""Do you need to remove more outliers?\n
            1. First approach: Using Median
            2. Second approach: Using Quartiles
            3. Third approach: Using Z Score
            4. No more removal \n""")
                approach = input("Please insert 1~4 : ")
                ref('TLS', min, approach)
            else:
                print("!!! Insert valid number !!! (Minimum number: 1~15, Approach: 1~4) \n")
                pass
        elif choice == '3':
            print("""Give us the minimum number of the traces. (1~15)""")
            min = input("The number of minimum traces? ")
            if int(min) <= 15 and int(min) >= 1:
                print("""Do you need to remove more outliers?\n
            1. First approach: Using Median
            2. Second approach: Using Quartiles
            3. Third approach: Using Z Score
            4. No more removal \n""")
                approach = input("Please insert 1~4 : ")
                ref('TOR', min, approach)
            else:
                print("!!! Insert valid number !!! (Minimum number: 1~15, Approach: 1~4) \n")
                pass
        elif choice == '4':
            print("Bye!")
            break
        else:
            print('!!! Please put the valid option(1~4). \n')


# how to call visiturls/tracecollection for corresponding urls?
# reference : https://medium.com/clarusway/z-score-and-how-its-used-to-determine-an-outlier-642110f3b482
