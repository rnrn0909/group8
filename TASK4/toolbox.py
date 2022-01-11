import sys
import subprocess

def main():
    args = sys.argv

    option = args[1:2]  # First element of args is the file name
    keyword = args[2:]

    # create the condition since argument/parameter is needed to get the result
    if len(option) == 0:
        print("\nYou didn't give any commands in!\nPlease put -h or -help to see the instruction.\n")

    else:           # if user put option
        for opt in option:
            #Print the instruction how to make use of the program
            if opt == '-h' or opt == '-help':
                print("")
                print(" Website Fingerprinting Toolbox ".center(80, '*'))
                print("\nUsage: toolbox.py [OPTIONS]\n")
                print("[ OPTIONS ]\n\t-h\t\t\tPrint overview information about this toolbox")
                print("\t-s [KEYWORD]\t\tStarts the toolbox in different operation modes")
                print("\t-l [KEYWORD]\t\tLoads for execution")
                print("\n[ KEYWORD ]\n\ttrends : Collect trending search keywords in Google Trends from various countries")
                print("\tpages : Collect pages from a randomly selected trend")
                print("\tvisit : Visit URLs collected in Firefox through TOR")
                print("\tdictionary : Generate JSON mapping of URL-hash for troubleshooting")
                print("\textraction : Extraction of data at different layers")
                print("\tautomatic : Automatic visit of pages ans extraction of TCP and TLS traces for these pages loads without any manual interaction")
                print("\tmerging : Merging of already existing TCP/TLS/TOR cell traces collected for a given URL in a single file")
                print("\toutlier : Detect and remove outliers")
                print("\tfeature : Extract features from network traces")

            #if -s is chosen, keyword is needed to do the instruction
            elif opt == '-s':
                if keyword:
                    for key in keyword:
                        #call the file and run its code
                        if key == 'trends':
                            subprocess.call(['python3', './scrapalltrendswithtor.py'])
                        elif key == 'pages':
                            subprocess.call(['python3', './searchtrendswithtorpy'])
                        elif key == 'visit':
                            subprocess.call(['python3', './visiturls.py'])
                        elif key == 'dictionary':
                            subprocess.call(['python3', './urlhashes.py'])
                        elif key == 'extraction':
                            subprocess.call(['python3', './tracecollection.py'])
                        elif key == 'automatic':
                            subprocess.call(['python3', './automatic.py'])
                        elif key == 'merging':
                            subprocess.call(['python3', './mergetraces.py'])
                        elif key == 'outlier':
                            subprocess.call(['python3', './outlierdetection.py'])
                        elif key == 'feature':
                            subprocess.call(['python3', './feature1.py'])
                        # ** Since (personally) using 2.7 and 3.8 versions, had to fix it 'python3' but if someone is
                        # using only one version of Python, don't need to use like this **

                        #ask the user to put the valid keyword
                        else:
                            print("Please enter valid keyword!")
                            print("\n[ KEYWORD ]\n\ttrends : Collect trending search keywords in Google Trends from various countries")
                            print("\tpages : Collect pages from a randomly selected trend")
                            print("\tvisit : Visit URLs collected in Firefox through TOR")
                            print("\tdictionary : Generate JSON mapping of URL-hash for troubleshooting")
                            print("\textraction : Extraction of data at different layers")
                            print(
                                "\tautomatic : Automatic visit of pages ans extraction of TCP and TLS traces for these pages loads without any manual interaction")
                            print(
                                "\tmerging : Merging of already existing TCP/TLS/TOR cell traces collected for a given URL in a single file")
                            print("\toutlier : Detect and remove outliers")
                            print("\tfeature : Extract features from network traces")
                            print("\nIf you need help, enter -h or -help for help. ")
                #if keyword is not matched, print the instruction again
                else:
                    print("Please enter valid keyword! ")
                    print("\n[ KEYWORD ]\n\ttrends : Collect trending search keywords in Google Trends from various countries")
                    print("\tpages : Collect pages from a randomly selected trend")
                    print("\tvisit : Visit URLs collected in Firefox through TOR")
                    print("\tdictionary : Generate JSON mapping of URL-hash for troubleshooting")
                    print("\textraction : Extraction of data at different layers")
                    print(
                        "\tautomatic : Automatic visit of pages ans extraction of TCP and TLS traces for these pages loads without any manual interaction")
                    print(
                        "\tmerging : Merging of already existing TCP/TLS/TOR cell traces collected for a given URL in a single file")
                    print("\toutlier : Detect and remove outliers")
                    print("\tfeature : Extract features from network traces")
                    print("\nIf you need help, enter -h or -help for help. ")


            elif opt == '-l':
                if keyword:
                    for key in keyword:
                        if key == 'database':                           #call the file and run its code
                            subprocess.call(['python', './loadfromdb.py'])

                        else:                                           #ask the user to put the valid keyword
                            print("Please enter valid keyword!")
                            print("\n[ KEYWORD ]\n\ttrends : Collect trending search keywords in Google Trends from various countries")
                            print("\tpages : Collect pages from a randomly selected trend")
                            print("\tvisit : Visit URLs collected in Firefox through TOR")
                            print("\tdictionary : Generate JSON mapping of URL-hash for troubleshooting")
                            print("\textraction : Extraction of data at different layers")
                            print(
                                "\tautomatic : Automatic visit of pages ans extraction of TCP and TLS traces for these pages loads without any manual interaction")
                            print(
                                "\tmerging : Merging of already existing TCP/TLS/TOR cell traces collected for a given URL in a single file")
                            print("\toutlier : Detect and remove outliers")
                            print("\tfeature : Extract features from network traces")
                            print("\nIf you need help, enter -h or -help for help. ")


                else:                                   #if keyword is not matched, print the instruction again
                    print("Please enter valid keyword!")
                    print("\n[ KEYWORD ]\n\ttrends : Collect trending search keywords in Google Trends from various countries")
                    print("\tpages : Collect pages from a randomly selected trend")
                    print("\tvisit : Visit URLs collected in Firefox through TOR")
                    print("\tdictionary : Generate JSON mapping of URL-hash for troubleshooting")
                    print("\textraction : Extraction of data at different layers")
                    print(
                        "\tautomatic : Automatic visit of pages ans extraction of TCP and TLS traces for these pages loads without any manual interaction")
                    print(
                        "\tmerging : Merging of already existing TCP/TLS/TOR cell traces collected for a given URL in a single file")
                    print("\toutlier : Detect and remove outliers")
                    print("\tfeature : Extract features from network traces")
                    print("\nIf you need help, enter -h or -help for help. ")


            else:                                       # print if user put wrong option
                print("Please put the valid options! ")
                print("\nUsage: toolbox.py [OPTIONS]\n")
                print("[ OPTIONS ]\n\t-h\t\t\tPrint overview information about this toolbox")
                print("\t-s [KEYWORD]\t\tStarts the toolbox in different operation modes")
                print("\t-l [KEYWORD]\t\tLoads for execution")
                print("[ KEYWORD ]\n\ttrends : Collect trending search keywords in Google Trends from various countries")
                print("\tpages : Collect pages from a randomly selected trend")
                print("\tvisit : Visit URLs collected in Firefox through TOR")
                print("\tdictionary : Generate JSON mapping  of URL-hash for troubleshooting")
                print("\tdatabase : Loads the database with the selected countries for the experiment")
                print("\textraction : Extraction of data at different layers")
                print(
                    "\tautomatic : Automatic visit of pages ans extraction of TCP and TLS traces for these pages loads without any manual interaction")
                print(
                    "\tmerging : Merging of already existing TCP/TLS/TOR cell traces collected for a given URL in a single file")
                print("\toutlier : Detect and remove outliers")
                print("\tfeature : Extract features from network traces")
                print("\nIf you need help, enter -h or -help for help. ")


if __name__ == '__main__':
    main()

