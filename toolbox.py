import sys
import subprocess

#create a function to process the argument/parameter
def main():
    args = sys.argv
    option = args[1:2]  # get -h or -s as option
    keyword = args[2:]  # get keyword from 3rd chunk

    # create the condition since argument/parameter is needed to get the result
    if len(option) == 0:
        print("\nYou didn't give any commands in!\nPlease specify the parameter or use -h or -help to see the instruction.\n")

    # If the condition is met, it will process based on the argument/parameter
    else:
        for opt in option:
            #Print the instruction how to make use of the program
            if opt == '-h' or opt == '-help':
                print("\nThis toolbox is for collecting and processing of random audio files from Youtube and Freemusicarchive.")
                print("\nUsage: toolbox.py [OPTIONS]\n")
                print("Options:\n\t-h\t\t\tprint overview information about this toolbox")
                print("\t-s [KEYWORD]\t\tstart toolbox in different operation modes")
                print("KEYWORD:\n\tcollect\t\t\tstart to collect random audio files")
                print("\tspec\t\t\tshow spectrogram from FFT result")
                print("\thash\t\t\tcollect hash of peaks")
                print("\thisto\t\t\tshow histogram")
                print("\tRF\t\t\texecute RandomForest Classification")
                print("\tKNN\t\t\texecute K Nearest Neighbors Classification")
                print("\tSVM\t\t\texecute SVM Classification")
            #if -s is chosen, keyword is needed to do the instruction
            elif opt == '-s':
                if keyword:
                    for key in keyword:
                        #call the file and run its code
                        if key == 'collect':
                            subprocess.call(['python3', 'downloader.py'])
                        elif key == 'spec':
                            subprocess.call(['python3', 'libspec.py'])
                        elif key == 'hash':
                            subprocess.call((['python3', 'peaky.py']))
                        elif key == 'histo':
                            subprocess.call(['python3', 'histo.py'])
                        elif key == 'RF':
                            subprocess.call(['python3', 'RF.py'])
                        elif key == 'KNN':
                            subprocess.call(['python3', 'KNN.py'])
                        elif key == 'SVM':
                            subprocess.call(['python3', 'svm.py'])
                        elif key == 'counter': #test performance
                            subprocess.call(['python3', 'counter.py'])
                        #ask the user to put the valid keyword
                        else:
                            print("Please enter the valid keyword. \n\n[KEYWORD]")
                            print("\tcollect\t\t\tstart to collect random audio files")
                            print("\tspec\t\t\tshow spectrogram from FFT result")
                            print("\thash\t\t\tcollect hash of peaks")
                            print("\thisto\t\t\tshow histogram")
                            print("\tRF\t\t\texecute RandomForest Classification")
                            print("\tKNN\t\t\texecute K Nearest Neighbors Classification")
                            print("\tSVM\t\t\texecute SVM Classification")
                              #if the keyword is not matched, print the instruction again
                else:
                    print("...There is no valid keyword!!! \n\n[KEYWORD]\n")
                    print("\tcollect\t\t\tstart to collect random audio files")
                    print("\tspec\t\t\tshow spectrogram from FFT result")
                    print("\thash\t\t\tcollect hash of peaks")
                    print("\thisto\t\t\tshow histogram")
                    print("\tRF\t\t\texecute RandomForest Classification")
                    print("\tKNN\t\t\texecute K Nearest Neighbors Classification")
                    print("\tSVM\t\t\texecute SVM Classification")
            # print this result if the argument or parameter is not matched
            else:
                print("\nUnrecognised argument.")
                print("\nUsage: toolbox.py [OPTIONS]\n")
                print("Options:\n\t-h\t\t\tprint overview information about this toolbox")
                print("\t-s [KEYWORD]\t\tstart toolbox in different operation modes")
                print("\n[KEYWORD]:")
                print("\tcollect\t\t\tstart to collect random audio files")
                print("\tspec\t\t\tshow spectrogram from FFT result")
                print("\thash\t\t\tcollect hash of peaks")
                print("\thisto\t\t\tshow histogram")
                print("\tRF\t\t\texecute RandomForest Classification")
                print("\tKNN\t\t\texecute K Nearest Neighbors Classification")
                print("\tSVM\t\t\texecute SVM Classification")

if __name__ == "__main__":
    main()
