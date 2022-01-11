import json
import glob

def geturlhash():
    with open("./hashes.json") as data_file:
        data = json.load(data_file)
    return data

def main(chosenhash):
    files=glob.glob(rf"./TRACES/TCP_{chosenhash}*")
    if len(files) != 0:
        print("URLs files to merge", files)
        print("Merged ", len(files), 'files. ')
        with open(rf'./alltraces/allTCPtraces_{chosenhash}', 'w') as outfile:
            for fname in files:
                with open(fname) as infile:
                    for line in infile:
                        outfile.write(line)
    else:
        print('No file to merge')

    files = glob.glob(rf"./TRACES/TOR_{chosenhash}*")
    if len(files) != 0:
        print("URLs files to merge", files)
        print("Merged ", len(files), 'files. ')

        with open(rf'./alltraces/allTORtraces_{chosenhash}', 'w') as outfile:
            for fname in files:
                with open(fname) as infile:
                    for line in infile:
                        outfile.write(line)
    else:
        print("No file to merge")

    files = glob.glob(rf"./TRACES/TLS_{chosenhash}*")
    if len(files) != 0:
        print("URLs files to merge", files)
        print("Merged ", len(files), 'files. ')
        with open(rf'./alltraces/allTLStraces_{chosenhash}', 'w') as outfile:
            for fname in files:
                with open(fname) as infile:
                    for line in infile:
                        outfile.write(line)
    else:
        print('No file to merge')

if __name__ == '__main__':
    chosenhash = input("Which hash? ")
    main(chosenhash)