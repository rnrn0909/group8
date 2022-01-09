import os
import json
import glob

def geturlhash():
    with open("./hashes.json") as data_file:
        data = json.load(data_file)
    return data

def main():
    hashesu=[]
    for root, dirs, files in os.walk("./TRACES"):
        for file in files:
            if file.endswith(".txt"):
                 pathtocap=os.path.join(root, file)
                 items = file.split('_')
                 urlhash=items[1]
                 hashesu.append(urlhash)
                 circid=(items[2].split('.'))[0]


    hashesu = list(set(hashesu))

    print(hashesu)

    for hash in hashesu:
        files=glob.glob(rf"./TRACES/TCP_{hash}*")
        if len(files) != 0:
            print("URLs files to merge", files)
            with open(rf'./alltraces/allTCPtraces_{hash}', 'w') as outfile:
                for fname in files:
                    with open(fname) as infile:
                        for line in infile:
                            outfile.write(line)
        else:
            print('No file to merge')

        files = glob.glob(rf"./TRACES/TOR_{hash}*")
        if len(files) != 0:
            print("URLs files to merge", files)
            with open(rf'./alltraces/allTORtraces_{hash}', 'w') as outfile:
                for fname in files:
                    with open(fname) as infile:
                        for line in infile:
                            outfile.write(line)
        else:
            print("No file to merge")

        files = glob.glob(rf"./TRACES/TLS_{hash}*")
        if len(files) != 0:
            print("URLs files to merge", files)
            with open(rf'./alltraces/allTLStraces_{hash}', 'w') as outfile:
                for fname in files:
                    with open(fname) as infile:
                        for line in infile:
                            outfile.write(line)
        else:
            print('No file to merge')

if __name__ == '__main__':
    main()