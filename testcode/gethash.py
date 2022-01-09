import json
from mysql.connector import (connection)
import os


conn = connection.MySQLConnection(user='root', password='root', port="3306",
                                  host='127.0.0.1',
                                  database='webprintdb', auth_plugin='mysql_native_password')

newwrite = []
query = """SELECT url, urlhash FROM subpages"""
cursor = conn.cursor()
dic = cursor.execute(query)
for (url, urlhash) in cursor:
    newwrite.append(url)
    newwrite.append(urlhash)

json_object = json.dumps(newwrite, indent=4)
with open('hashes.json', 'w') as outfile:
    outfile.write(json_object)


# def geturlhash():
#     with open("./hashes.json") as data_file:
#         data = json.load(data_file)
#     return data
#
#
# for root, dirs, files in os.walk("./TRACES"):
#     for file in files:
#         if file.endswith(".txt"):
#              # print(os.path.join(root, file)) #dir
#              pathtocap=os.path.join(root, file)
#
#              items = file.split('_')
#              print("urlhash ", items[1])
#              urlhash=items[1]
#              circid=(items[2].split('.'))[0]
#              print("circuit id", circid)
#
#              data = geturlhash()
#              for key, value in data.items():
#                 if key==urlhash:
#                     print(key, value)
