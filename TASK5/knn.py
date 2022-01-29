import numpy as np
from pandas import read_csv
import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score, RepeatedKFold
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import confusion_matrix
import matplotlib.pyplot as plt
from sklearn.metrics import accuracy_score, precision_score, recall_score
from sklearn.preprocessing import RobustScaler
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import MaxAbsScaler
from sklearn.preprocessing import PowerTransformer
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import classification_report
import sys
import os
import json
from mysql.connector import (connection)
import mysql.connector
from urllib.parse import urlparse

def featurelist():
    filelist = []
    for root, dir, files in os.walk('./includeOLfeature/'):
        for file in files:
            if file.endswith('.csv') and 'TOR' in file:
                filelist.append(file)
    return filelist


def geturlhash():
    with open("./urlhashes.json") as data_file:
        data = json.load(data_file)
    return data

def hundreddomain():
    validurl = []
    conn = connection.MySQLConnection(user='root', password='root', port="3306",
                                      host='127.0.0.1',
                                      database='webprintdb', auth_plugin='mysql_native_password')

    query = """SELECT id_mainpage, url FROM websites"""
    cursor = conn.cursor()
    cursor.execute(query)
    for id_mainpage, url in cursor:
        validurl.append(id_mainpage)  # use id_mainpage as label/index of array
        validurl.append(urlparse(url).netloc)
    conn.close()
    validurl = np.array(validurl)
    validurl = np.reshape(validurl, (len(validurl) // 2, 2))
    return validurl

def create_label():
    target_label = []
    validurl = hundreddomain()
    filelist = featurelist()
    urldata = geturlhash()
    for file in filelist:
        filehash = file.split('_')[2]
        for url, savedhash in urldata.items():
            if filehash == savedhash:
                domain = urlparse(url).netloc
                for y in range(len(validurl)):
                    if domain == validurl[y][1]:
                        target_label.append(validurl[y][0])
                    else:
                        pass
    return target_label

def main():
    print(' Start '.center(60, '*'))
    # feature = read_csv('hash.csv', delimiter=',')
    col_list = ['TOTAL_PKT', 'INCOMING_PKT', 'OUTGOING_PKT', 'PKTORDER_IN_STD', 'PKTORDER_IN_AVER', 'PKTORDER_OUT_STD',
                'PKTORDER_OUT_AVER', 'CHUNK20_STD', 'CHUNK20_MEAN', 'CHUNK20_MEDIAN', 'CHUNK20_MAX', 'FIRST30_IN',
                'FIRST30_OUT',
                'LAST30_IN', 'LAST30_OUT', 'PKT/S_MEAN', 'PKT/S STD', 'PKT/S MEDIAN', 'PKT/S MIN', 'PKT/S MAX',
                'INTER_IN_MAX', 'INTER_IN_MEAN', 'INTER_IN_STD', 'INTER_IN_Q3', 'INTER_OUT_MAX', 'INTER_OUT_MEAN',
                'INTER_OUT_STD', 'INTER_OUT_Q3',
                'IN_Q1', 'IN_Q2', 'IN_Q3', 'IN_TOTALTIME', 'OUT_Q1', 'OUT_Q2', 'OUT_Q3', 'OUT_TOTALTIME',
                'SIZE_IN_MEAN', 'SIZE_IN_MIN', 'SIZE_IN_MAX', 'SIZE_IN_STD', 'SIZE_OUT_MEAN', 'SIZE_OUT_MIN',
                'SIZE_OUT_MAX', 'SIZE_OUT_STD',
                'SIZE_IN_TOTAL', 'SIZE_OUT_TOTAL', 'TCP_MEAN', 'TCP_STD', 'TCP_MAX', 'TLS_MEAN', 'TLS_STD', 'TLS_MAX']
    n_feats = len(col_list)
    # number of packets in type of trace affects 10% (the most powerful feature)
    # and traces from same url have all same value for 'TCP_MEAN', 'TCP_STD', 'TCP_MAX', 'TLS_MEAN', 'TLS_STD', 'TLS_MAX'

    filelist = featurelist()
    datalist = []
    print(' Start to read csv files... ')
    print(' This work can take a few seconds. \n')
    for file in filelist:
        filepath = './includeOLfeature/' + file
        data = read_csv(filepath)
        data.fillna(0, inplace=True)        # fill NaN value with 0
        # n_feats = data.shape[1]
        dataset = np.array(data)
        for item in dataset:
            element = np.array(item)        # len(element) = 63
            element = element[1:]           # remove index column(element[0]) from csv file
            onlyfloatarr = []
            for i in range(len(element)):          # len(element) = 52
                onlyfloatarr.append(float(element[i]))
            datalist.append(onlyfloatarr)
    data_target = create_label()

    x_train, x_test, y_train, y_test = train_test_split(datalist, data_target, shuffle=True, test_size=0.3,
                                                        random_state=20)
    print('Please select how to normalize your data. \n')
    print('\t1. RobustScaler \n\t2. StandardScaler \n\t3. MaxAbsScaler \n\t4. PowerTransformer \n\t5. MinMaxScaler\n')
    normchoice = input('Which method? (1~5) ')
    ######################### scaler ##############################
    if normchoice == '1':
        scaler = RobustScaler(quantile_range=(25, 75))
        x_train = scaler.fit_transform(x_train)
        x_test = scaler.transform(x_test)
    elif normchoice == '2':
        scaler = StandardScaler()
        x_train = scaler.fit_transform(x_train)
        x_test = scaler.transform(x_test)
    elif normchoice == '3':
        scaler = MaxAbsScaler()
        x_train = scaler.fit_transform(x_train)
        x_test = scaler.fit_transform(x_test)
    elif normchoice == '4':
        scaler = PowerTransformer(method='yeo-johnson')  # positive and negative
        x_train = scaler.fit_transform(x_train)  #
        x_test = scaler.fit_transform(x_test)
    elif normchoice == '5':
        scaler = MinMaxScaler()
        x_train = scaler.fit_transform(x_train)
        x_test = scaler.fit_transform(x_test)
    else:
        print('Invalid option. No scaling. ')
        sys.exit()              # stop running

    print("")
    print('Please choose the number of cross validation. The number must be bigger than 1. ')
    nrtofold = input('k? ')
    clf = KNeighborsClassifier(1)       # best nr of neighbors = 1
    clf.fit(x_train, y_train)
    kf = RepeatedKFold(n_splits=int(nrtofold), n_repeats=40, random_state=1)
    score = cross_val_score(clf, x_train, y_train, cv=kf, scoring="accuracy")
    print('CV Score: %.3f' % score.mean())
    y_pred = clf.predict(x_test)
    print('Accuracy : %.3f' % accuracy_score(y_test, y_pred))
    print(classification_report(y_test, y_pred))            # including accuracy score, recall...etc.
    feature_i_score = []
    print('Feature\t\t\tAccuracy: ')
    for n in range(n_feats):
        datalist = np.array(datalist)
        new_x = datalist[:, n].reshape(-1, 1)
        scores = cross_val_score(clf, new_x, data_target, cv=kf, scoring="accuracy")
        print(f'{col_list[n]}', '\t\t\t', '%.6f' % scores.mean())
        feature_i_score.append(scores.mean())

    print(feature_i_score.sort(reverse=True))
    # how to show from the most important feature with feature name?



if __name__ == "__main__":
    main()


# https://python-course.eu/machine-learning/k-nearest-neighbor-classifier-in-python.php
# https://towardsdatascience.com/building-a-k-nearest-neighbors-k-nn-model-with-scikit-learn-51209555453a
# https://doljokilab.tistory.com/12
# https://machinelearningmastery.com/k-nearest-neighbors-for-machine-learning/
# https://github.com/WillKoehrsen/feature-selector
# Random KNN feature selection - a fast and stable alternative to Random Forests, Shengqiao Li et al.
#  then the best way to estimate feature importance is by taking the sample to predict on,
#  and computing its distance from each of its nearest neighbors for each feature (call these neighb_dist).
#  Then do the same computations for a few random points (call these rand_dist) instead of the nearest neighbors.
#  Then for each feature, you take the ratio of neighb_dist / rand_dist, and the smaller the ratio, the more important that feature is.
#  KNN is suited for lower dimensional data.
#  KNN can benefit from feature selection that reduces the dimensionality of the input feature space.


# def str_column_to_float(dataset, column):
#     for row in dataset:
#         row[column] = float(str(row[column]).strip())

# def min_max_normalize(lst):
#     normalized = []
#     for value in lst:
#         normalized_num = (value - min(lst)) / (max(lst) - min(lst))
#         normalized.append(normalized_num)
#     return normalized