import numpy as np
from pandas import read_csv
import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.model_selection import RepeatedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn import preprocessing
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import confusion_matrix
import matplotlib.pyplot as plt
from sklearn import metrics
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

    query = """SELECT url FROM websites"""
    cursor = conn.cursor()
    cursor.execute(query)
    for url in cursor:
        validurl.append(urlparse(url[0]).netloc)
    conn.close()
    return validurl

def create_label():
    target_label = []
    validurl = hundreddomain()
    filelist = featurelist()
    for x in range(len(filelist)):
        data = geturlhash()
        filehash = filelist[x].split('_')[2]
        for url, savedhash in data.items():
            if filehash == savedhash:
                domain = urlparse(url).netloc
                for y in range(len(validurl)):
                    if domain == validurl[y]:
                        target_label.append(y)
                    else:
                        pass
    return target_label


def even_odd(lst):      # Since there is no specific label in my dataset,
    if len(lst) % 2 == 0:       # case: even
        data_target = [0]*(len(lst)//2) +[1]*(len(lst)//2)            # dummy label, nr of each label = len(datalist)//2
        return data_target
    elif len(lst) % 2 == 1:     # case: odd
        data_target = [0]*(len(lst)//2) + [1]*(len(lst)//2 + 1)
        return data_target
    else:
        pass

def main():
    print(' Start '.center(60, '*'))
    col_list = ['TOTAL_PKT', 'INCOMING_PKT', 'OUTGOING_PKT', 'PKTORDER_IN_STD', 'PKTORDER_IN_AVER', 'PKTORDER_OUT_STD',
                'PKTORDER_OUT_AVER', 'CHUNK20_STD', 'CHUNK20_MEAN', 'CHUNK20_MEDIAN', 'CHUNK20_MAX', 'FIRST30_IN', 'FIRST30_OUT',
                'LAST30_IN', 'LAST30_OUT', 'PKT/S_MEAN', 'PKT/S STD', 'PKT/S MEDIAN', 'PKT/S MIN', 'PKT/S MAX',
                'INTER_IN_MAX', 'INTER_IN_MEAN', 'INTER_IN_STD', 'INTER_IN_Q3', 'INTER_OUT_MAX', 'INTER_OUT_MEAN', 'INTER_OUT_STD', 'INTER_OUT_Q3',
                'IN_Q1', 'IN_Q2', 'IN_Q3', 'IN_TOTALTIME', 'OUT_Q1', 'OUT_Q2', 'OUT_Q3', 'OUT_TOTALTIME',
                'SIZE_IN_MEAN', 'SIZE_IN_MIN', 'SIZE_IN_MAX', 'SIZE_IN_STD', 'SIZE_OUT_MEAN', 'SIZE_OUT_MIN', 'SIZE_OUT_MAX', 'SIZE_OUT_STD',
                'SIZE_IN_TOTAL', 'SIZE_OUT_TOTAL', 'TCP_MEAN', 'TCP_STD', 'TCP_MAX', 'TLS_MEAN', 'TLS_STD', 'TLS_MAX']

    # number of packets in type of trace affects 10% (the most powerful feature)
    # and traces from same url have all same value for 'TCP_MEAN', 'TCP_STD', 'TCP_MAX', 'TLS_MEAN', 'TLS_STD', 'TLS_MAX'
    # = they are the most powerful feature
    # element_col = []
    # for z in range(0, 45):
    #     element_col.append(col_list[z])
    # for y in range(56, 62):
    #     element_col.append(col_list[y])

    filelist = featurelist()
    datalist = []
    # target_label = []
    print(' Start to read csv files... ')
    print(' This work can take a few seconds. \n')
    for file in filelist:
        filepath = './includeOLfeature/' + file
        raw_data = read_csv(filepath)
        data = raw_data.copy()
        data.fillna(0, inplace=True)        # fill NaN value with 0
        dataset = np.array(data)
        for item in dataset:
            element = np.array(item)        # len(element) = 53
            element = element[1:]           # remove index column(element[0]) from list
            onlyfloatarr = []
            for i in range(len(element)):          # len(element) = 52
                if element[i] != 'None':           # remove invalid string (if there is)
                    onlyfloatarr.append(float(element[i]))
                else:
                    element[i] = 0
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
        scaler = PowerTransformer(method='yeo-johnson')     # positive and negative
        x_train = scaler.fit_transform(x_train)
        x_test = scaler.fit_transform(x_test)
    elif normchoice == '5':
        scaler = MinMaxScaler()
        x_train = scaler.fit_transform(x_train)
        x_test = scaler.fit_transform(x_test)
    else:
        print('Invalid option. No scaling. ')
        sys.exit()
    #------------------------------------------------------------------------------------------------------------------#
    print("")
    print('Please choose the number of cross validation. The number must be bigger than 1. ')
    nrtofold = input('k? ')
    clf = RandomForestClassifier(n_estimators=200, random_state=0)
    clf.fit(x_train, y_train)
    kf = RepeatedKFold(n_splits=int(nrtofold), n_repeats=40, random_state=1)
    score = cross_val_score(clf, x_train, y_train, cv=kf, scoring="accuracy")
    print('Score:', '%.3f' % score.mean())
    y_pred = clf.predict(x_test)
    # print('Accuracy :', metrics.accuracy_score(y_test, y_pred))
    print(classification_report(y_test, y_pred))            # to show values in text
    #------------------------------------------------------------------------------------------------------------------#
    feature_scores = pd.Series(clf.feature_importances_, index=col_list).sort_values(ascending=False)
    print('10 most important features')
    print(feature_scores[:10])      # top 10 important features
    datalist = np.array(datalist)
    n_feature = datalist.shape[1]       # number of feature := len(element_col)
    plt.figure(figsize=(40, 40))
    plt.barh(col_list, clf.feature_importances_, align='center')
    plt.ylim(-1, n_feature)
    plt.xlabel('feature importance', size=11)
    plt.ylabel('feature', size=11)
    plt.show()


if __name__ == "__main__":
    main()




# https://alex-blog.tistory.com/entry/Machine-Learning-Random-Forest-%EB%9E%9C%EB%8D%A4-%ED%8F%AC%EB%A0%88%EC%8A%A4%ED%8A%B8-%EC%98%88%EC%8B%9C-feat-python
# https://towardsdatascience.com/feature-scaling-effect-of-different-scikit-learn-scalers-deep-dive-8dec775d4946
# https://towardsdatascience.com/feature-selection-with-pandas-e3690ad8504b
# https://towardsdatascience.com/accuracy-precision-recall-or-f1-331fb37c5cb9
# https://www.kaggle.com/dom12345/feature-selection-and-knn-classification

# Precision: Accuracy of positive predictions. Precision = TP/(TP + FP)
# Recall: Fraction of positives that were correctly identified. Recall = TP/(TP+FN)
# F1 Score = 2*(Recall * Precision) / (Recall + Precision)
# Accuracy : (TP+TN) / all
# macro avg = (normal+abnormal) /2 * precision or recall or f1 score
# weighted avg = normal/(normal+abnormal)  *  precision or recall or f1 score

# initial feature list
# col_list = ['TOTAL_PKT', 'INCOMING_PKT', 'OUTGOING_PKT', 'PKTORDER_IN_STD', 'PKTORDER_IN_AVER', 'PKTORDER_OUT_STD',
#                 'PKTORDER_OUT_AVER', 'CHUNK20_STD', 'CHUNK20_MEAN', 'CHUNK20_MEDIAN', 'CHUNK20_MAX', 'FIRST30_IN', 'FIRST30_OUT',
#                 'LAST30_IN', 'LAST30_OUT', 'PKT/S_MEAN', 'PKT/S STD', 'PKT/S MEDIAN', 'PKT/S MIN', 'PKT/S MAX',
#                 'INTER_IN_MAX', 'INTER_IN_MEAN', 'INTER_IN_STD', 'INTER_IN_Q3', 'INTER_OUT_MAX', 'INTER_OUT_MEAN', 'INTER_OUT_STD', 'INTER_OUT_Q3',
#                 'IN_Q1', 'IN_Q2', 'IN_Q3', 'IN_TOTALTIME', 'OUT_Q1', 'OUT_Q2', 'OUT_Q3', 'OUT_TOTALTIME',
#                 'SIZE_IN_MEAN', 'SIZE_IN_MIN', 'SIZE_IN_MAX', 'SIZE_IN_STD', 'SIZE_OUT_MEAN', 'SIZE_OUT_MIN', 'SIZE_OUT_MAX', 'SIZE_OUT_STD',
#                 'SIZE_IN_TOTAL', 'SIZE_OUT_TOTAL', 'MOST_IN_IP', 'IN_IP_%', 'MOST_OUT_IP', 'OUT_IP_%',  # 62-17 = 45
#                 'MOST_SRC', 'SRC_%', 'MOST_DST', 'DST_%', 'MOST_SENT_BYTES_IP', 'SENT_BYTES_BY_IP',     # 45+7 = 52
#                 'TCP_MEAN', 'TCP_STD', 'TCP_MAX', 'TLS_MEAN', 'TLS_STD', 'TLS_MAX']     # 62 features


# def min_max_normalize(lst):
#     normalized = []
#     for value in lst:
#         normalized_num = (value - min(lst)) / (max(lst) - min(lst))
#         normalized.append(normalized_num)
#     return normalized