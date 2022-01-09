import json
import zipfile
import zlib
import requests
from bs4 import BeautifulSoup
import torinfo
from zipfile import ZipFile
from time import sleep
from selenium.webdriver.firefox import webdriver
from urllib.parse import urlparse
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from mysql.connector import (connection)
import mysql.connector
from selenium.common.exceptions import TimeoutException
from seleniumwire import webdriver
import logging
from scapy.all import *
import os
# from selenium import webdriver  # commented to use seleniumwire  instead
from threading import Thread  # for threading
from time import perf_counter  # for threading

from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.options import Log

class visitclass:
    def __init__(self):
        self.filezip = ""

    def srcfolder(self, url):
        domain = urlparse(url).netloc
        print(domain)
        dirNameWebsite = rf'Screenshots/{domain}/'
        try:
            os.makedirs(dirNameWebsite)
            print("Directory ", dirNameWebsite, " Domain folder created in Screenshots ")
        except FileExistsError:
            print("Directory ", dirNameWebsite, " Domain folder  already exists in Screenshots")

        # creates folder structure for SOURCE CODE of the DOMAINS
        domain = urlparse(url).netloc
        print(domain)
        dirNameWebsite = rf'HTML/{domain}/'
        try:
            os.makedirs(dirNameWebsite)
            print("Directory ", dirNameWebsite, " Domain folder created in HTML")
        except FileExistsError:
            print("Directory ", dirNameWebsite, " Domain folder  already exists in HTML")

        # creates folder structure for LOGS  of the DOMAINS
        domain = urlparse(url).netloc
        print(domain)
        dirNameWebsite = rf'LOGS/{domain}/'
        try:
            os.makedirs(dirNameWebsite)
            print("Directory ", dirNameWebsite, " Domain folder created in LOGS")
        except FileExistsError:
            print("Directory ", dirNameWebsite, " Domain folder  already exists in LOGS")
        return domain

    def mainloadfunc(self, chosenhash, noOfTraces):
        self.profile = webdriver.FirefoxProfile()
        self.profile.set_preference("network.proxy.type", 1)
        self.profile.set_preference("network.proxy.socks", '127.0.0.1')
        self.profile.set_preference("network.proxy.socks_port", 9050)
        self.profile.set_preference("network.proxy.socks_remote_dns", False)
        self.profile.set_preference('javascript.enabled', False)  # javascript
        self.profile.set_preference('dom.security.https_first', True)  # http first
        self.profile.set_preference('security.csp.enable', True)  # Enable content security policy
        self.profile.set_preference('security.mixed_content.block_active_content', True)  # blocks active content
        self.profile.set_preference('browser.link.open_newwindow', 1)  # open links in the same tab
        self.profile.update_preferences()
        self.options = {
            'enable_har': True,  # to create HAR file
            'proxy': {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050',
                'connection_timeout': 10
            }
        }
        # ---- PARAMETER INPUTS
        self.flag = 0
        self.failedtoloadTimeout = []  # Initialize list of pages that didnt load

        chosentimeout = input("Please enter the maximum timeout in seconds for pages to load:\n")
        # ^ give my own value? (annoying to put value everytime when executing outlierdetection)

        self.conn = connection.MySQLConnection(user='root', password='root', port="3306",
                                               host='127.0.0.1',
                                               database='webprintdb', auth_plugin='mysql_native_password')

        cursor = self.conn.cursor(buffered=True)
        querywebsites = """SELECT id_mainpage, id_subpage, url, urlhash, chosenclicks FROM subpages WHERE urlhash = '%s' """ % (
                chosenhash)
        cursor.execute(querywebsites)

        for id_mainpage, id_subpage, url, urlhash, chosenclicks in cursor:
            selectedwebsite = int(id_mainpage)
            print(id_mainpage, url)
            domain = self.srcfolder(url)  # creates folder structure for screenshot of the DOMAINS

            # INITIATE CONTROL LISTS
            self.alltheURLS = []  # contains all the urls from a website

            self.RedirectionList = []  # to control redirectioned urls
            self.ErrorsList = []  # to control urls with errors
            self.EmptyList = []  # to control empty urls
            # timeout pages is implemented below

            logging.basicConfig(filename=rf"./LOGS/errores.log", format="%(asctime)s: %(levelname)s: %(message)s",
                                    datefmt="%m/%d/%Y %I:%M:%S %p", level=logging.ERROR, filemode="a")
            logger1 = logging.getLogger()
            logger1.setLevel(logging.ERROR)

            for x in range(int(noOfTraces)):
                urlsniff = url
                hashname = urlhash
                CircuitID = torinfo.get_current_circuit()
                EntryNode = torinfo.get_entry()
                MiddleNode = torinfo.getmiddlenode()
                ExitNode = torinfo.getexitnode()
                start_time = perf_counter()
                threads = []

                t1 = Thread(target=self.newsniff, args=(chosentimeout, hashname, domain, CircuitID))
                t2 = Thread(target=self.loadsameurl, args=(
                        urlsniff, chosentimeout, id_subpage, EntryNode, MiddleNode, ExitNode, CircuitID, domain,
                        hashname))
                threads.append(t1)
                threads.append(t2)
                t1.start()
                t2.start()
                torinfo.renew_tor_ip()  # gets a new circuit

                    # wait for the threads to complete
                for t in threads:
                    t.join(timeout=int(chosentimeout))

                end_time = perf_counter()
                print(f'It took {end_time - start_time: 0.2f} second(s) to complete.')
                    # END OF SNIFFER
                try:
                    os.system("kill -9 $(pidof /usr/lib/firefox/firefox)")
                except:
                    print("not able to kill")

                # ---- EXPORT THE FAILED TO LOAD SUBPAGES TO FILE
                print("The following urls didn't load correctly")
                print(self.failedtoloadTimeout)
                with open(rf'./LOGS/{domain}/timedoutpages.txt', 'w') as filehandle:
                    for url in self.failedtoloadTimeout:
                        filehandle.write('%s\n' % url)
                filehandle.close()
                # ------ END OF EXPORT
                # print("The following urls had errors: ")
                # print(self.ErrorsList)
                # print("The following urls had redirection: ")
                # print(self.RedirectionList)
                # print("The following urls had empty pages: ")
                # print(self.EmptyList)

                ### code to add rediectin +error +empty + failed to load and make it a set to remove duplicated
                notSuccessful = (
                    set().union(self.ErrorsList, self.RedirectionList, self.EmptyList, self.failedtoloadTimeout))

                # SuccesfullPages= Substract unsuccessfull urls from the whole set
                successfullPages = [x for x in self.alltheURLS if x not in notSuccessful]
                # print("The following were successfully loaded: ")
                # print(successfullPages)

                with open(rf'./LOGS/{domain}/succesfullpages.txt', 'w') as filehandle2:
                    for url in successfullPages:
                        filehandle2.write('%s\n' % url)
                filehandle2.close()
        self.conn.close()  # close DB connection

    def foldercreation(self):
        # ------------------------------------- FOLDER STRUCTURE CREATION---
        dirName1 = 'Screenshots/'
        dirName2 = 'HTML/'
        dirName3 = 'LOGS/'
        try:
            os.makedirs(dirName1)
            print("Directory ", dirName1, " Screenshots folder created ")
        except FileExistsError:
            print("Directory ", dirName1, " Screenshots folder  already exists")

        try:
            os.makedirs(dirName2)
            print("Directory ", dirName2, " HTML folder created ")
        except FileExistsError:
            print("Directory ", dirName2, " HTML folder  already exists")

        try:
            os.makedirs(dirName3)
            print("Directory ", dirName3, " LOGS folder created ")
        except FileExistsError:
            print("Directory ", dirName3, " LOGS folder  already exists")

        # ---------------------------------------- END FOLDER CREATION----

    def newsniff(self, chosentimeout, hashname, domain, CircuitID):
        dirName4 = rf'LOGS/{domain}/{hashname}/SNIFFS/'
        try:
            os.makedirs(dirName4)
            print("Directory ", dirName4, " Sniffs folder created ")
        except FileExistsError:
            print("Directory ", dirName4, " Sniffs folder  already exists")

        print("start new sniffing session...")
        # params
        count = 0
        print("Sniffing...please wait ")
        print("The Circuit ID for this sniffing is: ", CircuitID)

        if not (os.path.exists(
                rf"./LOGS/{domain}/{hashname}/SNIFFS/{hashname}_pkts_{CircuitID}.cap")):  # if it doesnt exist already  with this circuit
            pkts = sniff(count=int(count), timeout=int(chosentimeout))
            wrpcap(rf"./LOGS/{domain}/{hashname}/SNIFFS/{hashname}_pkts_{CircuitID}.cap", pkts)
            zf = zipfile.ZipFile(rf"./LOGS/{domain}/{hashname}/SNIFFS/{hashname}_pkts_{CircuitID}.zip", mode='w',
                                 compression=zipfile.ZIP_DEFLATED)
            try:

                zf.write(rf"./LOGS/{domain}/{hashname}/SNIFFS/{hashname}_pkts_{CircuitID}.cap")
                os.remove(rf"./LOGS/{domain}/{hashname}/SNIFFS/{hashname}_pkts_{CircuitID}.cap")

            except:
                print("Error compressing file")
            zf.close()


    def loadsameurl(self, urlsniff, chosentimeout, id_subpage, EntryNode, MiddleNode, ExitNode, CircuitId, domain,
                    hashname):  # load url

        print("ID SUBPAGE", id_subpage)
        browser = webdriver.Firefox(firefox_profile=self.profile, log_path='./LOGS/geckodriver.log',
                                    seleniumwire_options=self.options)
        browser.set_page_load_timeout(int(chosentimeout))
        self.flag = 0

        # start of a new page loading
        print(urlsniff)
        self.alltheURLS.append(urlsniff)  # fills all the urls list

        if self.flag == 1:  # kills and restarts a new window
            os.system("kill -9 $(pidof /usr/lib/firefox/firefox)")  # make sure other processes are killed

            browser = webdriver.Firefox(firefox_profile=self.profile, log_path='./LOGS/geckodriver.log',
                                        seleniumwire_options=self.options)

        try:
            browser.get(urlsniff)
            fileToWriteforBrokenPages = open(rf"./LOGS/brokenpages.txt", "a")
            for request in browser.requests:
                if request.url == urlsniff:
                    if ((
                            request.response.status_code >= 400 and request.status_code <= 499)):  # check errors client and server side
                        self.ErrorsList.append(urlsniff)
                        fileToWriteforBrokenPages.write(rf"{hashname}_{CircuitId}" + '\n')  # add to brokenpages
                    if (request.response.headers['Content-length']) == 0:
                        self.EmptyList.append(urlsniff)
                        fileToWriteforBrokenPages.write(rf"{hashname}_{CircuitId}" + '\n')
                    if ((request.response.status_code >= 300 and request.status_code <= 399)):  # check for redirection
                        self.RedirectionList.append(urlsniff)
                        fileToWriteforBrokenPages.write(rf"{hashname}_{CircuitId}" + '\n')

            soup = BeautifulSoup(browser.page_source, 'html.parser')  # if Google captcha is on page
            is_captcha_on_page = soup.find("textarea", id="g-recaptcha-response") is not None
            if is_captcha_on_page == True:
                fileToWriteforBrokenPages.write(rf"{hashname}_{CircuitId}" + '\n')

            fileToWriteforBrokenPages.close()

            # PERFORMACE

            navigationStart = browser.execute_script("return window.performance.timing.navigationStart")
            responseStart = browser.execute_script("return window.performance.timing.responseStart")
            domComplete = browser.execute_script("return window.performance.timing.domComplete")
            loadEventEnd = browser.execute_script("return performance.timing.loadEventEnd")
            resourceStats = browser.execute_script("return performance.getEntriesByType('resource')")
            navigationStats = browser.execute_script("return performance.getEntriesByType('navigation')")
            completeStats = browser.execute_script("return performance.toJSON()")

            backendPerformance = responseStart - navigationStart
            frontendPerformance = domComplete - responseStart
            finalTime = (loadEventEnd - navigationStart)
            finaltimesec = finalTime / 1000

            print("Back End: %s" % backendPerformance)
            print("Front End: %s" % frontendPerformance)
            print("Navigation start: ", navigationStart)
            print("Final load time", finaltimesec)
            print("Resource statistics", resourceStats)
            print("Navigation Statistics", navigationStats)
            print("Complete Statistics", completeStats)

            # logs about TOR
            CircuitID = torinfo.get_current_circuit()
            EntryNodeName = EntryNode[1]
            EntryIP = EntryNode[2]

            MiddleNodeName = MiddleNode[1]
            MiddleIP = MiddleNode[2]

            ExitNodeName = ExitNode[1]
            ExitIP = ExitNode[2]
            with open(rf"./LOGS/{domain}/{hashname}_torlogs_{CircuitID}.txt", "w") as fileToWriteforTor:
                fileToWriteforTor.write(rf"Circuit ID:{CircuitID}" + '\n')
                fileToWriteforTor.write(rf"Entry Node: {EntryNodeName}" + '\n')
                fileToWriteforTor.write(rf"Entry IP: {EntryIP}" + '\n')
                fileToWriteforTor.write(rf"Middle Node: {MiddleNodeName}" + '\n')
                fileToWriteforTor.write(rf"Exit IP: {MiddleIP}" + '\n')
                fileToWriteforTor.write(rf"Exit Node: {ExitNodeName}" + '\n')
                fileToWriteforTor.write(rf"Exit IP: {ExitIP}" + '\n')
            # insert tor logs in the database
            cursorfortorlogs = self.conn.cursor()
            inserttorlog = """INSERT INTO torlogs (id_subpage,url,circuit_id,entry_node,entry_node_ip,middle_node,middle_node_ip,exit_node,exit_node_ip) 
                                              VALUES 
                                              (%s, %s, %s,%s, %s, %s,%s, %s, %s) """

            torrecord = (
                id_subpage, urlsniff, CircuitId, EntryNodeName, EntryIP, MiddleNodeName, MiddleIP, ExitNodeName, ExitIP)

            try:
                cursorfortorlogs.execute(inserttorlog, torrecord)
                self.conn.commit()
                print("SUCCESS AT SAVING THE TOR LOG")

            except mysql.connector.Error as err:
                # Rolling back in case of error
                print("fail at saving at db the tor log", err)
                # self.conn.rollback()
                rf"./LOGS/{domain}/{hashname}/SNIFFS/{hashname}_pkts_{CircuitID}.zip"
            # end logs about TOR

            # SAVING TIME LOGS
            cursorfortimelogs = self.conn.cursor()

            inserttimelog = """INSERT INTO timelogs (id_subpage,url,circuit_id,start_time, finish_time, load_time) 
                                                      VALUES 
                                                      (%s, %s, %s,%s, %s, %s) """

            timerecord = (id_subpage, urlsniff, CircuitId, navigationStart, loadEventEnd, finalTime)

            try:
                cursorfortimelogs.execute(inserttimelog, timerecord)
                self.conn.commit()
                print("SUCCESS AT SAVING THE TIME LOG")

            except mysql.connector.Error as err:
                # Rolling back in case of error
                print("fail at saving at db the time log", err)
                # self.conn.rollback()
                os.remove(rf"./LOGS/{domain}/{hashname}/SNIFFS/{hashname}_pkts_{CircuitID}.zip")


            hasloaded = 1
            self.flag = 1
        except TimeoutException as TimeoutErr:
            hasloaded = 0
            ToLog = str(logging.exception(rf"A timeout error has occurred loading the URL: {urlsniff}"))
            fileloggerPageLoad = open(rf"./LOGS/{domain}/{hashname}_errorlogs.log", "a")
            fileloggerPageLoad.write(ToLog)
            fileloggerPageLoad.close()
            print("Exception has been thrown. Takes too long to load " + str(TimeoutErr))
            self.failedtoloadTimeout.append(urlsniff)
            # print('Captured packet will be deleted. ')
            # os.remove(rf"./LOGS/{domain}/{hashname}/SNIFFS/{hashname}_pkts_{CircuitId}.zip")

        print('done')

if __name__ == "__main__":
    while True:
        try:
            objvisitclass = visitclass()
            objvisitclass.foldercreation()
            print("\n Visiting an specific URL..")
            chosenhash = input("Please enter the hash of the subpage:\n")
            noOfTraces = input("Please enter the number of traces you would like to collect:\n")
            objvisitclass.mainloadfunc(chosenhash, noOfTraces)
            question = input("Wanna stop? Y/N ")
            if question == 'y' or 'Y':
                print('Stop execution. ')
                break
            elif question == 'n' or question == 'N':
                pass
            else:
                print('You didn\'t make any choice. Keep processing... ')
                pass
        except TimeoutException:
            print('Error \n', TimeoutException)


    # from 'Calling function again...', can i get only refhash? >> yes.
    # noOrTraces = 15 - len(newapproach)
    # or just get 15 traces again? (due to errors)
