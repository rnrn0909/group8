from datetime import date

from mysql.connector import (connection)

# for iterating
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from selenium.webdriver import Firefox
from selenium.webdriver.firefox.service import Service

# set tor settings
profile_path = r'/home/kcofls88/.mozilla/firefox/wabpu6by.default'      # location of firefox profile
# service = Service(r'/home/kcofls88/Desktop/project/geckodriver.exe')
profile = webdriver.FirefoxProfile()
profile.set_preference('profile', profile_path)
profile.set_preference("network.proxy.type", 1)
profile.set_preference("network.proxy.socks", '127.0.0.1')
profile.set_preference("network.proxy.socks_port", 9050)
profile.set_preference("network.proxy.socks_remote_dns", False)
profile.update_preferences()
#end set tor setting

import mysql.connector


conn = connection.MySQLConnection(
    user='root',
    password='root',
    port='3306',
    host='localhost',
    database='webprintdb',
    auth_plugin='mysql_native_password')


query = ('''SELECT id_country,country,countrycode FROM  `countries` ''')

cursor = conn.cursor()
cursor.execute(query)

driver = webdriver.Firefox(executable_path=r'/usr/local/bin/geckodriver')

# iterate over the cursor over all the countries
for (id_country, country, countrycode) in cursor:
    # start of scraping for each country
    driver.get('https://trends.google.com/trends/trendingsearches/daily?geo=' + countrycode)

    myLength = len(
        WebDriverWait(driver, 20).until(EC.visibility_of_all_elements_located((By.XPATH, "//div[@class='title']"))))
    print('We will dive into Google '+str(country))
    numberoftrends= int(input("Enter Number of trends >> "))
    # gather 200 trends
    for i in {numberoftrends}:
        while True:
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            try:
                WebDriverWait(driver, 20).until(EC.element_to_be_clickable(
                    (By.XPATH, "//div[@class='feed-load-more-button'][@ng-click=\"ctrl.loadMoreFeedItems()\"]"))).click()
                WebDriverWait(driver, 20).until(
                    lambda driver: len(driver.find_elements_by_xpath("//div[@class='title']")) > myLength)
                titles = driver.find_elements_by_xpath("//div[@class='title']")
                myLength = len(titles)
            except TimeoutException:
                break

    for title in titles:
        print(title.text, id_country, country, countrycode)  # writes each trend

        # start of inserting each trend in db
        today = date.today()
        countryselected = id_country
        conn2 = connection.MySQLConnection(
            user='root', password='root',
            port='3306', host='localhost', database='webprintdb',
            auth_plugin='mysql_native_password')
# can't we just use conn and cursor?
        cursor2forinsert = conn2.cursor()
        inserttrends = """INSERT INTO trends (trend,id_country,trenddate) 
                                   VALUES 
                                   (%s, %s, %s) """  # title.text, countryselected,today

        record = (title.text, countryselected, today)
        try:
            # Executing the SQL command
            cursor2forinsert.execute(inserttrends, record)

            # Commit your changes in the database
            conn2.commit()
            print("SUCCESS AT SAVING")

        except:
            # Rolling back in case of error
            print("fail at saving at db ")
            conn2.rollback()

        # end of inserting each trend in db
        # end of scraping for each country
driver.quit()
# after finishing scraping from all countries, close the driver


