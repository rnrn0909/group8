
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
from selenium.webdriver.firefox.firefox_profile import FirefoxProfile

from selenium.webdriver.firefox import webdriver

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait

profile = webdriver.FirefoxProfile()
profile.set_preference("network.proxy.type", 1)
profile.set_preference("network.proxy.socks", '127.0.0.1')
profile.set_preference("network.proxy.socks_port", 9050)
profile.set_preference("network.proxy.socks_remote_dns", False)
profile.update_preferences()
browser = webdriver.Firefox(firefox_profile=profile,firefox_binary=FirefoxBinary(R'/home/kcofls88/Desktop/project/tor-browser_en-US/Browser/firefox'))
browser.get("https://check.torproject.org/")
