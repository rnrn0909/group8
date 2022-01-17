import time

import requests
import time
from stem import Signal
# From the STEM examples page
# https://stem.torproject.org/tutorials/examples/list_circuits.html

from stem import CircStatus
from stem.control import Controller


def renew_tor_ip():
  with Controller.from_port(port=9051) as controller:
    controller.authenticate(password="welcome")
    controller.signal(Signal.NEWNYM)
    #time.sleep(3)

def get_current_ip():
  session = requests.session()

  # TO Request URL with SOCKS over TOR
  session.proxies = {}
  session.proxies['http'] = 'socks5h://localhost:9050'
  session.proxies['https'] = 'socks5h://localhost:9050'

  try:
    r = session.get('http://httpbin.org/ip')
    ip = session.get('http://httpbin.org/ip').json()['origin']
    print("Current IP:", ip)
  except Exception as e:
    print(str(e))
  else:
    return ip


def get_all_circuits():
  with Controller.from_port(port = 9051) as controller:
    controller.authenticate(password="welcome")


    for circ in sorted(controller.get_circuits()):
      if circ.status != CircStatus.BUILT:
        continue

      print("")
      print("Circuit %s (%s)" % (circ.id, circ.purpose))

      for i, entry in enumerate(circ.path):
        div = '+' if (i == len(circ.path) - 1) else '|'
        fingerprint, nickname = entry

        desc = controller.get_network_status(fingerprint, None)
        address = desc.address if desc else 'unknown'

        print(" %s- %s (%s, %s)" % (div, fingerprint, nickname, address))

def get_current_circuit():
    currentip = get_current_ip()
    with Controller.from_port(port=9051) as controller:
      controller.authenticate(password="welcome")
      #controller.signal(Signal.NEWNYM)

      for circ in sorted(controller.get_circuits()):
        if circ.status != CircStatus.BUILT:
          continue

        print("")
        print("Circuit %s (%s)" % (circ.id, circ.purpose))

        for i, entry in enumerate(circ.path):
          div = '+' if (i == len(circ.path) - 1) else '|'
          fingerprint, nickname = entry

          desc = controller.get_network_status(fingerprint, None)
          address = desc.address if desc else 'unknown'


          print(" %s- %s (%s, %s)" % (div, fingerprint, nickname, address))

          if address==currentip:
              print("The current circuit is:", circ.id)
              currentcircuit=circ.id
              currentfingerprint=fingerprint
              currentnickname=nickname
              currentip=address
              return currentcircuit



def get_entry():
  currentcircuit=get_current_circuit()
  global currentip
  currentip=get_current_ip()
  with Controller.from_port() as controller:
    controller.authenticate(password="welcome")

    for circ in controller.get_circuits():
      if circ.status != CircStatus.BUILT:
        continue  # skip circuits that aren't yet usable

      entry_fingerprint = circ.path[0][0]
      entry_descriptor = controller.get_network_status(entry_fingerprint, None)

      entry_fp, entry_nickname = circ.path[0]

      entry_desc = controller.get_network_status(entry_fp, None)
      entry_address = entry_desc.address if entry_desc else 'unknown'



      if (entry_descriptor and ((currentcircuit)==(circ.id))):
        print("Circuit %s ENTRY NODE starts with %s" % (circ.id, entry_descriptor.address))
      #else:
       # print("Unable to determine the address belonging to circuit %s" % circ.id)

      if (entry_address):
        print("Entry relay")
        print("  fingerprint: %s" % entry_fp)
        entryfingerprint=entry_fp
        print("  nickname: %s" % entry_nickname)
        entrynickname=entry_nickname
        print("  address: %s" % entry_address)
        entryaddress=entry_address

        return entry_fp, entry_nickname, entry_address

def getmiddlenode():
  currentcircuit = get_current_circuit()
  with Controller.from_port() as controller:
    controller.authenticate(password="welcome")

    for circ in controller.get_circuits():
      if circ.status != CircStatus.BUILT:
        continue  # skip circuits that aren't yet usable



      middle_fp, middle_nickname = circ.path[-2]

      middle_desc = controller.get_network_status(middle_fp, None)
      middle_address = middle_desc.address if middle_desc else 'unknown'

      if ((middle_address) and (currentcircuit==circ.id)):
        print("Middle relay")
        print("Circ id,", circ.id)
        print("  fingerprint: %s" % middle_fp)
        print("  nickname: %s" % middle_nickname)
        print("  address: %s" % middle_address)

        return middle_fp, middle_nickname, middle_address

def getexitnode():
  currentip = get_current_ip()
  with Controller.from_port(port=9051) as controller:
    controller.authenticate(password="welcome")
    # controller.signal(Signal.NEWNYM)

    for circ in sorted(controller.get_circuits()):
      if circ.status != CircStatus.BUILT:
        continue

      print("")
      print("Circuit %s (%s)" % (circ.id, circ.purpose))

      for i, entry in enumerate(circ.path):
        div = '+' if (i == len(circ.path) - 1) else '|'
        fingerprint, nickname = entry

        desc = controller.get_network_status(fingerprint, None)
        address = desc.address if desc else 'unknown'

        print(" %s- %s (%s, %s)" % (div, fingerprint, nickname, address))

        if address == currentip:
          exitfingerprint = fingerprint
          exitnickname = nickname
          exitip = address
          return exitfingerprint, exitnickname, exitip

renew_tor_ip()
get_current_ip()
#=get_entry()
get_all_circuits()
#get_current_circuit()
a= getmiddlenode()
print("The middle node is : ",a)
