# network_package
Network utility package. Do not use it on a network other than yours. Using Scapy (CC BY-NC-SA 2.5)

Credit Pierre-François Bonnefoi for expulse.py (deauthentification packet)

Use 'list_macs.py' first in order to get all devices connected.
Use 'expulse.py' to expulse with deauth all devices finded.

'list_macs.py' will create a list of devices in a file and 'expulse.py' will read it.

NOT FINISHED !
(probably not functionnal to deauth and the list will find all connected devices even which are connected by RJ-45 -> futur improvement : only wifi devices)

# expulse.py
How to
```
sudo python expulse.py
```

# list_macs.py
How to
```
python list_macs.py
```