TCP Catch All
=============

A scapy based python script to open TCP servers on demand
to catch all incoming TCP requests and log the sent data.

Usage
-----
```
usage: catch-all-tcp.py [-h] -i INTERFACE [-s SRC_IP] [-b BIND_IP] [-p PORT]
                        [-n] [-d DIR] [-r]

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        interface to sniff on (e.g. eth0)
  -s SRC_IP, --src-ip SRC_IP
                        start servers only if a request is coming from this ip
  -b BIND_IP, --bind-ip BIND_IP
                        IP to bind to (e.g. the IP of the interface)
  -p PORT, --port PORT  Start server for port (allowed multiple times)
  -n, --notify          show a notification with notify-send when a server was
                        started
  -d DIR, --dir DIR     target directory for logfiles
  -r, --drop-rst        use iptables to drop outgoing RST packets (required to
                        accept even the earliest request)
```

Start to listen on eth0 and log the incoming traffic into the directory foo:

``
./catch-all-tcp.py -i eth0 -d foo
``

Start to listen on eth0 and start servers for the ports 80 and 8080:

``
./catch-all-tcp.py -i eth0 -p 80 -p 8080
``

Requirements
------------

- python >= 3.5
- scapy
- [python-helperlib](https://github.com/bluec0re/python-helperlib) (optional)
- iptables (optional)
- notify-send (optional)
