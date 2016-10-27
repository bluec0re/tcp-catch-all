#!/usr/bin/env python3
# coding: utf-8
# author: bluec0re
#
# Copyright (c) 2016, bluec0re <coding@bluec0re.eu>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import socketserver
import subprocess
import argparse
import threading
import logging
import time
import pathlib
import sys
from datetime import datetime
from functools import partial
import signal

from scapy.all import sniff, TCP, IP, sendp
try:
    from helperlib import print_hexdump
except ImportError:
    print("python-helperlib not found. hexdump output not available", file=sys.stderr)

    def print_hexdump(*args, **kwargs):
        pass

try:
    from helperlib.logging import default_config
except ImportError:
    print("python-helperlib not found. Fallback to logging.basicConfig", file=sys.stderr)

    def defaultConfig(*args, **kwargs):
        logging.basicConfig()

__version__ = '1.0'

log = logging.getLogger(__name__)


def send_message(message):
    try:
        subprocess.Popen(['notify-send', '-u', 'low', message])
    except Exception as e:
        log.warning("Couldn't show notification %r: %s", message, str(e))


class Catcher(socketserver.StreamRequestHandler):
    def setup(self):
        super().setup()
        self.log = logging.getLogger("{}.{}".format(
            type(self).__name__,
            self.server.server_address[1])
        )
        self.server.requests.append(self.request)

    def handle(self):
        self.log.info("New connection to %r from %r",
                      self.server.server_address,
                      self.client_address)

        filename = None
        if self.server.catcher.logdir is not None:
            filename = self.server.catcher.logdir / "{}_{}-{}_{}.log".format(
                        *(self.server.server_address + self.client_address)
                        )

        for block in iter(partial(self.request.recv, 1024 * 4), b''):
            self.log.info('Received %d bytes from %r', len(block), self.client_address)
            if filename is not None:
                with filename.open('a') as fp:
                    fp.write("{}: {}\n".format(datetime.now(), block.hex()))
            print_hexdump(block, colored=True, cols=16)

        self.log.info("Closing connection to %r from %r",
                      self.server.server_address,
                      self.client_address)


class TCPCatchAll:
    def __init__(self, interface, bind, src=None, notify=False, logdir=None):
        self.intf = interface
        self.src = src
        self.bind = bind
        self.notify = notify
        if logdir is not None:
            self.logdir = pathlib.Path(logdir)
            self.logdir.mkdir(exist_ok=True)
        else:
            self.logdir = logdir
        self._ports = {}
        self.log = logging.getLogger("{}.{}".format(
            type(self).__name__,
            self.intf,
            self.bind)
        )

    def run(self):
        filter = 'tcp[0xd]&18=2'  # only tcp packets with SYN flag
        # filter = 'tcp'
        if self.src:
            filter += ' and host {}'.format(self.src)  # only coming from this IP

        self.log.info('Starting catch all on %s @ %s', self.bind, self.intf)
        try:
            sniff(iface=self.intf, filter=filter, prn=self.process)
        finally:
            self.shutdown()

    def shutdown(self):
        if not self._ports:
            return

        self.log.info('Shutting down %d servers. Waiting 5s for graceful close', len(self._ports))
        for s, _ in self._ports.values():
            if not s:
                continue

            s.shutdown()

            for r in s.requests:
                s.shutdown_request(r)

        time.sleep(5)
        self.log.info('Closing servers.')
        for s, _ in self._ports.values():
            if not s:
                continue

            s.server_close()

            for r in s.requests:
                s.close_request(r)

        self.log.info('Waiting for threads.')
        for _, t in self._ports.values():
            if t and t.is_alive():
                t.join()

    def process(self, packet):
        if packet[TCP].flags != 2:
            packet.show()
            return

        port = packet[TCP].dport
        src = packet[IP].src

        self.log.debug('New SYN from %s:%d for port %d',
                       src,
                       packet[TCP].sport,
                       port)

        if port not in self._ports and (not self.src or self.src == src):
            try:
                self.start_server(port)
                sendp(packet)
            except OSError as e:
                self.log.error("Can't start server: %s", str(e), exc_info=True)
                if e.errno == 98:  # already in use
                    self._ports[port] = (None, None)

    def start_server(self, port):
        assert port not in self._ports, "{} already running".format(port)

        self.log.info('Starting server on port %d', port)

        s = socketserver.ThreadingTCPServer((self.bind, port),
                                            Catcher)
        s.requests = []
        s.catcher = self

        def serve(s):
            s.serve_forever(1)
            self.log.info('Closed server %r', s.server_address)

        t = threading.Thread(target=serve, args=(s,))
        self._ports[port] = (s, t)
        t.start()

        if self.notify:
            send_message('Server started on {}:{}'.format(*s.server_address))

    def stop_server(self, port):
        assert port in self._ports, "{} not running".format(port)

        s, t = self._ports.pop(port)

        if s is not None:
            s.shutdown()
            for r in s.requests:
                s.shutdown_request(r)

            if t.is_alive():
                time.sleep(1)

                s.close()
                for r in s.requests:
                    s.close_request(r)

                if t.is_alive():
                    t.join()


def stop_server_handler(tca, sig, stack_frame):
    try:
        port = int(input('Enter Port to close: '))
        print("Stopping server @", port, end='...')
        tca.stop_server(port)
        print("Done")
    except Exception as e:
        print(e)
    print("Continue..")


def main(argv=None):
    default_config()

    desc = 'TCP Catch All {}'.format(__version__)
    desc += '\n' + '#' * len(desc)
    parser = argparse.ArgumentParser(description=desc, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-i', '--interface', required=True, help='interface to sniff on (e.g. eth0)')
    parser.add_argument('-s', '--src-ip', help='start servers only if a request is coming from this ip')
    parser.add_argument('-b', '--bind-ip', default='', help='IP to bind to (e.g. the IP of the interface)')
    parser.add_argument('-p', '--port', action='append', type=int,
                        help='Start server for port (allowed multiple times)')
    parser.add_argument('-n', '--notify', action='store_true', help='show a notification with notify-send when a server was started')
    parser.add_argument('-d', '--dir', help='target directory for logfiles')
    parser.add_argument('-r', '--drop-rst', action='store_true', help='use iptables to drop outgoing RST packets (required to accept even the earliest request)')

    args = parser.parse_args(args=argv)

    cmd = ['iptables', '-A', 'OUTPUT', '-o', args.interface,
           '-p', 'tcp', '--tcp-flags', 'RST', 'RST', '-j', 'DROP']
    if args.src_ip:
        cmd += ['-d', args.src_ip]
    if args.bind_ip:
        cmd += ['-s', args.bind_ip]

    if args.drop_rst:
        subprocess.check_call(cmd)
    else:
        print('You might want to consider to filter outgoing closed ports by')
        print(' '.join(cmd))


    tca = TCPCatchAll(args.interface, args.bind_ip, args.src_ip, args.notify, args.dir)
    signal.signal(signal.SIGUSR1, partial(stop_server_handler, tca))

    if args.port:
        for port in args.port:
            tca.start_server(port)
    tca.run()

if __name__ == "__main__":
    main()
