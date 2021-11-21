#!/usr/bin/env python3
# pip3 install scapy
import argparse
import ipaddress
import logging
import re
import signal
import struct
import socket
import subprocess

from scapy.layers.inet6 import ICMPv6NDOptPrefixInfo, ICMPv6ND_RA

IP_ADDR_MATCHER = re.compile(
    r"inet6 (?P<address>[0-9a-f:]+)/(?P<netmask>[0-9]{1,3}) .*? "
    r"preferred_lft (?P<preferred>(forever|\d+sec))",
    re.DOTALL | re.MULTILINE | re.I,
)

IPV6_ALLNODES_MCAST = "ff02::1"
ICMPV6_TYPE_RA = 134


class Terminating(Exception):
    pass


class StaticMAddrDaemon:

    iface = None

    def __init__(self):
        signal.signal(signal.SIGINT, self.sigterm)
        signal.signal(signal.SIGTERM, self.sigterm)
        self.logging_init()

    def receiver(self):
        logging.debug(f"start for iface {self.iface}")
        # Look up multicast group address in name server and find out IP version
        addrinfo = socket.getaddrinfo(IPV6_ALLNODES_MCAST, None)[0]

        # Create a socket
        s = socket.socket(
            addrinfo[0], socket.SOCK_RAW, socket.getprotobyname("ipv6-icmp")
        )
        s.setsockopt(socket.SOL_SOCKET, 25, str(self.iface + "\0").encode("utf-8"))

        # Allow multiple copies of this program on one machine
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        group_bin = socket.inet_pton(addrinfo[0], addrinfo[4][0])
        # Join group
        mreq = group_bin + struct.pack("@I", 0)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)

        # Loop, processing data we receive
        try:
            while True:
                data, sender = s.recvfrom(1500)
                ra = self.decode_ra(data)
                if ra:
                    self.act_on_ra(ra)
        except Terminating:
            logging.warning("Terminated, exitting gracefully...")

    def decode_ra(self, data):
        if len(data) < 1:
            return None

        if data[0] != ICMPV6_TYPE_RA:
            # Not the RA we're looking for
            return None

        try:
            ra = ICMPv6ND_RA(data)
        except Exception:
            ra = None

        return ra

    def launch_ip(self, iface):
        cmd = f"ip -6 address show dev {iface} scope global"
        result = subprocess.run(cmd.split(" "), stdout=subprocess.PIPE)
        return result.stdout.decode("utf-8")

    def set_lifetime(self, iface, address, preferred):
        """
        ip addr change 2001:db8:c001:ff00::6 preferred_lft forever dev br0.2
        ip addr change 2001:db8:c001:ff00::6 preferred_lft 0 dev br0.2
        """
        logging.info(
            f'Updating lifetime of address {address} on device {iface} to "{preferred}"'
        )
        cmd = f"ip -6 address change {address} preferred_lft {preferred} dev {iface}"
        subprocess.run(cmd.split(" "), stdout=subprocess.PIPE)

    def process_lft(self, lft):
        if lft == "forever":
            secs = 2 ** 31
        else:
            try:
                secs = int(lft.strip("sec"))
            except Exception:
                secs = 2 ** 31
        return secs

    def match_ips(self, ip_output):
        addrs = []
        for entry in IP_ADDR_MATCHER.finditer(ip_output):
            addrs.append(
                {
                    "address": ipaddress.ip_address(entry.group("address")),
                    "netmask": entry.group("netmask"),
                    "lft": self.process_lft(entry.group("preferred")),
                }
            )
        return addrs

    def load_addresses_for_iface(self, iface):
        """
        # ip -6 address show dev br0.2
        7: br0.2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
            qdisc noqueue state UP group default qlen 1000
        inet6 2001:db8:babe:f200::6/64 scope global
           valid_lft forever preferred_lft forever
        inet6 2001:db8:babe:f200::5/64 scope global
           valid_lft forever preferred_lft forever
        inet6 2001:db8:babe:f200::4/64 scope global
           valid_lft forever preferred_lft forever
        inet6 2001:db8:c001:ff00::6/64 scope global
           valid_lft forever preferred_lft 995sec
        inet6 2001:db8:c001:ff00::5/64 scope global deprecated
           valid_lft forever preferred_lft 0sec
        inet6 2001:db8:c001:ff00::4/64 scope global
           valid_lft forever preferred_lft forever
        inet6 fe80::f652:14ff:fe3e:d7a0/64 scope link
           valid_lft forever preferred_lft forever
        """
        ips = self.launch_ip(iface)
        addrs = self.match_ips(ips)
        return addrs

    def process_prefixes_ifaces(self, prefixes, iface):
        """
        [{'A': 1,
          'L': 1,
          'R': 0,
          'preferred': 120,
          'prefix': IPv6Network('2001:db8:babe:f200::/64'),
          'valid': 300},
         {'A': 1,
          'L': 1,
          'R': 0,
          'preferred': 0,
          'prefix': IPv6Network('2001:db8:c001:ff00::/64'),
          'valid': 0}]
        [{'address': '2001:db8:babe:f200::6', 'lft': 2147483648, 'netmask': '64'},
         {'address': '2001:db8:babe:f200::5', 'lft': 2147483648, 'netmask': '64'},
         {'address': '2001:db8:babe:f200::4', 'lft': 2147483648, 'netmask': '64'},
         {'address': '2001:db8:c001:ff00::6', 'lft': 0, 'netmask': '64'},
         {'address': '2001:db8:c001:ff00::5', 'lft': 0, 'netmask': '64'},
         {'address': '2001:db8:c001:ff00::4', 'lft': 0, 'netmask': '64'}]
        """
        addresses = self.load_addresses_for_iface(iface)
        for prefix in prefixes:
            logging.debug(
                f'Processing prefix {prefix["prefix"]}, '
                f'preferred {prefix["preferred"]}...'
            )
            for address in addresses:
                if not address["address"] in prefix["prefix"]:
                    continue
                if address["lft"] > 0 and prefix["preferred"] == 0:
                    self.set_lifetime(iface, address["address"], "0")
                if address["lft"] == 0 and prefix["preferred"] > 0:
                    self.set_lifetime(iface, address["address"], "forever")

    def act_on_ra(self, packet):
        logging.debug("=== captured packet START ===")
        icmpv6 = packet[ICMPv6ND_RA]
        prefixes = []
        for p in icmpv6.iterpayloads():
            # only process the ICMPv6NDOptPrefixInfo payload
            if not isinstance(p, ICMPv6NDOptPrefixInfo):
                continue
            """
            <ICMPv6NDOptPrefixInfo  type=3 len=4 prefixlen=64 L=1 A=1 R=0 res1=0
              validlifetime=0x12c preferredlifetime=0x78 res2=0x0
              prefix=2001:db8:babe:f200:: |
            <ICMPv6NDOptPrefixInfo  type=3 len=4 prefixlen=64 L=1 A=1 R=0 res1=0
              validlifetime=0x0 preferredlifetime=0x0 res2=0x0
              prefix=2001:db8:c001:ff00:: |
            <ICMPv6NDOptMTU  type=5 len=1 res=0x0 mtu=1492 |
            <ICMPv6NDOptSrcLLAddr  type=1 len=1 lladdr=24:8a:07:5d:d7:30 |>>>>
            """
            prefinfo = p[ICMPv6NDOptPrefixInfo]
            prefix = {
                "prefix": ipaddress.ip_network(
                    f"{prefinfo.prefix}/{prefinfo.prefixlen}"
                ),
                "L": prefinfo.L,
                "A": prefinfo.A,
                "R": prefinfo.R,
                "valid": prefinfo.validlifetime,
                "preferred": prefinfo.preferredlifetime,
            }
            prefixes.append(prefix)
        if len(prefixes) > 0:
            self.process_prefixes_ifaces(prefixes, self.iface)
        logging.debug("=== captured packet END ===")

    @staticmethod
    def sigterm(x, y):
        raise Terminating()

    def parse_args(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("-i", "--interface", type=str, required=True)
        args = parser.parse_args()
        self.iface = args.interface
        return args

    def get_interface(self):
        return self.iface

    def logging_init(self):
        logging.basicConfig(
            level=logging.DEBUG,
            datefmt="%Y-%m-%d %H:%M:%S",
            format="%(asctime)s.%(msecs)03d %(levelname)s %(module)s - "
                   "%(funcName)s: %(message)s",
        )


def main():
    daemon = StaticMAddrDaemon()
    daemon.parse_args()
    daemon.receiver()


if __name__ == "__main__":
    main()
