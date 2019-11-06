import fcntl
import struct
import os
import threading
from scapy.layers.inet import IP
import logging

from .constants import *
from .rpyutils import set_ip_address

log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logger = logging.getLogger(__name__)

# To override the default severity of logging
logger.setLevel('DEBUG')

# Use FileHandler() to log to a file
file_handler = logging.FileHandler("python3-fakeap.log")
formatter = logging.Formatter(log_format)
file_handler.setFormatter(formatter)

# Don't forget to add the file handler
logger.addHandler(file_handler)


class TunInterface(threading.Thread):
    def __init__(self, ap, name="fakeap"):
        threading.Thread.__init__(self)

        if len(name) > IFNAMSIZ:
            raise Exception("Tun interface name cannot be larger than " + str(IFNAMSIZ))

        self.name = name
        self.setDaemon(True)
        self.ap = ap

        # Virtual interface
        self.fd = open('/dev/net/tun', 'rb+', buffering=0)
        ifr_flags = IFF_TUN | IFF_NO_PI  # Tun device without packet information
        logger.info("Name is type {0} and is {1}".format(type(name), name))
        logger.info("ifr_flags is type {0} and is {1}".format(type(ifr_flags), ifr_flags))
        ifreq = struct.pack('16sH', name.encode('utf-8'), ifr_flags)
        logger.info("ifreq is type {0} and is {1}".format(type(ifreq), ifreq))
        fcntl.ioctl(self.fd, TUNSETIFF, ifreq)  # Syscall to create interface

        # Assign IP and bring interface up
        set_ip_address(name, self.ap.ip)

        print("Created TUN interface %s at %s. Bind it to your services if needed." % (name, self.ap.ip))

    def write(self, pkt):
        os.write(self.fd.fileno(), str(pkt[IP]))  # Strip layer 2

    def read(self):
        raw_packet = os.read(self.fd.fileno(), DOT11_MTU)
        return raw_packet

    def close(self):
        os.close(self.fd.fileno())

    def run(self):
        while True:
            raw_packet = self.read()
            self.ap.callbacks.cb_tint_read(raw_packet)