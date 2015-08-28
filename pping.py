#!/usr/bin/env python

import argparse
import errno
import random
import select
import socket
import struct
import sys

from os import getpid
from timeit import default_timer as now

# some default values - if we don't need them, remove 'em later
ICMP_DATA_SIZE = 56
ICMP_HEADER_SIZE = 8
IP_HEADER_SIZE = 20
DEFAULT_REQUEST_COUNT = 3
DEFAULT_REQUEST_DELAY = 1
DEFAULT_REQUEST_SIZE = 56
DEFAULT_REQUEST_TIMEOUT = 5 # seconds

def die(msg):
    print msg
    sys.exit(0)

def format_time(timeInSeconds):
    units = ["s", "ms", "mis"]

    for unit in units:
        if timeInSeconds > 1:
            return timeInSeconds, unit
        timeInSeconds *= 1000

def int_to_ipv4(input):
    return ".".join([str((input >> offset) & 0xff) for offset in [24, 16, 8, 0]])

def checksum(byteString):
    l = len(byteString)

    if l % 2 != 0:
        byteString += b"\00"

    count = 0
    sum = 0

    while count < l:
        sum += (ord(byteString[count + 1]) << 8) + ord(byteString[count])
        count += 2

    sum &= 0xffffffff
    sum = (sum >> 16) + (sum & 0xffff)    # Add high 16 bits to low 16 bits
    sum += (sum >> 16)                    # Add carry from above (if any)
    ret_val = ~sum & 0xffff               # Invert and truncate to 16 bits
    ret_val = socket.htons(ret_val)

    return ret_val

def random_payload(lowerBoundary = 64, upperBoundary = 90):
    return "".join([chr(random.randrange(lowerBoundary, upperBoundary)) for _ in range(size)])

def filter_empty_args(args):
    return dict((k, v) for k, v in args.items() if v != None)

class ICMPHeader():
    def __init__(self, data):
        if type(data) is str:
            unpacked = struct.unpack("!BBHHH", data)

            self.type = unpacked[0]
            self.code = unpacked[1]
            self.checksum = unpacked[2]
            self.identifier = unpacked[3]
            self.sequence_number = unpacked[4]

        elif type(data) is dict:
            self.fromDict(data)

        elif data is None:
            self.fromDict({
                "type" : 0,
                "code" : 0,
                "checksum" : 0,
                "identifier" : 0,
                "sequence_number" : 0
            })

    def toDict(self):
        return vars(self)

    def fromDict(self, values):
        self.type = values["type"] if "type" in values else None
        self.code = values["code"] if "code" in values else None
        self.checksum = values["checksum"] if "checksum" in values else None
        self.identifier = values["identifier"] if "identifier" in values else getpid() & 0xffff
        self.sequence_number = values["sequence_number"] if "sequence_number" in values else None

    def toBinaryString(self):
        return struct.pack("!BBHHH", self.type, self.code, self.checksum, self.identifier, self.sequence_number)

class IPHeader():
    def __init__(self, data):
        if type(data) is str:
            unpacked = struct.unpack("!BBHHHBBHII", data)
            src = unpacked[8]
            dst = unpacked[9]

            self.version          = unpacked[0] >> 4
            self.ip_header_length = unpacked[0] & 0xf
            self.type_of_service  = unpacked[1]
            self.total_length     = unpacked[2]
            self.identification   = unpacked[3]
            self.flags            = unpacked[4] >> 12
            self.fragment_offset  = unpacked[4] & 0x0fff
            self.time_to_live     = unpacked[5]
            self.protocol         = unpacked[6]
            self.checksum         = unpacked[7]
            self.source           = int_to_ipv4(src)
            self.destination      = int_to_ipv4(dst)

        #elif type(data) is dict:
        #   self.fromDict(data)

    def toDict(self):
        return vars(self)

class ICMPEchoRequest():
    def __init__(self, size = ICMP_DATA_SIZE, seq = 0, payloadRangeFrom = 64, payloadRangeTo = 90, id = None):
        self._type = 8
        self._code = 0

        # The checksum is cleared to zero in initial state.
        self._checksum = 0

        # If code = 0, an identifier to aid in matching echos and replies, may be zero.
        self._identifier = id

        if id == None:
            self._identifier = getpid() & 0xffff # truncate to fit in header field

        # If code = 0, a sequence number to aid in matching echos and replies, may be zero.
        self._sequenceNumber = seq

        self._payload = "".join([chr(random.randrange(payloadRangeFrom, payloadRangeTo)) for _ in range(size)])

    def _calculateChecksum(self, source_string):
        # The checksum is the 16-bit ones's complement of the one's
        # complement sum of the ICMP message starting with the ICMP Type.
        # @see RFC 792

        # @see RFC 1071
        #   (1)  Adjacent octets to be checksummed are paired to form 16-bit
        #        integers, and the 1's complement sum of these 16-bit integers is
        #        formed.
        #
        #   (2)  To generate a checksum, the checksum field itself is cleared,
        #        the 16-bit 1's complement sum is computed over the octets
        #        concerned, and the 1's complement of this sum is placed in the
        #        checksum field.

        strLen = len(source_string)

        # If the total length is odd, data is padded with one octet of zeros
        if strLen % 2 != 0:
            source_string += b"\00"

        count = 0
        sum = 0

        while count < strLen:
            # According to RFC 1071, there's no need to care about byte order. So, we don't care.
            sum   += (ord(source_string[count + 1]) << 8) + ord(source_string[count])
            count += 2

        sum &= 0xffffffff
        sum = (sum >> 16) + (sum & 0xffff) # Add high 16 bits to low 16 bits
        sum += (sum >> 16)                 # Add carry from above (if any)
        ret_val = ~sum & 0xffff            # Invert and truncate to 16 bits
        ret_val = socket.htons(ret_val)

        return ret_val

    def asString(self):
        dummy_header   = struct.pack("!BBHHH", self._type, self._code, self._checksum, self._identifier, self._sequenceNumber)
        self._checksum = self._calculateChecksum(dummy_header + self._payload)

        return struct.pack("!BBHHH", self._type, self._code, self._checksum, self._identifier, self._sequenceNumber) + self._payload

class Ping:
    # def __init__(self, destinationHost, timeout = 5, count = 3, size = ICMP_DATA_SIZE):
    def __init__(self, destinationHost, **kwargs):
        self.requests = []

        try:
            self.destination = socket.gethostbyname(destinationHost)
        except BaseException as e:
            die("unknown host: " + destinationHost)

        # these attributes were named arguments in the previous version
        self.timeout = DEFAULT_REQUEST_TIMEOUT
        self.count   = DEFAULT_REQUEST_COUNT
        self.size    = DEFAULT_REQUEST_SIZE

        self.requests_received = 0
        self.requests_total = 0

        self.time_total = 0.0
        self.time_min = float(0xffffffff)
        self.time_max = 0.0

        # whitelist attributes which can be changed from outside
        attr_keys = ["timeout", "count", "size", "delay"]
        for attr in kwargs:
            if hasattr(self, attr) and attr in attr_keys:
                self.__dict__[attr] = kwargs[attr]

    def run(self):
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except socket.error, (err_code, err_msg): # @todo: please - make me beautiful.
            if err_code == errno.EPERM: # operation not permitted
                etype, evalue, etb = sys.exc_info()
                evalue = etype(
                    "%s - ICMP messages can only be send from processes running as root." % evalue
                )
                die(str(etype) + " " + str(evalue))
            # raise
        # raise

        self.printBannerLine()

        for i in range(0, self.count):
            # icmp_header = ICMPHeader({"type" : 8, "code" : 0, "checksum" : 0, "sequence_numer" : i})
            icmp_packet = ICMPEchoRequest(self.size, i)

            # store request
            self.requests += [icmp_packet]
            self.requests_total += 1

            send_time = self.sendPing(icmp_packet)

            if send_time == None:
                return

            recv_time, packet_size, ip_reply_header, icmp_reply_header = self.recvPong()

            if recv_time:
                # print "recv_time"
                icmp_header = icmp_reply_header.toDict()

                if icmp_header["identifier"] == icmp_packet._identifier:

                    if icmp_header["sequence_number"] == icmp_packet._sequenceNumber:
                        rtt, rtt_unit = format_time(recv_time - send_time)

                        if icmp_header["type"] == 0:
                            self.requests_received += 1
                            self.printPingLine(rtt, packet_size, ip_reply_header.toDict(), icmp_header, rtt_unit)

                            if self.time_max < rtt:
                                self.time_max = rtt

                            if self.time_min > rtt:
                                self.time_min = rtt

                            self.time_total += rtt

                        if icmp_header["type"] == 3:
                            self.printDestinationUnreachable(icmp_header["code"])

                else:
                    self.printDestinationHostUnreachable()

            else:
                self.printTimeout()

        self._socket.close()
        self.printResultLine()

    def sendPing(self, request):
        sendTime = now()
        self._socket.sendto(request.asString(), (self.destination, 1))
        return sendTime

    """
    @return recv_time, packet_size, ip_header, icmp_header
    """
    def recvPong(self):
        timeout = self.timeout
        entered_function = now()

        while True:
            # print "recvPong while ..."
            if now() - entered_function > timeout:
                # print "TIMEOUT!"
                return None, 0, 0, 0

            readable, writable, exceptional = select.select([self._socket], [], [])

            if readable == []:
                # print "TIMEOUT [select]"
                return None, 0, None, None

            packet_data, address = self._socket.recvfrom(1024)
            # print "self._socket.recvfrom ..."
            recv_time = now()

            icmp_header = ICMPHeader(packet_data[20:28])
            ip_header = IPHeader(packet_data[:20])

            return recv_time, len(packet_data), ip_header, icmp_header

    def printPingLine(self, rtt, receivedBytes, ipHeader, icmpHeader, rttUnit = "ms"):
        out = "{0} bytes from {1}: icmp_seq={2} ttl={3} time:  {4:.2f} {5}"

        print out.format((receivedBytes - IP_HEADER_SIZE), ipHeader["source"], icmpHeader["sequence_number"], ipHeader["time_to_live"], rtt, rttUnit)

    def printTimeout(self):
        print "Request timed out."

    def printResultLine(self):
        print ""
        print "--- ping statistics for {0} ---".format(self.destination)
        print "{total} packets transmitted, {received} received, {loss}% loss, time {t_value:.3f} {t_unit}".format(
            total = self.requests_total,
            received = self.requests_received,
            loss = ((1.0 - float(self.requests_received) / float(self.requests_total)) * 100),
            t_value = self.time_total,
            t_unit = "[time_unit]"
        )
        print "rtt min/avg/max/mdev = {0:.3f}/{1:.3f}/{2:.3f}/{3} {4}".format(self.time_min, (self.time_total / self.requests_received), self.time_max, "[rtt_mdev]", "[time_unit]")

    def printBannerLine(self):
        try:
            resolved_host = "{0} ({1})".format(socket.gethostbyaddr(self.destination)[0], self.destination)
        except:
            resolved_host = self.destination

        print "PING {0} {1}({2}) bytes of data.".format(resolved_host, self.size, (self.size + ICMP_HEADER_SIZE + IP_HEADER_SIZE))

    def printDestinationHostUnreachable(self):
        print "Destination Host Unreachable."

    def printDestinationUnreachable(self, code):
        print {
             0 : "DESTINATION NETWORK UNREACHABLE",
             1 : "DESTINATION HOST UNREACHABLE",
             2 : "DESTINATION PROTOCOL UNREACHABLE",
             3 : "DESTINATION PORT UNREACHABLE",
             4 : "FRAGMENTATION REQUIRED",
             5 : "SOURCE ROUTE FAILED",
             6 : "DESTINATION NETWORK UNKNOWN",
             7 : "DESTINATION HOST UNKNOWN",
             8 : "SOURCE HOST ISOLATED",
             9 : "NETWORK ADMINISTRATELY PROHIBITED",
            10 : "HOST ADMINISTRATELY PROHIBITED",
            11 : "NETWORK UNREACHABLE FOR TOS",
            12 : "HOST UNREACHABLE FOR TOS",
            13 : "COMMUNICATION ADMINISTRATELY PROHIBITED",
            14 : "HOST PRECEDENCE VIOLATION",
            15 : "PRECEDENCE CUTOFF IN EFFECT"
        }[code]

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--count", type=int, dest="count")
    parser.add_argument("-d", "--delay", type=int, dest="delay")
    parser.add_argument("-s", "--size", type=int, dest="size")
    parser.add_argument("-t", "--timeout", type=int, dest="timeout")
    parser.add_argument("destination", type=str)

    args = vars(parser.parse_args())
    args = filter_empty_args(args)

    if "destination" in args and args["destination"] != None:
        dest = args["destination"]
        p = Ping(dest, **args)

        try:
            p.run()

        except KeyboardInterrupt:
            print ""
            die(p.printResultLine())