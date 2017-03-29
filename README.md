# pyc2
simple c2 written in python2 to demonstrate security concepts. use icmp echo requests and replies to trade base64 encoded commands and replies. Video explaining some of the security concepts and implementation decisions: https://www.youtube.com/watch?v=ggYRh0w3cPk

requires scapy (pip install scapy)

enter the c2 IP address in the c2_config.py file.

command_list should be a list of commands, one per line, exactly how you would enter it into the cli. use echo >> command_list to add new commands to the file:

echo "cat /etc/passwd" >> command_list

probably won't work on windows (i tried to get scapy running on windows 10 and gave up, you might have better success)

c2 server requires that icmp echo packets are ignored by the kernel:

in linux:
echo 1 >/proc/sys/net/ipv4/icmp_echo_ignore_all
