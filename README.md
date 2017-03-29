# pyc2
simple c2 written in python2 to demonstrate security concepts. use icmp echo requests and replies to trade base64 encoded commands and replies. Video explaining some of the security concepts and implementation decisions: https://www.youtube.com/watch?v=ggYRh0w3cPk

requires scapy (pip install scapy)

enter the c2 IP address in the c2_config.py file.

command_list should be a list of commands, one per line, exactly how you would enter it into the cli. use echo >> command_list to add new commands to the file:

echo "cat /etc/passwd" >> command_list
