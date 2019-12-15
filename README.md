# CSEC462_Project

This is a project to develop agents to detect DHCP spoofing attacks on a network.

The file can be run as a one time check or repeating every so many seconds.

usage: agent.py [-h] [-t TIME] [--file FILE] expected_server_ip

This program is used to detect rogue DHCP servers

positional arguments:
  expected_server_ip

optional arguments:
  -h, --help          show this help message and exit
  -t TIME             Time between actions in seconds
  --file FILE         logfile, default project.log
