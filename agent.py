from scapy.all import *
import time
import argparse
import sys

def detect(ip):
    scapy.all.conf.checkIPaddr = False
    fam,hw = scapy.all.get_if_raw_hwaddr(scapy.all.conf.iface)
    
    dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff", src=hw, type=0x0800) / \
    IP(src="0.0.0.0",dst="255.255.255.255") / \
        scapy.all.UDP(sport=68,dport=67) / \
        scapy.all.BOOTP(op=1, chaddr=hw) / \
        scapy.all.DHCP(options=[("message-type","discover"),"end"])
    sendp(dhcp_discover)

    ans,unans = scapy.all.srp(dhcp_discover)
    packets = []
    for snd,rcv in ans:
        if rcv[DHCP].options[0][1] == 2:
            recvIP = rcv[IP].src
            if recvIP != ip:
                packets.append((True, recvIP))
            else:
                packets.append((False, recvIP))
    return packets

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This program is used to detect rogue DHCP servers', add_help=True)
    parser.add_argument('-t', action='store', dest="time", type=int,
                        help="Time between actions in seconds")
    parser.add_argument("--file", help="logfile, default project.log", action='store', dest="file", default="project.log")
    parser.add_argument('expected_server_ip')
    
    args = parser.parse_args()
    if args.expected_server_ip == None:
        sys.exit(0)
        
    if args.time != None:
        while True:
            packets = detect(args.expected_server_ip)
            f = open(args.file, "a")
            packets = detect(args.expected_server_ip)
            for x in packets:
                if x[0] == True:
                    temp = "Malicious response detected: " + str(x[1] + "\n")
                    f.write(temp)
                else:
                    temp = "Benign response detected: " + str(x[1] + "\n")
                    f.write(temp)
            f.close()
            time.sleep(args.time)

    else:
        f = open(args.file, "a")
        packets = detect(args.expected_server_ip)
        for x in packets:
            if x[0] == True:
                temp = "Malicious response detected: " + str(x[1])
                f.write(temp)
            else:
                temp = "Benign response detected: " + str(x[1])
                f.write(temp)
        f.close()
