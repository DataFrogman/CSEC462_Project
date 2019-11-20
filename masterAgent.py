import socket

dict = {}

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.SOCK_DGRAM)

while True:
    data, sender = s.recvfrom(65565)
    packet = data
    ip_header = packet[0:20]
    iph = unpack('!BBHHHBBH4s4s' , ip_header)

    version_ihl = iph[0]
    version = version_ihl &gt;&gt; 4
    ihl = version_ihl &amp; 0xF

    iph_length = ihl * 4
    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8]);
    d_addr = socket.inet_ntoa(iph[9]);

    dhcp_header = 
