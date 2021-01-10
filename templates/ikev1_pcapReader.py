from scapy.all import *

def openPCAPFile(path):
    return rdpcap(path)

# returns only the ISAKMP Layer of the Packet
def getISAKMPPackets(packets):
    filteredPackets = []
    for pkt in packets:
        if pkt.haslayer(scapy.layers.isakmp.ISAKMP):
            filteredPackets.append(pkt)
    return filteredPackets
