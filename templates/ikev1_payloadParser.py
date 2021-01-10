from scapy.all import *
import binascii

ISAKMP_NONCE_NAME = "ISAKMP Nonce"  # 10
ISAKMP_KEX_NAME = "ISAKMP Key Exchange"  # 4


def getIniatorSAPacket(packets):
    # Find first packet that contains SA
    # Equivalent to return packets[0].getlayer(scapy.layers.isakmp.ISAKMP) if packets are in order
    for pkt in packets:
        if pkt.next_payload == 1:  # 1 == SA
            return pkt.getlayer(scapy.layers.isakmp.ISAKMP)


def getResponderSAPacket(packets):
    # Find first packet that contains SA
    # Equivalent to return packets[1].getlayer(scapy.layers.isakmp.ISAKMP) if packets are in order
    i = 1
    for pkt in packets:
        if pkt.next_payload == 1:  # 1 == SA
            if i >= 2:
                return pkt.getlayer(scapy.layers.isakmp.ISAKMP)
            else:
                i += 1


def getInitiatorKENoncePacket(packets):
    # Find first packet that contains KE
    for pkt in packets:
        if pkt.next_payload == 4:  # 4 == KE
            return pkt.getlayer(scapy.layers.isakmp.ISAKMP)


def getResponderKENoncePacket(packets):
    # Find first packet that contains KE
    i = 1
    for pkt in packets:
        if pkt.next_payload == 4:  # 4 == KE
            if i >= 2:
                return pkt.getlayer(scapy.layers.isakmp.ISAKMP)
            else:
                i += 1


def getInitiatorIdentificationPacket(packets):
    # Find first packet that contains KE
    for pkt in packets:
        if pkt.next_payload == 5:  # 5 == IP
            return pkt.getlayer(scapy.layers.isakmp.ISAKMP)


# name == payload name
def getPayloadFromISAKMP(packet, name):
    return packet[name].load


# forResponder == True/False
def getCookieFromISAKMP(packet, forResponder):
    if forResponder:
        # true -> responder cookie
        return packet.resp_cookie
    else:
        # false -> initiator cookie
        return packet.init_cookie


def getEncryptedData(packet):
    # Responder ID consist of  IDType||ProtoID||Port||load
    return packet.load
