import binascii
import hashlib
import hmac

from Crypto.Cipher import AES

from templates import ikev1_payloadParser as ikeParser
from templates import ikev1_pcapReader as pcapReader

pcapPath = "../pcaps/ikev1-psk-main-mode-incomplete.pcap"
dictPath = "../dict/list-main-mode-solution.txt"
# dictPath = "../dict/list.txt"

# required diffie hellman secret of the responder (attacker)
dhSecret = binascii.unhexlify(
    "34B52971CD61F18048EE97D20DA488A4634125F300DC2D1F470BDBB68B989FB999A2721328084C165CBEBDCA0C08B516799132B8F647AE46BD2601028EC7E3954AAF612828826A031FF08B7AE4057CAE0ADB51453BAAE84691705E913BA95067B816385C37D2BD85701501F94A1AA27FFC20A9546EC9DEFF8A1CB33588819A55")

# idHex  = ...||PayloadLength||IDType||ProtocolID||Port||IPAddress
idHex = "0800000c01000000c0a80064"
idPlainValue = binascii.unhexlify(idHex)
idLength = idHex.__len__()


def bytesToHex(byteStr):
    return binascii.hexlify(byteStr)


def computeKey(PSK, nonceI, nonceR):
    k = hmac.new(PSK, msg=nonceI + nonceR, digestmod=hashlib.sha1)
    return k


def deriveKeys(key, initCookie, respCookie):
    key_d = hmac.new(key, dhSecret + initCookie + respCookie + bytes.fromhex("00"), digestmod=hashlib.sha1)
    key_a = hmac.new(key, key_d.digest() + dhSecret + initCookie + respCookie + bytes.fromhex("01"),
                     digestmod=hashlib.sha1)
    key_e = hmac.new(key, key_a.digest() + dhSecret + initCookie + respCookie + bytes.fromhex("02"),
                     digestmod=hashlib.sha1)
    return {"key_d": key_d, "key_a": key_a, "key_e": key_e}


# IV is computed via the SHA1 hash of the Key Exchange parameter
# /* initial IV = hash(g^xi | g^xr) */
def computeIV(initKeX, respKeX):
    return hashlib.sha1(initKeX + respKeX)


if __name__ == '__main__':
    print("We are looking for: " + idHex + "\n")
    # 1. open pcap
    netPackets = pcapReader.openPCAPFile(pcapPath)
    ikePackets = pcapReader.getISAKMPPackets(netPackets)
    # 2. get required values
    initKENoncePacket = ikeParser.getInitiatorKENoncePacket(ikePackets)
    respKENoncePacket = ikeParser.getResponderKENoncePacket(ikePackets)
    initSAPacket = ikeParser.getIniatorSAPacket(ikePackets)
    respSAPacket = ikeParser.getResponderSAPacket(ikePackets)

    initNONCE = ikeParser.getPayloadFromISAKMP(initKENoncePacket, ikeParser.ISAKMP_NONCE_NAME)
    respNONCE = ikeParser.getPayloadFromISAKMP(respKENoncePacket, ikeParser.ISAKMP_NONCE_NAME)

    respCookie = ikeParser.getCookieFromISAKMP(respSAPacket, True)
    initCookie = ikeParser.getCookieFromISAKMP(initSAPacket, False)

    respKEX = ikeParser.getPayloadFromISAKMP(respKENoncePacket, ikeParser.ISAKMP_KEX_NAME)
    initKEX = ikeParser.getPayloadFromISAKMP(initKENoncePacket, ikeParser.ISAKMP_KEX_NAME)

    aesIV = computeIV(initKEX, respKEX).digest()[0:16]
    initIDPacket = ikeParser.getInitiatorIdentificationPacket(ikePackets)
    encryptedData = ikeParser.getEncryptedData(initIDPacket)

    # 3. read dict line by line
    with open(dictPath) as f:
        for line in f:
            # remove newline from string
            line = line.rstrip('\n')
            key = computeKey(bytes(line, encoding='utf8'), initNONCE, respNONCE)
            keys = deriveKeys(key.digest(), initCookie, respCookie)
            cipher = AES.new(keys["key_e"].digest()[0:16], AES.MODE_CBC, iv=aesIV)
            decryptedData = cipher.decrypt(encryptedData)
            if bytesToHex(decryptedData)[0:idLength] == idHex.encode():
                print("Found our key! " + line)
                break
