#!/usr/bin/python
import json
import base64
import binascii
import paho.mqtt.client as mosquitto
import struct

TOPIC_RX = "gateway/aa555a0000000101/rx"
TOPIC_TX = "gateway/aa555a0000000101/tx"
TOPIC_APP = "application/aabbccddeeff1122/node/0011223344556677/rx"

MTYPE_JOIN_REQUEST = 0
MTYPE_JOIN_ACCEPT = 1
MTYPE_UNCONFIRMED_DATA_UP = 2
MTYPE_UNCONFIRMED_DATA_DOWN = 3
MTYPE_CONFIRMED_DATA_UP = 4
MTYPE_CONFIRMED_DATA_DOWN = 5
MTYPE_RFU = 6
MTYPE_PROPRIETARY = 7


WEAK_KEYS = [
    "01-02-03-04-05-06-07-08-09-0A-0B-0C-0D-0E-10",
    "00-00-00-00-00-00-00-00-00-00-00-00-00-00-00",
    "11-11-00-00-00-00-00-00-00-00-00-00-00-00-00",
    "22-22-00-00-00-00-00-00-00-00-00-00-00-00-00",
    "33-33-00-00-00-00-00-00-00-00-00-00-00-00-00",
    "44-44-00-00-00-00-00-00-00-00-00-00-00-00-00",
    "55-55-00-00-00-00-00-00-00-00-00-00-00-00-00",
    "66-66-00-00-00-00-00-00-00-00-00-00-00-00-00",
    "77-77-00-00-00-00-00-00-00-00-00-00-00-00-00",
    "88-88-00-00-00-00-00-00-00-00-00-00-00-00-00",
    "99-99-00-00-00-00-00-00-00-00-00-00-00-00-00",
    "AA-AA-00-00-00-00-00-00-00-00-00-00-00-00-00",
    "BB-BB-00-00-00-00-00-00-00-00-00-00-00-00-00",
    "CC-CC-00-00-00-00-00-00-00-00-00-00-00-00-00",
    "DD-DD-00-00-00-00-00-00-00-00-00-00-00-00-00",
    "EE-EE-00-00-00-00-00-00-00-00-00-00-00-00-00",
    "FF-FF-00-00-00-00-00-00-00-00-00-00-00-00-00",
    ]

def generateSKey(key, nonce):
    encrypt(key, blob)
    

def ComputeMIC(data):
    pass

def processApplicationData(data):
    print "[fcnt: %s  fport:%s]" % (data['fCnt'], data['fPort'])
    if data['data'] != None:
        appdata = base64.decodestring(data['data'])
        print " *** Received data from node: %i bytes" % len(appdata)
        print " ->  %s" % appdata
    else:
        print " *** No data"

def MType(byte):
    return struct.unpack("b", byte)[0] >> 5

    
    
def processPacketRx(data):
    mhdr = data[0]
    MacPayload = data[1:-4]
    mic = data[-4:]
    assert(len(data) == len(mhdr) + len(MacPayload) + len(mic))

    mtype = MType(mhdr)
    if mtype == MTYPE_JOIN_REQUEST:
        print " *** Join-request"
        AppEUI = data[1:9]
        DevEUI = data[9:17]
        Nonce = data[17:19]
        
        AppEUI = AppEUI[::-1]
        DevEUI = DevEUI[::-1]
        Nonce = Nonce[::-1]
        print "  AppEUI: %s" % binascii.hexlify(AppEUI)
        print "  DevEUI: %s" % binascii.hexlify(DevEUI)
        print "  Nonce:  %s" % binascii.hexlify(Nonce)
        print "  MIC: %s" % binascii.hexlify(mic)
    elif MType(mhdr) == MTYPE_UNCONFIRMED_DATA_UP:
        FHdr = MacPayload[0:8]
        FRMPayload = MacPayload[8:]
        assert(len(FHdr) + len(FRMPayload) == len(MacPayload))
        devAddr, fCtrl, fCnt, fPort = struct.unpack("=IBHB", FHdr)
        print " *** Unconfirmed data up"
        print "  DevAddr: %08x    fCtrl: %02x   fCtnt: %04x   fPort: %02x" % (devAddr, fCtrl, fCnt, fPort)
        print "  Data: %s" % binascii.hexlify(FRMPayload)
    else:
        print "Unsupported type"

def processPacketTx(data):
    mhdr = data[0]
    MacPayload = data[1:-4]
    mic = data[-4:]
    assert(len(mhdr) + len(MacPayload) + len(mic) == len(data))
    
    mtype = MType(mhdr)
    if mtype == MTYPE_JOIN_REQUEST:
        raise "Request should not come on rx"
    elif MType(mhdr) == MTYPE_UNCONFIRMED_DATA_UP:
        raise "Should not occur"
    elif MType(mhdr) == MTYPE_JOIN_ACCEPT:
        AppNonce = MacPayload[0:3]
        NetID = MacPayload[3:6]
        DevAddr = MacPayload[6:10]        
        print " *** Join Accept"
        print "  Data: %s" % binascii.hexlify(MacPayload)
    else:
        print "Unsupported type"

def on_message(client, userdata, msg):
    data = json.loads(msg.payload)
    print "=======> Received message on topic %s" % msg.topic
    if msg.topic == TOPIC_RX:
        print " ---> Rx: Received Message at %s" % data['rxInfo']['time']
        binData = base64.decodestring(data['phyPayload'])
        print " Decoded data: " + binascii.hexlify(binData)
        processPacketRx(binData)
    elif msg.topic == TOPIC_TX:
        print " ---> Rx: Intercepting Message on TX" # data['txInfo']['time']        
        binData = base64.decodestring(data['phyPayload'])
        print " Decoded data: " + binascii.hexlify(binData)
        processPacketTx(binData)
    elif msg.topic == TOPIC_APP:
        print " ---> Application data from node %s" % data['devEUI']        
        processApplicationData(data)

MQTT_HOST = "192.168.56.135"


def main():
    client = mosquitto.Mosquitto()
    print " ## Connecting to %s" % MQTT_HOST
    client.connect(MQTT_HOST)
    client.on_message = on_message
    for q in [TOPIC_RX, TOPIC_TX, TOPIC_APP]:
        print " ## Subscribing to %s" % q
        client.subscribe(q)
    client.loop_forever()



if __name__ == "__main__":
    main()
