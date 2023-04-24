
from socket import *
import socket
import os
import sys
import struct
import time
import select
import binascii
import pandas as pd

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 60
TIMEOUT = 2.0
TRIES = 1


# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise

def checksum(string):
    # In this function we make the checksum of our packet
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2

    if countTo < len(string):
        csum += (string[len(string) - 1])
        csum &= 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def build_packet():
    icmpID = os.getpid() & 0xFFFF
    myChecksum = 0
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, icmpID, 1)
    data = struct.pack("d", time.time())
    myChecksum = checksum(header + data)
    if sys.platform == 'darwin':
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, icmpID, 1)
    packet = header + data
    return packet

def get_route(hostname):
    timeLeft = TIMEOUT
    df = pd.DataFrame(columns=['Hop Count', 'Try', 'IP', 'Hostname', 'Response Code'])
    destAddr = gethostbyname(hostname)
    print(f"this is destAddr : {destAddr}")

    for ttl in range(1, MAX_HOPS):
        for tries in range(TRIES):

            # Fill in start
            # Make a raw socket named mySocket
            #icmp = socket.getprotobyname("icmp")
            mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            # Fill in end

            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                # print(f"this is howlonginselect:{howLongInSelect}")
                # print(f"this is whatreddy[0] :{whatReady[0]}")
                if whatReady[0] == []:  # Timeout
                 # Fill in start
                 # append response to your dataframe including hop #, try #, and "timeout" responses as required by the acceptance criteria
                    resp = [[ttl, tries, 'NaN', destAddr, 'timeout1']]
                    new_df = pd.DataFrame(resp, columns=['Hop Count', 'Try', 'IP', 'Hostname', 'Response Code'])
                    df = pd.concat([df, new_df], ignore_index=True)
                    print(df)
                 # print (df)
                 # Fill in end
                recvPacket, addr = mySocket.recvfrom(1024)
                print(f"this is full addr:{addr}")
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                  # Fill in start
                  # append response to your dataframe including hop #, try #, and "timeout" responses as required by the acceptance criteria
                    resp = [[ttl, tries, 'NaN', destAddr, 'timeout2']]
                    new_df = pd.DataFrame(resp, columns=['Hop Count', 'Try', 'IP', 'Hostname', 'Response Code'])
                    df = pd.concat([df, new_df], ignore_index=True)
                    print(df)
            except Exception as e:
             print(e) # uncomment to view exceptions
             continue
            else:
                # Fill in start
                # Fetch the icmp type from the IP packet
                icmpheader = recvPacket[20:28]
                types, code, checksum, packetid, sequence = struct.unpack("bbHHh", icmpheader)
                router_ip = addr[0]
                print(f"this is routers_ip:{router_ip}")
                # Fill in end
                try:  # try to fetch the hostname of the router that returned the packet - don't confuse with the hostname that you are tracing
                 # Fill in start
                    routername = gethostbyaddr(router_ip)
                    print(f"this is routername inside try{routername}")
                 # Fill in end
                except herror:  # if the router host does not provide a hostname use "hostname not returnable"
                 # Fill in start
                 routername = "hostname not returnable"
                 print(routername)
                 # Fill in end

                if types == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    resp = [[ttl, tries, router_ip, routername[0], '11']]
                    new_df = pd.DataFrame(resp, columns=['Hop Count', 'Try', 'IP', 'Hostname', 'Response Code'])
                    df = pd.concat([df, new_df], ignore_index=True)
                    # df = pd.concat([df, pd.DataFrame({'Hop Count': [ttl], 'Try': [tries], 'IP': [router_ip],
                    #                                   'Hostname': [routername], 'Response Code': [11]})])
                    # Fill in start
                    # You should update your dataframe with the required column field responses here

                    # Fill in end
                elif types == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    # Fill in start

                    resp = [[ttl, tries, router_ip, routername[0], '3']]
                    new_df = pd.DataFrame(resp, columns=['Hop Count', 'Try', 'IP', 'Hostname', 'Response Code'])
                    df = pd.concat([df, new_df], ignore_index=True)
                    # You should update your dataframe with the required column field responses here
                    # Fill in end
                elif types == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    # Fill in start
                    # You should update your dataframe with the required column field responses here

                    resp = [[ttl, tries, router_ip, routername[0], '0']]
                    new_df = pd.DataFrame(resp, columns=['Hop Count', 'Try', 'IP', 'Hostname', 'Response Code'])
                    df = pd.concat([df, new_df], ignore_index=True)
                    # Fill in end
                    return df
                else:
                 # Fill in start
                 # If there is an exception/error to your if statements, you should append that to your df here

                 resp = [[ttl, tries, router_ip, routername[0], 'no idea']]
                 new_df = pd.DataFrame(resp, columns=['Hop Count', 'Try', 'IP', 'Hostname', 'Response Code'])
                 df = pd.concat([df, new_df], ignore_index=True)
                 # Fill in end
                break
    return df


if __name__ == '__main__':
    get_route("google.co.il")
