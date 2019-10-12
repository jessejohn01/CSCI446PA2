import network_3_0
import argparse
import time
from time import sleep
import hashlib


class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    ## length of md5 checksum in hex
    checksum_length = 32 
        
    def __init__(self, seq_num, msg_S):
        self.seq_num = seq_num
        self.msg_S = msg_S
        
    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        #extract the fields
        seq_num = int(byte_S[Packet.length_S_length : Packet.length_S_length+Packet.seq_num_S_length])
        msg_S = byte_S[Packet.length_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        return self(seq_num, msg_S)
        
        
    def get_byte_S(self):
        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(self.length_S_length)
        #compute the checksum
        checksum = hashlib.md5((length_S+seq_num_S+self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return length_S + seq_num_S + checksum_S + self.msg_S


    @staticmethod
    def corrupt(byte_S):
        #extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length : Packet.seq_num_S_length+Packet.seq_num_S_length]
        checksum_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length : Packet.seq_num_S_length+Packet.length_S_length+Packet.checksum_length]
        msg_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        
        #compute the checksum locally
        checksum = hashlib.md5(str(length_S+seq_num_S+msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        #and check if the same
        return checksum_S != computed_checksum_S
        

class RDT:
    ## latest sequence number used in a packet
    seq_num = 1
    ## buffer of bytes read from network
    byte_buffer = ''

    def __init__(self, role_S, server_S, port):
        self.network = network_3_0.NetworkLayer(role_S, server_S, port)
    
    def disconnect(self):
        self.network.disconnect()
        
    def rdt_1_0_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        self.seq_num += 1
        self.network.udt_send(p.get_byte_S())
        
    def rdt_1_0_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
        while True:
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.length_S_length):
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S #not enough bytes to read the whole packet
            #create packet from buffer content and add to return string
            p = Packet.from_byte_S(self.byte_buffer[0:length])
            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
            #remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            #if this was the last packet, will return on the next iteration


    def waitForACK(self,p):   #Wait for an ACK Packet. Basically listening for a packet.
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        while True: #Keep grabbing bytes.
            byte_S = self.network.udt_receive()
            self.byte_buffer += byte_S
            if(len(self.byte_buffer) >= Packet.length_S_length): # Check to make sure we have enough bytes for a packet.
                length = int(self.byte_buffer[:Packet.length_S_length])

                if(len(self.byte_buffer) >= length): # Check our bytes are the right length
                    if(Packet.corrupt(self.byte_buffer[0:length])): #Check for corruption
                        self.byte_buffer = self.byte_buffer[length:]
                        self.network.udt_send(p.get_byte_S()) #If not resend.
                    else:
                        receivedPacket = Packet.from_byte_S(self.byte_buffer[0:length])
                        self.byte_buffer = self.byte_buffer[length:]
                        if(receivedPacket.msg_S == 'ACK' and receivedPacket.seq_num >= self.seq_num):#Check if ACK packet.
                            self.seq_num = self.seq_num + 1
                            return
                        else:
                            self.network.udt_send(p.get_byte_S())
                    
    def waitForMore(self, ack): #Method for making sure there is no resends. Wait for .1 seconds
        end = time.time() + .1
        byte_buffer2 = ''
        while (time.time() < end):
            isDuplicate = False
            bytes2 = self.network.udt_receive()
            byte_buffer2 += bytes2

            if (len(byte_buffer2) < Packet.length_S_length): #restarts if not enough bytes
                continue #restart loop
            length = int(byte_buffer2[:Packet.length_S_length])
            if (len(byte_buffer2) < length): #Restart if not matching length
                continue #restart

            if (Packet.corrupt(byte_buffer2[0:length])): #Is the packet corrupt?
                nack = Packet(self.seq_num, 'NACK') #Create NACK packet.
                self.network.udt_send(nack.get_byte_S()) #Send
                byte_buffer2 = '' #Empty the buffer.
                if (isDuplicate): #Checks for duplicates and adds more time
                    end = end + .1
                continue
            else: # Time expired
                p2 = Packet.from_byte_S(byte_buffer2[0:length])
                if (p2.seq_num == self.seq_num - 1): #Check if it was a different packet.
                    isDuplicate = True
                    end = end + .1
                    self.network.udt_send(ack.get_byte_S()) #We don't have to wait anymore send ACK.
                    byte_buffer2 = ''
                else:
                    nack = Packet(self.seq_num, 'NACK')
                    self.network.udt_send(nack.get_byte_S())
                    break


    def rdt_3_0_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        self.network.udt_send(p.get_byte_S())

        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S

        while True: # Keep checking for packets.
            timeoutTime = time.time() + .05 #Timer for lost packets.
            while(time.time() < timeoutTime):
                byte_S = self.network.udt_receive()
                self.byte_buffer += byte_S
                if(len(self.byte_buffer) >= Packet.length_S_length):
                    length = int(self.byte_buffer[:Packet.length_S_length])
                    if(len(self.byte_buffer) >= length): #Make sure packet is right length.
                        if(Packet.corrupt(self.byte_buffer[0:length])): #Check to make sure not corrupt.
                            self.byte_buffer = self.byte_buffer[length:]
                            break
                        else:
                            receivedPacket = Packet.from_byte_S(self.byte_buffer[0:length])
                            self.byte_buffer = self.byte_buffer[length:]
                            if(receivedPacket.msg_S == 'ACK' and receivedPacket.seq_num >= self.seq_num): #Check if right ACK packet for one we sent.
                                self.seq_num = self.seq_num + 1
                                self.byte_buffer = self.byte_buffer[length:]
                                return
                            else:
                                break #Break out the timer somethings wrong.
            self.network.udt_send(p.get_byte_S())


    def rdt_3_0_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        while True: #Keep checking for packets.
            if (len(self.byte_buffer) < Packet.length_S_length): #Is packet right length
                return ret_S
            length = int(self.byte_buffer[:Packet.length_S_length])
            if (len(self.byte_buffer) < length):
                return ret_S
            if(Packet.corrupt(self.byte_buffer[0:length])): # Check for corrupt packets.
                nack = Packet(self.seq_num, 'NACK')
                self.network.udt_send(nack.get_byte_S())
                self.byte_buffer = self.byte_buffer[length:]
            else:
                p = Packet.from_byte_S(self.byte_buffer[0:length])
                if (p.seq_num <= self.seq_num): #Is packet right sequence number.
                    ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                    self.seq_num = self.seq_num + 1
                    ack = Packet(p.seq_num, 'ACK')
                    self.network.udt_send(ack.get_byte_S())
                    end = time.time() + .2
                    byte_buffer2 = ''
                    while(time.time() < end):
                        isDuplicate = False
                        bytes2 = self.network.udt_receive()
                        byte_buffer2 += bytes2
                        try:
                            if (len(byte_buffer2) < Packet.length_S_length):
                                continue
                        except ValueError:
                            continue
                        length = int(byte_buffer2[:Packet.length_S_length])
                        if (len(byte_buffer2) < length):
                            continue
                        if(Packet.corrupt(byte_buffer2[0:length])):
                            nack = Packet(self.seq_num, 'NACK')
                            self.network.udt_send(nack.get_byte_S())
                            byte_buffer2 = ''
                            if(isDuplicate):
                                end = end + .2
                            continue
                        else:
                            p2 = Packet.from_byte_S(byte_buffer2[0:length])
                            if (p2.seq_num <= self.seq_num-1):
                                isDuplicate = True
                                end = end + .2
                                ack1 = Packet(p2.seq_num, 'ACK')
                                self.network.udt_send(ack1.get_byte_S())
                                byte_buffer2 = ''
                            else:
                                nack = Packet(self.seq_num, 'NACK')
                                self.network.udt_send(nack.get_byte_S())
                                break
                else:
                    nack = Packet(self.seq_num, 'NACK')
                    self.network.udt_send(nack.get_byte_S())
                self.byte_buffer = self.byte_buffer[length:]


if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()
    
    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_1_0_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_1_0_receive())
        rdt.disconnect()
        
        
    else:
        sleep(1)
        print(rdt.rdt_1_0_receive())
        rdt.rdt_1_0_send('MSG_FROM_SERVER')
        rdt.disconnect()
        


        
        