import socket
import struct
from uuid import getnode as get_mac
from random import randint


class server :
    def __init__(self) :
        self.TransactionID = b''
        self.xid = b''
        self.ciaddr = b''
        self.yiaddr = b''
        self.siaddr = b''
        self.mac = b''
        self.next_server = b'\x00\x00\x00\x00'
        self.dhcp_server = b'\xc0\xa8\x0b\xed'
        self.lease_time = b'\x00\x01\x51\x80'
        self.router = b'\xc0\xa8\x0b\xed'
        self.DNS = b'\xa8\x5f\x01\x01'
        self.subnet_mask = b'\xff\xff\xff\x00'
        self.message_type = b''
        self.request_subnet_mask = 0
        self.request_router = 0
        self.request_DNS = 0
        self.request_ip = b''
        self.ip = {}
        for i in range(100,200) :
            self.ip[i] = 0

        

    def data_init(self, data) :
        self.data = data
    def reuse_init(self) :
        self.request_subnet_mask = 0
        self.request_router = 0
        self.request_DNS = 0
        self.TransactionID = b''
        self.yiaddr = b''
        self.request_ip = b''

    def build_Offer_packet(self) :
        
        for k in range(100, 200) :
            if self.ip[k] == 0 :
                self.ip[k] = self.mac
                self.yiaddr = struct.pack("!B", k) 
                break
        
        print('\n*** Send DHCPOffer packet ***\n')
        packet = b''
        packet += b'\x02' #op 2 -> send to client
        packet += b'\x01' #htype 1 -> ethernet
        packet += b'\x06' #hlen 6 -> ethernet
        packet += b'\x00' #hops
        packet += self.TransactionID  #xid
        packet += b'\x00\x00' #secs
        packet += b'\x80\x00' #flags 8 -> brocast
        packet += b'\x00\x00\x00\x00' #ciaddr client ip
        packet += b'\xc0\xa8\x0b' + self.yiaddr #yiaddr your ip
        packet += b'\x00\x00\x00\x00' #siaddr server ip
        packet += b'\x00\x00\x00\x00' #giaddr relay agent or 0
        packet += self.mac     #chaddr Hardware addr
        packet += b'\x00'*10 #rest chaddr
        packet += b'\x00'*64 #sname
        packet += b'\x00'*128 #file
        packet += b'\x63\x82\x53\x63' #magic cookie
        packet += b'\x35\x01\x02' #option = 53 len = 1 message type = 2 
        packet += b'\x36\x04' + self.dhcp_server     
        packet += b'\x33\x04' + self.lease_time
        if self.request_subnet_mask == 1 :
            packet += b'\x01\x04' + self.subnet_mask
        if self.request_router == 1 :
            packet += b'\x03\x04' + self.router
        if self.request_DNS == 1 :
            packet += b'\x06\x04' + self.DNS
        packet += b'\xff' #end option

        return packet
    
    def build_Ack_packet(self) :
        print('\n*** Send DHCPAck packet ***\n')
        packet = b''
        packet += b'\x02' #op 2 -> send to client
        packet += b'\x01' #htype 1 -> ethernet
        packet += b'\x06' #hlen 6 -> ethernet
        packet += b'\x00' #hops
        packet += self.TransactionID  #xid
        packet += b'\x00\x00' #secs
        packet += b'\x80\x00' #flags 8 -> brocast
        packet += b'\x00\x00\x00\x00' #ciaddr client ip
        packet += b'\xc0\xa8\x0b' + self.yiaddr #yiaddr your ip
        packet += b'\x00\x00\x00\x00' #siaddr server ip
        packet += b'\x00\x00\x00\x00' #giaddr relay agent or 0
        packet += self.mac     #chaddr Hardware addr
        packet += b'\x00'*10 #rest chaddr
        packet += b'\x00'*64 #sname
        packet += b'\x00'*128 #file
        packet += b'\x63\x82\x53\x63' #magic cookie
        packet += b'\x35\x01\x05' #option = 53 len = 1 message type = 2 
        packet += b'\x36\x04' + self.dhcp_server     
        packet += b'\x33\x04' + self.lease_time
        if self.request_subnet_mask == 1 :
            packet += b'\x01\x04' + self.subnet_mask
        if self.request_router == 1 :
            packet += b'\x03\x04' + self.router
        if self.request_DNS == 1 :
            packet += b'\x06\x04' + self.DNS
        packet += b'\xff' #end option

        return packet
    
    def unpack(self) :
        self.TransactionID = self.data[4:8]
        self.mac = self.data[28:34]
        
        i = 240
        while True :
            if self.data[i] == 53 :
                self.message_type = self.data[i+2]
                i += 3
            elif self.data[i] == 55 :
                i += 2
                for j in range(i, i+self.data[i-1] ) :
                    if self.data[i] == 3 :
                        self.request_router = 1
                        i+= 1
                    elif self.data[i] == 1 :
                        self.request_subnet_mask = 1
                        i+= 1
                    elif self.data[i] == 6 :
                        self.request_DNS = 1
                        i+= 1
                    else :
                        i += 1
            elif self.data[i] == 50 :
                self.request_ip = data[i+2:i+6]
                i += 6
                
            elif self.data[i] == 255 :
               break;
            else :
                i += (self.data[i+1] + 2)
        
    def print_result(self) :
        if self.message_type == 1 :
            print ('Recive DHCPDiscover packet')
        elif self.message_type == 3 :
            print ('Recive DHCPRequest packet')


if __name__ == '__main__' :
    dhcps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)


    try:
        dhcps.bind(('192.168.17.237', 67))    #send from port 67
    except Exception as e:
        print('port 68 in use...')
        dhcps.close()
        input('press any key to quit...')
        exit()
    test = server()
    print ('\nServer is up\n')
    while True :
        while True:

            data = dhcps.recv(65535)
            test.data_init(data)
            test.unpack()
            if test.message_type:
                test.print_result()
                break

        dhcps.sendto(test.build_Offer_packet(), ('<broadcast>', 68))        
        print('DHCPOffer sent packet\n')
        while True:
            data = dhcps.recv(65535)
            test.data_init(data)
            test.unpack()
            if test.message_type:
                test.print_result()
                break

        dhcps.sendto(test.build_Ack_packet(), ('<broadcast>', 68))        
        print('DHCPAck sent packet\n')
        test.reuse_init()    

        
    
