import socket
import struct
from uuid import getnode as get_mac
from random import randint

class client:
    def __init__(self):
        self.TransactionID = b"" #identifier
        for i in range(0, 4) :
            num = randint(0, 255)
            self.TransactionID += struct.pack('!B', num)

        self.mac = b""
        
        #get mac address
        tmp = (bin(get_mac()))
        tmp = tmp[2:] #mac[0:1] = \b
        while len(tmp) < 48 :
            tmp = '0' + tmp
        for i in range(0, 12, 2) : #pack :
            j = int(tmp[i:i+2], 16)
            self.mac += struct.pack('!B', j)

        self.message_type = ''
        self.your_ip = ''
        self.next_server = ''
        self.dhcp_server = ''
        self.lease_time = ''
        self.router = ''
        self.DNS = []
        self.subnet_mask = ''
    def data_init(self, data):
        self.data = data

    def build_Discover_packet(self) : #generate packet
        print('\n*** Send DHCPDiscover packet ***\n')
        packet = b''
        packet += b'\x01' #op 1 -> send to server
        packet += b'\x01' #htype 1 -> ethernet
        packet += b'\x06' #hlen 6 -> ethernet
        packet += b'\x00' #hops
        packet += self.TransactionID  #xid
        packet += b'\x00\x00' #secs
        packet += b'\x80\x00' #flags 8 -> brocast
        packet += b'\x00\x00\x00\x00' #ciaddr client ip
        packet += b'\x00\x00\x00\x00' #yiaddr your ip
        packet += b'\x00\x00\x00\x00' #siaddr server ip
        packet += b'\x00\x00\x00\x00' #giaddr relay agent or 0
        packet += self.mac     #chaddr Hardware addr
        packet += b'\x00'*10 #rest chaddr
        packet += b'\x00'*64 #sname
        packet += b'\x00'*128 #file
        packet += b'\x63\x82\x53\x63' #magic cookie
        packet += b'\x35\x01\x01' #option = 53 len = 1 message type = 1 (discover) l
        packet += b'\x37\x03\x03\x01\x06'
        packet += b'\xff' #end option
        
        return packet

    def build_Request_packet(self) : #generate packet
        print('\n*** Send DHCPRequest packet ***\n')
        packet = b''
        packet += b'\x01' #op 1 -> send to server
        packet += b'\x01' #htype 1 -> ethernet
        packet += b'\x06' #hlen 6 -> ethernet
        packet += b'\x00' #hops
        packet += self.TransactionID  #xid
        packet += b'\x00\x00' #secs
        packet += b'\x80\x00' #flags 8 -> brocast
        packet += self.your_ip #ciaddr client ip
        packet += b'\x00\x00\x00\x00' #yiaddr your ip
        packet += b'\x00\x00\x00\x00' #siaddr server ip
        packet += b'\x00\x00\x00\x00' #giaddr relay agent or 0
        packet += self.mac     #chaddr Hardware addr
        packet += b'\x00'*10 #rest chaddr
        packet += b'\x00'*64 #sname
        packet += b'\x00'*128 #file
        packet += b'\x63\x82\x53\x63' #magic cookie
        packet += b'\x35\x01\x03' #option = 53 len = 1 message type = 3 (request) l
        packet += b'\x36\x04' + self.dhcp_server
        packet += b'\x32\x04' + self.your_ip
        packet += b'\xff' #end option
        
        return packet
        
    
    def unpack(self) :
        print('Got packet')
        print('Unpack...\n')
        if data[4:8] == self.TransactionID :
            self.message_type = self.data[0]
            self.your_ip = self.data[16:20]
            self.next_server = self.data[20:24]

            i = 240
            while True :
                if self.data[i] == 53 :
                    self.message_type = self.data[i+2]
                    i += 3
                elif self.data[i] == 51 :
                    self.lease_time = self.data[i+2:i+6]
                    i += 6
                elif self.data[i] == 54 :
                    self.dhcp_server = self.data[i+2:i+6]
                    i += 6
                elif self.data[i] == 3 :
                    self.router = self.data[i+2:i+6]
                    i+= 6
                elif self.data[i] == 1 :
                    self.subnet_mask = self.data[i+2:i+6]
                    i+= 6
                elif self.data[i] == 6 :
                    num = int(self.data[i+1]/4)
                    for j in range (0, 4*num, 4) :
                        self.DNS.append(self.data[i+j+2:i+j+6])
                        i += ( 2 + self.data[i+1])
                elif self.data[i] == 255 :
                    break;
                else :
                    i += (self.data[i+1] + 2)
                    
                   
    def print_result (self) :
        if self.message_type == 2 :
            print ('This is a DHCPOffer packet.\n')
            print ('Offer IP :' + str(self.your_ip[0]) + '.' + str(self.your_ip[1]) + '.' + str(self.your_ip[2]) + '.' + str(self.your_ip[3]))
            print ('DHCP Server :' + str(self.dhcp_server[0]) + '.' +  str(self.dhcp_server[1]) + '.' + str(self.dhcp_server[2]) + '.' + str(self.dhcp_server[3]))                                                                                                         
            print ('Subnet mask :' + str(self.subnet_mask[0]) + '.' +  str(self.subnet_mask[1]) + '.' + str(self.subnet_mask[2]) + '.' + str(self.subnet_mask[3]))
            print ('Lease time :' + str(struct.unpack('!L', self.lease_time)[0]))
            print ('Default gateway :' + str(self.router[0]) + '.' + str(self.router[1]) + '.' + str(self.router[2]) + '.' + str(self.router[3]))
            print ('DNS server :')
            if len(self.DNS) :
                print (str(self.DNS[0][0]) + '.' + str(self.DNS[0][1]) + '.' + str(self.DNS[0][2]) + '.' + str(self.DNS[0][3]))
            else :
                for i in range (0, len(self.DNS)) :
                    print (str(self.DNS[i][0]) + '.' + str(self.DNS[i][1]) + '.' + str(self.DNS[i][2]) + '.' + str(self.DNS[i][3]) + ', ')
        elif self.message_type == 5 :
            print ('This is a DHCPAck packet.\n')
            print ('Offer IP :' + str(self.your_ip[0]) + '.' + str(self.your_ip[1]) + '.' + str(self.your_ip[2]) + '.' + str(self.your_ip[3]))
            print ('DHCP Server :' + str(self.dhcp_server[0]) + '.' +  str(self.dhcp_server[1]) + '.' + str(self.dhcp_server[2]) + '.' + str(self.dhcp_server[3]))                                                                                                         
            print ('Subnet mask :' + str(self.subnet_mask[0]) + '.' +  str(self.subnet_mask[1]) + '.' + str(self.subnet_mask[2]) + '.' + str(self.subnet_mask[3]))
            print ('Lease time :' + str(struct.unpack('!L', self.lease_time)[0]))
            print ('Default gateway :' + str(self.router[0]) + '.' + str(self.router[1]) + '.' + str(self.router[2]) + '.' + str(self.router[3]))
            print ('DNS server :')
            if len(self.DNS) :
                print (str(self.DNS[0][0]) + '.' + str(self.DNS[0][1]) + '.' + str(self.DNS[0][2]) + '.' + str(self.DNS[0][3]))
            else :
                for i in range (0, len(self.DNS)) :
                    print (str(self.DNS[i][0]) + '.' + str(self.DNS[i][1]) + '.' + str(self.DNS[i][2]) + '.' + str(self.DNS[i][3]) + ', ')
if __name__ == '__main__':
    dhcps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    try:
        dhcps.bind(('192.168.17.237', 68))    #send from port 68  
    except Exception as e:
        print('port 68 in use...')
        dhcps.close()
        input('press any key to quit...')
        exit()

    test = client()
    dhcps.sendto(test.build_Discover_packet(), ('<broadcast>', 67))
    print('DHCPDiscover sent packet\n')

    #receiving DHCPOffer packet  
    dhcps.settimeout(3)
    try:
        while True:
            data = dhcps.recv(65535)
            test.data_init(data)
            test.unpack()
            if test.message_type:
                test.print_result()
                break
    except socket.timeout as e:
        print(e)

    dhcps.sendto(test.build_Request_packet(), ('<broadcast>', 67))


    print('DHCPRequest sent packet\n')
    #receiving DHCPAck packet  
    dhcps.settimeout(3)
    try:
        while True:
            data = dhcps.recv(65535)
            test.data_init(data)
            test.unpack()
            if test.message_type:
                test.print_result()
                break
    except socket.timeout as e:
        print(e)

        
    dhcps.close()   #close the socket
    
    exit()
