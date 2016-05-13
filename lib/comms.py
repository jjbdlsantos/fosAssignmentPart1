import struct

from Crypto.Cipher import XOR

from dh import create_dh_key, calculate_dh_secret
from Crypto import Random
from Crypto.Random.Fortuna import FortunaGenerator

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.sendprng = None
        self.recvprng = None
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret

        ### TODO: Your code here!
        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(shared_hash))

        # Default XOR algorithm can only take a key of length 32
        self.cipher = XOR.new(shared_hash[:4])

    def send(self, data):
        
        if self.cipher:
            if self.sendprng == None: #if we don't have a PRNG then make one
                DHString = str(shared_secret) #making it out of this, which becomes the seed
                A, B = DHString[:len(DHString)/2], DHString[len(DHString)/2:]
                A = A.encode("ascii")
                B = B.encode("ascii")
                
                self.sendprng = FortunaGenerator.AESGenerator() #making the "A" PRNG
                self.sendprng.reseed(A)
                self.recvprng = FortunaGenerator.AESGenerator() #making the "B" PRNG
                self.recvprng.reseed(B)

            packet_id = self.sendprng.pseudo_random_data(128) #starting or continuing the sequence (generating the next number in the sequence)
            data = data + packet_id
            
            encrypted_data = self.cipher.encrypt(data)
            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def recv(self):
            
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        encrypted_data = self.conn.recv(pkt_len)
        if self.cipher: #it's in here because it's after the channel is open
            if self.sendprng == None: #if we don't have a PRNG then make one
                DHString = str(shared_secret) #making it out of this, which becomes the seed
                A, B = DHString[:len(DHString)/2], DHString[len(DHString)/2:]
                A = A.encode("ascii")
                B = B.encode("ascii")
                
                self.sendprng = FortunaGenerator.AESGenerator() #making the "B" PRNG
                self.sendprng.reseed(B)
                self.recvprng = FortunaGenerator.AESGenerator() #making the "A" PRNG
                self.recvprng.reseed(A)

            packet_id = self.sendprng.pseudo_random_data(128) #starting or continuing the sequence (generating the next number in the sequence)

            data = self.cipher.decrypt(encrypted_data)
            data = data[:-128] #gets me the message
            received_id = data[-128:] #gets me the packet id

            if received_id == packet_id: #if the id I received matches the id that was sent (is expected) then great!
                print("Legit")

            else: #otherwise it's from a bad person so delete it!
                print("Not legit, ABORT")
                data = None #get rid of the message because it's a fake!
            
            
            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data

        return data

    def close(self):
        self.conn.close()
