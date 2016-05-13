import struct

from Crypto.Cipher import XOR

from dh import create_dh_key, calculate_dh_secret

from Crypto.Random.Fortuna import FortunaGenerator
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose

        self.shared_hash = None
        self.cipher_key = None
        self.hmac_key = None
        self.is_initialised = False
        self.sendprng = None
        self.recvprng = None

        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret

        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            self.shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(self.shared_hash))

            # TODO: PRNG using shared_secret as the seed for self.cipher_key and self.hmac_key
            # Use the shared secret as the seed for a PRNG to generate keys
            prng = FortunaGenerator.AESGenerator()
            prng.reseed(bytes(self.shared_hash, "ascii"))
            # Randomly generate a 128-bit key for hmac
            self.hmac_key = prng.pseudo_random_data(128)

        # Default XOR algorithm can only take a key of length 32
        self.cipher = XOR.new(self.shared_hash[:4])
        self.is_initialised = True

    def send(self, data):
        if self.is_initialised:
            if self.sendprng == None: #if we don't have a PRNG then make one
                # Making it out of the DH secret, which becomes the seed
                index = int(len(self.shared_hash) / 2)
                seed_a = self.shared_hash[:index]
                seed_b = self.shared_hash[index:]
                seed_a = seed_a.encode("ascii")
                seed_b = seed_b.encode("ascii")

                self.sendprng = FortunaGenerator.AESGenerator() #making the "A" PRNG
                self.sendprng.reseed(seed_a)
                self.recvprng = FortunaGenerator.AESGenerator() #making the "B" PRNG
                self.recvprng.reseed(seed_b)

            message_id = self.sendprng.pseudo_random_data(128) #starting or continuing the sequence (generating the next number in the sequence)

            hmac = HMAC.new(self.hmac_key, digestmod=SHA256)  # TODO: is SHA256 a good idea?
            hmac.update(data)

            print("First ID: {}".format(message_id))

            message = data + message_id + bytes(hmac.hexdigest(), "ascii")

            encrypted_data = self.cipher.encrypt(message)
            if self.verbose:
                print("Original data: {}".format(data))
                print("Message ID: {}".format(message_id))
                print("HMAC: {}".format(hmac.hexdigest()))
                print("Data + Message ID + HMAC: {}".format(message))
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
        if self.is_initialised: #it's in here because it's after the channel is open
            if self.sendprng == None: #if we don't have a PRNG then make one
                index = int(len(self.shared_hash) / 2)
                seed_a = self.shared_hash[:index]
                seed_b = self.shared_hash[index:]
                seed_a = seed_a.encode("ascii")
                seed_b = seed_b.encode("ascii")
                
                self.sendprng = FortunaGenerator.AESGenerator() #making the "B" PRNG
                self.sendprng.reseed(seed_b)
                self.recvprng = FortunaGenerator.AESGenerator() #making the "A" PRNG
                self.recvprng.reseed(seed_a)

            message = self.cipher.decrypt(encrypted_data)
            data = message[:-192] #gets me the message
            received_id = message[-192:-64] #gets me the packet id
            hmac_recv = message[-64:]

            # Generate the expected message_id
            message_id = self.recvprng.pseudo_random_data(128) #starting or continuing the sequence (generating the next number in the sequence)

            print("Expected ID: {}".format(message_id))

            # Generate the correct HMAC
            hmac = HMAC.new(self.hmac_key, digestmod=SHA256)
            hmac.update(data)

            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
                print("ID Received: {}".format(received_id))
                print("ID Expected: {}".format(message_id))
                print("HMAC Received: {}".format(hmac_recv))
                print("HMAC Expected: {}".format(hmac))

            if received_id == message_id: #if the id I received matches the id that was sent (is expected) then great!
                print("Message IDs match!")
                # Check if the generated and received HMACs match
                if bytes(hmac.hexdigest(), "ascii") == hmac_recv:
                    # If they do, assume the data received has not been tampered with
                    print("HMACs match!")
                else:
                    # If the HMACs don't match, discard the data and return None
                    print("HMACs don't match!")
                    data = None
            else: #otherwise it's from a bad person so delete it!
                print("Not legit, ABORT")
                data = None #get rid of the message because it's a fake!
        else:
            data = encrypted_data

        return data

    def close(self):
        self.conn.close()

