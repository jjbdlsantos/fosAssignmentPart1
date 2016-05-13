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

        self.cipher_key = None
        self.hmac_key = None

        # Flag indicating if a session has been initiated
        self.is_initialised = False

        # PRNG used to generate unique IDs for each message sent
        self.send_prng = None
        # PRNG used to generate the expected ID for a received message
        self.recv_prng = None

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
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(shared_hash))

            self.generate_keys(shared_hash)
            self.initialise_prngs(shared_hash)

        # Default XOR algorithm can only take a key of length 32
        self.cipher = XOR.new(shared_hash[:4])
        self.is_initialised = True

    def send(self, data):
        if self.is_initialised:
            # Generate a random number for the message ID
            message_id = self.send_prng.pseudo_random_data(128)
            # Calculate the HMAC
            hmac = HMAC.new(self.hmac_key, digestmod=SHA256)  # TODO: is SHA256 a good idea?
            hmac.update(data)
            # Add the ID and HMAC to the message
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

        if self.is_initialised:
            message = self.cipher.decrypt(encrypted_data)

            # Split the message back into its component parts (data, ID and HMAC)
            data = message[:-192] #gets me the message
            received_id = message[-192:-64] #gets me the packet id
            hmac_recv = message[-64:]

            # Generate the expected message_id
            message_id = self.recv_prng.pseudo_random_data(128) #starting or continuing the sequence (generating the next number in the sequence)
            # Generate the HMAC for the received data
            hmac = HMAC.new(self.hmac_key, digestmod=SHA256)
            hmac.update(data)

            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
                print("ID Received: {}".format(received_id))
                print("ID Expected: {}".format(message_id))
                print("HMAC Received: {}".format(hmac_recv))
                print("HMAC Expected: {}".format(hmac.hexdigest()))

            # Check if the expected and received message IDs match
            if received_id == message_id:
                # If they do, the message is not a replay
                print("Message IDs match!")

                # Check if the generated and received HMACs match
                if bytes(hmac.hexdigest(), "ascii") == hmac_recv:
                    # If they do, assume the data received has not been tampered with
                    print("HMACs match!")
                else:
                    # If the HMACs don't match, discard the data and return an error
                    print("HMACs don't match!")
                    data = "Error! HMACs don't match."
            else:
                # If the IDs don't match, discard the data and return an error
                print("Message IDs don't match!")
                data = "Error! IDs don't match."
        else:
            data = encrypted_data

        return data

    def close(self):
        self.conn.close()

    def generate_keys(self, seed):
        # Randomly generate keys for AES and HMAC

        # Create and seed the PRNG
        prng = FortunaGenerator.AESGenerator()
        prng.reseed(seed.encode("ascii"))

        # TODO: Randomly generate a 128-bit key for AES

        # Randomly generate a 128-bit key for HMAC
        self.hmac_key = prng.pseudo_random_data(128)

    def initialise_prngs(self, seed):
        # Initialise the PRNGs to use for generating the message IDs for messages sent and
        # determining the expected message ID for messages received (used to prevent replay attacks)

        # Split shared_secret into two halves to use as seeds
        index = int(len(seed) / 2)
        seed_a = seed[:index]
        seed_b = seed[index:]
        seed_a = seed_a.encode("ascii")
        seed_b = seed_b.encode("ascii")

        # Create and seed the PRNGs
        prng_a = FortunaGenerator.AESGenerator()
        prng_a.reseed(seed_b)
        prng_b = FortunaGenerator.AESGenerator()
        prng_b.reseed(seed_a)

        # Assign the PRNGs depending on if it's a server or a client
        if self.server:
            self.send_prng = prng_a
            self.recv_prng = prng_b
        else:
            self.send_prng = prng_b
            self.recv_prng = prng_a

