from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from colorama import Fore, Back, Style
import numpy as np
import time
import wallet

class Transaction:
    def __init__(self, pk_sender: ec.EllipticCurvePublicKey, 
             pk_receiver: ec.EllipticCurvePublicKey, 
             amount: int):
        self.pk_sender = pk_sender
        self.pk_receiver = pk_receiver
        self.amount = np.uint32(amount)
        self.signature = b''
        print("Creating new transaction...")
    

    def serialize(self) -> bytes:
        pk_sender_bytes = self.pk_sender.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pk_receiver_bytes = self.pk_receiver.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pk_sender_bytes + pk_receiver_bytes + int(self.amount).to_bytes(4, 'big')


    def serialize_signed(self) -> bytes:
        return self.serialize() + self.signature


    def sign(self, sk_sender: ec.EllipticCurvePrivateKey):
        # Use ECDSA to sign the message
        message = self.serialize()
        self.signature = sk_sender.sign(message, ec.ECDSA(hashes.SHA256()))
        #self.signature = b'\x00' * 70 # dummy signature


    def verify(self):
        message = self.serialize()
        try:
            self.pk_sender.verify(self.signature, message, ec.ECDSA(hashes.SHA256()))
            print(Fore.GREEN + "✅ Signature is valid!" + Style.RESET_ALL)
            return True
        except Exception as e:
            print(Fore.RED + f"❌ Signature verification failed: {e}" + Style.RESET_ALL)
            return False

    def __str__(self) -> str:
        return (f"Sender: {self.pk_sender.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()}\n"
                f"Receiver: {self.pk_receiver.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()}\n"
                f"Amount: {self.amount}\n"
                f"Signature: {self.signature.hex()}\n")

class Block:
    def __init__(self, previous_hash: bytes, difficulty: int, transactions: list):
        self.previous_hash = previous_hash
        self.difficulty = difficulty  # Represented as an integer
        self.transactions = transactions  # List of Transaction objects
        self.nonce = 0

    def compute_hash(self) -> bytes:
        serialised_tx = b''.join([tx.serialize_signed() for tx in self.transactions])
        # Combine block attributes into a single byte string
        block_content = (self.previous_hash +
                         self.difficulty.to_bytes(4, byteorder='big') +
                         serialised_tx +
                         self.nonce.to_bytes(4, byteorder='big'))
        digest = hashes.Hash(hashes.SHA256())
        digest.update(block_content)
        return digest.finalize()

    def has_valid_proof(self) -> bool:
        block_hash = self.compute_hash().hex()
        return block_hash.startswith('0' * self.difficulty)

    def mine(self):
        print("Starting mining...")
        # Pre-compute the constant part outside the loop
        serialized_tx = b''.join([tx.serialize_signed() for tx in self.transactions])
        constant_part = (self.previous_hash +
                         self.difficulty.to_bytes(4, byteorder='big') +
                         serialized_tx)

        start_time = time.time()
        iterations = 0
        while True:
            # Only update the nonce portion for each iteration
            block_content = constant_part + self.nonce.to_bytes(4, byteorder='big')
            digest = hashes.Hash(hashes.SHA256())
            digest.update(block_content)
            current_hash = digest.finalize().hex()
            iterations+=1

            if iterations % 1000000 == 0:
                elapsed = time.time() - start_time
                hashrate = iterations / elapsed
                print(f"Current hashrate: {hashrate:.0f} hashes/sec")

            if current_hash.startswith('0' * self.difficulty):
                print(f"Nonce found: {self.nonce}")
                print(f"Block hash: {current_hash}")
                elapsed = time.time() - start_time
                print(f"Found block in {elapsed:.2f} seconds")
                break
            self.nonce += 1


    def __str__(self) -> str:
        tx_details = "\n".join([str(tx) for tx in self.transactions])
        return (f"Previous Hash: {self.previous_hash.hex()}\n"
                f"Difficulty: {self.difficulty}\n"
                f"Transactions:\n{tx_details}\n"
                f"Nonce: {self.nonce}\n"
                f"Block Hash: {self.compute_hash().hex()}\n")

def main():
    
    w = wallet.Wallet()
    w.save("something")
    


    sk_key1, pub_key1 = wallet.import_key_pair("wallet/ecc-key.pem", "wallet/ecc-public.pem")
    sk_key2, pub_key2 = wallet.import_key_pair("wallet/ecc-key2.pem", "wallet/ecc-public2.pem")

    t1 = Transaction(pub_key1, pub_key2, 3)
    t1.sign(sk_key1)
    print(t1)
    t1.verify()

    random_data = "Hello World!"
    random_hash = hashes.Hash(hashes.SHA256())
    random_hash.update(random_data.encode("ascii"))
    previous_block_hash = random_hash.finalize()

    b1 = Block(previous_block_hash, 4, [t1])
    print("\n\n")
    #print(b1)
    b1.mine()

    if(b1.has_valid_proof() == True):
       print(Fore.GREEN + "✅ Nonce is valid!" + Style.RESET_ALL)
    else:
        print(Fore.RED + "❌ Nonce is not valid" + Style.RESET_ALL)

    t2 = Transaction(pub_key1, pub_key2, 54)
    t2.sign(sk_key1)
    t2.verify()

    t3 = Transaction(pub_key1, pub_key2, 4)
    t3.sign(sk_key1)
    t3.verify()

    t4 = Transaction(pub_key1, pub_key2, 23)
    t4.sign(sk_key1)
    t4.verify()

    transactions = []
    transactions.append(t2)
    transactions.append(t3)
    transactions.append(t4)

    b2 = Block(b1.compute_hash(), 4, transactions)
    print("\n\n")
    #print(b1)
    b2.mine()

    if(b2.has_valid_proof() == True):
       print(Fore.GREEN + "✅ Nonce is valid!" + Style.RESET_ALL)
    else:
        print(Fore.RED + "❌ Nonce is not valid" + Style.RESET_ALL)


if __name__ == "__main__":
    main()
