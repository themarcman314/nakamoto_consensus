from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
import numpy as np
from colorama import Fore, Back, Style

class Transaction:
    pk_sender:ec.EllipticCurvePublicKey
    pk_receiver:ec.EllipticCurvePublicKey
    amount:np.uint32
    signature:bytes

class Block:
    previous_block_hash:hashes.SHA256
    difficulty:np.uint32
    transactions:Transaction = []
    nonce:np.uint32

def main():
    sk_key1, pub_key1 = import_key_pair("keys/ecc-key.pem", "keys/ecc-public.pem")
    sk_key2, pub_key2 = import_key_pair("keys/ecc-key2.pem", "keys/ecc-public2.pem")

    new_transaction = createTransaction(sk_key1, pub_key1, pub_key2, 14)
    printTransaction(new_transaction)
    
    verifyTransaction(new_transaction, new_transaction.pk_sender)

    random_data = "Hello World!"

    random_hash = hashes.Hash(hashes.SHA256())
    random_hash.update(random_data.encode("ascii"))

    previous_block_hash = random_hash.finalize()
    
    print(f"Previous block hash :\n{previous_block_hash.hex()}")
    
    difficulty = np.uint32(4)

    transactions:Transaction = []
    transactions.append(new_transaction)

    nonce = find_nonce(previous_block_hash, difficulty, transactions)

    new_block = create_block(previous_block_hash, difficulty, nonce, transactions)
    print("\n")
    print_block(new_block)

    verify_block(previous_block_hash, new_block)





def print_block(block:Block):
    print("=================================================")
    print("=================================================")
    print("Previous block hash :\n" + Fore.CYAN + f"{block.previous_block_hash}" + Style.RESET_ALL)
    print("Difficulty :\n" + Fore.CYAN + f"{block.difficulty}" + Style.RESET_ALL)
    print("Transactions :")
    for tx in block.transactions:
        print("$   $    $    $    $    $    $    $    $    $    $")
        print(Style.NORMAL + Back.GREEN + Fore.BLACK, end="")
        printTransaction(tx)
        print(Style.RESET_ALL, end="")
        print("$   $    $    $    $    $    $    $    $    $    $")
    print("Nonce :\n" + Fore.CYAN + f"{block.nonce}" + Style.RESET_ALL)
    print("=================================================")
    print("=================================================")

def verify_block(previous_block_hash:hashes.SHA256, new_block:Block):
    serialised_tx = b''
    for tx in new_block.transactions:
        serialised_tx += serialize_transaction(tx)
    block = new_block.previous_block_hash + int(new_block.difficulty).to_bytes(4, byteorder='big') + serialised_tx + int(new_block.nonce).to_bytes(4, byteorder='big')
    digest = hashes.Hash(hashes.SHA256()) 
    digest.update(block)
    hashed_block = digest.finalize()
    hashed_block_hex = hashed_block.hex()

    print("Block hash :\n" + Fore.CYAN + f"{hashed_block_hex}" + Style.RESET_ALL)
    if hashed_block_hex.startswith('0' * new_block.difficulty):
        print(Fore.GREEN + "✅ Proof of work is verified!" + Style.RESET_ALL)
    else:
        print(Fore.RED + "Proof of work is did not verified" + Fore.RESET_ALL)



def create_block(previous_block_hash:hashes.SHA256, difficulty:np.uint32, nonce:np.uint32, transactions:Transaction = [])->Block:
    block = Block()
    block.previous_block_hash = previous_block_hash
    block.difficulty = difficulty
    block.transactions = transactions
    block.nonce = nonce
    return block

def find_nonce(previous_block_hash:hashes.SHA256, difficulty:np.uint32, transactions:Transaction = [])->np.uint32:
    print("\n\n")
    found = 0
    nonce = np.uint32(0)
    serialised_tx = b''
    for tx in transactions:
        serialised_tx += serialize_transaction(tx)
    while(found == 0):
        block = previous_block_hash + int(difficulty).to_bytes(4, byteorder='big') + serialised_tx + int(nonce).to_bytes(4, byteorder='big')
        digest = hashes.Hash(hashes.SHA256()) 
        digest.update(block)
        hashed_block = digest.finalize()
        hashed_block_hex = hashed_block.hex()
        #print(hashed_block_hex)
        if hashed_block_hex.startswith('0' * difficulty):
            print(Fore.RED + "found nonce!" + Style.RESET_ALL)
            print(Fore.YELLOW + f"nonce : {nonce}" + Style.RESET_ALL)
            print(hashed_block_hex)
            return nonce
        nonce += 1


def serialize_transaction(tx: Transaction) -> bytes:
    # Serialize public keys
    pk_sender_bytes = tx.pk_sender.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    pk_receiver_bytes = tx.pk_receiver.public_bytes(encoding=serialization.Encoding.DER,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    # Serialize amount (unsigned 32-bit integer)
    amount_bytes = int(tx.amount).to_bytes(4, byteorder='big')
    
    return pk_sender_bytes + pk_receiver_bytes + amount_bytes + tx.signature
    


def import_key_pair(path_private_key:str, path_public_key:str):
    # Load the private key from a PEM file
    with open(path_private_key, "rb") as key_file:
        private_key = load_pem_private_key(
            key_file.read(),
            password=None  # Use a password if the key is encrypted
        )
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        print(Fore.GREEN + "✅ Private key imported successfully" + Style.RESET_ALL)
    else: print(Fore.RED + "❌ Problem importing Private key" + Style.RESET_ALL)

    with open(path_public_key, "rb") as key_file:
        public_key = load_pem_public_key(key_file.read())
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        print(Fore.GREEN + "✅ Public key imported successfully\n" + Style.RESET_ALL)
    else: print(Fore.RED + "❌ Problem importing Public key\n" + Style.RESET_ALL)

    return private_key, public_key





def createTransaction(sk_sender:ec.EllipticCurvePrivateKey, pk_sender:ec.EllipticCurvePublicKey, pk_receiver:ec.EllipticCurvePublicKey, amount:int)->Transaction:

    new_transaction = Transaction()

    pk_sender_bytes = pk_sender.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    pk_receiver_bytes = pk_sender.public_bytes(encoding=serialization.Encoding.DER,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    message = pk_sender_bytes + pk_receiver_bytes + amount.to_bytes(4, 'big')

    new_transaction.pk_sender = pk_sender
    new_transaction.pk_receiver = pk_receiver
    new_transaction.amount = amount
    
    new_transaction.signature = sk_sender.sign(
       message,
       ec.ECDSA(hashes.SHA256()))

    new_transaction.signature = b'\x00' * 70 # dummy signature
    return new_transaction

def printTransaction(my_transaction:Transaction):
    pk_sender_pem = my_transaction.pk_sender.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pk_receiver_pem = my_transaction.pk_receiver.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print("pk sender : \n" + f"{pk_sender_pem}\n")
    print("pk receiver : \n" + f"{pk_receiver_pem}\n")
    print("transaction amount :\n" + f"{my_transaction.amount}\n")
    print("signature : \n" + f"{my_transaction.signature}")

def verifyTransaction(transaction:Transaction, pk_sender:ec.EllipticCurvePublicKey):
    pk_sender:ec.EllipticCurvePublicKey
    pk_receiver:ec.EllipticCurvePublicKey
    amount:int
    signature:bytes

    pk_sender_bytes = transaction.pk_sender.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    pk_receiver_bytes = transaction.pk_sender.public_bytes(encoding=serialization.Encoding.DER,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    data = pk_sender_bytes + pk_receiver_bytes + transaction.amount.to_bytes(4, 'big')

    try:
        pk_sender.verify(transaction.signature, data, ec.ECDSA(hashes.SHA256()))
        print(Fore.GREEN + "✅ Signature is valid!" + Style.RESET_ALL)
    except Exception as e:
        print(f"❌ Signature verification failed: {e}")


if __name__ == "__main__":
    main()
