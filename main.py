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
    nounce:np.uint32

def main():
    sk_key1, pub_key1 = import_key_pair("keys/ecc-key.pem", "keys/ecc-public.pem")
    sk_key2, pub_key2 = import_key_pair("keys/ecc-key2.pem", "keys/ecc-public2.pem")

    new_transaction = createTransaction(sk_key1, pub_key1, pub_key2, 2)
    printTransaction(new_transaction)
    
    verifyTransaction(new_transaction, new_transaction.pk_sender)

    random_data = "Hello World!"

    random_hash = hashes.Hash(hashes.SHA256())
    random_hash.update(random_data.encode("ascii"))

    previous_block = random_hash.finalize()
    
    print(f"Previous block hash : \n{previous_block.hex()}")
    
    difficulty = np.uint32(3)

    transactions:Transaction = []
    transactions.append(new_transaction)

    find_nounce(previous_block, difficulty, transactions)


def find_nounce(previous_block_hash:hashes.SHA256, difficulty:np.uint32, transactions:Transaction = [])->Block:
    nounce = 0
    #block = previous_block_hash + difficulty.tobytes() + transactions + 


    


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

    print("pk sender : \n" + Fore.CYAN + f"{pk_sender_pem}\n" + Style.RESET_ALL)
    print("pk receiver : \n" + Fore.CYAN + f"{pk_receiver_pem}\n" + Style.RESET_ALL)
    print(Fore.MAGENTA + f"transaction amount : {my_transaction.amount}\n" + Style.RESET_ALL)
    print("signature : \n" + Fore.CYAN + f"{my_transaction.signature}\n" + Style.RESET_ALL)

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
