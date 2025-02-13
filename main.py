from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

class Transaction:
    pk_sender:ec.EllipticCurvePublicKey
    pk_receiver:ec.EllipticCurvePublicKey
    amount:int
    signature:bytes

#class Block:
    #header
    #transactions[]:Transaction
    #footer

def main():
    message = b"Hello World!"
    sk_key1, pub_key1 = import_key_pair("keys/ecc-key.pem", "keys/ecc-public.pem")
    sk_key2, pub_key2 = import_key_pair("keys/ecc-key2.pem", "keys/ecc-public2.pem")

    new_transaction = createTransaction(sk_key1, pub_key1, pub_key2, 2)
    printTransaction(new_transaction)
    
    verifyTransaction(new_transaction, new_transaction.pk_sender)



def import_key_pair(path_private_key:str, path_public_key:str):
    # Load the private key from a PEM file
    with open(path_private_key, "rb") as key_file:
        private_key = load_pem_private_key(
            key_file.read(),
            password=None  # Use a password if the key is encrypted
        )
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        print("✅ Private key imported successfully")
    else: print("❌ Problem importing Private key")

    with open(path_public_key, "rb") as key_file:
        public_key = load_pem_public_key(key_file.read())
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        print("✅ Public key imported successfully\n")
    else: print("❌ Problem importing Public key\n")

    return private_key, public_key





def createTransaction(sk_sender:ec.EllipticCurvePrivateKey, pk_sender:ec.EllipticCurvePublicKey, pk_receiver:ec.EllipticCurvePublicKey, amount:int):

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
    print(f"pk sender : {my_transaction.pk_sender}\n")
    print(f"pk receiver : {my_transaction.pk_receiver}\n")
    print(f"transaction amount : {my_transaction.amount}\n")
    print(f"signature : {my_transaction.signature}\n")

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
        print("✅ Signature is valid!")
    except Exception as e:
        print(f"❌ Signature verification failed: {e}")


    

if __name__ == "__main__":
    main()
