from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

#class Transaction:
#    pk_sender
#    pk_receiver
#    amount:int
#    signature:bytes

#class Block:
    #header
    #transactions[]:Transaction
    #footer



def main():
    message = b"Hello World!"
    pr_key1, pub_key1 = import_key_pair("keys/ecc-key.pem", "keys/ecc-public.pem")

    # Sign the message using the private key of the sender
    




def import_key_pair(path_private_key:str, path_public_key:str):
    # Load the private key from a PEM file
    with open(path_private_key, "rb") as key_file:
        private_key = load_pem_private_key(
            key_file.read(),
            password=None  # Use a password if the key is encrypted
        )
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        print("Private key imported successfully")
    else: print("Problem importing Private key")

    with open(path_public_key, "rb") as key_file:
        public_key = load_pem_public_key(key_file.read())
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        print("Public key imported successfully")
        print(type(ec.EllipticCurvePublicKey))
    else: print("Problem importing Public key")

    return private_key, public_key





    #def createTransaction(pk_sender:EllipticCurvePublicKey, pk_receiver:EllipticCurvePublicKey, amount:int):
    #     pk_sender = pk_sender
    #     pk_receiver = pk_receiver
    #     amount:int = amount
    # 
    #     public_bytes = public_key.public_bytes(
    #         encoding=serialization.Encoding.DER,  # Use DER for raw bytes
    #         format=serialization.PublicFormat.SubjectPublicKeyInfo
    #     )
    #     print(public_bytes)  # Prints as b"..."
    # 
    # 
    #     #message = 
    # 
    # 
    # 
    #     signature:int = pr_key1.sign(
    #         message,
    #         ec.ECDSA(hashes.SHA256()))
    #     print(f"Signature: {signature.hex()}")
 






if __name__ == "__main__":
    main()
