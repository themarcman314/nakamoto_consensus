import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import ec
from colorama import Fore, Back, Style


class Wallet:
    # Creates wallet and saves pk and sk in wallet dir
    def __init__(self):
        self.sk = ec.generate_private_key(ec.SECP256K1())
        self.pk = self.sk.public_key()

    def serialize(self):
        sk_pem = self.sk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        pk_pem = self.pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return sk_pem, pk_pem

    def save(self, file_name):

        sk_pem, pk_pem = self.serialize()

        # Create the directory
        try:
            os.mkdir("wallet")
            print(f"Wallet dir created successfully.")
        except FileExistsError:
            print(f"Wallet dir already exists.")
        except PermissionError:
            print(f"Permission denied: Unable to create wallet dir.")
        except Exception as e:
            print(f"An error occurred: {e}")

        with open("./wallet/" + file_name + "_sk.pem", "w") as sk_file:
            sk_file.write(sk_pem.decode('utf-8'))

        with open("./wallet/" + file_name + "_pk.pem", "w") as pk_file:
            pk_file.write(pk_pem.decode('utf-8'))


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
