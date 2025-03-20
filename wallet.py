from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import ec
from colorama import Fore, Back, Style

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
