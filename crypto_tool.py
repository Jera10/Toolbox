import argparse
import os
import sys
from cryptography.fernet import Fernet

def load_key(key_file):
    try:
        with open(key_file, 'rb') as f:
            key = f.read()
        return key
    except FileNotFoundError:
        print(f"Nyckelfilen '{key_file}' hittades inte.")
        sys.exit(1)
        
        
def encrypt_file(key, filename):
    # Initialiserar Fernet med den givna nyckeln
    fernet = Fernet(key)
    # Läser in originalfilen
    with open(filename, 'rb') as file:
        original = file.read()
    # Krypterar data
    encrypted = fernet.encrypt(original)
    # Sparar den krypterade datan i en ny fil
    encrypted_filename = filename + '.encrypted'
    with open(encrypted_filename, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)
    # Tar bort originalfilen
    os.remove(filename)
    print(f"Originalfilen '{filename}' har krypterats och tagits bort. Krypterad fil sparad som '{encrypted_filename}'.")



def decrypt_file(key, filename):
    # Initialiserar Fernet med den givna nyckeln
    fernet = Fernet(key)
    # Läser in den krypterade filen
    with open(filename, 'rb') as encrypted_file:
        encrypted = encrypted_file.read()
    # Dekrypterar data
    decrypted = fernet.decrypt(encrypted)
    # Återställer originalfilnamnet
    original_filename = filename.replace('.encrypted', '')
    # Sparar den dekrypterade datan i originalfilen
    with open(original_filename, 'wb') as decrypted_file:
        decrypted_file.write(decrypted)
    # Tar bort den krypterade filen
    os.remove(filename)
    print(f"Krypterade filen '{filename}' har dekrypterats och tagits bort. Originalfilen återställd som '{original_filename}'.")


def main():
    # Skapar huvudparsern
    parser = argparse.ArgumentParser(description='Kryptera eller dekryptera filer med en symmetrisk nyckel.')
    subparsers = parser.add_subparsers(dest='command', help='Kommandon')

    # Parser för "encrypt"-kommandot
    encrypt_parser = subparsers.add_parser('encrypt', help='Kryptera en fil')
    encrypt_parser.add_argument('-f', '--file', required=True, help='Fil att kryptera')
    encrypt_parser.add_argument('-k', '--key', required=True, help='Nyckelfil')

    # Parser för "decrypt"-kommandot
    decrypt_parser = subparsers.add_parser('decrypt', help='Dekryptera en fil')
    decrypt_parser.add_argument('-f', '--file', required=True, help='Fil att dekryptera')
    decrypt_parser.add_argument('-k', '--key', required=True, help='Nyckelfil')

    # Parserar argumenten
    args = parser.parse_args()

    if args.command == 'encrypt':
        # Laddar nyckeln och krypterar filen
        key = load_key(args.key)
        encrypt_file(key, args.file)
    elif args.command == 'decrypt':
        # Laddar nyckeln och dekrypterar filen
        key = load_key(args.key)
        decrypt_file(key, args.file)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
