from cryptography.fernet import Fernet

def generate_key():
    # Genererar en nyckel för kryptering
    key = Fernet.generate_key()
    # Sparar nyckeln i en fil
    with open('key.key', 'wb') as key_file:
        key_file.write(key)
    print("Nyckel genererad och sparad i 'key.key'.")

if __name__ == '__main__':
    generate_key()
