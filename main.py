from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256


def encrypt_file(key, input_file, output_file):
    cipher = AES.new(key, AES.MODE_CBC)
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    with open(output_file, 'wb') as f:
        f.write(cipher.iv)
        f.write(ciphertext)


def decrypt_file(key, input_file, output_file):
    with open(input_file, 'rb') as f:
        iv = f.read(AES.block_size)
        ciphertext = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_text = unpad(cipher.decrypt(ciphertext), AES.block_size)

    with open(output_file, 'wb') as f:
        f.write(decrypted_text)


def main():
    key = input("Enter your password: ")
    key = SHA256.new(key.encode()).digest()
    print(f'Key ${key}')
    input_file = 'plain.txt'
    encrypted_file = 'encrypted_file.bin'
    decrypted_file = 'decrypted_file.txt'

    # Encrypt the file
    # encrypt_file(key, input_file, encrypted_file)
    # print(f'File "{input_file}" encrypted and saved as "{encrypted_file}".')

    # Decrypt the file
    decrypt_file(key, encrypted_file, decrypted_file)
    print(f'File "{encrypted_file}" decrypted and saved as "{decrypted_file}".')


if __name__ == "__main__":
    main()
