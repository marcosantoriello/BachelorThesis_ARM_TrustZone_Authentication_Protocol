from binascii import unhexlify

from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

import serial
import time
import binascii


def main():
    with open("private_key.pem", "r") as key_file:
        private_key = RSA.import_key(key_file.read())

    print('[+] Successfully read RSA private key')
    signature_verified = False

    ser = serial.Serial('COM3', 115200, bytesize=8, timeout=10)
    time.sleep(3)

    print('[*] Sending the request...')
    ser.write(b'CONNECTION REQUEST\n')

    print('[*] Waiting for the challenge...')
    time.sleep(1)
    challenge = ser.read(256)

    if len(challenge) <= 0:
        print('[-] There was an error in receiving the challenge')

    else:
        print('[+] Challenge received')
        print(challenge.decode())
        print('[*] Signing the challenge...')
        try:
            digest = SHA256.new(challenge)
            signature = pkcs1_15.new(private_key).sign(digest)
            print('[*] Sending the response...')
            time.sleep(5)
            print(len(signature))
            ser.write(signature + b'\n')

            while True:
                message = ser.read(256).decode().strip()
                print(message)
                if "Signature verified" in message:
                    signature_verified = True
                    break
                elif "Failure" in message:
                    signature_verified = False
                    break
            print(f'Signature: {signature}')

            if signature_verified:
                print('[+] Signature verified')
            else:
                print('[-] Signature verification failed')
        except (ValueError, TypeError):
            print("[-] There was an error in signing the challenge")


if __name__ == '__main__':
    main()


