#!/usr/bin/env python3
import socket
import telnetlib

def xor_hexstrings(xs, ys):
    #print(xs, ys)
    xs = bytes.fromhex(xs)
    ys = bytes.fromhex(ys)
    result = bytes( [(x ^ y) for x, y in zip(xs, ys)] )
    return result

if __name__ == '__main__':
    s = socket.socket()
    s.connect(('34.124.157.94', 10590))
    t = telnetlib.Telnet()
    t.sock = s

    # Enter plaintext
    print(t.read_until(b':'))
    t.write(b'00'*40 + b'\n')

    # Receive ciphertexts
    ciphertexts = []
    for i in range(256):
        print(t.read_until(b':'))
        ciphertext = t.read_until(b'\n').decode().strip()
        ciphertexts.append(ciphertext)
        print(">>>", ciphertext)

    # Receive cipher-flag
    print(t.read_until(b'Flag:'))
    cipherflag = t.read_until(b'\n').decode().strip()
    print(">>>", cipherflag)

    # Try to decrypt
    for i, ct in enumerate(ciphertexts):
        plaintext = xor_hexstrings(cipherflag, ct)
        print(i, "**", plaintext)

        if b'grey' in plaintext:
            quit()
