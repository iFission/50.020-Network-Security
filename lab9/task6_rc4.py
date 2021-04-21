import binascii
import struct


def KSA(key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    return S


def PRGA(S):
    K = 0
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        yield K


def RC4(key):
    S = KSA(key)
    return PRGA(S)


def crack_rc4(key, ciphertext):
    ## Use RC4 to generate keystream
    keystream = RC4(key)
    # print(keystream)

    # ## Cracking the ciphertext
    plaintext = ""
    for i in ciphertext:
        plaintext += ('{:02X}'.format(i ^ next(keystream)))

    return plaintext


if __name__ == '__main__':
    pass
    # RC4 algorithm please refer to http://en.wikipedia.org/wiki/RC4

    ## key = a list of integer, each integer 8 bits (0 ~ 255)
    ## ciphertext = a list of integer, each integer 8 bits (0 ~ 255)
    ## binascii.unhexlify() is a useful function to convert from Hex string to integer list

    # using SN=2000
    IV = "46bcf4"
    key = "1F1F1F1F1F"
    ICV_encrypted = "8ba2536e"
    cipher_data = "98999de0ce2db11eb2169a5d442143cdd0470a8832f6712745fb4ffacdcc9ff99681c1da2f8c479ef446300eaa68aaca018b6a0a985c" + ICV_encrypted

    plain_data_with_crc = crack_rc4(binascii.unhexlify(IV + key),
                                    binascii.unhexlify(cipher_data))

    print("plain_data_with_crc:", plain_data_with_crc)

    CRC_recovered = plain_data_with_crc[-len(ICV_encrypted):]
    print("CRC_recovered:", CRC_recovered)
    plain_data = plain_data_with_crc[:-len(ICV_encrypted)]
    print("plain_data:", plain_data)

    CRC_calculated = struct.pack(
        '<L',
        binascii.crc32(bytes.fromhex(plain_data)) & 0xfffffffff).hex()
    print("CRC_calculated:", CRC_calculated)
