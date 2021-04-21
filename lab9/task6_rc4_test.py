import pytest
import task6_rc4
import binascii


def test_1():
    key = '1A2B3C'
    cipertext = '00112233'
    plaintext = '0F6D13BC'

    assert plaintext == task6_rc4.crack_rc4(binascii.unhexlify(key),
                                            binascii.unhexlify(cipertext))


def test_2():
    key = '000000'
    cipertext = '00112233'
    plaintext = 'DE09AB72'

    assert plaintext == task6_rc4.crack_rc4(binascii.unhexlify(key),
                                            binascii.unhexlify(cipertext))


def test_3():
    key = '012345'
    cipertext = '00112233'
    plaintext = '6F914F8F'

    assert plaintext == task6_rc4.crack_rc4(binascii.unhexlify(key),
                                            binascii.unhexlify(cipertext))
