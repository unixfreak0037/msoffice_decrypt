#!/usr/bin/env python3
#
# msoffice document decryption routines
#
# this is designed to meet a very specific use case for me
# this isn't meant to crack documents -- see hashcat for that
#

import base64
import collections
import functools
import hashlib
import logging
import olefile
import os, os.path
import re
import sys

from struct import unpack, pack
from binascii import hexlify, unhexlify
from xml.dom.minidom import parseString

from Crypto.Cipher import AES

ENCRYPTION_TYPE_STANDARD = 'standard'
ENCRYPTION_TYPE_EXTENSIBLE = 'extensible'
ENCRYPTION_TYPE_AGILE = 'agile'

algorithm_RC4 = 'RC4'
algorithm_128_BIT_AES = '128-bit AES'
algorithm_192_BIT_AES = '192-bit AES'
algorithm_256_BIT_AES = '256-bit AES'

AGILE_ALGORITHM_AES = 'AES'
AGILE_ALGORITHM_RC2 = 'RC2'
AGILE_ALGORITHM_RC4 = 'RC4'
AGILE_ALGORITHM_DES = 'DES'
AGILE_ALGORITHM_DESX = 'DESX'
AGILE_ALGORITHM_3DES = '3DES'
AGILE_ALGORITHM_3DES_112 = '3DES_112'

AGILE_CHAINING_MODE_CBC = 'ChainingModeCBC'
AGILE_CHAINING_MODE_CFB = 'ChainingModeCFB'

whitespace_re = re.compile(r'\s')

class InvalidInputException(Exception):
    pass

class ParsingError(Exception):
    pass

class UnsupportedAlgorithm(Exception):
    pass

StandardEncryptionInfo = collections.namedtuple('StandardEncryptionInfo', [
    'version_major',
    'version_minor',
    'algorithm',
    'key_size',
    'salt',
    'encrypted_verifier',
    'verifier_hash_size',
    'encrypted_verifier_hash'])

AgileEncryptionInfo = collections.namedtuple('AgileEncryptionInfo', [
    'key_data_salt', 
    'key_data_hash_algorithm',
    'encrypted_key_vaue', 
    'spin_value', 
    'password_salt',
    'password_hash_algorithm',
    'password_key_bits',
    'encrypted_verifier_hash_input',
    'encrypted_verifier_hash_value',
    'cipher_algorithm',
    'cipher_chaining',
    'block_size'])

def hashCalc(i, algorithm):
    if algorithm == 'SHA512':
        return hashlib.sha512(i)
    elif algorithm == 'SHA384':
        return hashlib.sha384(i)
    elif algorithm == 'SHA256':
        return hashlib.sha256(i)
    elif algorithm == 'SHA-1':
        return hashlib.sha1(i)
    elif algorithm == 'MD5':
        return hashlib.md5(i)
    else:
        raise UnsupportedAlgorithm("unsupported hash algorithm {}".format(algorithm))

class MSOfficeDecryptor(object):
    """Utility class to decrypt Microsoft Office documents."""
    def __init__(self, source_file, output_file):
        self.source_file = source_file
        self.output_file = output_file

        self.loaded = False
        self.is_ole_file = False
        self.is_encrypted = False
        self.encryption_type = None
        self.encryption_info = None

        self.load()

    def load(self):
        # have we already loaded?
        if self.loaded:
            return

        self.loaded = True

        if not olefile.isOleFile(self.source_file):
            return False

        self.is_ole_file = True

        ole = olefile.OleFileIO(self.source_file)
        try:
            # is this document encrypted?
            if not ole.exists('encryptioninfo') or not ole.exists('encryptedpackage'):
                self.is_encrypted = False
                return

            self.is_encrypted = True
            info_stream = ole.openstream('EncryptionInfo')
            
            # is this standard, extensible or agile encryption?
            # agile will have an xml tag after the first 8 bytes
            info_stream.seek(8)
            xml_header = info_stream.read(5)
            info_stream.seek(0)

            if xml_header == b'<?xml':
                self.encryption_type = ENCRYPTION_TYPE_AGILE
                self.parse_agile_encryption_info(info_stream)
                return

            # initially we assume it's standard
            # the code to parse standard will figure out if it's extensible
            self.encryption_type = ENCRYPTION_TYPE_STANDARD
            self.parse_standard_encryption_info(info_stream)

        finally:
            ole.close()

    def parse_standard_encryption_info(self, info_stream):
        """Parses a given standard directory entry for EncryptionInfo."""

        EncryptionVersionInfo_MAJOR, EncryptionVersionInfo_MINOR = unpack('<HH', info_stream.read(4))
        EncryptionHeaderFlags = info_stream.read(4)
        EncryptionHeaderSize, = unpack('<L', info_stream.read(4))
        EncryptionHeader = info_stream.read(EncryptionHeaderSize)
        info_stream.seek(-EncryptionHeaderSize, 1)
        Flags, = unpack('<L', info_stream.read(4))
        fReserved1 = (1 << 0) & Flags
        fReserved2 = (1 << 1) & Flags
        fCryptoAPI = (1 << 2) & Flags
        fDocProps = (1 << 3) & Flags
        fExternal = (1 << 4) & Flags
        fAES = (1 << 5) & Flags
        SizeExtra = info_stream.read(4)
        AlgID, = unpack('<L', info_stream.read(4))
        algorithm = None

        if not fCryptoAPI and not fAES and fExternal and AlgID == 0x00000000:
            self.encryption_type = ENCRYPTION_TYPE_EXTENSIBLE
            # this isn't something anyone can support so we're done here
            return
        elif fCryptoAPI and not fAES and not fExternal and AlgID == 0x00000000:
            algorithm = algorithm_RC4
        elif fCryptoAPI and not fAES and not fExternal and AlgID == 0x00006801:
            algorithm = algorithm_RC4
        elif fCryptoAPI and fAES and not fExternal and AlgID == 0x00000000:
            algorithm = algorithm_128_BIT_AES
        elif fCryptoAPI and fAES and not fExternal and AlgID == 0x0000660E:
            algorithm = algorithm_128_BIT_AES
        elif fCryptoAPI and fAES and not fExternal and AlgID == 0x0000660F:
            algorithm = algorithm_192_BIT_AES
        elif fCryptoAPI and fAES and not fExternal and AlgID == 0x00006610:
            algorithm = algorithm_256_BIT_AES
        else:
            # TODO warn
            # default to the common one
            pass
            
        AlgIDHash, = unpack('<L', info_stream.read(4))
        KeySize, = unpack('<L', info_stream.read(4))
        ProviderType = info_stream.read(4)
        Reserved1 = info_stream.read(4)
        Reserved2 = info_stream.read(4)
        CPSName = b''
        while True:
            char = info_stream.read(2)
            if char == b'\x00\x00':
                break

            if char == '':
                break
            
            CPSName += char

            if len(CPSName) > 1000:
                raise ParsingError("invalid CPSName (corrupt document?)")

        CPSName = CPSName.decode('UTF-16LE')

        SaltSize = info_stream.read(4)
        Salt = info_stream.read(16)
        #logging.debug("Salt (hex) = {}".format(hexlify(Salt)))
        EncryptedVerifier = info_stream.read(16)
        #logging.debug("EncryptedVerifier (hex) = {}".format(hexlify(EncryptedVerifier)))
        VerifierHashSize, = unpack('<L', info_stream.read(4))
        #logging.debug("VerifierHashSize = {}".format(VerifierHashSize)) # this should be 20 because we're using SHA1
        EncryptedVerifierHash = info_stream.read(20 if algorithm == algorithm_RC4 else 32)
        #logging.debug("EncryptedVerifierHash (hex) = {}".format(hexlify(EncryptedVerifierHash)))

        self.encryption_info = StandardEncryptionInfo(
            EncryptionVersionInfo_MAJOR,
            EncryptionVersionInfo_MINOR,
            algorithm,
            KeySize,
            Salt,
            EncryptedVerifier,
            VerifierHashSize,
            EncryptedVerifierHash)

    def parse_agile_encryption_info(self, info_stream):
        info_stream.seek(8)
        xml = parseString(info_stream.read())
        keyDataSalt = xml.getElementsByTagName('keyData')[0].getAttribute('saltValue')
        keyDataSalt = base64.b64decode(keyDataSalt)
        keyDataHashAlgorithm = xml.getElementsByTagName('keyData')[0].getAttribute('hashAlgorithm')
        schema = 'http://schemas.microsoft.com/office/2006/keyEncryptor/password'
        spinValue = xml.getElementsByTagNameNS(schema, 'encryptedKey')[0].getAttribute('spinCount')
        spinValue = int(spinValue)
        blockSize = xml.getElementsByTagNameNS(schema, 'encryptedKey')[0].getAttribute('blockSize')
        blockSize = int(blockSize)
        cipherAlgorithm = xml.getElementsByTagNameNS(schema, 'encryptedKey')[0].getAttribute('cipherAlgorithm')
        cipherChaining = xml.getElementsByTagNameNS(schema, 'encryptedKey')[0].getAttribute('cipherChaining')
        encryptedKeyValue = xml.getElementsByTagNameNS(schema, 'encryptedKey')[0].getAttribute('encryptedKeyValue')
        encryptedKeyValue = base64.b64decode(encryptedKeyValue)
        passwordSalt = xml.getElementsByTagNameNS(schema, 'encryptedKey')[0].getAttribute('saltValue')
        passwordSalt = base64.b64decode(passwordSalt)
        passwordHashAlgorithm = xml.getElementsByTagNameNS(schema, 'encryptedKey')[0].getAttribute('hashAlgorithm')
        passwordKeyBits = xml.getElementsByTagNameNS(schema, 'encryptedKey')[0].getAttribute('keyBits')
        passwordKeyBits = int(passwordKeyBits)

        encryptedVerifierHashInput = xml.getElementsByTagNameNS(schema, 'encryptedKey')[0].getAttribute('encryptedVerifierHashInput')
        encryptedVerifierHashInput = base64.b64decode(encryptedVerifierHashInput)
        encryptedVerifierHashValue = xml.getElementsByTagNameNS(schema, 'encryptedKey')[0].getAttribute('encryptedVerifierHashValue')
        encryptedVerifierHashValue = base64.b64decode(encryptedVerifierHashValue)

        self.encryption_info = AgileEncryptionInfo(
            keyDataSalt,
            keyDataHashAlgorithm,
            encryptedKeyValue,
            spinValue,
            passwordSalt,
            passwordHashAlgorithm,
            passwordKeyBits,
            encryptedVerifierHashInput,
            encryptedVerifierHashValue,
            cipherAlgorithm,
            cipherChaining,
            blockSize)

    def decrypt(self, password):
        """Decrypts the office file with the given password."""
        if not self.is_decryptable:
            return False

        key = self.get_encryption_key(password)
        if key is None:
            return False

        if self.encryption_type == ENCRYPTION_TYPE_STANDARD:
            if self.encryption_info.algorithm == algorithm_128_BIT_AES:
                return self.decrypt_aes_128(key)
        elif self.encryption_type == ENCRYPTION_TYPE_AGILE:
            if self.encryption_info.cipher_algorithm == AGILE_ALGORITHM_AES and \
            self.encryption_info.cipher_chaining == AGILE_CHAINING_MODE_CBC:
                return self.decrypt_agile_aes_cbc(key)

    def get_encryption_key(self, password):
        if self.encryption_type == ENCRYPTION_TYPE_STANDARD:
            if self.encryption_info.algorithm == algorithm_128_BIT_AES:
                return self.get_aes_128_encryption_key(password)
            else:
                raise UnsupportedAlgorithm("encryption algorithm {} not implemented (yet)".format(
                                          self.encryption_info.algorithm))

        elif self.encryption_type == ENCRYPTION_TYPE_AGILE:
            if self.encryption_info.cipher_algorithm == AGILE_ALGORITHM_AES and \
            self.encryption_info.cipher_chaining == AGILE_CHAINING_MODE_CBC:
                return self.get_agile_aes_cbc_encryption_key(password)
            else:
                raise UnsupportedAlgorithm("agile cipher {} chaining mode {} not supported (yet)".format(
                                          self.encryption_info.cipher_algorithm,
                                          self.encryption_info.cipher_chaining))

            return self.get_agile_encryption_key(password)

        return None

    def get_agile_aes_cbc_encryption_key(self, password):
        # Initial round sha512(salt + password)
        h = hashCalc(self.encryption_info.password_salt + password.encode("UTF-16LE"), 
                     self.encryption_info.password_hash_algorithm)

        # Iteration of 0 -> spincount-1; hash = sha512(iterator + hash)
        for i in range(0, self.encryption_info.spin_value, 1):
            h = hashCalc(pack("<I", i) + h.digest(), self.encryption_info.password_hash_algorithm)

        h2 = hashCalc(h.digest() + b'\x14\x6e\x0b\xe7\xab\xac\xd0\xd6', self.encryption_info.password_hash_algorithm)
        # Needed to truncate skey to bitsize
        a = hexlify(h2.digest())[:2*self.encryption_info.password_key_bits//8]
        skey3 = unhexlify(a)

        # AES encrypt the encryptedKeyValue with the skey and salt to get secret key
        aes = AES.new(skey3, AES.MODE_CBC, self.encryption_info.password_salt)
        skey = aes.decrypt(self.encryption_info.encrypted_key_vaue) # <-- I know that's right

        # decrypt the verifier hash input
        h2 = hashCalc(h.digest() + b'\xfe\xa7\xd2\x76\x3b\x4b\x9e\x79', self.encryption_info.password_hash_algorithm)
        a = hexlify(h2.digest())[:2*self.encryption_info.password_key_bits//8]
        skey3 = unhexlify(a)
        aes = AES.new(skey3, AES.MODE_CBC, self.encryption_info.password_salt)
        decrypted_verifier_hash_input = aes.decrypt(self.encryption_info.encrypted_verifier_hash_input)

        # decrypt the verifier hash value
        h2 = hashCalc(h.digest() + b'\xd7\xaa\x0f\x6d\x30\x61\x34\x4e', self.encryption_info.password_hash_algorithm)
        a = hexlify(h2.digest())[:2*self.encryption_info.password_key_bits//8]
        skey3 = unhexlify(a)
        aes = AES.new(skey3, AES.MODE_CBC, self.encryption_info.password_salt)
        decrypted_verifier_hash_value = aes.decrypt(self.encryption_info.encrypted_verifier_hash_value)

        computed_hash = hashCalc(decrypted_verifier_hash_input, self.encryption_info.key_data_hash_algorithm).digest()
        computed_hash = computed_hash[:len(decrypted_verifier_hash_value)]
        if computed_hash != decrypted_verifier_hash_value:
            return None
        
        return skey

    def get_aes_128_encryption_key(self, password):
        """Returns the AES 128 key (as a byte string) or None if the password is wrong."""

        salt = self.encryption_info.salt
        encryptedVerifier = self.encryption_info.encrypted_verifier
        encryptedVerifierHash = self.encryption_info.encrypted_verifier_hash
        verifierHashSize = self.encryption_info.verifier_hash_size

        assert isinstance(salt, bytes)
        # The salt used MUST be generated randomly and MUST be 16 bytes in size.
        assert len(salt) == 16
        assert isinstance(password, str)
        assert isinstance(encryptedVerifier, bytes)
        assert len(encryptedVerifier) == 16

        # The password MUST be provided as an array of Unicode characters. 
        password = password.encode('UTF-16LE', errors='ignore')

        # This hashing algorithm MUST be SHA-1.
        h = hashlib.sha1(salt + password)
        for iteration in range(50000):
            h = hashlib.sha1(pack("<L", iteration) + h.digest())

        # After the final hash data has been obtained, the encryption key MUST be generated by using the final hash data, 
        # and the block number MUST be 0x00000000. The encryption algorithm MUST be specified in the EncryptionHeader.AlgID field. 
        # The encryption algorithm MUST use ECB mode.
        # The method used to generate the hash data that is the input into the key derivation algorithm is as follows:
        #   Hfinal = H(Hn + block) <-- literally just means add an extra 4 bytes of 0x00 to the end
        
        hash_final = hashlib.sha1(h.digest() + pack('<L', 0)).digest()

        #logging.debug("hash_final = {}".format(hash_final))

        # Let cbRequiredKeyLength be equal to the size, in bytes, of the required key length for the relevant encryption algorithm 
        # as specified by the EncryptionHeader structure. Note that cbRequiredKeyLength MUST be less than or equal to 40.
        cbRequiredKeyLength = 128 // 8 # 128 bit AES # XXX do the rest
        #logging.debug("cbRequiredKeyLength = {}".format(cbRequiredKeyLength))
        
        # Let cbHash be the number of bytes output by the hashing algorithm H.
        cbHash = len(hash_final)
        #logging.debug("cbHash = {}".format(cbHash))

        # Form a 64-byte buffer by repeating the constant 0x36 64 times. 
        # XOR Hfinal into the first cbHash bytes of this buffer, and compute a hash of the resulting 64-byte 
        # buffer by using hashing algorithm H. This will yield a hash value of length cbHash. Let the resulting value be called X1.
        X1 = bytearray([0x36] * 64)
        for index, value in enumerate(hash_final):
            X1[index] = X1[index] ^ hash_final[index]

        #logging.debug("X1 mutated = {}".format(hexlify(X1)))

        #sha1_hasher = SHA.new()
        #sha1_hasher.update(bytes(X1))
        #X1 = sha1_hasher.digest()
        X1 = hashlib.sha1(bytes(X1)).digest()
        #logging.debug("X1 = {}".format(hexlify(X1)))

        # Form another 64-byte buffer by repeating the constant 0x5C 64 times. 
        # XOR Hfinal into the first cbHash bytes of this buffer, and compute a hash of the resulting 64-byte 
        # buffer by using hash algorithm H. This yields a hash value of length cbHash. Let the resulting value be called X2.
        X2 = bytearray([0x5C] * 64)
        for index, value in enumerate(hash_final):
            X2[index] = X2[index] ^ hash_final[index]

        #sha1_hasher = SHA.new()
        #sha1_hasher.update(bytes(X2))
        #X2 = sha1_hasher.digest()
        X2 = hashlib.sha1(bytes(X2)).digest()

        # Concatenate X1 with X2 to form X3, which will yield a value twice the length of cbHash.
        X3 = X1 + X2
        #logging.debug("X3 = {}".format(hexlify(X3)))

        # Let keyDerived be equal to the first cbRequiredKeyLength bytes of X3.
        keyDerived = X3[:cbRequiredKeyLength]
        #logging.debug("key = {}".format(hexlify(keyDerived)))

        # 2.3.4.9 Password Verification (Standard Encryption)
        # (1) Generate an encryption key as specified in section 2.3.4.7.
        # (2) Decrypt the EncryptedVerifier field of the EncryptionVerifier structure as specified in section 2.3.3, 
        # and generated as specified in section 2.3.4.8, to obtain the Verifier value. 
        # The resulting Verifier value MUST be an array of 16 bytes.
        
        aes = AES.new(keyDerived, AES.MODE_ECB, salt)
        Verifier = aes.decrypt(encryptedVerifier)
        #logging.debug("encryptedVerifier = {}".format(hexlify(encryptedVerifier)))
        #logging.debug("decryptedVerifier = {}".format(hexlify(Verifier)))

        # (3) Decrypt the EncryptedVerifierHash field of the EncryptionVerifier structure to obtain the hash of the Verifier value. 
        # The number of bytes used by the encrypted Verifier hash MUST be 32. 
        # The number of bytes used by the decrypted Verifier hash is given by the VerifierHashSize field, which MUST be 20.
        aes = AES.new(keyDerived, AES.MODE_ECB, salt)
        #logging.debug("length of encryptedVerifierHash = {}".format(len(encryptedVerifierHash)))
        decryptedVerifierHash = aes.decrypt(encryptedVerifierHash)[:20]
        #logging.debug("encryptedVerifierHash = {}".format(hexlify(encryptedVerifierHash)))
        #logging.debug("decryptedVerifierHash = {}".format(hexlify(decryptedVerifierHash)))
        #logging.debug("length of decryptedVerifierHash = {}".format(len(decryptedVerifierHash)))

        # (4) Calculate the SHA-1 hash value of the Verifier value calculated in step 2.
        calculatedVerifierHash = hashlib.sha1(Verifier).digest()
        #logging.debug("calculatedVerifierHash = {}".format(hexlify(calculatedVerifierHash)))
        #logging.debug("length of calculatedVerifierHash = {}".format(len(calculatedVerifierHash)))

        # (5) Compare the results of step 3 and step 4. If the two hash values do not match, the password is incorrect.
        if calculatedVerifierHash != decryptedVerifierHash:
            return None

        return keyDerived

    def decrypt_aes_128(self, encryption_key):
        ole = olefile.OleFileIO(self.source_file)
        try:
            aes = AES.new(encryption_key)

            with open(self.output_file, 'wb') as fp:
                ep = ole.openstream('EncryptedPackage')
                stream_size, = unpack('<Q', ep.read(8))
                while stream_size > 0:
                    encrypted_data = ep.read(16)
                    if len(encrypted_data) < 16:
                        encrypted_data += bytes(bytearray([0x00] * (16 - len(encrypted_data))))
                    fp.write(aes.decrypt(encrypted_data))
                    stream_size -= 16

            return True

        finally:
            ole.close()

    def decrypt_agile_aes_cbc(self, encryption_key):
        SEGMENT_LENGTH = 4096
        ole = olefile.OleFileIO(self.source_file)
        ep = ole.openstream('EncryptedPackage')
        try:
            obuf = b''
            totalSize = unpack('<I', ep.read(4))[0]
            #sys.stderr.write("totalSize: {}\n".format(totalSize))
            ep.seek(8)
            with open(self.output_file, 'wb') as fp:
                for i, ibuf in enumerate(iter(functools.partial(ep.read, SEGMENT_LENGTH), b'')):
                    saltWithBlockKey = self.encryption_info.key_data_salt + pack('<I', i)
                    iv = hashCalc(saltWithBlockKey, self.encryption_info.key_data_hash_algorithm).digest()
                    iv = iv[:16]
                    aes = AES.new(encryption_key, AES.MODE_CBC, iv)
                    dec = aes.decrypt(ibuf)
                    fp.write(dec)

            return True

        finally:
            ole.close()

    def guess(self, password_list=[]):
        """Returns the correct password out of the password_list, or None if none of them are correct."""
        if not self.is_decryptable:
            return None

        # https://isc.sans.edu/diary/rss/23774
        password_list.insert(0, 'VelvetSweatshop')

        for password in password_list:
            if not isinstance(password_list, list):
                if password == '':
                    break

            key = self.get_encryption_key(password)
            if key:
                return password

        return None

    # this meets a specific use case I have
    def find_password(self, text_file=None, text_content=None, range_low=4, range_high=14, byte_limit=1024, list_limit=1000):
        """Given a text file, return a list of all the likely passwords, assuming the password is in there somewhere."""
        assert text_content is None or isinstance(text_content, str)

        if not text_content:
            with open(text_file, 'rb') as fp:
                data = fp.read(byte_limit).decode('UTF-8', errors='ignore')
        else:
            data = text_content

        password_list = set()
        for r in range(range_low, range_high + 1):
            for i in range(0, byte_limit - r):
                password = data[i:i + r]
                if not password:
                    continue

                # assume whitespace characters are not going to be in passwords
                if whitespace_re.search(password):
                    continue

                password_list.add(password)
                if len(password_list) >= list_limit:
                    break

        return list(password_list)

    @property
    def is_decryptable(self):
        return self.is_ole_file == True and \
               self.is_encrypted == True and \
               self.encryption_type != ENCRYPTION_TYPE_EXTENSIBLE

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser("Extract and decrypt the encrypted contents of a Microsoft Office file.")
    parser.add_argument('-p', '--password', 
        help="The password to use for decryption.")
    parser.add_argument('--empty-password', action='store_true', default=False,
        help="Use an empty password string as the password.")
    parser.add_argument('-P', '--password-list', action='store_true', default=False,
        help="Read password list from standard input.")
    #parser.add_argument('--log-level', dest='log_level', default=None,
        #help="The logging level to use (DEBUG, INFO, WARNING or ERROR).")
    parser.add_argument('-i', '--iterate', default=None,
        help="Iterate over the given file for possible passwords.")
    parser.add_argument('-r', '--range-low', type=int, default=4,
        help="Increment range (low) for iteration.")
    parser.add_argument('-R', '--range-high', type=int, default=14,
        help="Increment range (high) for iteration.")
    parser.add_argument('-l', '--limit', type=int, default=1024,
        help="Byte limit of file iteration.")
    parser.add_argument('-L', '--password-list-limit', type=int, default=1000,
        help="Maximum number of passwords attempts.")
    parser.add_argument('office_file')
    parser.add_argument('output_file')
    args = parser.parse_args()

    logging.getLogger().setLevel(logging.INFO)

    decryptor = MSOfficeDecryptor(args.office_file, args.output_file)
    if not decryptor.is_ole_file:
        print("{} is not an OLE document".format(args.office_file))
        sys.exit(1)

    if not decryptor.is_encrypted:
        print("{} is not an encrypted document".format(args.office_file))
        sys.exit(1)

    # https://isc.sans.edu/diary/rss/23774
    if decryptor.decrypt('VelvetSweatshop'):
        print("decrypted {} into {} using default password VelvetSweatshop".format(args.office_file, args.output_file))
        sys.exit(0)

    if args.iterate:
        args.password = decryptor.guess(decryptor.find_password(args.iterate, None, args.range_low, 
                                        args.range_high, args.limit, args.password_list_limit))
        if args.password:
            print("found password: {}".format(args.password))
    elif args.password_list:
        args.password = decryptor.guess(sys.stdin)

        if args.password:
            print("found password: {}".format(args.password))
    elif args.empty_password:
        args.password = ''

    if args.password is not None:
        if decryptor.decrypt(args.password):
            print("decrypted {} into {}".format(args.office_file, args.output_file))
            sys.exit(0)
        else:
            print("ERROR: invalid password")
            sys.exit(1)
    else:
        print("ERROR: no valid password available")
        sys.exit(1)
