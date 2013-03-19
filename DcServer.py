#!/usr/bin/env python
# dc-server.py

import rsa, os, hashlib
from Crypto.Cipher import AES

keybits = 512
publickeyfile= 'keys/id_rsa.pub'
privatekeyfile = 'keys/id_rsa'
userpath = 'users/'
adminpath = 'admins/'
sessionpath = 'sessions/'

class DcServer:
    def __init__(self):
        try:
            pubkey = rsa.PublicKey.load_pkcs1(open(publickeyfile).read())
            prikey = rsa.PrivateKey.load_pkcs1(open(privatekeyfile).read())
            assert pubkey.n==prikey.n and pubkey.e==prikey.e, ' Publio key and private key are not a pair!'
        except:
            (publickey, privatekey) = rsa.newkeys(keybits)
            file = open(publickeyfile, 'w')
            file.write(publickey.save_pkcs1())
            file.close()
            file = open(privatekeyfile, 'w')
            file.write(privatekey.save_pkcs1())
            file.close()

    def getPubkey(self):
        pubkey = rsa.PublicKey.load_pkcs1(open(publickeyfile).read())
        return str(pubkey.n), str(pubkey.e)

    def __decryptFromStr(self, crypto):
        privatekey = rsa.PrivateKey.load_pkcs1(open(privatekeyfile).read())
        return self.__decryptWithKey(crypto, privatekey)

    def __decryptWithKey(self, crypto, prikey):
        return rsa.decrypt(rsa.transform.int2bytes(int(crypto)), prikey)

    def __get32bitkey(self, msg):
        return hashlib.md5(msg).hexdigest()

    def __encrypt2str(self, message, pubkey):
        return str(rsa.transform.bytes2int(rsa.encrypt(message, pubkey)))

    def loginAdmin(self, encryptName, encryptPasswd, session_pubkey_n, session_pubkey_e):
        privatekey = rsa.PrivateKey.load_pkcs1(open(privatekeyfile).read())
        name = self.__decryptWithKey(encryptName, privatekey)
        passwd = self.__decryptWithKey(encryptPasswd, privatekey)
        try:
            file = open("%s/%s"%(adminpath, name), 'r')
            passwd_store = file.read()
            file.close()
            assert hashlib.sha1(passwd).hexdigest() != passwd_store, ' Password is NOT correct!'
            pubkey = rsa.PublicKey(int(session_pubkey_n), int(session_pubkey_e))
            file = open("%s/%s"%(sessionpath, name), 'w')
            file.write(pubkey.save_pkcs1())
            file.close()
            return True
        except:
            return False

    def addAdmin(self, name, passwd):
        if os.path.isfile("%s/%s"%(adminpath,name)):
            return False
        else:
            file = open("%s/%s"%(adminpath, name), 'w')
            file.write(hashlib.sha1(passwd).hexdigest())
            file.close()
            return True

    def addUser(self, encryptoName, encryptoPasswd, encryptoAccess, encryptoSecret, encryptoTenant_id, encryptoUser_id):
        prikey = rsa.PrivateKey.load_pkcs1(open(privatekeyfile).read())
        name = self.__decryptWithKey(encryptoName, prikey)
        passwd = self.__decryptWithKey(encryptoPasswd, prikey)
        if os.path.isfile("%s/%s"%(userpath, name)):
            return False
        else:
            passwdkey = hashlib.sha1(passwd).hexdigest()

            aesEncryptor = AES.new(self.__get32bitkey(passwd), AES.MODE_CBC)
            access = aesEncryptor.encrypt(self.__decryptWithKey(encryptoAccess, prikey))
            secret = aesEncryptor.encrypt(self.__decryptWithKey(encryptoSecret, prikey))
            tenant_id = aesEncryptor.encrypt(self.__decryptWithKey(encryptoTenant_id, prikey))
            user_id = aesEncryptor.encrypt(self.__decryptWithKey(encryptoUser_id, prikey))

            file = open("%s/%s"%(userpath, name), 'wb')
            file.write("%s\r\n%s\r\n%s\r\n%s\r\n%s" % (passwdkey, access, secret, tenant_id, user_id))
            file.close()
            return True

    def loginUser(self, encryptName, encryptPasswd, session_pubkey_n, session_pubkey_e):
        prikey = rsa.PrivateKey.load_pkcs1(open(privatekeyfile).read())
        name = self.__decryptWithKey(encryptName, prikey)
        passwd = self.__decryptWithKey(encryptPasswd, prikey)
        if not os.path.isfile("%s/%s"%(userpath,name)):
            return False
        try:
            file = open("%s/%s"%(userpath, name), 'rb')
            passwdkey, encryptoAccess, encryptoSecret, encryptoTenant_id, encryptoUser_id = file.read().split('\r\n')
            file.close()
            assert hashlib.sha1(passwd).hexdigest() == passwdkey, ' Password is NOT correct!'
            userpubkey = rsa.PublicKey(int(session_pubkey_n), int(session_pubkey_e))
            aesEncryptor = AES.new(self.__get32bitkey(passwd), AES.MODE_CBC)
            return [self.__encrypt2str(aesEncryptor.decrypt(x), userpubkey) for x in [encryptoAccess, encryptoSecret, encryptoTenant_id, encryptoUser_id]]
        except:
            return False
