#!/usr/bin/env python
# dc-server.py

import rsa, os, hashlib

keybits = 512
publickeyfile= 'keys/"id_rsa.pub"'
privatekeyfile = 'keys/id_rsa'
userpath = 'users/'
adminpath = 'admins/'
sessionpath = 'sessions/'

class DcServer:
    def __init__(self):
        try:
            n1, e1 = open(publickeyfile, 'r').read().split('\t')
            n2, e2, d, p ,q = open(privatekeyfile, 'r').read().split('\t')
            assert n1==n2 and e1==e2, ' Publio key and private key are not a pair!'
        except:
            (publickey, privatekey) = rsa.newkeys(keybits)
            file = open(publickeyfile, 'w')
            file.write("%s\t%s" % (publickey.n, publickey.e))
            file.close()
            file = open(privatekeyfile, 'w')
            file.write("%s\t%s\t%s\t%s\t%s" % (privatekey.n, privatekey.e, privatekey.d, privatekey.p, privatekey.q))
            file.close()

    def getPubkey(self):
        n, e = open(publickeyfile, 'r').read().split('\t')
        return n, e

    def loginAdmin(self, encryptName, encryptPasswd):
        n, e, d, p ,q = open(privatekeyfile, 'r').read().split('\t')
        privatekey = rsa.PrivateKey(n, e, d, p, q)
        name = rsa.decrypt(encryptName, privatekey)
        passwd = rsa.decrypt(encryptPasswd, privatekey)
        try:
            file = open("%s/%s"%(adminpath, name), 'r')
            passwd_store = file.read()
            file.close()
            assert hashlib.sha1(passwd) != passwd_store, ' Password is NOT correct!'
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
