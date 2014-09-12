# -*- coding: utf-8 -*-

# Copyright (C) 2010-2013 Avencall
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import os
import time
import random
import shutil
import magic
from M2Crypto import RSA, X509, m2, EVP, ASN1

CIPHERS = {
    'aes': 'aes_128_cbc',
    'des': 'des_ede_cbc',
    'des3': 'des_ede3_cbc',
    'idea': 'idea_cbc'
}

DEFAULT_CIPHER = CIPHERS['aes']

# certificates/keys magic headers
MAGIC = {
    '-----BEGIN CERTIFICATE-----\n': 'certificate',
    '-----BEGIN RSA PRIVATE KEY-----\n': 'privkey',
    '-----BEGIN DSA PRIVATE KEY-----\n': 'privkey',
    '-----BEGIN PUBLIC KEY-----\n': 'pubkey',
    '-----BEGIN CERTIFICATE REQUEST-----\n': 'request',
}

class OpenSSL(object):

    def __init__(self, config):
        self.certsdir = config.openssl.certsdir
        if not os.path.exists(self.certsdir):
            os.makedirs(self.certsdir)

        self.m = magic.open(magic.MAGIC_NONE)
        self.m.load('/usr/share/file/magic.mgc')

    def _get_abs_path_file(self, namefile):
        rel_file_path = os.path.join(self.certsdir, namefile)
        abs_file_path = os.path.abspath(rel_file_path)

        if not abs_file_path.startswith(self.certsdir):
            raise ("file not valid")

        return abs_file_path

    def _keyfile(self, name):
        """private key"""
        return self._get_abs_path_file(name + '.key')

    def _crtfile(self, name):
        """certificate"""
        return self._get_abs_path_file(name + '.crt')

    def _pemfile(self, name):
        """private key + certificate"""
        return self._get_abs_path_file(name + '.pem')

    def _pubfile(self, name):
        """pub key"""
        return self._get_abs_path_file(name + '.pub')

    def listCertificates(self):
        """Return list of available certificates & keys
        """
        certs = []

        for fname in os.listdir(self.certsdir):
            cert = {
                'name': fname.split('.', 2)[0],
                'types': [],
                'filename': fname,
                'path': os.path.join(self.certsdir, fname)
            }

            # guess what filetype is it, reading content,
            #  and searching for '---- BEGIN xxx ----' lines
            with open(os.path.join(self.certsdir, fname)) as f:
                content = f.read()

                for g, n in MAGIC.iteritems():
                    if g in content:
                        cert['types'].append(n)

                if 'certificate' in cert['types']:
                    x509 = X509.load_cert(os.path.join(self.certsdir, fname))

                    cert.update({
                        'CA': x509.check_ca() == 1,
                        'autosigned': str(x509.get_subject()) == str(x509.get_issuer()),
                        'length': len(x509.get_pubkey().get_rsa()),
                        'fingerprint': 'md5:' + x509.get_fingerprint(),
                        'validity-end': x509.get_not_after().get_datetime().strftime("%Y/%m/%d %H:%M:%S %Z"),
                    })

            certs.append(cert)

        return certs

    def getCertificateInfos(self, filename):
        """Return informations about a certificate

                    args:
                        . certificate filename

                    returns
                        a dictionary containing certificate informations

                    >>> getCertificateInfos('wiki.proformatique.com')
                        {
                            'sn'             : 2445288...L
                            'CA'             : 0
                            'length'         : 4242,
                            'fingerprint'    : 'md5:0000...'
                            'validity-start' : '2011/04/14 13:04:26 UTC',
                            'validity-end'   : '2012/12/12 12:12:12 UTC',
                            'subject'        : {
                               'C': 'FR',
                      'CN': 'wiki.proformatique.com',
                          'L': 'Puteaux',
                              'O': 'Proformatique',
                           'OU': 'R&D Department',
                      'ST': 'France',
                          'emailAddress': 'webmaster@proformatique.com'
                            },
                            'issuer'        : {
                                 'C': 'FR',
                             'CN': '*',
                         'L': 'Puteaux',
                             'O': 'Proformatique',
                                 'OU': 'R&D Department',
                               'ST': 'France',
                                 'emailAddress': 'passe-partout@proformatique.com'
                            },
                            'extensions'     : {}
                        }
        """
        if not os.path.exists(os.path.join(self.certsdir, filename)):
            raise ("%s certificate not found" % filename)

        cert = X509.load_cert(os.path.join(self.certsdir, filename))
        infos = {
            'sn': cert.get_serial_number(),
            'CA': cert.check_ca() == 1,
            'autosigned': str(cert.get_subject()) == str(cert.get_issuer()),
            'length': len(cert.get_pubkey().get_rsa()),
            'fingerprint': 'md5:' + cert.get_fingerprint(),
            'validity-start': cert.get_not_before().get_datetime().strftime("%Y/%m/%d %H:%M:%S %Z"),
            'validity-end': cert.get_not_after().get_datetime().strftime("%Y/%m/%d %H:%M:%S %Z"),
            'path': self._pemfile(filename)
        }

        infos['subject'] = dict([(k, v) for (k, v) in [nid.split('=') for nid in
                                                       str(cert.get_subject()).split('/') if len(nid) > 0]])
        infos['issuer'] = dict([(k, v) for (k, v) in [nid.split('=') for nid in
                                                      str(cert.get_issuer()).split('/') if len(nid) > 0]])

        exts = {}
        for i in xrange(cert.get_ext_count()):
            e = cert.get_ext_at(i)
            exts[e.get_name()] = e.get_value()
        infos['extensions'] = exts

        return infos

    def getPubKey(self, filename):
        """Export certificate public key

                    args:
                        . certificate name

                    returns
                        a text stream (pubkey)

                    >>> getPubKey('wiki.proformatique.com')
                    -----BEGIN PUBLIC KEY-----
                    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDGPItvzRZKECt6mLOpuFLZUAqy
                    U7CRFcTSUidTK75Hy5x10FvkNT1B6v/anL6+h2Smpyx6cs9NnnmfY8KVifONLHnb
                    kOZOsQH73gWUrS12tMC1ZhQjz53POFQLGEK8wYq84IwD7F5IzoMXZA0nyi2YCyxO
                    Drz539XmIqqVxSOfVwIDAQAB
                    -----END PUBLIC KEY-----
        """
        if not os.path.exists(self._pubfile(filename)):
            raise ("%s pubkey not found" % filename)

        with open(self._pubfile(filename)) as f:
            pubkey = f.read()

        return pubkey

    def export(self, filename):
        """Export certificate, private key or public key

                args:
                      . filename
        """
        abs_file_path = self._get_abs_path_file(filename)

        if not os.path.exists(abs_file_path):
            raise ("file not found")

        with open(abs_file_path, 'r') as f:
            content = f.read()

        return content

    def _makekey(self, name, password='', keylen=1024, cipher=DEFAULT_CIPHER):
        """Create a RSA key.

                    *private function*

                    args:
                        . name     : key name (filename will be 'name.key')
            . password : key password (if empty, key will be passwordless)
                        . keylen   : private key size, in bits
                        . cipher   : cipher used to encrypt key

                    returns:
                      . the key
        """
        # Create private key
        rsa = RSA.gen_key(keylen, m2.RSA_F4)

        def _getpwd(*_args):
            return password
        # NOTE: when empty password, need not to use a cipher, or generated key file is empty
        rsa.save_key(self._keyfile(name),
                     cipher=cipher if len(password) > 0 else None,
                     callback=_getpwd)

        rsa.save_pub_key(self._pubfile(name))

        # create symlinks in /var/lib/asterisk/keys
        # (required for IAX trunks)
        os.symlink(self._keyfile(name), os.path.join('/var/lib/asterisk/keys', name + '.key'))
        os.symlink(self._pubfile(name), os.path.join('/var/lib/asterisk/keys', name + '.pub'))

        return rsa

    def _makerequest(self, name, privkey, subject):
        """Create a Certificate Request (CSR).

                    args:
                        . name    : certificate request name
                        . privkey : private key request is base on
                        . subject : certificat information fields (CN, OU, O, L, ST, C, emailAddress)

                    returns:
                        . the request, and the associated public key
        """
        # Create public key
        pubkey = EVP.PKey()
        pubkey.assign_rsa(privkey)

        # Create request
        req = X509.Request()
        # req.set_version(req.get_version())
        req.set_pubkey(pubkey)
        name = X509.X509_Name()
        name.CN = subject.get('CN', '*')
        name.OU = subject.get('OU', 'R&D Department')
        name.O = subject.get('O', 'Proformatique')
        name.L = subject.get('L', 'Puteaux')
        name.ST = subject.get('ST', 'France')
        name.C = subject.get('C', 'FR')
        name.emailAddress = subject.get('emailAddress', 'xivo-users@lists.proformatique.com')

        req.set_subject_name(name)
        req.sign(pubkey, 'sha1')

        return req, pubkey

    def _makecert(self, request, (issuerCert, issuerKey), validity=365, extens={}):
        """Create a X509 certificate.

                    Usually, a final certificate is signed by a CA.
                    In this case, issuerCert and issuerKey are respectively the X509 CA
                    certificate and the private key associated with.

                    For a self-signed certificate, or a CA certificate, issuerCert is the request
                    itself, and issuerKey the public key associated with.

                    args:
                        . request               : the request (CSR) for our certificate
                        . issuerCert, issuerKey : certificate + key to sign CSR with (usually CA cert/key)
                        . validity              : certificate validity duration (in days)
                            certificate validity start from now until now+validity
                        . extens                : certificat key/value extensions
                            i.e: a CA certificate need 'basicConstraints: CA=TRUE' extension

                    returns:
                        the X509 certificate

                    NOTE: certificate serial number MUST be unique.
        """
        # Create x509 certificate
        cert = X509.X509()
        cert.set_version(2)
        cert.set_serial_number(random.randint(0, 9999999999))

        t = ASN1.ASN1_UTCTIME()
        t.set_time(long(time.time()))
        cert.set_not_before(t)

        t = ASN1.ASN1_UTCTIME()
        t.set_time(long(time.time() + 60 * 60 * 24 * int(validity)))
        cert.set_not_after(t)

        cert.set_pubkey(request.get_pubkey())
        cert.set_subject(request.get_subject())

        for k, v in extens.iteritems():
            exten = X509.new_extension(k, v)
            cert.add_ext(exten)

        cert.set_issuer(issuerCert.get_subject())
        cert.sign(issuerKey, 'sha1')

        return cert

    def createSSLCACertificate(self, args):
        """Create a CA certificate.

                    args (* == required):
                      * name        (str)  : certificate name. MUST be unique
                        . password    (str)  : CA password
                                default = none
                        . length      (int)  : private key size, in bits
                                default = 1024
                        . validity    (int)  : certificate validity (in days) from now
                                default = 365

                        == issuer/subject keys ==
                        . CN           (str)  : CommonName                (default=*)
                        . C            (str)  : Country                   (default=FR)
                        . ST           (str)  : State                     (default=France)
                        . L            (str)  : Location                  (default=Puteaux)
                        . O            (str)  : Organization              (default=Proformatique)
                        . OU           (str)  : OrganizationalUnit        (default=R&D)
                        . emailAddress (str)  : ...                                 (default=xivo-users@lists.proformatique.com)

                    NOTE: we save certificate private key (ext .key), X509 certificate (ext .cert)
                    and concanenation of both (ext .PEM) on disk in self.certsdir directory

                >>> createSSLCACertificate({
                        'name'         : 'proformatique'
                        'length'       : 1024,
                        'validity'     : 365,
                        'password'     : 'abcd',
                        'CN'           : '*'
                        'C'            : 'FR',
                        'ST'           : 'France',
                        'L'            : 'Puteaux',
                        'O'            : 'Proformatique',
                        'OU'           : 'R&D',
                        'emailAddress' : 'xivo-users@lists.proformatique.com',
                    })
        """
        if 'name' not in args:
            raise ("missing 'name' option")
        elif os.path.exists(os.path.join(self.certsdir, args['name'] + '.key')):
            raise ("a certificat with this name is already found (%s)" % os.path.join(self.certsdir, args['name'] + '.key'))

        # Create private key
        pkey = self._makekey(args['name'], args.get('password', ''), int(args.get('length', 1024)))

        # Create request
        # pubkey != req.get_pubkey() !!!
        req, pubkey = self._makerequest(args['name'], pkey, args)

        # Create x509 certificate (autosigned)
        cert = self._makecert(req, (req, pubkey), args.get('validity', 365), {'basicConstraints': 'CA:TRUE'})

        #  saving certificate
        cert.save(self._crtfile(args['name']))
        # make PEM as concatenation of key + x509 certificate
        pem = open(os.path.join(self.certsdir, args['name'] + '.pem'), 'wb')
        for f in [os.path.join(self.certsdir, args['name'] + ext) for ext in ('.key', '.crt')]:
            shutil.copyfileobj(open(f, 'rb'), pem)
        pem.close()

        return True

    def createSSLCertificate(self, args):
        """
                    args keys (* == required):
                      * name        (str)  : certificate name. MUST be unique
                        . autosigned  (0|1)  : autosigned certificate
                                default = 0
                        . password    (str)  : CA password
                                default = none
                        . ca          (str)  : CA name (if autosigned == 0)
                        . ca_password (str)  : if CA needs a password  (if not, you'll be throwed to hell!)
                        . length      (int)  : private key size, in bits
                                default = 1024
                        . validity    (int)  : certificate validity (in days) from now
                                default = 365
                        . cipher      (str)  : 'des','des3',aes','idea'

                        == issuer/subject keys ==
                        . CN           (str)  : CommonName                (default=*)
                        . C            (str)  : Country                   (default=FR)
                        . ST           (str)  : State                     (default=France)
                        . L            (str)  : Location                  (default=Puteaux)
                        . O            (str)  : Organization              (default=Proformatique)
                        . OU           (str)  : OrganizationalUnit        (default=R&D)
                        . emailAddress (str)  : ...                                 (default=xivo-users@lists.proformatique.com)

                    NOTE: we save certificate private key (ext .key), X509 certificate (ext .cert)
                    and concanenation of both (ext .PEM) on disk in self.certsdir directory

                >>> createSSLCertificate({
                        'name'         : 'wiki'
                        'length'       : 512,
                        'validity'     : 15,
                        'password'     : 'abcd',
                        'CN'           : 'wiki.proformatique.com'
                        'C'            : 'FR',
                        'ST'           : 'France',
                        'L'            : 'Puteaux',
                        'O'            : 'Proformatique',
                        'OU'           : 'R&D',
                        'emailAddress' : 'gbour@proformatique.com',
                    })
        """
        if 'name' not in args:
            raise ("missing 'name' option")
        elif os.path.exists(os.path.join(self.certsdir, str(args['name']) + '.key')):
            raise ("a certificat with this name is already found")

        autosigned = int(args.get('autosigned', 0))
        if autosigned == 0:
            if 'ca' not in args:
                raise ("missing 'ca' option")
            elif not os.path.exists(os.path.join(self.certsdir, str(args['ca']) + '.key')):
                raise ("CA certificate key not found")

            # loading CA private key
        # NOTE: RSA fail to read password (with "bad password read message") if we
            # make "args.get()" IN _getpass()
            pwd = args.get('ca_password', '')

            def _getpass(*args, **kwargs):
                return pwd

            try:
                _cakey = RSA.load_key(os.path.join(self.certsdir, args['ca'] + '.key'), _getpass)
            except RSA.RSAError:
                raise ("invalid CA password")
            cakey = EVP.PKey()
            cakey.assign_rsa(_cakey)

            cacert = X509.load_cert(self._crtfile(args['ca']))

        cipher = CIPHERS.get(args.get('cipher'), DEFAULT_CIPHER)

        # Create private key
        pkey = self._makekey(args['name'], args.get('password', ''),
                             int(args.get('length', 1024)), cipher)

        # Create request
        # pubkey != req.get_pubkey() !!!
        req, pubkey = self._makerequest(args['name'], pkey, args)
        if autosigned == 1:
            cacert = req
            cakey = pubkey

        # Create x509 certificate / signed with CA key
        cert = self._makecert(req, (cacert, cakey), int(args.get('validity', 365)))
        cert.save(self._crtfile(args['name']))

        # make PEM as concatenation of key + x509 certificate
        pem = open(os.path.join(self.certsdir, args['name'] + '.pem'), 'wb')
        for f in [os.path.join(self.certsdir, args['name'] + ext) for ext in ('.key', '.crt')]:
            shutil.copyfileobj(open(f, 'rb'), pem)
        pem.close()

        return True

    def deleteCertificate(self, certificate):
        """
        """
        certificate = os.path.join(certificate, '.pem')
        if not os.path.exists(os.path.join(self.certsdir, certificate)):
            raise ("'%s' certificat not found" % certificate)

        os.remove(os.path.join(self.certsdir, certificate))

        #  deleting symlinks if exists
        for name in (certificate, certificate + '.pub', certificate + '.key'):
            path = os.path.join('/var/lib/asterisk/keys', name)
            if os.path.lexists(path) and os.path.islink(path) and os.readlink(path) == os.path.join(self.certsdir, certificate):
                os.remove(path)

        return True

    def _import(self, args):
        if 'name' not in args:
            raise ("missing 'name' arg")
        elif 'content' not in args:
            raise ("missing 'content' arg")
        elif os.path.exists(os.path.join(self.certsdir, args['name'])):
            raise ("a certificate named '%s' already exists" % args['name'])

        types = []
        for g, n in MAGIC.iteritems():
            if g in args['content']:
                types.append(n)

        if len(types) == 0:
            raise ("'%s' is not a valid SSL certificat or key" % args['name'])

        with open(os.path.join(self.certsdir, args['name']), 'w') as f:
            f.write(args['content'])

        # symlinks for IAX keys
        if len(types) == 1:
            if   types[0] == 'pubkey':
                os.symlink(os.path.join(self.certsdir, args['name']), os.path.join('/var/lib/asterisk/keys', args['name'] + ('' if args['name'].endswith('.pub') else '.pub')))
            elif types[0] == 'privkey':
                os.symlink(os.path.join(self.certsdir, args['name']), os.path.join('/var/lib/asterisk/keys', args['name'] + ('' if args['name'].endswith('.key') else '.key')))

        return True
