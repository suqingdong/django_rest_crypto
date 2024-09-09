import json
import base64

from Cryptodome.Cipher import AES
from Cryptodome.Util import Padding


class EncryptData(object):
    def __init__(self, data, key):
        self.text = self.check_data(data)
        self.key = key

    def check_mode(self, mode):
        mode = mode.upper().replace('MODE_', '')
        if mode not in self.avail_modes:
            raise Exception(f'unsupported mode: "{mode}", choose from {list(self.avail_modes.keys())}')
        return mode

    def check_data(self, data):
        try:
            text = json.dumps(data, ensure_ascii=False).encode()
        except:
            text = str(data).encode()
        return text

    @property
    def avail_modes(self):
        return {
            each.replace('MODE_', ''): getattr(AES, each)
            for each in dir(AES)
            if each.startswith('MODE_')
        }

    def encrypt(self, mode, **kwargs):
        mode = self.check_mode(mode)
        func = getattr(self, 'encrypt_' + mode.lower())
        res = func(**kwargs)
        return dict(res, mode=mode)

    def encrypt_ecb(self):
        cipher = AES.new(self.key, AES.MODE_ECB)

        pad_data = Padding.pad(self.text, AES.block_size)
        cy_bytes = cipher.encrypt(pad_data)
        ct = base64.b64encode(cy_bytes).decode()

        return {'ciphertext': ct}

    def encrypt_cbc(self, iv=None):
        pad_data = Padding.pad(self.text, AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        iv = cipher.iv
        cy_bytes = cipher.encrypt(pad_data)
        ct = base64.b64encode(cy_bytes).decode()

        return {'ciphertext': ct, 'iv': base64.b64encode(iv).decode()}

    def encrypt_ctr(self, nonce=None):
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
        nonce = cipher.nonce
        cy_bytes = cipher.encrypt(self.text)
        ct = base64.b64encode(cy_bytes).decode()
        return {'ciphertext': ct, 'iv': base64.b64encode(nonce).decode()}

    def encrypt_cfb(self, iv=None):
        cipher = AES.new(self.key, AES.MODE_CFB, iv=iv)
        iv = cipher.iv
        cy_bytes = cipher.encrypt(self.text)
        ct = base64.b64encode(cy_bytes).decode()
        return {'ciphertext': ct, 'iv': base64.b64encode(iv).decode()}

    def encrypt_ofb(self, iv=None):
        cipher = AES.new(self.key, AES.MODE_OFB, iv=iv)
        iv = cipher.iv
        cy_bytes = cipher.encrypt(self.text)
        ct = base64.b64encode(cy_bytes).decode()
        return {'ciphertext': ct, 'iv': base64.b64encode(iv).decode()}

    def encrypt_ccm(self, nonce=None):
        cipher = AES.new(self.key, AES.MODE_CCM, nonce=nonce)
        nonce = cipher.nonce
        cy_bytes = cipher.encrypt(self.text)
        ct = base64.b64encode(cy_bytes).decode()
        return {'ciphertext': ct, 'nonce': base64.b64encode(nonce).decode()}

    def encrypt_eax(self, nonce=None):
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        nonce = cipher.nonce
        cy_bytes = cipher.encrypt(self.text)
        ct = base64.b64encode(cy_bytes).decode()
        return {'ciphertext': ct, 'nonce': base64.b64encode(nonce).decode()}

    def encrypt_gcm(self, nonce=None):
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        nonce = cipher.nonce
        cy_bytes = cipher.encrypt(self.text)
        ct = base64.b64encode(cy_bytes).decode()
        return {'ciphertext': ct, 'nonce': base64.b64encode(nonce).decode()}

    def encrypt_siv(self, nonce=None):
        cipher = AES.new(self.key, AES.MODE_SIV, nonce=nonce)
        cy_bytes, tag = cipher.encrypt_and_digest(self.text)
        ct = base64.b64encode(cy_bytes).decode()
        return {'ciphertext': ct, 'nonce': base64.b64encode(nonce).decode(), 'tag': base64.b64encode(tag).decode()}

    def encrypt_ocb(self, nonce=None):
        cipher = AES.new(self.key, AES.MODE_OCB, nonce=nonce)
        cy_bytes, tag = cipher.encrypt_and_digest(self.text)
        ct = base64.b64encode(cy_bytes).decode()
        return {'ciphertext': ct, 'nonce': base64.b64encode(nonce).decode(), 'tag': base64.b64encode(tag).decode()}


if __name__ == "__main__":
    key = b'1234567890ABCDEF' * 2
    data = 'hello world'
    iv = AES.get_random_bytes(16)
    nonce = AES.get_random_bytes(16)

    ed = EncryptData(data, key)
    
    print(ed.encrypt(mode='ECB'))
    print(ed.encrypt(mode='CBC'))
    print(ed.encrypt(mode='CTR'))
    print(ed.encrypt(mode='CFB'))
    print(ed.encrypt(mode='OFB'))
    print(ed.encrypt(mode='CCM'))
    print(ed.encrypt(mode='EAX'))
    print(ed.encrypt(mode='GCM'))

    print(ed.encrypt(mode='SIV', nonce=nonce))
    print(ed.encrypt(mode='OCB', nonce=nonce[:15]))
