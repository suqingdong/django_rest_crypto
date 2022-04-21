# Crypto Middleware for DjangoRestFramework

### Installation
```bash
python3 -m pip install django_rest_crypto
```


### Usage
```python
# settings.py

MIDDLEWARES += [
    'django_rest_crypto.middlewares.EncryptData',
]


ENCRYPT_KEY = b'1234567890ABCDE'    # 16, 24 or 32 bytes, required
ENCRYPT_MODE = 'CBC'                # default
ENCRYPT_IV = b'1234567890ABCDE'     # optional
ENCRYPT_NONCE = b'1234567890ABCDE'  # optional
```
