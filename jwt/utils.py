import base64
import binascii
import re
from typing import Union
try:
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
except ModuleNotFoundError:
    pass
_PEMS = {b'CERTIFICATE', b'TRUSTED CERTIFICATE', b'PRIVATE KEY', b'PUBLIC KEY', b'ENCRYPTED PRIVATE KEY', b'OPENSSH PRIVATE KEY', b'DSA PRIVATE KEY', b'RSA PRIVATE KEY', b'RSA PUBLIC KEY', b'EC PRIVATE KEY', b'DH PARAMETERS', b'NEW CERTIFICATE REQUEST', b'CERTIFICATE REQUEST', b'SSH2 PUBLIC KEY', b'SSH2 ENCRYPTED PRIVATE KEY', b'X509 CRL'}
_PEM_RE = re.compile(b'----[- ]BEGIN (' + b'|'.join(_PEMS) + b')[- ]----\r?\n.+?\r?\n----[- ]END \\1[- ]----\r?\n?', re.DOTALL)
_CERT_SUFFIX = b'-cert-v01@openssh.com'
_SSH_PUBKEY_RC = re.compile(b'\\A(\\S+)[ \\t]+(\\S+)')
_SSH_KEY_FORMATS = [b'ssh-ed25519', b'ssh-rsa', b'ssh-dss', b'ecdsa-sha2-nistp256', b'ecdsa-sha2-nistp384', b'ecdsa-sha2-nistp521']