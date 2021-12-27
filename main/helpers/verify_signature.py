from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from sign.settings import STATIC_ROOT


def verify_signature(document, signature):
    signature_data = signature.read()
    signature.close()

    sign_file = open(document.file.path, 'rb')
    sign_file_data = sign_file.read()
    sign_file.close()

    cert = open(STATIC_ROOT + 'main/certificate.pem', 'rb')
    cert_data = cert.read()
    cert.close()
    certificate = x509.load_pem_x509_certificate(cert_data)

    public_key = certificate.public_key()
    try:
        if public_key.verify(signature_data, sign_file_data, ec.ECDSA(hashes.SHA256())) == None:
            return True
    except:
        pass
    return False