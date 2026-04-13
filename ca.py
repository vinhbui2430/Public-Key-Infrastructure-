import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_root_ca():
    # 1. Generate the CA's Master Private Key
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096, # Root CAs usually use larger keys for extra security!
    )

    # 2. Define the CA's "Subject" (Who this certificate is about)
    # Since it's self-signed, the Subject and the Issuer are the exact same entity.
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"VN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Hanoi"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Hanoi"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Impregnable PKI"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"MyRootCA"),
    ])

    # 3. Build the Certificate
    cert_builder = x509.CertificateBuilder()
    cert_builder = cert_builder.subject_name(subject)
    cert_builder = cert_builder.issuer_name(issuer)
    cert_builder = cert_builder.public_key(ca_private_key.public_key())
    
    # Root certs are usually valid for a long time (e.g., 10 years)
    cert_builder = cert_builder.not_valid_before(datetime.datetime.utcnow())
    cert_builder = cert_builder.not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650) 
    )
    
    # Serial numbers must be unique
    cert_builder = cert_builder.serial_number(x509.random_serial_number())

    # IMPORTANT: We add an extension to explicitly say "I am a CA"
    cert_builder = cert_builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    )

    # 4. Sign the certificate with its OWN private key
    root_certificate = cert_builder.sign(
        private_key=ca_private_key, 
        algorithm=hashes.SHA256()
    )

    return ca_private_key, root_certificate
