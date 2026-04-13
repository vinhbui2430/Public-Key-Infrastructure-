from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID

def generate_csr():
    # 1. The Client generates their OWN key pair
    # (They will guard the private_key with their life)
    client_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # 2. The Client defines who they are (Their Identity)
    subject_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"VN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Hanoi"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Hanoi"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Awesome Cryptography Project"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"client.awesomedemo.com"),
    ])

    # 3. The Client builds the "Passport Application" (CSR)
    # Notice we don't put the private key inside the builder, it automatically 
    # attaches the public key during the signing step below.
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject_name)

    # 4. The Magic Step: The Client SIGNS the CSR with their PRIVATE KEY.
    # This proves they own the key without revealing what the key is!
    csr = csr_builder.sign(
        private_key=client_private_key, 
        algorithm=hashes.SHA256()
    )

    # 5. Serialize the CSR so we can send it over the network to the RA
    pem_csr = csr.public_bytes(serialization.Encoding.PEM)
    
    return client_private_key, pem_csr

# The client saves the private key locally, and sends pem_csr to the RA!