from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

def verify_csr_request(pem_csr_data):
    print("RA: Receiving 'Passport Application' (CSR)...")
    
    # 1. Load the CSR from the bytes the client sent
    csr = x509.load_pem_x509_csr(pem_csr_data)
    
    # 2. Extract the public key from the CSR
    client_public_key = csr.public_key()
    print("Checking public key")
    print(client_public_key)
    # 3. The Math Check: Verify the signature!
    try:
        # We ask the public key object to verify if the signature on the CSR is valid
        # It checks if S^e (mod n) matches the hash of the CSR contents.
        print(client_public_key.verify(
        csr.signature,
        csr.tbs_certrequest_bytes,
        padding.PKCS1v15(),
        csr.signature_hash_algorithm,
    ))
        print("RA Check 1: Cryptographic Signature is VALID. Math checks out! ✅")
    except InvalidSignature:
        print("RA Check 1: FAILED! Someone tampered with this or used the wrong key. ❌")
        return False
        
    # 4. The Identity Check (Simulation)
    subject = csr.subject
    print(f"RA Check 2: Verifying identity for: {subject.rfc4514_string()}...")
    # (In real life, we'd check a database or send an email here)
    print("RA Check 2: Identity confirmed. ✅")
    
    # If both checks pass, the RA approves the CSR!
    print("RA: CSR Approved. Passing to the Big Boss (Root CA) for signing.")
    return csr

# Imagine we passed the pem_csr from our client.py to this function
# approved_csr = verify_csr_request(pem_csr)