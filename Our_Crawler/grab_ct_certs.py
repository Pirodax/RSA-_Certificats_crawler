import base64, struct, os
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

LOG_BASE = "https://ct.googleapis.com/logs/us1/argon2024"
START = 0
COUNT = 20  # commence petit; tu pourras augmenter ensuite

os.makedirs("certs_der", exist_ok=True)

def parse_tls_cert_chain(tls_bytes: bytes):
    certs = []
    if len(tls_bytes) < 3:
        return certs
    total_len = int.from_bytes(tls_bytes[0:3], "big")
    pos, end = 3, 3 + total_len
    end = min(end, len(tls_bytes))
    while pos + 3 <= end:
        clen = int.from_bytes(tls_bytes[pos:pos+3], "big")
        pos += 3
        if pos + clen > len(tls_bytes):
            break
        certs.append(tls_bytes[pos:pos+clen])
        pos += clen
    return certs

def main():
    end = START + COUNT - 1
    url = f"{LOG_BASE}/ct/v1/get-entries?start={START}&end={end}"
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    entries = r.json().get("entries", [])
    print(f"Entrées récupérées: {len(entries)}")

    saved = 0
    for i, e in enumerate(entries, start=START):
        extra_b64 = e.get("extra_data")
        if not extra_b64:
            continue
        chain_bytes = base64.b64decode(extra_b64)
        ders = parse_tls_cert_chain(chain_bytes)

        for j, der in enumerate(ders):
            try:
                cert = x509.load_der_x509_certificate(der)
            except Exception:
                continue

            subj = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()

            # Empreinte SPKI (utile pour le dédoublonnage)
            spki = cert.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            h = hashes.Hash(hashes.SHA256())
            h.update(spki)
            spki_fpr = h.finalize().hex()[:16]

            print(f"- entry {i}[{j}] subj={subj} | issuer={issuer} | spki={spki_fpr}")

            with open(f"certs_der/entry_{i}_{j}.der", "wb") as f:
                f.write(der)
            saved += 1

    print(f"Certificats DER sauvegardés: {saved}")

if __name__ == "__main__":
    main()
