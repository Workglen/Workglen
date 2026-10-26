#!/usr/bin/env python3
"""Generate synthetic public test vectors locally using Python cryptography.
Development only; no network, subprocess, deployed key or runtime dependency.
The embedded private test key is deliberately public and must never be deployed.
"""
import hashlib
import json
from pathlib import Path
import cryptography
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ed25519
import base64
import re

root = Path(__file__).resolve().parents[1]
vectors = []
for bits in (1024, 2048, 4096):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    message = b"Synthetic Workglen DKIM provider fixture\r\n" + bytes(range(256))
    for name, form in (("pkcs1", ser.PublicFormat.PKCS1), ("spki", ser.PublicFormat.SubjectPublicKeyInfo)):
        public = key.public_key().public_bytes(ser.Encoding.DER, form)
        for algorithm, digest in (("rsa-sha256", hashes.SHA256()), ("rsa-sha1", hashes.SHA1())):
            vectors.append(dict(label=f"rsa-{bits}-{name}-{algorithm}", kind="rsa", algorithm=algorithm,
                bits=bits, record="v=DKIM1; k=rsa; p=" + base64.b64encode(public).decode(),
                message=message.hex(), signature=key.sign(message, padding.PKCS1v15(), digest).hex()))
    if bits == 2048:
        private_test_key = key.private_bytes(ser.Encoding.DER, ser.PrivateFormat.PKCS8, ser.NoEncryption()).hex()
for i in range(32):
    key = ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f"public-test-seed-{i}".encode()).digest())
    public = key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    message = bytes(range(256))[:i * 7] + f"Synthetic test {i}".encode()
    vectors.append(dict(label=f"ed25519-{i}", kind="ed25519", algorithm="ed25519-sha256", bits=256,
        record="v=DKIM1; k=ed25519; p=" + base64.b64encode(public).decode(), message=message.hex(),
        signature=key.sign(hashlib.sha256(message).digest()).hex()))
lengths = [0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 1024, 4097, 1_000_000]

def canonical_header(line, mode):
    if mode == "simple":
        return line
    name, value = line.split(b":", 1)
    value = re.sub(rb"\r\n(?=[ \t])", b"", value[:-2])
    value = re.sub(rb"[ \t]+", b" ", value).strip(b" \t")
    return name.lower() + b":" + value + b"\r\n"

messages = []
rsa_key = ser.load_der_private_key(bytes.fromhex(private_test_key), password=None)
ed_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
headers = [b"From: Sender <sender@dkim.test>\r\n", b"To: Recipient <receiver@example.test>\r\n",
    b"Subject:\t Native \t provider\r\n\tcompatibility \r\n", b"Date: Tue, 20 Oct 2026 12:00:00 +0000\r\n",
    b"Message-ID: <synthetic@dkim.test>\r\n"]
body = b"First \t line \t\r\nSecond\tline\t\r\n\r\n\r\n"
for algorithm in ("rsa-sha256", "rsa-sha1", "ed25519-sha256"):
    for ch in ("simple", "relaxed"):
        for cb in ("simple", "relaxed"):
            lines = body.split(b"\r\n")
            if cb == "relaxed":
                lines = [re.sub(rb"[ \t]+", b" ", line).rstrip(b" \t") for line in lines]
            while lines and not lines[-1]: lines.pop()
            canonical_body = b"\r\n".join(lines) + b"\r\n"
            hash_fn = hashlib.sha1 if algorithm == "rsa-sha1" else hashlib.sha256
            bh = base64.b64encode(hash_fn(canonical_body).digest()).decode()
            dkim = f"DKIM-Signature: v=1; a={algorithm}; c={ch}/{cb}; d=dkim.test; s=test; h=from:to:subject:date:message-id; bh={bh}; b=".encode()
            signed = b"".join(canonical_header(line, ch) for line in headers) + canonical_header(dkim+b"\r\n", ch)[:-2]
            if algorithm.startswith("rsa"):
                signature = rsa_key.sign(signed, padding.PKCS1v15(), hashes.SHA1() if algorithm == "rsa-sha1" else hashes.SHA256())
                public = rsa_key.public_key().public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)
                kind = "rsa"
            else:
                signature = ed_key.sign(hashlib.sha256(signed).digest())
                public = ed_key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
                kind = "ed25519"
            raw = dkim + base64.b64encode(signature) + b"\r\n" + b"".join(headers) + b"\r\n" + body
            messages.append(dict(label=f"{algorithm}-{ch}-{cb}", raw=raw.decode(),
                record=f"v=DKIM1;k={kind};p="+base64.b64encode(public).decode()))
out = dict(provenance=f"Python cryptography {cryptography.__version__}; independent local test generation",
    warning="Synthetic fixtures only. The private_test_key is intentionally public, never deploy it.",
    private_test_key=private_test_key, vectors=vectors, messages=messages,
    hashes=[dict(length=n, sha1=hashlib.sha1(b'a'*n).hexdigest(), sha256=hashlib.sha256(b'a'*n).hexdigest()) for n in lengths])
target = root / "tests/fixtures/mailauth-crypto.json"
target.parent.mkdir(exist_ok=True)
target.write_text(json.dumps(out, indent=2) + "\n")
print(f"Wrote {len(vectors)} signature and {len(lengths)} hash vectors to {target}")
