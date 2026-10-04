"""AICL CA (research/14 s.5): a root CA the organization trusts, and one leaf certificate whose SAN list is every
intercepted provider host (plus the gateway's own names), so the gateway can terminate TLS for them.

    python -m aicl_gateway.ca init      create the root CA (data/ca/aicl-ca.pem + key) if missing
    python -m aicl_gateway.ca leaf      (re)issue the leaf for the policy's intercepted hosts
    python -m aicl_gateway.ca export    print the CA path and the install command per OS / runtime

The CA key never leaves the gateway host (file mode 0600 where the OS supports it). The leaf is reissued when
the policy's host list changes or it is within 2 days of expiry.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_CN = "AICL Control Layer Root CA"
LEAF_EXTRA = ["localhost", "aicl-gateway"]


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _write(path: Path, data: bytes, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if private:                       # created 0600 from the first byte (never briefly world-readable)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    else:
        path.write_bytes(data)


def init_ca(cert_path: str | Path, key_path: str | Path, days: int = 365, force: bool = False) -> x509.Certificate:
    cert_path, key_path = Path(cert_path), Path(key_path)
    if cert_path.exists() and key_path.exists() and not force:
        return x509.load_pem_x509_certificate(cert_path.read_bytes())
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_CN),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AICL")])
    now = _now()
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                         content_commitment=False, key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    _write(key_path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()), private=True)
    _write(cert_path, cert.public_bytes(serialization.Encoding.PEM))
    return cert


def _sans(hosts: list[str], ips: list[str]) -> list[x509.GeneralName]:
    out: list[x509.GeneralName] = [x509.DNSName(h) for h in dict.fromkeys(hosts + LEAF_EXTRA)]
    for ip in dict.fromkeys(ips + ["127.0.0.1"]):
        try:
            out.append(x509.IPAddress(ipaddress.ip_address(ip)))
        except ValueError:
            pass
    return out


def leaf_ips(cert: x509.Certificate) -> list[str]:
    try:
        return sorted(str(i) for i in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                      .get_values_for_type(x509.IPAddress))
    except x509.ExtensionNotFound:
        return []


def leaf_hosts(cert: x509.Certificate) -> list[str]:
    try:
        return sorted(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                      .get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        return []


def issue_leaf(ca_cert_path: str | Path, ca_key_path: str | Path, hosts: list[str], out_cert: str | Path,
               out_key: str | Path, ips: list[str] | None = None, days: int = 30) -> x509.Certificate:
    ca_cert = x509.load_pem_x509_certificate(Path(ca_cert_path).read_bytes())
    ca_key = serialization.load_pem_private_key(Path(ca_key_path).read_bytes(), password=None)
    key = ec.generate_private_key(ec.SECP256R1())
    now = _now()
    cn = hosts[0] if hosts else "aicl-gateway"
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName(_sans(list(hosts), list(ips or []))), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False, key_cert_sign=False,
                                         crl_sign=False, content_commitment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    _write(Path(out_key), key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()), private=True)
    # full chain: leaf + CA, so clients that only trust the root still build the path
    _write(Path(out_cert), cert.public_bytes(serialization.Encoding.PEM) + ca_cert.public_bytes(serialization.Encoding.PEM))
    return cert


def _signed_by(cert: x509.Certificate, root: x509.Certificate) -> bool:
    try:
        root.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        return True
    except Exception:  # noqa: BLE001 - a leaf from another (regenerated) CA must be reissued
        return False


def ensure(tls: dict, hosts: list[str], ips: list[str], root: Path | None = None) -> tuple[Path, Path]:
    """CA present (created once), leaf current for `hosts` -> (leaf chain path, leaf key path)."""
    base = root or Path.cwd()
    ca_cert, ca_key = base / tls["ca_cert"], base / tls["ca_key"]
    init_ca(ca_cert, ca_key)
    leaf_cert, leaf_key = ca_cert.parent / "aicl-leaf.pem", ca_cert.parent / "aicl-leaf.key"
    want = sorted(set(hosts + LEAF_EXTRA))
    want_ips = sorted(set(ips + ["127.0.0.1"]))
    root = x509.load_pem_x509_certificate(ca_cert.read_bytes())
    fresh = False
    if leaf_cert.exists() and leaf_key.exists():
        cur = x509.load_pem_x509_certificate(leaf_cert.read_bytes())
        fresh = (leaf_hosts(cur) == want and leaf_ips(cur) == want_ips and cur.issuer == root.subject
                 and _signed_by(cur, root) and cur.not_valid_after_utc - _now() > dt.timedelta(days=2))
    if not fresh:
        issue_leaf(ca_cert, ca_key, hosts, leaf_cert, leaf_key, ips=ips, days=int(tls.get("leaf_days", 30)))
    return leaf_cert, leaf_key


def publish(ca_cert: Path, out_dir: Path) -> Path:
    """Copy the root certificate (public) to a directory clients can read; the key stays private."""
    out_dir.mkdir(parents=True, exist_ok=True)
    dst = out_dir / "aicl-ca.pem"
    dst.write_bytes(Path(ca_cert).read_bytes())
    return dst


INSTALL = """AICL root CA: {ca}

Trust it on every client machine (once, as an administrator / via MDM or GPO in an organization):
  Windows   certutil -addstore -f Root "{ca}"            (current user only: certutil -user -addstore Root ...)
  macOS     sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "{ca}"
  Linux     sudo cp "{ca}" /usr/local/share/ca-certificates/aicl-ca.crt && sudo update-ca-certificates
Runtimes that keep their own trust store:
  Node / Claude Code   NODE_EXTRA_CA_CERTS="{ca}"
  Python (requests)    REQUESTS_CA_BUNDLE=<system bundle + aicl-ca.pem>     httpx / ssl: SSL_CERT_FILE=...
  Rust (Codex)         SSL_CERT_FILE=<system bundle + aicl-ca.pem>
Then point the client's DNS at the AICL resolver (DHCP option 6) and block direct egress (research/14 s.1).
"""


def main(argv: list[str] | None = None) -> int:
    from aicl_core.interception import interception_cfg, intercepted_hosts
    from aicl_core.policy import load_policy
    args = list(sys.argv[1:] if argv is None else argv)
    cmd = args[0] if args else "export"
    pol = load_policy(os.environ.get("AICL_POLICY") or "policy/policy.yaml")
    cfg = interception_cfg(pol.raw)
    tls = cfg["tls"]
    if cmd == "init":
        init_ca(tls["ca_cert"], tls["ca_key"], force="--force" in args)
        print(f"CA ready: {tls['ca_cert']}")
    elif cmd == "leaf":
        cert, _ = ensure(tls, intercepted_hosts(cfg), [cfg["dns"]["gateway_ip"]])
        print(f"leaf for {', '.join(intercepted_hosts(cfg))}: {cert}")
    elif cmd == "export":
        init_ca(tls["ca_cert"], tls["ca_key"])
        print(INSTALL.format(ca=Path(tls["ca_cert"]).resolve()))
    else:
        print("usage: python -m aicl_gateway.ca init [--force] | leaf | export", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
