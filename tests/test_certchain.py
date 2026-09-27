from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

import certchain

NOW = dt.datetime.now(dt.UTC)
AIA_URL = "http://ca.example.test/intermediate.crt"


@dataclass
class Issued:
    cert: x509.Certificate
    key: ec.EllipticCurvePrivateKey

    @property
    def pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)


def make_cert(
    subject: str,
    issuer: Issued | None = None,
    *,
    ca: bool = False,
    key: ec.EllipticCurvePrivateKey | None = None,
    sans: list[str] | None = None,
    aia: str | None = None,
    days: int = 365,
) -> Issued:
    key = key or ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer.cert.subject if issuer else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=1))
        .not_valid_after(NOW + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    if aia:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess(
                [x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(aia))]
            ),
            critical=False,
        )
    signer = issuer.key if issuer else key
    return Issued(builder.sign(signer, hashes.SHA256()), key)


@pytest.fixture
def pki(monkeypatch):
    root = make_cert("Test Root", ca=True)
    inter = make_cert("Test Intermediate", root, ca=True)
    leaf = make_cert("www.example.test", inter, sans=["www.example.test", "*.example.test"], aia=AIA_URL)
    monkeypatch.setattr(certchain, "load_trust_store", lambda: [root.cert])
    return root, inter, leaf


# ───────── chain building ─────────


def test_build_chain_fixes_order(pki):
    root, inter, leaf = pki
    report = certchain.Report()
    chain = certchain.build_chain([inter.cert, leaf.cert], report)
    assert chain == [leaf.cert, inter.cert]
    assert any(c.title == "Fixed the order" for c in report.checks)


def test_build_chain_removes_duplicates(pki):
    _, inter, leaf = pki
    report = certchain.Report()
    chain = certchain.build_chain([leaf.cert, inter.cert, inter.cert], report)
    assert chain == [leaf.cert, inter.cert]
    assert any(c.title == "Removed duplicates" for c in report.checks)


def test_build_chain_skips_unrelated(pki):
    _, inter, leaf = pki
    stranger = make_cert("Unrelated CA", ca=True)
    report = certchain.Report()
    chain = certchain.build_chain([leaf.cert, inter.cert, stranger.cert], report)
    assert chain == [leaf.cert, inter.cert]
    assert any(c.title == "Certificate not part of the chain" for c in report.checks)


# ───────── verification ─────────


def test_verify_clean_chain(pki):
    _, inter, leaf = pki
    report = certchain.Report()
    tp = certchain.verify([leaf.cert, inter.cert], leaf.key, "www.example.test", report)
    assert tp is not None and tp.index == 1
    assert report.errors == 0
    assert report.warnings == 0


def test_verify_missing_intermediate(pki):
    _, _, leaf = pki
    report = certchain.Report()
    assert certchain.verify([leaf.cert], None, None, report) is None
    assert any(c.title == "Missing intermediate certificate" and c.ok is False for c in report.checks)


def test_verify_key_mismatch(pki):
    _, inter, leaf = pki
    report = certchain.Report()
    certchain.verify([leaf.cert, inter.cert], inter.key, None, report)
    assert any(c.title == "Private key does NOT match" for c in report.checks)


def test_verify_hostname_mismatch(pki):
    _, inter, leaf = pki
    report = certchain.Report()
    certchain.verify([leaf.cert, inter.cert], None, "a.b.example.test", report)
    assert report.errors == 1


def test_verify_root_in_file_is_a_warning(pki):
    root, inter, leaf = pki
    report = certchain.Report()
    certchain.verify([leaf.cert, inter.cert, root.cert], None, None, report)
    assert report.errors == 0
    assert any(c.title == "Root in the chain" for c in report.checks)


def test_verify_expiring_soon(pki, monkeypatch):
    root, inter, _ = pki
    leaf = make_cert("short.example.test", inter, sans=["short.example.test"], days=5)
    report = certchain.Report()
    certchain.verify([leaf.cert, inter.cert], None, None, report)
    assert any(c.title.startswith("Expires soon") for c in report.checks)


def test_cross_signed_root_is_trusted(monkeypatch):
    """leaf ← intermediate ← new root (cross-signed by old root) ← old root (cross-signed by ancient root).

    Only the new self-signed root is in the trust store — like Certum Trusted Root CA.
    """
    ancient = make_cert("Ancient Root", ca=True)
    old_root_self = make_cert("Old Root", ca=True)
    old_root_cross = make_cert("Old Root", ancient, ca=True, key=old_root_self.key)
    new_root_self = make_cert("New Root", ca=True)
    new_root_cross = make_cert("New Root", old_root_self, ca=True, key=new_root_self.key)
    inter = make_cert("Intermediate", new_root_self, ca=True)
    leaf = make_cert("site.example.test", inter, sans=["site.example.test"])
    monkeypatch.setattr(certchain, "load_trust_store", lambda: [new_root_self.cert])

    report = certchain.Report()
    chain = certchain.build_chain([leaf.cert, inter.cert, new_root_cross.cert, old_root_cross.cert], report)
    assert len(chain) == 4
    tp = certchain.verify(chain, None, None, report)
    # the intermediate is already signed by a trusted root — both cross-signs are extras
    assert tp is not None and tp.index == 1
    assert tp.extras(chain) == [new_root_cross.cert, old_root_cross.cert]
    assert report.errors == 0


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("www.example.test", True),
        ("api.example.test", True),
        ("WWW.EXAMPLE.TEST.", True),
        ("example.test", False),
        ("a.b.example.test", False),
        ("www.example.org", False),
    ],
)
def test_hostname_matches(host, expected):
    assert certchain.hostname_matches(host, ["www.example.test", "*.example.test"]) is expected


# ───────── parsing & writing ─────────


def test_parse_der_and_pkcs7(pki):
    _, inter, leaf = pki
    der = leaf.cert.public_bytes(serialization.Encoding.DER)
    assert certchain.parse_certs(der, "der") == [leaf.cert]
    p7 = pkcs7.serialize_certificates([leaf.cert, inter.cert], serialization.Encoding.DER)
    assert set(certchain.parse_certs(p7, "p7")) == {leaf.cert, inter.cert}  # PKCS#7 is an unordered SET
    p7pem = pkcs7.serialize_certificates([leaf.cert, inter.cert], serialization.Encoding.PEM)
    assert set(certchain.parse_certs(p7pem, "p7pem")) == {leaf.cert, inter.cert}


def test_parse_rejects_private_key(pki):
    _, _, leaf = pki
    pem = leaf.key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    with pytest.raises(certchain.CertError, match="private key"):
        certchain.parse_certs(pem, "key.pem")


def test_write_chain_never_glues_lines(pki, tmp_path):
    _, inter, leaf = pki
    out = tmp_path / "fullchain.crt"
    certchain.write_chain([leaf.cert, inter.cert], out)
    text = out.read_text()
    assert "----------" not in text
    assert text.endswith("\n")
    assert certchain.load_certs(out) == [leaf.cert, inter.cert]


# ───────── AIA ─────────


def test_complete_chain_fetches_via_aia(pki, monkeypatch):
    _, inter, leaf = pki
    monkeypatch.setattr(certchain, "download_certs", lambda url: [inter.cert] if url == AIA_URL else [])
    report = certchain.Report()
    chain = certchain.complete_chain([leaf.cert], report, lambda *_: True, from_server=False)
    assert chain == [leaf.cert, inter.cert]
    assert any(c.title == "Fetched intermediate via AIA" for c in report.checks)


def test_complete_chain_rejects_impostor(pki, monkeypatch):
    _, _, leaf = pki
    impostor = make_cert("Test Intermediate", ca=True)  # same name, different key
    monkeypatch.setattr(certchain, "download_certs", lambda url: [impostor.cert])
    report = certchain.Report()
    chain = certchain.complete_chain([leaf.cert], report, lambda *_: True, from_server=False)
    assert chain == [leaf.cert]
    assert any(c.title == "Fetched certificate did not sign ours" for c in report.checks)


def test_complete_chain_respects_refusal(pki, monkeypatch):
    _, _, leaf = pki
    monkeypatch.setattr(certchain, "download_certs", lambda url: pytest.fail("must not download"))
    chain = certchain.complete_chain([leaf.cert], certchain.Report(), lambda *_: False, from_server=False)
    assert chain == [leaf.cert]


# ───────── guessing & CLI ─────────


def write_pki_files(tmp_path: Path, pki) -> None:
    root, inter, leaf = pki
    (tmp_path / "certificate.crt").write_bytes(leaf.pem)
    (tmp_path / "intermediate.crt").write_bytes(inter.pem)
    (tmp_path / "ca-bundle.crt").write_bytes(inter.pem + root.pem)
    (tmp_path / "private.key").write_bytes(
        leaf.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    (tmp_path / "other.key").write_bytes(
        inter.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )


def test_guess_files(pki, tmp_path):
    write_pki_files(tmp_path, pki)
    g = certchain.guess_files(tmp_path, exclude=set())
    assert g.cert == tmp_path / "certificate.crt"
    assert g.intermediates == [tmp_path / "intermediate.crt"]
    assert g.key == tmp_path / "private.key"
    assert g.key_matches


def test_cli_automatic(pki, tmp_path, monkeypatch):
    write_pki_files(tmp_path, pki)
    monkeypatch.chdir(tmp_path)
    assert certchain.main(["-y", "--no-fetch", "-n", "www.example.test"]) == 0
    _, inter, leaf = pki
    assert certchain.load_certs(tmp_path / "fullchain.crt") == [leaf.cert, inter.cert]


def test_cli_check_reports_errors(pki, tmp_path, monkeypatch):
    _, _, leaf = pki
    (tmp_path / "leaf.crt").write_bytes(leaf.pem)
    monkeypatch.chdir(tmp_path)
    assert certchain.main(["--check", "leaf.crt", "--no-fetch"]) == 1
