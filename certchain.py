#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "rich>=13",
#     "cryptography>=42",
#     "certifi",
# ]
# ///
"""
🔐 certchain — build a correct fullchain (leaf + intermediates) for nginx & friends,
and verify that everything fits together.

Usage:
    certchain.py                                   # interactive (guesses files, asks the rest)
    certchain.py -y                                # fully automatic in the current directory
    certchain.py -c cert.crt -i intermediate.crt -k private.key -o fullchain.crt
    certchain.py --check fullchain.crt -k private.key   # verify an existing file only
    certchain.py --host example.com                # inspect the chain a live server sends
"""

from __future__ import annotations

import argparse
import datetime as dt
import functools
import socket
import ssl
import sys
import urllib.error
import urllib.request
import warnings
from dataclasses import dataclass, field
from pathlib import Path

import certifi
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

__version__ = "0.1.0"

console = Console()

BANNER = r"""
   ___          _    ___ _         _
  / __|___ _ _| |_ / __| |_  __ _(_)_ _
 | (__/ -_) '_|  _| (__| ' \/ _` | | ' \
  \___\___|_|  \__|\___|_||_\__,_|_|_||_|
"""

CERT_EXTS = {".crt", ".pem", ".cer", ".der", ".ca-bundle", ".bundle", ".p7b", ".p7c"}
KEY_EXTS = {".key", ".pem"}

# file-name guessing
CERT_WORDS = ("cert", "certificate", "crt")
KEY_WORDS = ("key",)
CHAIN_WORDS = ("intermediate", "inter", "chain", "bundle", "full", "root")
MAX_FILE_SIZE = 1_000_000
EXPIRY_WARNING_DAYS = 21


# ───────────────────────────── models ─────────────────────────────


@dataclass
class Check:
    ok: bool | None  # None = warning
    title: str
    detail: str = ""


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)

    def add(self, ok: bool | None, title: str, detail: str = "") -> None:
        self.checks.append(Check(ok, title, detail))

    @property
    def errors(self) -> int:
        return sum(1 for c in self.checks if c.ok is False)

    @property
    def warnings(self) -> int:
        return sum(1 for c in self.checks if c.ok is None)


class CertError(Exception):
    pass


# ───────────────────────────── X.509 helpers ─────────────────────────────


def cn(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if attrs:
        return str(attrs[0].value)
    orgs = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    return str(orgs[0].value) if orgs else name.rfc4514_string()


def is_ca(cert: x509.Certificate) -> bool:
    try:
        return cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
    except x509.ExtensionNotFound:
        return False  # no basicConstraints = not a CA (RFC 5280)


def is_self_signed(cert: x509.Certificate) -> bool:
    if cert.subject != cert.issuer:
        return False
    try:
        cert.verify_directly_issued_by(cert)
    except (InvalidSignature, ValueError, TypeError):
        return False  # names match but the signature does not — not self-signed
    return True


def sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound:
        return []  # legacy cert without SAN — reported by verify()
    return [str(v) for v in ext.get_values_for_type(x509.DNSName)] + [
        str(v) for v in ext.get_values_for_type(x509.IPAddress)
    ]


def fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex(":").upper()[:23] + "…"


def issued_by(child: x509.Certificate, parent: x509.Certificate) -> bool:
    if child.issuer != parent.subject:
        return False
    try:
        child.verify_directly_issued_by(parent)
    except (InvalidSignature, ValueError, TypeError):
        return False  # same name, different key — not the real issuer
    return True


def parse_certs(data: bytes, label: str) -> list[x509.Certificate]:
    """PEM (one or many), DER or PKCS#7 (.p7b/.p7c) — CAs ship all of them."""
    if b"-----BEGIN" in data:
        if b"PRIVATE KEY-----" in data and b"CERTIFICATE-----" not in data:
            raise CertError(f"{label} is a private key, not a certificate 🙃")
        try:
            if b"-----BEGIN PKCS7-----" in data:
                certs = pkcs7.load_pem_pkcs7_certificates(data)
            else:
                certs = x509.load_pem_x509_certificates(data)
        except ValueError as e:
            raise CertError(f"Cannot parse PEM in {label}: {e}") from e
    else:
        try:
            certs = [x509.load_der_x509_certificate(data)]
        except ValueError as der_err:
            try:
                certs = pkcs7.load_der_pkcs7_certificates(data)
            except ValueError as e:
                raise CertError(f"{label} is neither PEM, DER nor PKCS#7 ({der_err}; {e})") from e
    if not certs:
        raise CertError(f"No certificates in {label}")
    return certs


def load_certs(path: Path) -> list[x509.Certificate]:
    if not path.is_file():
        raise CertError(f"File not found: {path}")
    return parse_certs(path.read_bytes(), path.name)


def load_key(path: Path):
    if not path.is_file():
        raise CertError(f"File not found: {path}")
    data = path.read_bytes()
    try:
        return serialization.load_pem_private_key(data, password=None)
    except TypeError:
        pwd = Prompt.ask("🔑 The key is encrypted — passphrase", password=True)
        try:
            return serialization.load_pem_private_key(data, password=pwd.encode())
        except ValueError as e:
            raise CertError(f"Wrong passphrase or corrupted key: {e}") from e
    except ValueError:
        try:
            return serialization.load_der_private_key(data, password=None)
        except ValueError as e:
            raise CertError(f"{path.name} does not look like a private key: {e}") from e


@functools.cache
def load_trust_store() -> list[x509.Certificate]:
    # certifi ships an old root with a negative serial number — not our problem, silence only that
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        return x509.load_pem_x509_certificates(Path(certifi.where()).read_bytes())


def pub_bytes(obj) -> bytes:
    return obj.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


# ───────────────────────────── AIA: fetching missing intermediates ─────────────────────────────


def aia_issuer_urls(cert: x509.Certificate) -> list[str]:
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    except x509.ExtensionNotFound:
        return []  # the cert does not say where its issuer lives — nothing to fetch
    return [
        d.access_location.value
        for d in aia
        if d.access_method == AuthorityInformationAccessOID.CA_ISSUERS
        and isinstance(d.access_location, x509.UniformResourceIdentifier)
    ]


def download_certs(url: str) -> list[x509.Certificate]:
    if not url.lower().startswith(("http://", "https://")):
        raise CertError(f"Unsupported URL scheme: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": f"certchain/{__version__}"})  # noqa: S310 — scheme checked
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 — scheme checked above
        data = resp.read(MAX_FILE_SIZE)
    return parse_certs(data, url)


def complete_chain(chain: list[x509.Certificate], report: Report, allow, from_server: bool) -> list[x509.Certificate]:
    """Fetch missing intermediates via AIA until the chain reaches a trusted root.

    Downloads usually go over plain HTTP; that is fine because every fetched certificate
    must cryptographically sign the one below it, or it is rejected.
    """
    for _ in range(4):  # more than 4 intermediate levels does not happen in practice
        top = chain[-1]
        if is_self_signed(top) or trust_point(chain) is not None:
            return chain
        urls = aia_issuer_urls(top)
        if not urls or not allow(top, urls[0]):
            return chain
        parent = None
        for url in urls:
            with console.status(f"🌐 Fetching issuer from [bold]{url}[/]…", spinner="earth"):
                try:
                    fetched = download_certs(url)
                except (urllib.error.URLError, OSError, CertError) as e:
                    report.add(None, "Could not fetch issuer", f"{url}: {e}")
                    continue
            parent = next((c for c in fetched if issued_by(top, c)), None)
            if parent is None:
                report.add(False, "Fetched certificate did not sign ours", url)
                continue
            break
        if parent is None:
            return chain
        if is_self_signed(parent):
            return chain  # got a root — it does not belong in the file
        if from_server:
            report.add(False, "Server does NOT send the intermediate", f"missing: {cn(parent.subject)}")
        report.add(True, "Fetched intermediate via AIA", f"{cn(parent.subject)} ← {url}")
        chain.append(parent)
    return chain


# ───────────────────────────── file guessing ─────────────────────────────


@dataclass
class Guess:
    cert: Path | None = None
    intermediates: list[Path] = field(default_factory=list)
    key: Path | None = None
    key_matches: bool = False


def peek_certs(path: Path) -> list[x509.Certificate] | None:
    try:
        return load_certs(path)
    except CertError:
        return None  # not a certificate — while guessing that is simply a "no"


def peek_key(path: Path):
    data = path.read_bytes()
    if b"PRIVATE KEY" not in data:
        return None
    try:
        return serialization.load_pem_private_key(data, password=None)
    except TypeError:
        return None  # encrypted — cannot compare without the passphrase, asked for later
    except ValueError:
        return None  # corrupted / not a key — while guessing we just skip it


def name_has(path: Path, words: tuple[str, ...]) -> bool:
    n = path.name.lower()
    return any(w in n for w in words)


def guess_files(directory: Path, exclude: set[Path]) -> Guess:
    files = [
        p
        for p in sorted(directory.iterdir())
        if p.is_file() and p.resolve() not in exclude and p.stat().st_size < MAX_FILE_SIZE
    ]
    g = Guess()

    parsed = {
        p: c for p in files if (p.suffix.lower() in CERT_EXTS or name_has(p, CERT_WORDS)) and (c := peek_certs(p))
    }

    # leaf: name contains cert/certificate/crt and the file holds a non-CA certificate;
    # prefer single-cert files and names that do not look like a chain
    leafs = [p for p, cs in parsed.items() if name_has(p, CERT_WORDS) and any(not is_ca(c) for c in cs)]
    if not leafs:
        leafs = [p for p, cs in parsed.items() if any(not is_ca(c) for c in cs)]
    if not leafs:
        return g
    leafs.sort(key=lambda p: (name_has(p, CHAIN_WORDS), len(parsed[p]), p.name))
    g.cert = leafs[0]
    leaf = next(c for c in parsed[g.cert] if not is_ca(c))

    # intermediates: CA-only files that actually extend the chain from our leaf,
    # preferring intermediate-looking names and files with fewer certificates
    ca_files = {p: cs for p, cs in parsed.items() if p != g.cert and all(is_ca(c) for c in cs)}
    ca_files = dict(sorted(ca_files.items(), key=lambda kv: (not name_has(kv[0], CHAIN_WORDS), len(kv[1]), kv[0].name)))
    have = list(parsed[g.cert])
    current = have[-1] if len(have) > 1 else leaf
    for _ in range(4):
        hit = next(((p, c) for p, cs in ca_files.items() for c in cs if issued_by(current, c)), None)
        if hit is None or is_self_signed(hit[1]):
            break
        if hit[0] not in g.intermediates:
            g.intermediates.append(hit[0])
        current = hit[1]

    # key: name contains "key"; the one matching the certificate wins
    keys = [p for p in files if name_has(p, KEY_WORDS) and p not in parsed]
    for p in keys:
        k = peek_key(p)
        if k is not None and pub_bytes(k) == pub_bytes(leaf):
            g.key, g.key_matches = p, True
            break
    else:
        if len(keys) == 1:
            g.key = keys[0]
    return g


def show_guess(g: Guess) -> None:
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column()
    table.add_column(style="bold")
    table.add_column(style="dim")
    table.add_row("📄 certificate", g.cert.name if g.cert else "—", "")
    table.add_row(
        "🔗 intermediate",
        ", ".join(p.name for p in g.intermediates) or "—",
        "" if g.intermediates else "will try to fetch via AIA 🌐",
    )
    table.add_row(
        "🔑 key",
        g.key.name if g.key else "—",
        "matches the certificate ✨" if g.key_matches else ("not checked" if g.key else ""),
    )
    console.print(
        Panel(table, title="🔮 Guessing files in the current directory", border_style="magenta", box=box.ROUNDED)
    )


# ───────────────────────────── chain logic ─────────────────────────────


def build_chain(certs: list[x509.Certificate], report: Report) -> list[x509.Certificate]:
    """Find the leaf and put everything else in the right order."""
    # drop duplicates (people do paste the same intermediate twice)
    uniq: dict[bytes, x509.Certificate] = {}
    for c in certs:
        uniq.setdefault(c.fingerprint(hashes.SHA256()), c)
    if len(uniq) < len(certs):
        report.add(None, "Removed duplicates", f"{len(certs) - len(uniq)} repeated certificate(s)")
    pool = list(uniq.values())

    leaves = [c for c in pool if not is_ca(c)]
    if len(leaves) != 1:
        # fallback: the one nobody else in the pool was issued by
        leaves = [c for c in pool if not any(issued_by(o, c) for o in pool if o is not c)]
    if len(leaves) != 1:
        raise CertError(f"Cannot tell which certificate is the leaf ({len(leaves)} candidates)")

    chain = [leaves[0]]
    rest = [c for c in pool if c is not leaves[0]]
    while rest:
        parent = next((c for c in rest if issued_by(chain[-1], c)), None)
        if parent is None:
            break
        chain.append(parent)
        rest.remove(parent)

    for orphan in rest:
        report.add(None, "Certificate not part of the chain", f"{cn(orphan.subject)} — skipped")
    if certs[0].fingerprint(hashes.SHA256()) != chain[0].fingerprint(hashes.SHA256()):
        report.add(None, "Fixed the order", "leaf moved to the top")
    return chain


@dataclass
class TrustPoint:
    index: int  # position in the chain of the first certificate signed by a trusted root
    anchor: x509.Certificate  # that root, from the trust store

    def extras(self, chain: list[x509.Certificate]) -> list[x509.Certificate]:
        """Certificates past the trust point — cross-signs for legacy clients (excluding a root)."""
        return [c for c in chain[self.index + 1 :] if not is_self_signed(c)]


def trust_point(chain: list[x509.Certificate]) -> TrustPoint | None:
    """Walk up from the leaf and stop at the first certificate a client trusts.

    A chain does not have to end at a root from the store: CAs often append cross-signs
    (the same root signed by an older root) for the benefit of old clients. A cross-sign
    shares name and key with the trusted root, so the certificate below it already
    verifies against the store — everything above that point is optional.
    """
    store = load_trust_store()
    for i, c in enumerate(chain):
        issuer = next((r for r in store if issued_by(c, r)), None)
        if issuer is not None:
            return TrustPoint(i, issuer)
    return None


def hostname_matches(host: str, names: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for n in names:
        n = n.lower()
        if n == host:
            return True
        if n.startswith("*.") and host.count(".") == n.count(".") and host.endswith(n[1:]):
            return True
    return False


def verify(chain: list[x509.Certificate], key, hostname: str | None, report: Report) -> TrustPoint | None:
    now = dt.datetime.now(dt.UTC)
    leaf = chain[0]

    # validity dates
    for c in chain:
        left = c.not_valid_after_utc - now
        name = cn(c.subject)
        if c.not_valid_before_utc > now:
            report.add(False, f"Not yet valid: {name}", f"from {c.not_valid_before_utc:%Y-%m-%d}")
        elif left.total_seconds() < 0:
            report.add(False, f"EXPIRED: {name}", f"{c.not_valid_after_utc:%Y-%m-%d}")
        elif left.days < EXPIRY_WARNING_DAYS:
            report.add(None, f"Expires soon: {name}", f"{left.days} days left")
        elif c is leaf:
            report.add(True, "Certificate valid", f"until {c.not_valid_after_utc:%Y-%m-%d} ({left.days} days)")

    # signatures (build_chain only links certs whose signatures verify)
    for child, parent in zip(chain, chain[1:], strict=False):
        report.add(True, "Signature OK", f"{cn(child.subject)} ← {cn(parent.subject)}")

    if len(chain) > 1 and is_self_signed(chain[-1]):
        report.add(None, "Root in the chain", "unnecessary — clients already have it")

    # trust anchor
    top = chain[-1]
    tp = trust_point(chain)
    if tp is not None:
        report.add(True, "Chain leads to a trusted root", cn(tp.anchor.subject))
        extras = tp.extras(chain)
        if extras:
            report.add(
                None,
                "Cross-sign for legacy clients",
                f"{', '.join(cn(x.subject) for x in extras)} — modern clients don't need it, keeping it is harmless",
            )
    elif is_self_signed(top):
        report.add(False, "UNKNOWN root", f"{cn(top.subject)} is not in the Mozilla trust store")
    elif len(chain) == 1:
        report.add(False, "Missing intermediate certificate", f"issuer: {cn(top.issuer)}")
    else:
        report.add(False, "Broken chain", f"no issuer for: {cn(top.subject)}")

    # private key
    if key is not None:
        if pub_bytes(key) == pub_bytes(leaf):
            report.add(True, "Private key matches the certificate", type(key).__name__.replace("_", ""))
        else:
            report.add(False, "Private key does NOT match", "nginx will refuse to start with this pair")

    # host name
    names = sans(leaf)
    if not names:
        report.add(False, "No SAN", "modern browsers reject such certificates")
    if hostname:
        if hostname_matches(hostname, names):
            report.add(True, f"{hostname} matches", "")
        else:
            report.add(False, f"{hostname} does NOT match", ", ".join(names))
    return tp


# ───────────────────────────── presentation ─────────────────────────────


def show_chain(chain: list[x509.Certificate], tp: TrustPoint | None) -> None:
    now = dt.datetime.now(dt.UTC)

    def node(c: x509.Certificate, label: str, style: str) -> Text:
        days = (c.not_valid_after_utc - now).days
        color = "red" if days < 0 else "yellow" if days < EXPIRY_WARNING_DAYS else "green"
        t = Text()
        t.append(f"{label}  ", style="bold " + style)
        t.append(cn(c.subject), style="bold")
        t.append(f"\n   ⏳ until {c.not_valid_after_utc:%Y-%m-%d} ", style="dim")
        t.append(f"({days} days)", style=color)
        t.append(f"\n   🧬 {fingerprint(c)}", style="dim")
        return t

    if tp is not None and tp.index == len(chain) - 1:
        root = Tree(node(tp.anchor, "🏛️  root (client-side)", "magenta"), guide_style="bright_black")
    else:
        root = None

    parent = root
    for idx in range(len(chain) - 1, -1, -1):
        c = chain[idx]
        if is_self_signed(c):
            label, style = "🏛️  root (in file)", "magenta"
        elif tp is not None and idx > tp.index:
            label, style = "🔀 cross-sign (legacy clients)", "yellow"
        elif idx == 0:
            label, style = "📄 leaf", "green"
        else:
            label, style = "🔗 intermediate", "cyan"
        n = node(c, label, style)
        parent = Tree(n, guide_style="bright_black") if parent is None else parent.add(n)
        if root is None:
            root = parent

    leaf_names = sans(chain[0])
    if leaf_names:
        shown = ", ".join(leaf_names[:6]) + (f" … (+{len(leaf_names) - 6})" if len(leaf_names) > 6 else "")
        parent.add(Text(f"🌐 {shown}", style="blue"))

    console.print(Panel(root, title="⛓️  Certificate chain", border_style="cyan", box=box.ROUNDED))


def show_report(report: Report) -> None:
    table = Table(box=box.SIMPLE_HEAVY, show_header=False, expand=True, padding=(0, 1))
    table.add_column(width=3)
    table.add_column(style="bold")
    table.add_column(style="dim")
    icons = {True: "✅", False: "❌", None: "⚠️ "}
    for c in report.checks:
        table.add_row(icons[c.ok], c.title, c.detail)

    if report.errors:
        border, title = "red", f"💥 {report.errors} error(s), {report.warnings} warning(s)"
    elif report.warnings:
        border, title = "yellow", f"🟡 OK, but {report.warnings} warning(s)"
    else:
        border, title = "green", "🎉 All good!"
    console.print(Panel(table, title="🩺 Verification", subtitle=title, border_style=border, box=box.ROUNDED))


def show_nginx(out: Path, key_path: Path | None) -> None:
    conf = (
        f"ssl_certificate     {out.resolve()};\n"
        f"ssl_certificate_key {key_path.resolve() if key_path else '/path/to/private.key'};\n"
    )
    console.print(
        Panel(
            Syntax(conf, "nginx", theme="monokai", background_color="default", word_wrap=True),
            title="🧩 For your nginx config",
            border_style="blue",
            box=box.ROUNDED,
        )
    )
    console.print("  Then: [bold]sudo nginx -t && sudo systemctl reload nginx[/] 🚀\n")


# ───────────────────────────── interaction ─────────────────────────────


def candidates(exts: set[str]) -> list[Path]:
    return sorted(p for p in Path.cwd().iterdir() if p.is_file() and p.suffix.lower() in exts)


def ask_file(question: str, exts: set[str], optional: bool = False, guess: Path | None = None) -> Path | None:
    files = candidates(exts)
    if guess and guess not in files:
        files.append(guess)
    if files:
        table = Table(box=box.MINIMAL, show_header=False)
        for i, f in enumerate(files, 1):
            mark = " [magenta]🔮 guess[/]" if f == guess else ""
            table.add_row(f"[bold cyan]{i}[/]", f.name + mark)
        console.print(table)
    default = str(files.index(guess) + 1) if guess else ("" if optional else None)
    hint = "number or path" + (", Enter = skip" if optional and not guess else "")
    while True:
        answer = Prompt.ask(f"{question} [dim]({hint})[/]", default=default, show_default=bool(guess))
        answer = answer.strip()
        if not answer and optional:
            return None
        if answer.isdigit() and 1 <= int(answer) <= len(files):
            return files[int(answer) - 1]
        p = Path(answer).expanduser()
        if p.is_file():
            return p
        console.print(f"  [red]❌ No such file:[/] {answer}")


def write_chain(chain: list[x509.Certificate], out: Path) -> None:
    pem = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in chain)
    out.write_bytes(pem)  # every PEM block from cryptography ends with \n — no glued END/BEGIN lines
    out.chmod(0o644)


# ───────────────────────────── --host mode ─────────────────────────────


def fetch_server_chain(host: str, port: int) -> list[x509.Certificate]:
    ctx = ssl.create_default_context()
    # Verification is deliberately off: we want to SEE what a (possibly broken) server sends.
    # Nothing is transmitted over this connection; all checks happen in verify().
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            ders = tls.get_unverified_chain()  # Python 3.13+, list of DER blobs
    return [x509.load_der_x509_certificate(d) for d in ders]


# ───────────────────────────── main ─────────────────────────────


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="certchain",
        description="🔐 Build and verify a certificate fullchain for nginx (leaf + intermediates).",
    )
    ap.add_argument("-c", "--cert", type=Path, help="leaf certificate")
    ap.add_argument("-i", "--intermediate", type=Path, action="append", help="intermediate certificate(s)")
    ap.add_argument("-k", "--key", type=Path, help="private key (to check that it matches)")
    ap.add_argument("-o", "--output", type=Path, help="output file (default: fullchain.crt)")
    ap.add_argument("-n", "--hostname", help="check that the certificate covers this domain")
    ap.add_argument("--check", type=Path, metavar="FILE", help="only verify an existing fullchain file")
    ap.add_argument("--host", metavar="HOST[:PORT]", help="verify the chain a live server sends")
    ap.add_argument("-y", "--yes", action="store_true", help="never ask: use guessed files, overwrite without asking")
    ap.add_argument("--no-fetch", action="store_true", help="do not download missing intermediates via AIA")
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    console.print(Text(BANNER, style="bold cyan"), end="")
    console.print("  [dim]build & verify certificate chains for nginx[/]\n")

    report = Report()
    key = None
    out: Path | None = args.output  # with --check / --host: write the repaired chain
    hostname = args.hostname
    interactive = False

    if args.host:
        host, _, port = args.host.partition(":")
        hostname = hostname or host
        with console.status(f"🌍 Connecting to [bold]{host}:{port or 443}[/]…", spinner="earth"):
            try:
                certs = fetch_server_chain(host, int(port or 443))
            except OSError as e:
                console.print(f"[red]❌ Connection failed: {e}[/]")
                return 2
        report.add(True, "Server sent certificates", f"count: {len(certs)}")
        if len(certs) > 1 and not issued_by(certs[0], certs[1]):
            report.add(False, "Wrong order on the server", "the leaf must come first")
    elif args.check:
        certs = load_certs(args.check)
    else:
        guess = Guess()
        if not args.cert:
            exclude = {Path(args.output or "fullchain.crt").resolve()}
            guess = guess_files(Path.cwd(), exclude)
            if guess.cert:
                show_guess(guess)
        if not args.cert and not guess.cert and args.yes:
            raise CertError("No certificate found in the current directory — pass one with -c")
        use_guess = bool(guess.cert) and (args.yes or Confirm.ask("👉 Use these files?", default=True))
        interactive = not args.cert and not use_guess and not args.yes

        if use_guess:
            cert_path = guess.cert
        else:
            if interactive:
                console.print(Rule("📄 Step 1: leaf certificate", style="cyan"))
            cert_path = args.cert or ask_file("Which file is your certificate?", CERT_EXTS, guess=guess.cert)

        inter_paths = args.intermediate or []
        if not inter_paths:
            if use_guess:
                inter_paths = guess.intermediates
            elif interactive:
                console.print(Rule("🔗 Step 2: intermediate certificate", style="cyan"))
                console.print("  [dim]Don't have one? Press Enter — I'll try to fetch it via AIA 🌐[/]")
                first = guess.intermediates[0] if guess.intermediates else None
                p = ask_file("Which file is the intermediate?", CERT_EXTS, optional=True, guess=first)
                if p:
                    inter_paths = [p]

        key_path = args.key
        if not key_path:
            if use_guess:
                key_path = guess.key
            elif interactive:
                console.print(Rule("🔑 Step 3: private key (optional)", style="cyan"))
                key_path = ask_file("Private key to check?", KEY_EXTS, optional=True, guess=guess.key)
        args.key = key_path

        certs = load_certs(cert_path)
        for p in inter_paths:
            certs += load_certs(p)

        if not out:
            default = "fullchain.crt"
            out = Path(Prompt.ask("💾 Where to save the result?", default=default)) if interactive else Path(default)

        if (interactive or (use_guess and not args.yes)) and not hostname:
            hostname = Prompt.ask("🌐 Domain to check [dim](Enter = skip)[/]", default="", show_default=False) or None

    if args.key:
        key = load_key(args.key)

    console.print()
    with console.status("🔍 Analysing the chain…", spinner="dots"):
        chain = build_chain(certs, report)

    def allow_fetch(top: x509.Certificate, url: str) -> bool:
        if args.no_fetch:
            return False
        if args.yes or not sys.stdin.isatty():
            return True
        return Confirm.ask(f"🌐 Issuer of [bold]{cn(top.subject)}[/] is missing. Fetch it from {url}?", default=True)

    chain = complete_chain(chain, report, allow_fetch, from_server=bool(args.host))

    with console.status("🔍 Verifying…", spinner="dots"):
        tp = verify(chain, key, hostname, report)

    show_chain(chain, tp)
    show_report(report)

    if out is not None:
        extras = tp.extras(chain) if tp else []
        if (
            extras
            and not args.yes
            and Confirm.ask(
                f"🔀 Drop {len(extras)} cross-sign(s)? [dim](only needed by very old clients)[/]", default=False
            )
        ):
            chain = chain[: tp.index + 1]
        drop_root = len(chain) > 1 and is_self_signed(chain[-1])
        if drop_root and (args.yes or Confirm.ask("🏛️  Drop the unnecessary root from the output?", default=True)):
            chain = chain[:-1]

        if report.errors and not args.yes:
            if not Confirm.ask("[red]There are errors.[/] Save the file anyway?", default=False):
                console.print("👋 Nothing written.")
                return 1
        if out.exists() and not args.yes:
            if not Confirm.ask(f"⚠️  [bold]{out}[/] already exists. Overwrite?", default=False):
                console.print("👋 Nothing written.")
                return 1

        write_chain(chain, out)
        console.print(f"\n💾 Saved [bold green]{out}[/] ({len(chain)} certificate(s), leaf first) ✨\n")
        show_nginx(out, args.key)

    return 1 if report.errors else 0


def cli() -> None:
    try:
        sys.exit(main())
    except CertError as e:
        console.print(Panel(f"❌ {e}", border_style="red", title="Error"))
        sys.exit(2)
    except KeyboardInterrupt:
        console.print("\n👋 Interrupted.")
        sys.exit(130)


if __name__ == "__main__":
    cli()
