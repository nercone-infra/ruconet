import base64
import datetime
import importlib.util
import io
import ipaddress
import socket
import struct
import sys
import threading
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

SPEC = importlib.util.spec_from_file_location("ca", Path(__file__).resolve().parent.parent / "ca" / "ca.py")
ca = importlib.util.module_from_spec(SPEC)
sys.modules["ca"] = ca
SPEC.loader.exec_module(ca)

DOMAIN = "ruconet.internal"
PREFIX = ipaddress.IPv4Network("10.64.0.0/24")
SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"


@pytest.fixture
def network():
    return ca.Network(PREFIX, DOMAIN, "ruconet")


@pytest.fixture
def authority(tmp_path, network):
    authority = ca.Authority(tmp_path / "ca", "RucoNet CA", 7300, 30, ca.OpenSSL("openssl"))
    authority.ensure(network)
    return authority


@pytest.fixture
def root(authority):
    return x509.load_pem_x509_certificate(authority.certificate())


def request(key) -> bytes:
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ruconet")]))
    return builder.sign(key, hashes.SHA384()).public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def leaf(authority, network):
    return x509.load_pem_x509_certificate(authority.sign(request(ec.generate_private_key(ec.SECP384R1())), ca.Member("gitea"), network))


def test_root_is_version_3(root):
    assert root.version == x509.Version.v3


def test_root_is_self_issued(root):
    assert root.issuer == root.subject
    root.public_key().verify(root.signature, root.tbs_certificate_bytes, ec.ECDSA(root.signature_hash_algorithm))


def test_root_key_is_p384(root):
    assert isinstance(root.public_key(), ec.EllipticCurvePublicKey)
    assert isinstance(root.public_key().curve, ec.SECP384R1)


def test_root_signature_is_sha384(root):
    assert isinstance(root.signature_hash_algorithm, hashes.SHA384)


def test_root_basic_constraints(root):
    extension = root.extensions.get_extension_for_class(x509.BasicConstraints)
    assert extension.critical
    assert extension.value.ca
    assert extension.value.path_length == 0


def test_root_key_usage(root):
    extension = root.extensions.get_extension_for_class(x509.KeyUsage)
    assert extension.critical
    assert extension.value.key_cert_sign
    assert extension.value.crl_sign


def test_root_subject_key_identifier(root):
    extension = root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    assert not extension.critical
    assert extension.value.digest


def test_root_name_constraints(root):
    extension = root.extensions.get_extension_for_class(x509.NameConstraints)
    assert extension.critical
    assert set(extension.value.permitted_subtrees) == {x509.DNSName(DOMAIN), x509.IPAddress(PREFIX)}
    assert not extension.value.excluded_subtrees


def test_root_validity(root):
    assert root.not_valid_after_utc - root.not_valid_before_utc == datetime.timedelta(days=7300)


def test_root_serial_number(root):
    assert 0 < root.serial_number < 2 ** 159


def test_root_is_kept(authority, network):
    certificate = authority.certificate()
    authority.ensure(network)
    assert authority.certificate() == certificate


def test_root_key_is_private(authority):
    assert authority.key.stat().st_mode & 0o077 == 0
    assert authority.directory.stat().st_mode & 0o077 == 0


def test_leaf_is_version_3(leaf):
    assert leaf.version == x509.Version.v3


def test_leaf_is_issued_by_root(leaf, root):
    assert leaf.issuer == root.subject
    root.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm))


def test_leaf_signature_is_sha384(leaf):
    assert isinstance(leaf.signature_hash_algorithm, hashes.SHA384)


def test_leaf_subject(leaf):
    assert leaf.subject == x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"gitea.{DOMAIN}")])


def test_leaf_subject_alternative_name(leaf):
    extension = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert not extension.critical
    assert list(extension.value) == [x509.DNSName(f"gitea.{DOMAIN}")]


def test_leaf_satisfies_name_constraints(leaf):
    for name in leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName):
        assert name == DOMAIN or name.endswith(f".{DOMAIN}")


def test_leaf_basic_constraints(leaf):
    extension = leaf.extensions.get_extension_for_class(x509.BasicConstraints)
    assert extension.critical
    assert not extension.value.ca
    assert extension.value.path_length is None


def test_leaf_key_usage(leaf):
    extension = leaf.extensions.get_extension_for_class(x509.KeyUsage)
    assert extension.critical
    assert extension.value.digital_signature
    assert not extension.value.key_cert_sign
    assert not extension.value.crl_sign
    assert not extension.value.key_encipherment


def test_leaf_extended_key_usage(leaf):
    extension = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert set(extension.value) == {ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH}


def test_leaf_key_identifiers(leaf, root):
    subject = leaf.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    authority = leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    assert not subject.critical
    assert not authority.critical
    assert subject.value == x509.SubjectKeyIdentifier.from_public_key(leaf.public_key())
    assert authority.value.key_identifier == root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest


def test_leaf_validity(leaf):
    assert leaf.not_valid_after_utc - leaf.not_valid_before_utc == datetime.timedelta(days=30)


def test_leaf_serial_number(leaf):
    assert 0 < leaf.serial_number < 2 ** 159


def test_leaf_serial_numbers_are_unique(authority, network):
    key = ec.generate_private_key(ec.SECP384R1())
    serials = {x509.load_pem_x509_certificate(authority.sign(request(key), ca.Member("gitea"), network)).serial_number for _ in range(4)}
    assert len(serials) == 4


def test_leaf_uses_requested_key(authority, network):
    key = ec.generate_private_key(ec.SECP384R1())
    certificate = x509.load_pem_x509_certificate(authority.sign(request(key), ca.Member("gitea"), network))
    assert certificate.public_key().public_numbers() == key.public_key().public_numbers()


@pytest.mark.parametrize("key", [ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP521R1()), rsa.generate_private_key(65537, 3072)])
def test_rejects_other_keys(authority, network, key):
    with pytest.raises(ca.AuthorityError):
        authority.sign(request(key), ca.Member("gitea"), network)


def test_rejects_invalid_request(authority, network):
    with pytest.raises(ca.AuthorityError):
        authority.sign(b"-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n", ca.Member("gitea"), network)


def test_rejects_forged_request(authority, network):
    signed = x509.load_pem_x509_csr(request(ec.generate_private_key(ec.SECP384R1()))).public_bytes(serialization.Encoding.DER)
    forged = bytearray(signed)
    forged[-1] ^= 0x01
    pem = b"-----BEGIN CERTIFICATE REQUEST-----\n" + base64.encodebytes(bytes(forged)) + b"-----END CERTIFICATE REQUEST-----\n"
    with pytest.raises(ca.AuthorityError):
        authority.sign(pem, ca.Member("gitea"), network)


def test_expiring(authority, network):
    certificate = authority.sign(request(ec.generate_private_key(ec.SECP384R1())), ca.Member("gitea"), network)
    assert not authority.openssl.expiring(certificate)


def write_registry(directory: Path, members: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "network").write_text(
        f"PREFIX={PREFIX}\n"
        f"DOMAIN={DOMAIN}\n"
        "\n"
        "HUB=ruconet\n"
        "PORT=51820\n"
        'RESOLVERS="1.1.1.1@853#cloudflare-dns.com 1.0.0.1@853#cloudflare-dns.com"\n'
    )
    (directory / "members").write_text(members)
    return directory


MEMBERS = "# NAME ADDRESS\nruconet 10.64.0.1\ngateway 10.64.0.2 # edge\nmail 10.64.0.5\ngitea 10.64.0.7\n"


@pytest.fixture
def registry(tmp_path):
    return ca.Registry.from_directory(write_registry(tmp_path / "etc", MEMBERS))


def test_network_from_file(registry):
    assert registry.network == ca.Network(PREFIX, DOMAIN, "ruconet")


@pytest.mark.parametrize("address,name", [("10.64.0.1", "ruconet"), ("10.64.0.2", "gateway"), ("10.64.0.5", "mail"), ("10.64.0.7", "gitea")])
def test_find_member(registry, address, name):
    assert registry.find(ipaddress.ip_address(address)) == ca.Member(name)


@pytest.mark.parametrize("address", ["10.64.0.3", "10.64.1.7", "192.0.2.1", "::1", "::ffff:10.64.0.7"])
def test_find_rejects_address(registry, address):
    assert registry.find(ipaddress.ip_address(address)) is None


def test_find_rejects_missing_address(registry):
    assert registry.find(None) is None


@pytest.mark.parametrize("line", ["GITEA 10.64.0.7", "gi_tea 10.64.0.7", "gitea.example 10.64.0.7", "gitea 10.64.1.7", "gitea 10.64.0", "gitea", "# gitea 10.64.0.7"])
def test_registry_ignores_invalid_members(tmp_path, line):
    registry = ca.Registry.from_directory(write_registry(tmp_path / "etc", f"{line}\n"))
    assert registry.members == {}


def proxy(command: int = 0x1, family: int = 0x11, addresses: bytes | None = None, tlvs: bytes = b"", version: int = 0x2) -> bytes:
    if addresses is None:
        addresses = ipaddress.IPv4Address("10.64.0.7").packed + ipaddress.IPv4Address("10.64.0.1").packed + struct.pack("!HH", 40000, 443)
    body = addresses + tlvs
    return SIGNATURE + bytes([(version << 4) | command, family]) + struct.pack("!H", len(body)) + body


def tlv(kind: int, value: bytes) -> bytes:
    return bytes([kind]) + struct.pack("!H", len(value)) + value


def ssl(client: int, verify: int, *subtlvs: bytes) -> bytes:
    return tlv(0x20, bytes([client]) + struct.pack("!I", verify) + b"".join(subtlvs))


def read(data: bytes):
    stream = io.BytesIO(data)
    header = ca.ProxyHeader.read(stream)
    return header, stream.read()


def test_proxy_tcp4():
    header, rest = read(proxy() + b"GET / HTTP/1.0\r\n\r\n")
    assert header.command is ca.ProxyCommand.PROXY
    assert header.address == ipaddress.IPv4Address("10.64.0.7")
    assert rest == b"GET / HTTP/1.0\r\n\r\n"
    assert not header.verified


def test_proxy_tcp6():
    addresses = ipaddress.IPv6Address("2001:db8::7").packed + ipaddress.IPv6Address("2001:db8::1").packed + struct.pack("!HH", 40000, 443)
    header, _ = read(proxy(family=0x21, addresses=addresses))
    assert header.address == ipaddress.IPv6Address("2001:db8::7")


def test_proxy_unspec_has_no_address():
    header, _ = read(proxy(family=0x00, addresses=b""))
    assert header.address is None


def test_proxy_local_has_no_address():
    header, rest = read(proxy(command=0x0, family=0x00, addresses=b"") + b"data")
    assert header.command is ca.ProxyCommand.LOCAL
    assert header.address is None
    assert rest == b"data"


def test_proxy_local_discards_address_block():
    header, rest = read(proxy(command=0x0) + b"data")
    assert header.address is None
    assert rest == b"data"


def test_proxy_verified_client_certificate():
    header, _ = read(proxy(tlvs=ssl(0x07, 0, tlv(0x21, b"TLSv1.3"), tlv(0x22, b"gitea.ruconet.internal"))))
    assert header.verified
    assert header.common_name == "gitea.ruconet.internal"
    assert header.client == ca.ProxyClient.SSL | ca.ProxyClient.CERT_CONN | ca.ProxyClient.CERT_SESS


def test_proxy_verified_session_certificate():
    header, _ = read(proxy(tlvs=ssl(0x05, 0, tlv(0x22, b"gitea.ruconet.internal"))))
    assert header.verified


@pytest.mark.parametrize("client,verify", [(0x01, 0), (0x03, 1), (0x02, 0), (0x00, 0)])
def test_proxy_unverified_client_certificate(client, verify):
    header, _ = read(proxy(tlvs=ssl(client, verify, tlv(0x22, b"gitea.ruconet.internal"))))
    assert not header.verified


def test_proxy_ignores_unknown_tlvs():
    header, _ = read(proxy(tlvs=tlv(0x04, b"\x00" * 8) + tlv(0xE0, b"custom") + ssl(0x03, 0, tlv(0x25, b"EC384"), tlv(0x22, b"mail.ruconet.internal"))))
    assert header.verified
    assert header.common_name == "mail.ruconet.internal"


@pytest.mark.parametrize("data", [
    b"",
    b"PROXY TCP4 10.64.0.7 10.64.0.1 40000 443\r\n",
    SIGNATURE[:-1] + b"X" + b"\x21\x11\x00\x0c",
    proxy(version=0x1),
    proxy(version=0x3),
    proxy(command=0x2),
    proxy(family=0x41),
    proxy()[:-1],
    proxy(tlvs=b"\x20\x00"),
    proxy(tlvs=tlv(0x20, b"\x07\x00\x00")),
    proxy(tlvs=b"\x20\x00\x10\x07"),
    proxy(tlvs=ssl(0x07, 0, b"\x22\x00\x05ab")),
    proxy(tlvs=ssl(0x07, 0, tlv(0x22, b"\xff\xfe"))),
])
def test_proxy_rejects_invalid(data):
    with pytest.raises(ca.ProxyError):
        read(data)


@pytest.fixture
def service(tmp_path, registry, authority):
    letsencrypt = tmp_path / "letsencrypt" / "live" / "nercone.dev"
    letsencrypt.mkdir(parents=True)
    (letsencrypt / "fullchain.pem").write_bytes(b"fullchain")
    (letsencrypt / "privkey.pem").write_bytes(b"privkey")
    return ca.Service(registry, authority, ca.LetsEncrypt(tmp_path / "letsencrypt", "nercone.dev", frozenset({"gateway", "mail"})), ca.Store(tmp_path / "certs"), 8192, 3600)


def header(address: str, client: int = 0x00, verify: int = 1, common_name: str | None = None):
    return ca.ProxyHeader(ca.ProxyCommand.PROXY, ipaddress.ip_address(address), ca.ProxyClient(client), verify, common_name)


def test_sign_member(service):
    response = service.sign(header("10.64.0.7"), request(ec.generate_private_key(ec.SECP384R1())))
    assert response.status is ca.Status.OK
    certificate = x509.load_pem_x509_certificate(response.body)
    assert list(certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value) == [x509.DNSName(f"gitea.{DOMAIN}")]


@pytest.mark.parametrize("address", ["10.64.0.3", "192.0.2.1"])
def test_sign_rejects_non_member(service, address):
    assert service.sign(header(address), request(ec.generate_private_key(ec.SECP384R1()))).status is ca.Status.FORBIDDEN


def test_sign_rejects_local_command(service):
    assert service.sign(ca.ProxyHeader(ca.ProxyCommand.LOCAL), request(ec.generate_private_key(ec.SECP384R1()))).status is ca.Status.FORBIDDEN


def test_sign_rejects_invalid_request(service):
    assert service.sign(header("10.64.0.7"), b"invalid").status is ca.Status.BAD_REQUEST


def test_download(service):
    response = service.download(header("10.64.0.5", 0x03, 0, f"mail.{DOMAIN}"), ca.LetsEncryptFile.PRIVKEY)
    assert response.status is ca.Status.OK
    assert response.body == b"privkey"


@pytest.mark.parametrize("proxy_header", [
    header("10.64.0.7", 0x03, 0, f"gitea.{DOMAIN}"),
    header("10.64.0.3", 0x03, 0, f"cert.{DOMAIN}"),
    header("10.64.0.5"),
    header("10.64.0.5", 0x03, 1, f"mail.{DOMAIN}"),
    header("10.64.0.5", 0x01, 0, f"mail.{DOMAIN}"),
    header("10.64.0.5", 0x03, 0, f"gateway.{DOMAIN}"),
    header("10.64.0.5", 0x03, 0, None),
])
def test_download_rejects(service, proxy_header):
    assert service.download(proxy_header, ca.LetsEncryptFile.FULLCHAIN).status is ca.Status.FORBIDDEN


def test_renew_issues_hub_certificate(service):
    service.renew()
    certificate = x509.load_pem_x509_certificate(service.store.read("ruconet", "cert.pem"))
    assert list(certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value) == [x509.DNSName(f"ruconet.{DOMAIN}")]
    assert service.store.read("ruconet", "ca.pem") == service.authority.certificate()


@pytest.fixture
def server(service):
    ca.Handler.service = service
    server = ca.Server(("127.0.0.1", 0), ca.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address
    server.shutdown()
    server.server_close()


def exchange(address, data: bytes) -> bytes:
    with socket.create_connection(address, timeout=10) as connection:
        connection.sendall(data)
        connection.shutdown(socket.SHUT_WR)
        chunks = []
        while chunk := connection.recv(65536):
            chunks.append(chunk)
    return b"".join(chunks)


def test_server_serves_ca(server, service):
    response = exchange(server, proxy() + b"GET /ca.pem HTTP/1.0\r\n\r\n")
    assert response.startswith(b"HTTP/1.0 200 ")
    assert response.endswith(service.authority.certificate())


def test_server_requires_proxy_header(server):
    assert exchange(server, b"GET /ca.pem HTTP/1.0\r\n\r\n") == b""


def test_server_identifies_member_by_proxy_header(server):
    body = request(ec.generate_private_key(ec.SECP384R1()))
    response = exchange(server, proxy() + f"POST /ruconet HTTP/1.0\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
    assert response.startswith(b"HTTP/1.0 200 ")
    certificate = x509.load_pem_x509_certificate(response.split(b"\r\n\r\n", 1)[1])
    assert certificate.subject == x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"gitea.{DOMAIN}")])
