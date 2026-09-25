import ipaddress
import os
import re
import secrets
import shlex
import shutil
import struct
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum, IntEnum, IntFlag
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import BinaryIO, ClassVar


class AuthorityError(Exception):
    """Raised when the RucoNet CA cannot complete an operation."""


class ProxyError(Exception):
    """Raised when a PROXY protocol v2 header is malformed or unsupported."""


class Status(Enum):
    OK = 200
    BAD_REQUEST = 400
    FORBIDDEN = 403
    NOT_FOUND = 404
    PAYLOAD_TOO_LARGE = 413
    INTERNAL_SERVER_ERROR = 500


class ContentType(Enum):
    PEM = "application/x-pem-file"
    TEXT = "text/plain"


class LetsEncryptFile(Enum):
    FULLCHAIN = "fullchain.pem"
    PRIVKEY = "privkey.pem"


@dataclass(frozen=True)
class Member:
    name: str

    def fqdn(self, domain: str) -> str:
        return f"{self.name}.{domain}"


@dataclass(frozen=True)
class Network:
    prefix: ipaddress.IPv4Network
    domain: str
    hub: str

    @classmethod
    def from_file(cls, path: Path) -> "Network":
        values = dict(token.split("=", 1) for line in path.read_text().splitlines() for token in shlex.split(line, comments=True) if "=" in token)
        return cls(ipaddress.IPv4Network(values["PREFIX"]), values["DOMAIN"], values["HUB"])


@dataclass(frozen=True)
class Registry:
    network: Network
    members: dict[ipaddress.IPv4Address, Member]
    pattern: ClassVar[re.Pattern] = re.compile(r"[a-z0-9-]+")

    @classmethod
    def from_directory(cls, directory: Path) -> "Registry":
        network = Network.from_file(directory / "network")
        members = {}
        for line in (directory / "members").read_text().splitlines():
            fields = line.split("#", 1)[0].split()
            if len(fields) < 2 or not cls.pattern.fullmatch(fields[0]):
                continue
            try:
                address = ipaddress.IPv4Address(fields[1])
            except ValueError:
                continue
            if address in network.prefix:
                members[address] = Member(fields[0])
        return cls(network, members)

    def find(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address | None) -> Member | None:
        if not isinstance(address, ipaddress.IPv4Address):
            return None
        return self.members.get(address)


class ProxyCommand(IntEnum):
    LOCAL = 0x0
    PROXY = 0x1


class ProxyFamily(IntEnum):
    UNSPEC = 0x0
    INET = 0x1
    INET6 = 0x2
    UNIX = 0x3


class ProxyTLV(IntEnum):
    SSL = 0x20
    SSL_CN = 0x22


class ProxyClient(IntFlag):
    SSL = 0x01
    CERT_CONN = 0x02
    CERT_SESS = 0x04


@dataclass(frozen=True)
class ProxyHeader:
    command: ProxyCommand
    address: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    client: ProxyClient = ProxyClient(0)
    verify: int | None = None
    common_name: str | None = None
    signature: ClassVar[bytes] = b"\r\n\r\n\x00\r\nQUIT\n"
    lengths: ClassVar[dict[ProxyFamily, int]] = {ProxyFamily.UNSPEC: 0, ProxyFamily.INET: 12, ProxyFamily.INET6: 36, ProxyFamily.UNIX: 216}

    @classmethod
    def read(cls, stream: BinaryIO) -> "ProxyHeader":
        prefix = stream.read(16)
        if len(prefix) != 16 or prefix[:12] != cls.signature:
            raise ProxyError("missing PROXY protocol v2 signature")
        body = stream.read(struct.unpack("!H", prefix[14:16])[0])
        return cls.parse(prefix[12], prefix[13], body)

    @classmethod
    def parse(cls, version: int, family: int, body: bytes) -> "ProxyHeader":
        if version >> 4 != 2:
            raise ProxyError("unsupported PROXY protocol version")
        try:
            command = ProxyCommand(version & 0x0F)
            family = ProxyFamily(family >> 4)
        except ValueError as error:
            raise ProxyError(str(error)) from None
        length = cls.lengths[family]
        if len(body) < length:
            raise ProxyError("truncated PROXY protocol v2 header")
        if command is ProxyCommand.LOCAL:
            return cls(command)
        address = None
        if family is ProxyFamily.INET:
            address = ipaddress.IPv4Address(body[:4])
        elif family is ProxyFamily.INET6:
            address = ipaddress.IPv6Address(body[:16])
        client = ProxyClient(0)
        verify = None
        common_name = None
        for kind, value in cls.tlvs(body[length:]):
            if kind != ProxyTLV.SSL:
                continue
            if len(value) < 5:
                raise ProxyError("truncated PP2_TYPE_SSL")
            client = ProxyClient(value[0] & 0x07)
            verify = struct.unpack("!I", value[1:5])[0]
            for subkind, subvalue in cls.tlvs(value[5:]):
                if subkind == ProxyTLV.SSL_CN:
                    try:
                        common_name = subvalue.decode()
                    except UnicodeDecodeError:
                        raise ProxyError("invalid PP2_SUBTYPE_SSL_CN") from None
        return cls(command, address, client, verify, common_name)

    @staticmethod
    def tlvs(data: bytes) -> list[tuple[int, bytes]]:
        result = []
        offset = 0
        while offset < len(data):
            if len(data) - offset < 3:
                raise ProxyError("truncated TLV")
            kind, length = data[offset], struct.unpack("!H", data[offset + 1:offset + 3])[0]
            if len(data) - offset - 3 < length:
                raise ProxyError("truncated TLV")
            result.append((kind, data[offset + 3:offset + 3 + length]))
            offset += 3 + length
        return result

    @property
    def verified(self) -> bool:
        return bool(self.client & ProxyClient.SSL) and bool(self.client & (ProxyClient.CERT_CONN | ProxyClient.CERT_SESS)) and self.verify == 0


@dataclass(frozen=True)
class OpenSSL:
    binary: str

    def run(self, *arguments: str, data: bytes | None = None) -> bytes:
        result = subprocess.run([self.binary, *arguments], input=data, capture_output=True, timeout=60)
        if result.returncode != 0:
            raise AuthorityError(result.stderr.decode(errors="replace").strip())
        return result.stdout

    def key(self) -> bytes:
        return self.run("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384")

    def request(self, key: bytes) -> bytes:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "key.pem"
            path.write_bytes(key)
            return self.run("req", "-new", "-key", str(path), "-subj", "/CN=ruconet", "-sha384")

    def expiring(self, certificate: bytes) -> bool:
        output = self.run("x509", "-noout", "-startdate", "-enddate", data=certificate).decode()
        dates = dict(line.split("=", 1) for line in output.splitlines())
        start = datetime.strptime(dates["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        end = datetime.strptime(dates["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return end - datetime.now(timezone.utc) < (end - start) / 3


@dataclass(frozen=True)
class Authority:
    directory: Path
    name: str
    days: int
    leaf_days: int
    openssl: OpenSSL

    @classmethod
    def from_env(cls) -> "Authority":
        return cls(
            Path(os.environ.get("CA_DIRECTORY", "/var/lib/ca")),
            os.environ.get("CA_NAME", "RucoNet CA"),
            int(os.environ.get("CA_DAYS", 7300)),
            int(os.environ.get("CA_LEAF_DAYS", 30)),
            OpenSSL(os.environ.get("CA_OPENSSL", "openssl")),
        )

    @property
    def key(self) -> Path:
        return self.directory / "ca.key"

    @property
    def path(self) -> Path:
        return self.directory / "ca.pem"

    def certificate(self) -> bytes:
        return self.path.read_bytes()

    def ensure(self, network: Network) -> None:
        if self.key.exists() and self.path.exists():
            return
        self.directory.mkdir(parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)
        constraints = f"critical,permitted;DNS:{network.domain},permitted;IP:{network.prefix.network_address}/{network.prefix.netmask}"
        self.openssl.run(
            "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-384", "-sha384", "-nodes",
            "-days", str(self.days), "-subj", f"/CN={self.name}",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", f"nameConstraints={constraints}",
            "-keyout", str(self.key), "-out", str(self.path),
        )
        os.chmod(self.key, 0o600)
        print(f"ca: created {self.name}", flush=True)

    def sign(self, request: bytes, member: Member, network: Network) -> bytes:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            (directory / "request.pem").write_bytes(request)
            self.openssl.run("req", "-in", str(directory / "request.pem"), "-noout", "-verify")
            public = self.openssl.run("req", "-in", str(directory / "request.pem"), "-noout", "-pubkey")
            description = self.openssl.run("pkey", "-pubin", "-noout", "-text", data=public).decode()
            if "NIST CURVE: P-384" not in description:
                raise AuthorityError("the request key is not an EC P-384 key")
            (directory / "public.pem").write_bytes(public)
            fqdn = member.fqdn(network.domain)
            (directory / "extensions.cnf").write_text(
                "[ruconet]\n"
                "basicConstraints = critical,CA:FALSE\n"
                "keyUsage = critical,digitalSignature\n"
                "extendedKeyUsage = serverAuth,clientAuth\n"
                f"subjectAltName = DNS:{fqdn}\n"
                "subjectKeyIdentifier = hash\n"
                "authorityKeyIdentifier = keyid:always\n"
            )
            certificate = self.openssl.run(
                "x509", "-new", "-force_pubkey", str(directory / "public.pem"), "-subj", f"/CN={fqdn}",
                "-CA", str(self.path), "-CAkey", str(self.key), "-sha384",
                "-days", str(self.leaf_days), "-set_serial", f"0x{secrets.token_hex(16)}",
                "-extfile", str(directory / "extensions.cnf"), "-extensions", "ruconet",
            )
        print(f"ca: issued {fqdn}", flush=True)
        return certificate


@dataclass(frozen=True)
class Store:
    directory: Path

    def read(self, bundle: str, name: str) -> bytes | None:
        path = self.directory / bundle / name
        return path.read_bytes() if path.exists() else None

    def install(self, bundle: str, files: dict[str, bytes]) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        target = f".{bundle}.{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
        staging = Path(tempfile.mkdtemp(prefix=".tmp.", dir=self.directory))
        for name, content in files.items():
            (staging / name).write_bytes(content)
            os.chmod(staging / name, 0o600)
        staging.rename(self.directory / target)
        link = self.directory / f".{bundle}.link"
        link.unlink(missing_ok=True)
        link.symlink_to(target)
        link.replace(self.directory / bundle)
        for old in sorted(self.directory.glob(f".{bundle}.[0-9]*"))[:-2]:
            shutil.rmtree(old)
        print(f"ca: installed {bundle}", flush=True)


@dataclass(frozen=True)
class LetsEncrypt:
    directory: Path
    name: str
    members: frozenset[str]

    @classmethod
    def from_env(cls) -> "LetsEncrypt":
        return cls(
            Path(os.environ.get("LETSENCRYPT_DIRECTORY", "/etc/letsencrypt")),
            os.environ.get("LETSENCRYPT_NAME", "nercone.dev"),
            frozenset(os.environ.get("LETSENCRYPT_MEMBERS", "").split()),
        )

    def read(self, file: LetsEncryptFile) -> bytes | None:
        path = self.directory / "live" / self.name / file.value
        return path.read_bytes() if path.exists() else None


@dataclass(frozen=True)
class Response:
    status: Status
    body: bytes = b""
    content_type: ContentType = ContentType.TEXT

    @classmethod
    def text(cls, status: Status, message: str) -> "Response":
        return cls(status, f"{message}\n".encode())


@dataclass(frozen=True)
class Service:
    registry: Registry
    authority: Authority
    letsencrypt: LetsEncrypt
    store: Store
    maximum: int
    interval: int

    @classmethod
    def from_env(cls) -> "Service":
        return cls(
            Registry.from_directory(Path(os.environ.get("RUCONET_ETC", "/etc/ruconet"))),
            Authority.from_env(),
            LetsEncrypt.from_env(),
            Store(Path(os.environ.get("CA_STORE", "/etc/certs"))),
            int(os.environ.get("CA_MAXIMUM_REQUEST", 8192)),
            int(os.environ.get("CA_INTERVAL", 3600)),
        )

    @property
    def member(self) -> Member:
        return Member(self.registry.network.hub)

    def renew(self) -> None:
        self.authority.ensure(self.registry.network)
        certificate = self.store.read("ruconet", "cert.pem")
        if (
            certificate is not None
            and self.store.read("ruconet", "ca.pem") == self.authority.certificate()
            and not self.authority.openssl.expiring(certificate)
        ):
            return
        key = self.authority.openssl.key()
        certificate = self.authority.sign(self.authority.openssl.request(key), self.member, self.registry.network)
        self.store.install("ruconet", {"ca.pem": self.authority.certificate(), "cert.pem": certificate, "key.pem": key})

    def maintain(self) -> None:
        while True:
            try:
                self.renew()
            except (AuthorityError, OSError, KeyError, ValueError) as error:
                print(f"ca: failed to renew {self.member.name}: {error}", flush=True)
            time.sleep(self.interval)

    def ca(self) -> Response:
        return Response(Status.OK, self.authority.certificate(), ContentType.PEM)

    def sign(self, proxy: ProxyHeader, body: bytes) -> Response:
        member = self.registry.find(proxy.address)
        if member is None:
            return Response.text(Status.FORBIDDEN, "not a member of RucoNet")
        try:
            return Response(Status.OK, self.authority.sign(body, member, self.registry.network), ContentType.PEM)
        except AuthorityError as error:
            print(f"ca: rejected a request from {member.name}: {error}", flush=True)
            return Response.text(Status.BAD_REQUEST, "invalid certificate request")

    def download(self, proxy: ProxyHeader, file: LetsEncryptFile) -> Response:
        member = self.registry.find(proxy.address)
        if member is None or member.name not in self.letsencrypt.members:
            return Response.text(Status.FORBIDDEN, "not allowed")
        if not proxy.verified or proxy.common_name != member.fqdn(self.registry.network.domain):
            return Response.text(Status.FORBIDDEN, "client certificate required")
        content = self.letsencrypt.read(file)
        if content is None:
            return Response.text(Status.NOT_FOUND, "not issued yet")
        return Response(Status.OK, content, ContentType.PEM)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "ruconet-ca"
    sys_version = ""
    service: ClassVar[Service]
    proxy: ProxyHeader

    def handle(self) -> None:
        try:
            self.proxy = ProxyHeader.read(self.rfile)
        except ProxyError:
            return
        super().handle()

    def do_GET(self) -> None:
        if self.path == "/ca.pem":
            self.respond(self.service.ca())
            return
        prefix = "/letsencrypt/"
        if self.path.startswith(prefix):
            try:
                file = LetsEncryptFile(self.path[len(prefix):])
            except ValueError:
                self.respond(Response.text(Status.NOT_FOUND, "not found"))
                return
            self.respond(self.service.download(self.proxy, file))
            return
        self.respond(Response.text(Status.NOT_FOUND, "not found"))

    def do_POST(self) -> None:
        if self.path != "/ruconet":
            self.respond(Response.text(Status.NOT_FOUND, "not found"))
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self.respond(Response.text(Status.BAD_REQUEST, "Content-Length required"))
            return
        if length > self.service.maximum:
            self.respond(Response.text(Status.PAYLOAD_TOO_LARGE, "request too large"))
            return
        self.respond(self.service.sign(self.proxy, self.rfile.read(length)))

    def respond(self, response: Response) -> None:
        self.send_response(response.status.value)
        self.send_header("Content-Type", response.content_type.value)
        self.send_header("Content-Length", str(len(response.body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(response.body)

    def log_message(self, format: str, *args) -> None:
        pass


class Server(ThreadingHTTPServer):
    daemon_threads = True

    @classmethod
    def from_env(cls) -> "Server":
        host = os.environ.get("LISTEN_HOST", "127.0.0.1")
        port = int(os.environ.get("LISTEN_PORT", 8080))
        return cls((host, port), Handler)


if __name__ == "__main__":
    Handler.service = Service.from_env()
    Handler.service.renew()
    threading.Thread(target=Handler.service.maintain, daemon=True).start()
    Server.from_env().serve_forever()
