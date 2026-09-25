FROM debian:trixie-slim AS openssl-builder

ARG TRIXIE_PACKAGES_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY <<'EOF' /usr/local/bin/openssl-install
#!/bin/sh
set -eu

VERSION="$1"
TARGET="$2"

case "${TARGETARCH}" in
    amd64) ARCH=x86_64 ;;
    arm64) ARCH=aarch64 ;;
    *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;;
esac

NAME="openssl-${VERSION}-linux-${ARCH}"
URL="https://github.com/nercone-infra/openssl/releases/download/openssl-${VERSION}"
SOURCE=$(mktemp -d)

echo "Installing OpenSSL ${VERSION} (${NAME})"

curl -fsSL -o "${SOURCE}/${NAME}.tar.gz" "${URL}/${NAME}.tar.gz"
curl -fsSL "${URL}/SHA256SUMS" | grep "  ${NAME}.tar.gz\$" | (cd "${SOURCE}" && sha256sum -c -)
mkdir -p "${SOURCE}/openssl"
tar xzf "${SOURCE}/${NAME}.tar.gz" -C "${SOURCE}/openssl" --strip-components=1

if [ -d "${SOURCE}/openssl/lib64" ]; then
    LIBRARY="${SOURCE}/openssl/lib64"
else
    LIBRARY="${SOURCE}/openssl/lib"
fi

DIRECTORY=$(LD_LIBRARY_PATH="${LIBRARY}" "${SOURCE}/openssl/bin/openssl" version -d | sed -n 's/^OPENSSLDIR: "\(.*\)"$/\1/p')

mkdir -p "${TARGET}/bin" "${TARGET}/lib" "${TARGET}/ssl" "${TARGET}/include" "${TARGET}/root${DIRECTORY%/*}"
cp -a "${SOURCE}/openssl/bin/openssl" "${TARGET}/bin/"
cp -a "${LIBRARY}"/libssl.so* "${LIBRARY}"/libcrypto.so* "${TARGET}/lib/"
cp -a "${SOURCE}/openssl/ssl/openssl.cnf" "${TARGET}/ssl/"
cp -a "${SOURCE}/openssl/include/openssl" "${TARGET}/include/"
ln -s /etc/ssl/certs "${TARGET}/ssl/certs"
ln -s /etc/ssl/certs/ca-certificates.crt "${TARGET}/ssl/cert.pem"
ln -s /usr/local/ssl "${TARGET}/root${DIRECTORY}"
chown -hR root:root "${TARGET}"
rm -rf "${SOURCE}"
EOF

RUN chmod +x /usr/local/bin/openssl-install

FROM openssl-builder AS openssl

ARG TARGETARCH
ARG OPENSSL_VERSION

RUN openssl-install "${OPENSSL_VERSION}" /opt/openssl

FROM openssl-builder AS openssl3

ARG TARGETARCH
ARG OPENSSL3_VERSION

RUN openssl-install "${OPENSSL3_VERSION}" /opt/openssl

FROM debian:trixie-slim AS ruconet-builder

ARG TRIXIE_PACKAGES_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates clang make libexpat1-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=openssl /opt/openssl/include/ /usr/local/include/
COPY --from=openssl /opt/openssl/lib/ /usr/local/lib/

ARG UNBOUND_VERSION

RUN echo "Building Unbound ${UNBOUND_VERSION}" \
    && cd /tmp \
    && curl -fsSL -o "unbound-${UNBOUND_VERSION}.tar.gz" "https://nlnetlabs.nl/downloads/unbound/unbound-${UNBOUND_VERSION}.tar.gz" \
    && echo "$(curl -fsSL "https://nlnetlabs.nl/downloads/unbound/unbound-${UNBOUND_VERSION}.tar.gz.sha256")  unbound-${UNBOUND_VERSION}.tar.gz" | sha256sum -c - \
    && tar xzf "unbound-${UNBOUND_VERSION}.tar.gz" \
    && cd "unbound-${UNBOUND_VERSION}" \
    && ./configure \
        CC=clang \
        CFLAGS="-O2" \
        LDFLAGS="-Wl,-rpath,/usr/local/lib" \
        --prefix=/usr/local \
        --sysconfdir=/etc \
        --with-ssl=/usr/local \
        --with-pidfile= \
        --with-rootkey-file=/var/lib/unbound/root.key \
        --disable-static \
    && make -j"$(nproc)" \
    && make install DESTDIR=/opt/ruconet \
    && rm -rf /tmp/unbound-*

ARG HAPROXY_VERSION

RUN echo "Building HAProxy ${HAPROXY_VERSION}" \
    && cd /tmp \
    && curl -fsSL -o "haproxy-${HAPROXY_VERSION}.tar.gz" "https://www.haproxy.org/download/${HAPROXY_VERSION%.*}/src/haproxy-${HAPROXY_VERSION}.tar.gz" \
    && curl -fsSL "https://www.haproxy.org/download/${HAPROXY_VERSION%.*}/src/haproxy-${HAPROXY_VERSION}.tar.gz.sha256" | sha256sum -c - \
    && tar xzf "haproxy-${HAPROXY_VERSION}.tar.gz" \
    && cd "haproxy-${HAPROXY_VERSION}" \
    && make -j"$(nproc)" \
        CC=clang \
        TARGET=linux-glibc \
        USE_OPENSSL=1 \
        SSL_INC=/usr/local/include \
        SSL_LIB=/usr/local/lib \
        ADDLIB="-Wl,-rpath,/usr/local/lib" \
    && make install-bin PREFIX=/usr/local DESTDIR=/opt/ruconet \
    && rm -rf /tmp/haproxy-*

FROM debian:trixie-slim AS ruconet

ARG TRIXIE_PACKAGES_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends wireguard-tools iproute2 nftables netbase libexpat1 ca-certificates dns-root-data \
    && rm -rf /var/lib/apt/lists/*

COPY --from=openssl /opt/openssl/bin/ /usr/local/bin/
COPY --from=openssl /opt/openssl/lib/ /usr/local/lib/
COPY --from=openssl /opt/openssl/ssl/ /usr/local/ssl/
COPY --from=openssl /opt/openssl/root/ /
COPY --from=ruconet-builder /opt/ruconet/usr/local/ /usr/local/

RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/00-openssl.conf && ldconfig \
    && groupadd -r unbound && useradd -r -g unbound -s /usr/sbin/nologin -d /var/lib/unbound unbound \
    && groupadd -r haproxy && useradd -r -g haproxy -s /usr/sbin/nologin -d /nonexistent haproxy \
    && mkdir -p /var/lib/haproxy

COPY lib/ruconet.sh /usr/local/lib/ruconet.sh
COPY share/haproxy.cfg /usr/local/share/ruconet/haproxy.cfg
COPY etc/network etc/members /etc/ruconet/
COPY bin/ruconet-hub bin/ruconet-node /usr/local/bin/

STOPSIGNAL SIGTERM

CMD ["/usr/local/bin/ruconet-node"]

FROM debian:trixie-slim AS cert

ARG TRIXIE_PACKAGES_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=openssl3 /opt/openssl/bin/ /usr/local/bin/
COPY --from=openssl3 /opt/openssl/lib/ /usr/local/lib/
COPY --from=openssl3 /opt/openssl/ssl/ /usr/local/ssl/
COPY --from=openssl3 /opt/openssl/root/ /

RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/00-openssl.conf && ldconfig

COPY etc/network /etc/ruconet/network
COPY bin/cert-agent /usr/local/bin/cert-agent

STOPSIGNAL SIGTERM

CMD ["/usr/local/bin/cert-agent"]

FROM python:3-slim-trixie AS ca

COPY --from=openssl /opt/openssl/bin/ /usr/local/bin/
COPY --from=openssl /opt/openssl/lib/ /usr/local/lib/
COPY --from=openssl /opt/openssl/ssl/ /usr/local/ssl/
COPY --from=openssl /opt/openssl/root/ /

RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/00-openssl.conf && ldconfig

WORKDIR /srv

COPY ca/ca.py /srv/ca.py

STOPSIGNAL SIGTERM

CMD ["python3", "-u", "/srv/ca.py"]
