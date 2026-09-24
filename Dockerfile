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

FROM debian:trixie-slim AS base

ARG TRIXIE_PACKAGES_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends wireguard-tools iproute2 nftables unbound ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY lib/ruconet.sh /usr/local/lib/ruconet.sh

FROM base AS hub

COPY bin/ruconet-hub /usr/local/bin/ruconet-hub

STOPSIGNAL SIGTERM

CMD ["/usr/local/bin/ruconet-hub"]

FROM base AS node

RUN apt-get update && apt-get install -y --no-install-recommends unbound-host dns-root-data \
    && rm -rf /var/lib/apt/lists/*

COPY --from=openssl3 /opt/openssl/bin/ /usr/local/bin/
COPY --from=openssl3 /opt/openssl/lib/ /usr/local/lib/
COPY --from=openssl3 /opt/openssl/ssl/ /usr/local/ssl/
COPY --from=openssl3 /opt/openssl/root/ /

RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/00-openssl.conf && ldconfig

COPY etc/network etc/members /etc/ruconet/
COPY bin/ruconet-node /usr/local/bin/ruconet-node

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

FROM debian:trixie-slim AS nginx-builder

WORKDIR /build

ARG TRIXIE_PACKAGES_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates clang make libpcre2-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=openssl /opt/openssl/include/ /usr/local/include/
COPY --from=openssl /opt/openssl/lib/ /usr/local/lib/

ARG NGINX_VERSION

RUN echo "Building Nginx ${NGINX_VERSION}" \
    && curl -fsSL "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" | tar xz -C /tmp \
    && cd "/tmp/nginx-${NGINX_VERSION}" \
    && ./configure \
        --with-cc=clang \
        --prefix=/etc/nginx \
        --sbin-path=/usr/sbin/nginx \
        --conf-path=/etc/nginx/nginx.conf \
        --http-log-path=/var/log/nginx/access.log \
        --error-log-path=/var/log/nginx/error.log \
        --pid-path=/run/nginx.pid \
        --http-client-body-temp-path=/var/cache/nginx/client_body \
        --http-proxy-temp-path=/var/cache/nginx/proxy \
        --http-fastcgi-temp-path=/var/cache/nginx/fastcgi \
        --http-uwsgi-temp-path=/var/cache/nginx/uwsgi \
        --http-scgi-temp-path=/var/cache/nginx/scgi \
        --user=nginx \
        --group=nginx \
        --with-cc-opt="-I/usr/local/include -O2" \
        --with-ld-opt="-L/usr/local/lib -Wl,-rpath,/usr/local/lib" \
        --with-http_ssl_module \
        --with-http_realip_module \
        --with-stream \
        --with-stream_ssl_module \
        --with-stream_realip_module \
        --with-pcre \
        --with-pcre-jit \
    && make -j"$(nproc)" \
    && make install \
    && rm -rf /tmp/nginx-*

FROM debian:trixie-slim AS tls

ARG TRIXIE_PACKAGES_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends libpcre2-8-0 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r nginx && useradd -r -g nginx -s /usr/sbin/nologin -d /nonexistent nginx

COPY --from=openssl /opt/openssl/lib/ /usr/local/lib/
COPY --from=openssl /opt/openssl/ssl/ /usr/local/ssl/
COPY --from=openssl /opt/openssl/root/ /
COPY --from=nginx-builder /usr/sbin/nginx /usr/sbin/nginx
COPY --from=nginx-builder /etc/nginx/mime.types /usr/local/share/nginx/mime.types

RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/00-openssl.conf && ldconfig \
    && mkdir -p /etc/nginx.d /etc/certs /var/cache/nginx /var/log/nginx \
    && chown nginx:nginx /var/cache/nginx /var/log/nginx

COPY nginx/ /etc/nginx/
COPY bin/nginx-entrypoint /usr/local/bin/nginx-entrypoint

STOPSIGNAL SIGQUIT

CMD ["/usr/local/bin/nginx-entrypoint"]
