RUCONET_ETC=/etc/ruconet
RUCONET_LOCAL=/etc/ruconet.d
RUCONET_RUN=/run/ruconet
RUCONET_CERTS=/etc/certs/ruconet
RUCONET_HAPROXY=/usr/local/share/ruconet/haproxy.cfg
RUCONET_INTERFACE=ruconet
RUCONET_TABLE=51820
RUCONET_TTL=60
RUCONET_OVERHEAD=60
RUCONET_UNBOUND_PID=
RUCONET_HAPROXY_PID=
RUCONET_HAPROXY_APPLIED=

ruconet_log() {
    echo "ruconet: $*" >&2
}

ruconet_load() {
    PREFIX= DOMAIN= HUB= ENDPOINT= PORT= EGRESS= MTU= KEEPALIVE= RESOLVERS=
    . "${RUCONET_ETC}/network"
}

ruconet_digest() {
    cat "${RUCONET_ETC}/network" "${RUCONET_ETC}/members" "${RUCONET_ETC}/policy" "${RUCONET_LOCAL}/services" 2> /dev/null | sha256sum | cut -d ' ' -f 1
}

ruconet_members() {
    sed -e 's/#.*//' "${RUCONET_ETC}/members" | awk 'NF >= 2 && $1 ~ /^[a-z0-9-]+$/ { print $1, $2 }'
}

ruconet_invalid() {
    sed -e 's/#.*//' "${RUCONET_ETC}/members" | awk 'NF >= 2 && $1 !~ /^[a-z0-9-]+$/ { print $1 }'
}

ruconet_policy() {
    sed -e 's/#.*//' "${RUCONET_ETC}/policy" | awk 'NF >= 2'
}

ruconet_services() {
    sed -e 's/#.*//' "${RUCONET_LOCAL}/services" 2> /dev/null | awk 'NF >= 3'
}

ruconet_ports() {
    ruconet_entries | awk '$1 == "server" { print $2 }' | paste -s -d , -
}

ruconet_address() {
    ruconet_members | awk -v name="$1" '$1 == name { print $2; exit }'
}

ruconet_reverse() {
    echo "${PREFIX}" | awk -F '[./]' '{ zone = "in-addr.arpa"; for (i = 1; i <= int($5 / 8); i++) zone = $i "." zone; print zone }'
}

ruconet_variable() {
    printf 'RUCONET_PEER_%s_%s' "$(printf '%s' "$1" | tr 'a-z-' 'A-Z_')" "$2"
}

ruconet_peer_public_key() {
    printenv "$(ruconet_variable "$1" PUBLIC_KEY)"
}

ruconet_peer_preshared_key() {
    printenv "$(ruconet_variable "$1" PRESHARED_KEY)"
}

ruconet_public_key() {
    printf '%s\n' "${RUCONET_PRIVATE_KEY}" | wg pubkey
}

ruconet_interface() {
    ip link show "${RUCONET_INTERFACE}" > /dev/null 2>&1 || ip link add "${RUCONET_INTERFACE}" type wireguard
    ip address replace "${1}/${PREFIX#*/}" dev "${RUCONET_INTERFACE}"
    ip link set "${RUCONET_INTERFACE}" mtu "${MTU}" up
}

ruconet_rule() {
    while ip rule del "$@" 2> /dev/null; do :; done
    ip rule add "$@"
}

ruconet_unbound() {
    cat <<CONF
server:
    username: "unbound"
    chroot: ""
    directory: "/var/lib/unbound"
    pidfile: ""
    use-syslog: no
    logfile: ""
    verbosity: 1

    port: 53
    do-ip6: no

    num-threads: 1
    hide-identity: yes
    hide-version: yes

    qname-minimisation: yes
    prefetch: yes
    serve-expired: yes
    infra-keep-probing: yes
    infra-host-ttl: 60

    tls-cert-bundle: "/etc/ssl/certs/ca-certificates.crt"
    auto-trust-anchor-file: "/var/lib/unbound/root.key"

remote-control:
    control-enable: yes
    control-interface: "${RUCONET_RUN}/unbound.ctl"
    control-use-cert: no
CONF
}

ruconet_unbound_start() {
    mkdir -p /var/lib/unbound
    [ -s /var/lib/unbound/root.key ] || cp /usr/share/dns/root.key /var/lib/unbound/root.key
    chown -R unbound:unbound /var/lib/unbound
    unbound -d -p -c "${RUCONET_RUN}/unbound.conf" &
    RUCONET_UNBOUND_PID=$!
}

ruconet_unbound_stop() {
    if [ -n "${RUCONET_UNBOUND_PID}" ]; then
        kill "${RUCONET_UNBOUND_PID}" 2> /dev/null
        wait "${RUCONET_UNBOUND_PID}" 2> /dev/null
        RUCONET_UNBOUND_PID=
    fi
}

ruconet_unbound_watch() {
    if [ -n "${RUCONET_UNBOUND_PID}" ] && ! kill -0 "${RUCONET_UNBOUND_PID}" 2> /dev/null; then
        ruconet_log "unbound exited, restarting"
        ruconet_unbound_start
    fi
}

ruconet_unbound_reload() {
    unbound-control -c "${RUCONET_RUN}/unbound.conf" reload > /dev/null
}

ruconet_unbound_health() {
    unbound-control -c "${RUCONET_RUN}/unbound.conf" status > /dev/null 2>&1
}

ruconet_endpoint() {
    case "$1" in
        *:*[!0-9]*|*:|:*|*[!0-9a-z.:-]*) return 1 ;;
        *:*) [ "${1##*:}" -ge 1 ] && [ "${1##*:}" -le 65535 ] ;;
        *) return 1 ;;
    esac
}

ruconet_entry() {
    TIMEOUT=
    PROXY=
    VERIFY=required
    for OPTION in $4; do
        case "${OPTION}" in
            timeout=[0-9]*) TIMEOUT="${OPTION#timeout=}" ;;
            proxy)          PROXY=yes ;;
            optional)       VERIFY=optional ;;
            *)              ruconet_log "services: invalid option ${OPTION}"; return 1 ;;
        esac
    done
    case "$1" in
        server)
            ruconet_endpoint "0:$2" && [ "$2" -ge 1 ] || { ruconet_log "services: invalid port $2"; return 1; }
            ruconet_endpoint "$3" || { ruconet_log "services: invalid target $3"; return 1; }
            ;;
        client)
            ruconet_endpoint "$2" || { ruconet_log "services: invalid listen address $2"; return 1; }
            ruconet_endpoint "$3" && [ -n "$(ruconet_address "${3%:*}")" ] || { ruconet_log "services: unknown member in $3"; return 1; }
            [ -z "${PROXY}" ] && [ "${VERIFY}" = required ] || { ruconet_log "services: proxy and optional are only valid for server"; return 1; }
            ;;
        *)
            ruconet_log "services: invalid type $1"
            return 1
            ;;
    esac
}

ruconet_entries() {
    ruconet_services | while read -r TYPE LISTEN TARGET OPTIONS; do
        if ruconet_entry "${TYPE}" "${LISTEN}" "${TARGET}" "${OPTIONS}"; then
            printf '%s %s %s %s\n' "${TYPE}" "${LISTEN}" "${TARGET}" "${OPTIONS}"
        fi
    done
}

ruconet_haproxy() {
    ruconet_entries | while read -r TYPE LISTEN TARGET OPTIONS; do
        ruconet_entry "${TYPE}" "${LISTEN}" "${TARGET}" "${OPTIONS}"
        printf '\nlisten %s-%s\n' "${TYPE}" "${LISTEN}"
        if [ "${TYPE}" = server ]; then
            printf '    bind %s:%s ssl crt "@ruconet/ruconet" ca-file "%s/ca.pem" verify %s\n' "${ADDRESS}" "${LISTEN}" "${RUCONET_CERTS}" "${VERIFY}"
        else
            printf '    bind %s\n' "${LISTEN}"
        fi
        if [ -n "${TIMEOUT}" ]; then
            printf '    timeout client %s\n    timeout server %s\n' "${TIMEOUT}" "${TIMEOUT}"
        fi
        if [ "${TYPE}" = server ]; then
            printf '    server local %s%s\n' "${TARGET}" "${PROXY:+ send-proxy-v2 send-proxy-v2-ssl-cn}"
        else
            MEMBER="${TARGET%:*}"
            printf '    server %s %s:%s ssl crt "@ruconet/ruconet" ca-file "%s/ca.pem" verify required verifyhost %s.%s sni str(%s.%s)\n' \
                "${MEMBER}" "$(ruconet_address "${MEMBER}")" "${TARGET##*:}" "${RUCONET_CERTS}" "${MEMBER}" "${DOMAIN}" "${MEMBER}" "${DOMAIN}"
        fi
    done
}

ruconet_haproxy_start() {
    haproxy -W -db -p "${RUCONET_RUN}/haproxy.pid" -f "${RUCONET_HAPROXY}" -f "${RUCONET_RUN}/haproxy.cfg" &
    RUCONET_HAPROXY_PID=$!
}

ruconet_haproxy_stop() {
    if [ -n "${RUCONET_HAPROXY_PID}" ]; then
        kill "${RUCONET_HAPROXY_PID}" 2> /dev/null
        wait "${RUCONET_HAPROXY_PID}" 2> /dev/null
        RUCONET_HAPROXY_PID=
    fi
}

ruconet_haproxy_running() {
    [ -n "${RUCONET_HAPROXY_PID}" ] && kill -0 "${RUCONET_HAPROXY_PID}" 2> /dev/null
}

ruconet_haproxy_apply() {
    DIGEST=$({ printf '%s\n' "${ADDRESS}"; cat "${RUCONET_ETC}/members" "${RUCONET_LOCAL}/services" "${RUCONET_CERTS}"/*; } 2> /dev/null | sha256sum | cut -d ' ' -f 1)
    if [ "${DIGEST}" = "${RUCONET_HAPROXY_APPLIED}" ] && { [ -z "${RUCONET_HAPROXY_PID}" ] || ruconet_haproxy_running; }; then
        return 0
    fi
    if [ -z "$(ruconet_services)" ]; then
        ruconet_haproxy_stop
        RUCONET_HAPROXY_APPLIED="${DIGEST}"
        return 0
    fi
    if [ ! -s "${RUCONET_CERTS}/cert.pem" ] || [ ! -s "${RUCONET_CERTS}/key.pem" ] || [ ! -s "${RUCONET_CERTS}/ca.pem" ]; then
        ruconet_log "waiting for the RucoNet certificate in ${RUCONET_CERTS}"
        return 1
    fi
    ruconet_haproxy > "${RUCONET_RUN}/haproxy.cfg"
    haproxy -c -q -f "${RUCONET_HAPROXY}" -f "${RUCONET_RUN}/haproxy.cfg" || { ruconet_log "invalid services"; return 1; }
    if ruconet_haproxy_running; then
        kill -USR2 "${RUCONET_HAPROXY_PID}"
        ruconet_log "haproxy reloaded"
    else
        [ -z "${RUCONET_HAPROXY_PID}" ] || ruconet_log "haproxy exited, restarting"
        ruconet_haproxy_start
    fi
    RUCONET_HAPROXY_APPLIED="${DIGEST}"
}

ruconet_haproxy_health() {
    [ -z "$(ruconet_services)" ] || { [ -s "${RUCONET_RUN}/haproxy.pid" ] && kill -0 "$(head -n 1 "${RUCONET_RUN}/haproxy.pid")" 2> /dev/null; }
}
