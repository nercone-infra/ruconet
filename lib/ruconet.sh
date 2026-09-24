RUCONET_ETC=/etc/ruconet
RUCONET_RUN=/run/ruconet
RUCONET_INTERFACE=ruconet
RUCONET_TABLE=51820
RUCONET_TTL=60
RUCONET_OVERHEAD=60
RUCONET_UNBOUND_PID=

ruconet_log() {
    echo "ruconet: $*" >&2
}

ruconet_load() {
    PREFIX= DOMAIN= HUB= ENDPOINT= PORT= EGRESS= MTU= KEEPALIVE= RESOLVERS=
    . "${RUCONET_ETC}/network"
}

ruconet_digest() {
    cat "${RUCONET_ETC}/network" "${RUCONET_ETC}/members" "${RUCONET_ETC}/policy" 2> /dev/null | sha256sum | cut -d ' ' -f 1
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
    cat <<EOF
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

remote-control:
    control-enable: yes
    control-interface: "${RUCONET_RUN}/unbound.ctl"
    control-use-cert: no
EOF
}

ruconet_unbound_start() {
    mkdir -p /var/lib/unbound
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
