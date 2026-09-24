#!/bin/sh
set -u

certificates() {
    cat /etc/certs/*/* 2> /dev/null | sha256sum
}

running() {
    [ -s /run/nginx.pid ] && kill -0 "$(cat /run/nginx.pid)" 2> /dev/null
}

main() {
    until nginx -t -q 2> /tmp/nginx-test; do
        echo "nginx: waiting for a valid configuration: $(head -n 1 /tmp/nginx-test)" >&2
        sleep 10
    done

    (
        CURRENT=$(certificates)
        while sleep 60; do
            NEXT=$(certificates)
            if [ "${NEXT}" != "${CURRENT}" ] && nginx -t -q; then
                nginx -s reload
                CURRENT="${NEXT}"
            fi
        done
    ) &

    exec nginx -g 'daemon off;'
}

reload() {
    if ! running; then
        echo "nginx: not running yet, the configuration is loaded on start" >&2
        return 0
    fi
    nginx -t && nginx -s reload
}

case "${1:-main}" in
    main)   main ;;
    reload) reload ;;
    *)      echo "Usage: $0 [main|reload]" >&2; exit 2 ;;
esac
