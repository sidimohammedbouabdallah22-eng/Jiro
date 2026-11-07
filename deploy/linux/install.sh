#!/bin/sh
set -eu
package=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
destination=${DESTDIR:-}
if [ -n "$destination" ]; then
    case "$destination" in /*) ;; *) echo 'DESTDIR must be absolute' >&2; exit 1;; esac
elif [ "$(id -u)" != 0 ]; then
    echo 'Run the installer as root, or set DESTDIR for staging.' >&2
    exit 1
fi
for target in usr/lib/openwaf/waf-server usr/lib/openwaf/waf-admin usr/lib/openwaf/event-collector usr/lib/systemd/system/openwaf.service; do
    if [ -e "$destination/$target" ] || [ -L "$destination/$target" ]; then
        echo 'An installation exists. Follow the backup and upgrade procedure before replacing files.' >&2
        exit 1
    fi
done
install -d -m 0755 "$destination/usr/lib/openwaf" "$destination/usr/lib/systemd/system" "$destination/usr/lib/sysusers.d" "$destination/etc/openwaf"
install -m 0755 "$package/usr/lib/openwaf/waf-server" "$destination/usr/lib/openwaf/waf-server"
install -m 0755 "$package/usr/lib/openwaf/waf-admin" "$destination/usr/lib/openwaf/waf-admin"
install -m 0755 "$package/usr/lib/openwaf/event-collector" "$destination/usr/lib/openwaf/event-collector"
install -m 0644 "$package/usr/lib/systemd/system/openwaf.service" "$destination/usr/lib/systemd/system/openwaf.service"
install -m 0644 "$package/usr/lib/sysusers.d/openwaf.conf" "$destination/usr/lib/sysusers.d/openwaf.conf"
if [ ! -e "$destination/etc/openwaf/openwaf.env" ] && [ ! -L "$destination/etc/openwaf/openwaf.env" ]; then
    install -m 0644 "$package/etc/openwaf/openwaf.env" "$destination/etc/openwaf/openwaf.env"
fi
if [ -z "$destination" ]; then
    systemd-sysusers /usr/lib/sysusers.d/openwaf.conf
    if [ ! -e /etc/openwaf/admin-token ] && [ ! -L /etc/openwaf/admin-token ]; then
        credential_temp=$(mktemp /etc/openwaf/.admin-token.XXXXXXXX)
        trap 'rm -f -- "$credential_temp"' 0
        chmod 0600 "$credential_temp"
        od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > "$credential_temp"
        if [ "$(wc -c < "$credential_temp")" -ne 64 ]; then echo 'Credential generation failed' >&2; exit 1; fi
        ln "$credential_temp" /etc/openwaf/admin-token
        rm -f -- "$credential_temp"
        trap - 0
    fi
    systemctl daemon-reload
fi
echo 'Installed. Provision the certificate, configure /etc/openwaf/openwaf.env, then enable the service explicitly.'
