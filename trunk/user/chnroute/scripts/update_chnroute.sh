#!/bin/sh

#set -e -o pipefail

#[ "$1" != "force" ] && [ "$(nvram get ss_update_chnroute)" != "1" ] && exit 0

rm -f /tmp/chinadns_chnroute.txt
wget -O- 'http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest' | \
    awk -F\| '/CN\|ipv4/ { printf("%s/%d\n", $4, 32-log($5)/log(2)) }' > \
    /tmp/chinadns_chnroute.txt

[ ! -d /etc/storage/chinadns/ ] && mkdir /etc/storage/chinadns/
mv -f /tmp/chinadns_chnroute.txt /etc/storage/chinadns/chnroute.txt

#wget 'https://raw.githubusercontent.com/shadowsocks/ChinaDNS/master/iplist.txt' -O /etc/storage/chinadns/chinadns_iplist.txt

wget 'https://github.com/g3ne/hosts/raw/master/hosts.tar.gz' -O /etc/storage/dnsmasq/hosts.tar.gz

mtd_storage.sh save >/dev/null 2>&1

#[ -f /usr/bin/chinadns.sh ] && [ "$(nvram get chinadns_enable)" = "1" ] && /usr/bin/chinadns.sh restart >/dev/null 2>&1
#[ -f /usr/bin/shadowsocks.sh ] && [ "$(nvram get ss_enable)" = "1" ] && /usr/bin/shadowsocks.sh restart >/dev/null 2>&1

logger -st "chnroute" "Update done"
