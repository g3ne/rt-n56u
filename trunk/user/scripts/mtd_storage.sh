#!/bin/sh

result=0
mtd_part_name="Storage"
mtd_part_dev="/dev/mtdblock5"
#mtd_part_size=65536
mtd_part_size=200000
dir_storage="/etc/storage"
slk="/tmp/.storage_locked"
tmp="/tmp/storage.tar"
tbz="${tmp}.bz2"
hsh="/tmp/hashes/storage_md5"

func_get_mtd()
{
	local mtd_part mtd_char mtd_idx mtd_hex
	mtd_part=`cat /proc/mtd | grep \"$mtd_part_name\"`
	mtd_char=`echo $mtd_part | cut -d':' -f1`
	mtd_hex=`echo $mtd_part | cut -d' ' -f2`
	mtd_idx=`echo $mtd_char | cut -c4-5`
	if [ -n "$mtd_idx" ] && [ $mtd_idx -ge 4 ] ; then
		mtd_part_dev="/dev/mtdblock${mtd_idx}"
		mtd_part_size=`echo $((0x$mtd_hex))`
	else
		logger -t "Storage" "Cannot find MTD partition: $mtd_part_name"
		exit 1
	fi
}

func_mdir()
{
	[ ! -d "$dir_storage" ] && mkdir -p -m 755 $dir_storage
}

func_stop_apps()
{
	killall -q rstats
	[ $? -eq 0 ] && sleep 1
}

func_start_apps()
{
	/sbin/rstats
}

func_load()
{
	local fsz

	bzcat $mtd_part_dev > $tmp 2>/dev/null
	fsz=`stat -c %s $tmp 2>/dev/null`
	if [ -n "$fsz" ] && [ $fsz -gt 0 ] ; then
		md5sum $tmp > $hsh
		tar xf $tmp -C $dir_storage 2>/dev/null
	else
		result=1
		rm -f $hsh
		logger -t "Storage load" "Invalid storage data in MTD partition: $mtd_part_dev"
	fi
	rm -f $tmp
	rm -f $slk
}

func_tarb()
{
	rm -f $tmp
	cd $dir_storage
	find * -print0 | xargs -0 touch -c -h -t 201001010000.00
	find * ! -type d -print0 | sort -z | xargs -0 tar -cf $tmp 2>/dev/null
	cd - >>/dev/null
	if [ ! -f "$tmp" ] ; then
		logger -t "Storage" "Cannot create tarball file: $tmp"
		exit 1
	fi
}

func_save()
{
	local fsz
	logger -t "【保存数据】" "开始"
	echo "Save storage files to MTD partition \"$mtd_part_dev\""
	rm -f $tbz
	md5sum -c -s $hsh 2>/dev/null
	if [ $? -eq 0 ] ; then
		echo "Storage hash is not changed, skip write to MTD partition. Exit."
		logger -t "【保存数据】" "分区hash错误"
		rm -f $tmp
		return 0
	fi
	md5sum $tmp > $hsh
	bzip2 -9 $tmp 2>/dev/null
	fsz=`stat -c %s $tbz 2>/dev/null`
	if [ -n "$fsz" ] && [ $fsz -ge 16 ] && [ $fsz -le $mtd_part_size ] ; then
		mtd_write write $tbz $mtd_part_name
		if [ $? -eq 0 ] ; then
			echo "Done."
			logger -t "【保存数据】" "成功"
		else
			result=1
			echo "Error! MTD write FAILED"
			logger -t "Storage save" "Error write to MTD partition: $mtd_part_dev"
			logger -t "【保存数据】" "写入出错[$mtd_part_dev]"
		fi
	else
		result=1
		echo "Error! Invalid storage final data size: $fsz"
		logger -t "Storage save" "Invalid storage final data size: $fsz"
		[ $fsz -gt $mtd_part_size ] && logger -t "Storage save" "Storage using data size: $fsz > flash partition size: $mtd_part_size"
	fi
	rm -f $tmp
	rm -f $tbz
	logger -t "【保存数据】" "结束"
}

func_backup()
{
	rm -f $tbz
	bzip2 -9 $tmp 2>/dev/null
	if [ $? -ne 0 ] ; then
		result=1
		logger -t "Storage backup" "Cannot create BZ2 file!"
	fi
	rm -f $tmp
}

func_restore()
{
	local fsz tmp_storage

	[ ! -f "$tbz" ] && exit 1

	fsz=`stat -c %s $tbz 2>/dev/null`
	if [ -z "$fsz" ] || [ $fsz -lt 16 ] || [ $fsz -gt $mtd_part_size ] ; then
		result=1
		rm -f $tbz
		logger -t "Storage restore" "Invalid BZ2 file size: $fsz"
		return 1
	fi

	tmp_storage="/tmp/storage"
	rm -rf $tmp_storage
	mkdir -p -m 755 $tmp_storage
	tar xjf $tbz -C $tmp_storage 2>/dev/null
	if [ $? -ne 0 ] ; then
		result=1
		rm -f $tbz
		rm -rf $tmp_storage
		logger -t "Storage restore" "Unable to extract BZ2 file: $tbz"
		return 1
	fi
	if [ ! -f "$tmp_storage/start_script.sh" ] ; then
		result=1
		rm -f $tbz
		rm -rf $tmp_storage
		logger -t "Storage restore" "Invalid content of BZ2 file: $tbz"
		return 1
	fi

	func_stop_apps

	rm -f $slk
	rm -f $tbz
	rm -rf $dir_storage
	mkdir -p -m 755 $dir_storage
	cp -rf $tmp_storage /etc
	rm -rf $tmp_storage

	func_start_apps
}

func_erase()
{
	mtd_write erase $mtd_part_name
	if [ $? -eq 0 ] ; then
		rm -f $hsh
		rm -rf $dir_storage
		mkdir -p -m 755 $dir_storage
		touch "$slk"
	else
		result=1
	fi
}

func_reset()
{
	rm -f $slk
	rm -rf $dir_storage
	mkdir -p -m 755 $dir_storage
}

func_fill()
{
	dir_httpssl="$dir_storage/https"
	dir_dnsmasq="$dir_storage/dnsmasq"
	dir_ovpnsvr="$dir_storage/openvpn/server"
	dir_ovpncli="$dir_storage/openvpn/client"
	dir_sswan="$dir_storage/strongswan"
	dir_sswan_crt="$dir_sswan/ipsec.d"
	dir_inadyn="$dir_storage/inadyn"
	dir_crond="$dir_storage/cron/crontabs"
	dir_wlan="$dir_storage/wlan"
	dir_chnroute="$dir_storage/chinadns"
	dir_dnsmasq_china_conf="$dir_storage/dnsmasq-china-conf"

	script_start="$dir_storage/start_script.sh"
	script_started="$dir_storage/started_script.sh"
	script_shutd="$dir_storage/shutdown_script.sh"
	script_postf="$dir_storage/post_iptables_script.sh"
	script_postw="$dir_storage/post_wan_script.sh"
	script_inets="$dir_storage/inet_state_script.sh"
	script_vpnsc="$dir_storage/vpns_client_script.sh"
	script_vpncs="$dir_storage/vpnc_server_script.sh"
	script_ezbtn="$dir_storage/ez_buttons_script.sh"

	user_hosts="$dir_dnsmasq/hosts"
	user_dnsmasq_conf="$dir_dnsmasq/dnsmasq.conf"
	user_dnsmasq_serv="$dir_dnsmasq/dnsmasq.servers"
	user_ovpnsvr_conf="$dir_ovpnsvr/server.conf"
	user_ovpncli_conf="$dir_ovpncli/client.conf"
	user_inadyn_conf="$dir_inadyn/inadyn.conf"
	user_sswan_conf="$dir_sswan/strongswan.conf"
	user_sswan_ipsec_conf="$dir_sswan/ipsec.conf"
	user_sswan_secrets="$dir_sswan/ipsec.secrets"
	
	chnroute_file="/etc_ro/chnroute.bz2"
	dnsmasq_china_conf_file="/etc_ro/dnsmasq-china-conf/dnsmasq-china-conf.bz2"

	# create crond dir
	[ ! -d "$dir_crond" ] && mkdir -p -m 730 "$dir_crond"

	# create https dir
	[ ! -d "$dir_httpssl" ] && mkdir -p -m 700 "$dir_httpssl"

	# create chnroute.txt
	if [ ! -d "$dir_chnroute" ] ; then
		if [ -f "$chnroute_file" ]; then
			mkdir -p "$dir_chnroute" && tar jxf "$chnroute_file" -C "$dir_chnroute"
		fi
	fi

	# create dnsmasq-china-conf
	if [ ! -d "$dir_dnsmasq_china_conf" ] ; then
		if [ -f "$dnsmasq_china_conf_file" ]; then	
			mkdir -p "$dir_dnsmasq_china_conf" && tar jxf "$dnsmasq_china_conf_file" -C "$dir_dnsmasq_china_conf"
		fi
	fi
	
	
	
	#######################################
	smartdns_cpu_dog_sh="$dir_storage/smartdns.dog.sh"
	if [ ! -f "$smartdns_cpu_dog_sh" ] ; then
		cat > "$smartdns_cpu_dog_sh" <<EOF
#!/bin/sh
export PATH='/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin'
record=0
while true; do 
    pid=\$(top -b -n1 | grep "smartdns" | head -1 | awk '{print \$1}')
    cpu=\$(top -b -n1 | grep "smartdns" | head -1 | awk '{print \$7}')
    result=\${cpu/.*}
    if [[ \$record == \$pid ]]; then 
        kill -9 \$pid
        bin=/etc/storage/smartdns && [ ! -s \$bin ] && bin=smartdns
        \$bin -p /tmp/smartdns.pid -c /etc/storage/smartdns.conf
        logger -t "【重启smartdns】" "pid:\$pid, cpu:\$cpu"
    fi
    if [[ \$result > 60 ]]; then 
        let record=\${pid}
        else let record=0
    fi
    sleep 60
done
EOF
		chmod 755 "$smartdns_cpu_dog_sh"
	fi
	#######################################
	crontabs_admin="$dir_storage/cron/crontabs/admin"
	if [ ! -f "$crontabs_admin" ] ; then
		cat > "$crontabs_admin" <<EOF
* * * * * /etc/storage/dog.sh > /tmp/dog.sh.log 2>&1
*/30 * * * * sh -c 'rm -fr /tmp/nginx.err.log ; kill -USR1 \`ps|grep nginx|grep -v grep|awk "{print \$1}"\`' 2>&1
EOF
		chmod 644 "$crontabs_admin"
	fi
	#######################################
	nginx_dog_sh="$dir_storage/dog.sh"
	if [ ! -f "$nginx_dog_sh" ] ; then
		cat > "$nginx_dog_sh" <<EOF
#!/bin/sh
export PATH='/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin'
#ps;env;echo \$0 #/etc/storage/dog.sh
#################### nginx
count=\`ps|grep nginx|grep -v grep|grep -v /bin/sh|grep -v dog.sh|wc -l\`
if [ \$count -gt 0 ]; then
    echo NGINX_SKIP
else
	sleep 2
	count=\`ps|grep nginx|grep -v grep|grep -v /bin/sh|grep -v dog.sh|wc -l\`
	if [ \$count -gt 0 ]; then
		echo NGINX_SKIP
	else
		logger -t "【启动nginx】" "..." 
		nginx -c /etc/storage/nginx.conf 
	fi
fi
#################### smartdns
count=\`ps|grep smartdns|grep -v smartdns|grep -v /bin/sh|grep -v dog.sh|wc -l\`
if [ \$count -gt 0 ]; then
    echo SMARTDNS_SKIP
else
	sleep 2
	count=\`ps|grep smartdns|grep -v smartdns|grep -v /bin/sh|grep -v dog.sh|wc -l\`
	if [ \$count -gt 0 ]; then
		echo SMARTDNS_SKIP
	else
		logger -t "【启动smartdns】" "..." 
        bin=/etc/storage/smartdns && [ ! -s \$bin ] && bin=smartdns
        \$bin -p /tmp/smartdns.pid -c /etc/storage/smartdns.conf
	fi
fi
####################
EOF
		chmod 755 "$nginx_dog_sh"
	fi
	#######################################
	nginx_conf="$dir_storage/nginx.conf"
	if [ ! -f "$nginx_conf" ] ; then
		cat > "$nginx_conf" <<EOF
master_process off;
user nobody;
worker_processes  1;
#error_log /tmp/nginx.err.log debug;
error_log /tmp/nginx.err.log;
pid /tmp/nginx.pid;
events {
    worker_connections 1024;
}
stream {
    upstream group1 {
        hash \$remote_addr consistent;
        server 148.100.5.230:30001;
        server 148.100.5.231:30001;
        #server 165.227.81.240:30001;
        server 216.200.116.133:30001;
        server 216.200.116.15:30001;
        server 34.221.170.134:30001;
        server 150.109.49.169:30001;
        server 18.196.36.65:30001;
        #server 169.51.25.7:30001;
        #server 169.51.27.177:30001;
        server 45.33.109.44:30001;
        server 13.113.106.246:30001;
        server 119.28.51.119:30001;
        server 45.77.31.56:30001;
        #server 45.77.31.56:30001 down;
        #server backend1.example.com:12345 weight=5;
        #server 127.0.0.1:12345 max_fails=3 fail_timeout=30s;
        check interval=3000 rise=5 fall=5 timeout=1000 default_down=false type=tcp;
        #keepalive 32;
    }
    server {
        listen 127.0.0.1:30001;
        listen 127.0.0.1:30001 udp;
        proxy_connect_timeout 2s;
        #proxy_timeout 60s;#没有传输数据则关闭连接 
        proxy_pass group1;
    }
}
http {
    server {
        listen 888;
        location /upstreamstatus/ {
            healthcheck_status html;
        }
        location / {
			return 444;
        }   
    }
}
EOF
		chmod 644 "$nginx_conf"
	fi
	#######################################
	smartdns_conf="$dir_storage/smartdns.conf"
	if [ ! -f "$smartdns_conf" ] ; then
		cat > "$smartdns_conf" <<EOF
# dns server name, defaut is host name
# server-name, 
# example:
server-name DNS
# dns server bind ip and port, default dns server port is 53.
# bind [IP]:port, 
# example: 
#   IPV4: :53
#   IPV6  [::]:53
bind 127.0.0.1:535
#bind [::]:535
# dns cache size
# cache-size [number]
#   0: for no cache
cache-size 10240
# ttl for all resource record
# rr-ttl: ttl for all record
# rr-ttl-min: minimum ttl for resource record
# rr-ttl-max: maximum ttl for resource record
# example:
rr-ttl 300
rr-ttl-min 60
rr-ttl-max 86400
# set log level
# log-level [level], level=error, warn, info, debug
# log-size k,m,g
#log-level debug
log-level error
log-file ../../../../../../../../tmp/smartdns.log
#log-file /tmp/smartdns.log
log-size 128k
log-num 2


# remote udp dns server list
# server [IP]:[PORT], default port is 53
#server 8.8.8.8
#server 114.114.114.114
#server 119.29.29.29
#server 1.2.4.8
#server 9.9.9.9
#server 208.67.222.222
#server 199.85.126.10
#server 180.76.76.76
#server 223.5.5.5
#server 101.226.4.6
#server 123.125.81.6
#server 202.112.20.131
#server 202.202.0.33


#dig youtube.com @101.226.4.6 +tcp
# remote tcp dns server list
# server-tcp [IP]:[PORT], default port is 53
#HK
server-tcp 210.3.1.38
server-tcp 210.87.251.1
server-tcp 103.198.192.43
server-tcp 210.0.128.115
server-tcp 202.45.84.59
server-tcp 202.55.11.100
server-tcp 202.2.77.195
#TW
server-tcp 204.152.184.76
server-tcp 1.34.242.194
#JP
server-tcp 1.33.204.36
server-tcp 1.33.197.187
server-tcp 101.110.50.106
server-tcp 219.96.224.90
#PUB
server-tcp 1.1.1.1
server-tcp 8.8.8.8
#server-tcp 114.114.114.114
#server-tcp 119.29.29.29
#server-tcp 1.2.4.8
server-tcp 9.9.9.9
server-tcp 208.67.222.222
server-tcp 199.85.126.10


# specific address to domain
# address /domain/ip
# address /www.example.com/1.2.3.4
address /www.youtubex.com/1.2.3.4
EOF
		chmod 644 "$smartdns_conf"
	fi
	#######################################
	


	# create start script
	if [ ! -f "$script_start" ] ; then
		reset_ss.sh -a
	fi

	# create started script
	if [ ! -f "$script_started" ] ; then
		cat > "$script_started" <<EOF
#!/bin/sh
export PATH='/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin'
### Custom user script
### Called after router started and network is ready

### Example - load ipset modules
#modprobe ip_set
#modprobe ip_set_hash_ip
#modprobe ip_set_hash_net
#modprobe ip_set_bitmap_ip
#modprobe ip_set_list_set
#modprobe xt_set

########################################Nginx
addgroup nobody
#nginx -c /etc/storage/nginx.conf
#不能启动，改用cron实现 
#* * * * * /etc/storage/dog.sh > /tmp/dog.sh.log 2>&1 
#*/30 * * * * sh -c 'rm -fr /tmp/nginx.err.log ; kill -USR1 \`ps|grep nginx|grep -v grep|awk "{print \$1}"\`' 2>&1 
########################################Smartdns
bin=/etc/storage/smartdns && [ ! -f \$bin ] && bin=smartdns
logger -t "【启动】" "\$bin"
start-stop-daemon -S -b -x \$bin -- -p /tmp/smartdns.pid -c /etc/storage/smartdns.conf
#监控cpu占用重启 
start-stop-daemon -S -b -x /etc/storage/smartdns.dog.sh
########################################Dnsmasq
bin=/etc/storage/dnsmasq/hosts.tar.gz 
[ -f \$bin ] && wget 'https://github.com/g3ne/hosts/raw/master/hosts.tar.gz' -O \$bin && mtd_storage.sh save && sleep 5 
[ -f \$bin ] && tar -xzf \$bin -C /tmp && killall -SIGHUP dnsmasq 
########################################
logger -t "【启动脚本结束】" ""

EOF
		chmod 755 "$script_started"
	fi

	# create shutdown script
	if [ ! -f "$script_shutd" ] ; then
		cat > "$script_shutd" <<EOF
#!/bin/sh
export PATH='/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin'
### Custom user script
### Called before router shutdown
### \$1 - action (0: reboot, 1: halt, 2: power-off)

EOF
		chmod 755 "$script_shutd"
	fi

	# create post-iptables script

	if [ ! -f "$script_postf" ] ; then
		cat > "$script_postf" <<EOF
#!/bin/sh
export PATH='/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin'
### Custom user script
### Called after internal iptables reconfig (firewall update)

if [ -f "/tmp/shadowsocks_iptables.save" ]; then
	sh /tmp/shadowsocks_iptables.save
fi

EOF
		chmod 755 "$script_postf"
	fi

	# create post-wan script
	if [ ! -f "$script_postw" ] ; then
		cat > "$script_postw" <<EOF
#!/bin/sh
export PATH='/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin'
### Custom user script
### Called after internal WAN up/down action
### \$1 - WAN action (up/down)
### \$2 - WAN interface name (e.g. eth3 or ppp0)
### \$3 - WAN IPv4 address

wget 'https://github.com/g3ne/hosts/raw/master/hosts.tar.gz' -O /etc/storage/dnsmasq/hosts.tar.gz


EOF
		chmod 755 "$script_postw"
	fi

	# create inet-state script
	if [ ! -f "$script_inets" ] ; then
		cat > "$script_inets" <<EOF
#!/bin/sh
export PATH='/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin'
### Custom user script
### Called on Internet status changed
### \$1 - Internet status (0/1)
### \$2 - elapsed time (s) from previous state

logger -t "di" "Internet state: \$1, elapsed time: \$2s."

if [ -f "/bin/scutclient.sh" ]; then
	scutclient.sh restart
fi

EOF
		chmod 755 "$script_inets"
	fi

	# create vpn server action script
	if [ ! -f "$script_vpnsc" ] ; then
		cat > "$script_vpnsc" <<EOF
#!/bin/sh

### Custom user script
### Called after remote peer connected/disconnected to internal VPN server
### \$1 - peer action (up/down)
### \$2 - peer interface name (e.g. ppp10)
### \$3 - peer local IP address
### \$4 - peer remote IP address
### \$5 - peer name

peer_if="\$2"
peer_ip="\$4"
peer_name="\$5"

### example: add static route to private LAN subnet behind a remote peer

func_ipup()
{
#  if [ "\$peer_name" == "dmitry" ] ; then
#    route add -net 192.168.5.0 netmask 255.255.255.0 dev \$peer_if
#  elif [ "\$peer_name" == "victoria" ] ; then
#    route add -net 192.168.8.0 netmask 255.255.255.0 dev \$peer_if
#  fi
   return 0
}

func_ipdown()
{
#  if [ "\$peer_name" == "dmitry" ] ; then
#    route del -net 192.168.5.0 netmask 255.255.255.0 dev \$peer_if
#  elif [ "\$peer_name" == "victoria" ] ; then
#    route del -net 192.168.8.0 netmask 255.255.255.0 dev \$peer_if
#  fi
   return 0
}

case "\$1" in
up)
  func_ipup
  ;;
down)
  func_ipdown
  ;;
esac

EOF
		chmod 755 "$script_vpnsc"
	fi

	# create vpn client action script
	if [ ! -f "$script_vpncs" ] ; then
		cat > "$script_vpncs" <<EOF
#!/bin/sh

### Custom user script
### Called after internal VPN client connected/disconnected to remote VPN server
### \$1        - action (up/down)
### \$IFNAME   - tunnel interface name (e.g. ppp5 or tun0)
### \$IPLOCAL  - tunnel local IP address
### \$IPREMOTE - tunnel remote IP address
### \$DNS1     - peer DNS1
### \$DNS2     - peer DNS2

# private LAN subnet behind a remote server (example)
peer_lan="192.168.9.0"
peer_msk="255.255.255.0"

### example: add static route to private LAN subnet behind a remote server

func_ipup()
{
#  route add -net \$peer_lan netmask \$peer_msk gw \$IPREMOTE dev \$IFNAME
   return 0
}

func_ipdown()
{
#  route del -net \$peer_lan netmask \$peer_msk gw \$IPREMOTE dev \$IFNAME
   return 0
}

logger -t vpnc-script "\$IFNAME \$1"

case "\$1" in
up)
  func_ipup
  ;;
down)
  func_ipdown
  ;;
esac

EOF
		chmod 755 "$script_vpncs"
	fi

	# create Ez-Buttons script
	if [ ! -f "$script_ezbtn" ] ; then
		cat > "$script_ezbtn" <<EOF
#!/bin/sh
export PATH='/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin'
### Custom user script
### Called on WPS or FN button pressed
### \$1 - button param

[ -x /opt/bin/on_wps.sh ] && /opt/bin/on_wps.sh \$1 &

EOF
		chmod 755 "$script_ezbtn"
	fi

	# create user dnsmasq.conf
	[ ! -d "$dir_dnsmasq" ] && mkdir -p -m 755 "$dir_dnsmasq"
	for i in dnsmasq.conf hosts ; do
		[ -f "$dir_storage/$i" ] && mv -n "$dir_storage/$i" "$dir_dnsmasq"
	done
	if [ ! -f "$user_dnsmasq_conf" ] ; then
		cat > "$user_dnsmasq_conf" <<EOF
# Custom user conf file for dnsmasq
# Please add needed params only!

### Web Proxy Automatic Discovery (WPAD)
dhcp-option=252,"\n"

### Set the limit on DHCP leases, the default is 150
#dhcp-lease-max=150

### Add local-only domains, queries are answered from hosts or DHCP only
#local=/router/localdomain/

### Examples:

### Enable built-in TFTP server
#enable-tftp

### Set the root directory for files available via TFTP.
#tftp-root=/opt/srv/tftp

### Make the TFTP server more secure
#tftp-secure

### Set the boot filename for netboot/PXE
#dhcp-boot=pxelinux.0

### 额外hosts文件 
addn-hosts=/tmp/hosts
### smartdns 
no-resolv
server=127.0.0.1#535

EOF
	if [ -f /usr/bin/vlmcsd ]; then
		cat >> "$user_dnsmasq_conf" <<EOF
### vlmcsd related
srv-host=_vlmcs._tcp,my.router,1688,0,100

EOF
	fi
	if [ -f /usr/bin/chinadns ]; then
		cat >> "$user_dnsmasq_conf" <<EOF
### ChinaDNS related
#no-resolv
#server=127.0.0.1#5302

EOF
	fi
	if [ -d /etc_ro/dnsmasq-china-conf ]; then
		cat >> "$user_dnsmasq_conf" <<EOF
### dnsmasq-china-list related
#no-resolv
#conf-dir=/etc/storage/dnsmasq-china-conf
#server=127.0.0.1#5301

EOF
	fi
		chmod 644 "$user_dnsmasq_conf"
	fi

	# create user dns servers
	if [ ! -f "$user_dnsmasq_serv" ] ; then
		cat > "$user_dnsmasq_serv" <<EOF
# Custom user servers file for dnsmasq
# Example:
#server=/mit.ru/izmuroma.ru/10.25.11.30

EOF
		chmod 644 "$user_dnsmasq_serv"
	fi

	# create user inadyn.conf"
	[ ! -d "$dir_inadyn" ] && mkdir -p -m 755 "$dir_inadyn"
	if [ ! -f "$user_inadyn_conf" ] ; then
		cat > "$user_inadyn_conf" <<EOF
# Custom user conf file for inadyn DDNS client
# Please add only new custom system!

### Example for twoDNS.de:

#system custom@http_srv_basic_auth
#  ssl
#  checkip-url checkip.two-dns.de /
#  server-name update.twodns.de
#  server-url /update\?hostname=
#  username account
#  password secret
#  alias example.dd-dns.de

EOF
		chmod 644 "$user_inadyn_conf"
	fi

	# create user hosts
	if [ ! -f "$user_hosts" ] ; then
		cat > "$user_hosts" <<EOF
# Custom user hosts file
# Example:
# 192.168.1.100		Boo

EOF
		chmod 644 "$user_hosts"
	fi

	# create user AP confs
	[ ! -d "$dir_wlan" ] && mkdir -p -m 755 "$dir_wlan"
	if [ ! -f "$dir_wlan/AP.dat" ] ; then
		cat > "$dir_wlan/AP.dat" <<EOF
# Custom user AP conf file

EOF
		chmod 644 "$dir_wlan/AP.dat"
	fi

	if [ ! -f "$dir_wlan/AP_5G.dat" ] ; then
		cat > "$dir_wlan/AP_5G.dat" <<EOF
# Custom user AP conf file

EOF
		chmod 644 "$dir_wlan/AP_5G.dat"
	fi

	# create openvpn files
	if [ -x /usr/sbin/openvpn ] ; then
		[ ! -d "$dir_ovpncli" ] && mkdir -p -m 700 "$dir_ovpncli"
		[ ! -d "$dir_ovpnsvr" ] && mkdir -p -m 700 "$dir_ovpnsvr"
		dir_ovpn="$dir_storage/openvpn"
		for i in ca.crt dh1024.pem server.crt server.key server.conf ta.key ; do
			[ -f "$dir_ovpn/$i" ] && mv -n "$dir_ovpn/$i" "$dir_ovpnsvr"
		done
		if [ ! -f "$user_ovpnsvr_conf" ] ; then
			cat > "$user_ovpnsvr_conf" <<EOF
# Custom user conf file for OpenVPN server
# Please add needed params only!

### Max clients limit
max-clients 10

### Internally route client-to-client traffic
client-to-client

### Allow clients with duplicate "Common Name"
;duplicate-cn

### Keepalive and timeout
keepalive 10 60

### Process priority level (0..19)
nice 3

### Syslog verbose level
verb 0
mute 10

EOF
			chmod 644 "$user_ovpnsvr_conf"
		fi

		if [ ! -f "$user_ovpncli_conf" ] ; then
			cat > "$user_ovpncli_conf" <<EOF
# Custom user conf file for OpenVPN client
# Please add needed params only!

### If your server certificates with the nsCertType field set to "server"
ns-cert-type server

### Process priority level (0..19)
nice 0

### Syslog verbose level
verb 0
mute 10

EOF
			chmod 644 "$user_ovpncli_conf"
		fi
	fi

	# create strongswan files
	if [ -x /usr/sbin/ipsec ] ; then
		[ ! -d "$dir_sswan" ] && mkdir -p -m 700 "$dir_sswan"
		[ ! -d "$dir_sswan_crt" ] && mkdir -p -m 700 "$dir_sswan_crt"
		[ ! -d "$dir_sswan_crt/cacerts" ] && mkdir -p -m 700 "$dir_sswan_crt/cacerts"
		[ ! -d "$dir_sswan_crt/certs" ] && mkdir -p -m 700 "$dir_sswan_crt/certs"
		[ ! -d "$dir_sswan_crt/private" ] && mkdir -p -m 700 "$dir_sswan_crt/private"

		if [ ! -f "$user_sswan_conf" ] ; then
			cat > "$user_sswan_conf" <<EOF
### strongswan.conf - user strongswan configuration file

EOF
			chmod 644 "$user_sswan_conf"
		fi
		if [ ! -f "$user_sswan_ipsec_conf" ] ; then
			cat > "$user_sswan_ipsec_conf" <<EOF
### ipsec.conf - user strongswan IPsec configuration file

EOF
			chmod 644 "$user_sswan_ipsec_conf"
		fi
		if [ ! -f "$user_sswan_secrets" ] ; then
			cat > "$user_sswan_secrets" <<EOF
### ipsec.secrets - user strongswan IPsec secrets file

EOF
			chmod 644 "$user_sswan_secrets"
		fi
	fi
}

case "$1" in
load)
	func_get_mtd
	func_mdir
	func_load
	;;
save)
	[ -f "$slk" ] && exit 1
	func_get_mtd
	func_mdir
	func_tarb
	func_save
	;;
backup)
	func_mdir
	func_tarb
	func_backup
	;;
restore)
	func_get_mtd
	func_restore
	;;
erase)
	func_get_mtd
	func_erase
	;;
reset)
	func_stop_apps
	func_reset
	func_fill
	func_start_apps
	;;
fill)
	func_mdir
	func_fill
	;;
*)
	echo "Usage: $0 {load|save|backup|restore|erase|reset|fill}"
	exit 1
	;;
esac

exit $result
