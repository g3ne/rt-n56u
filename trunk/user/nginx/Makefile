#
#pushd /opt/rt-n56u/trunk/user/nginx/
#chmod 777 nginx ; rm -fr nginx.tgz ; tar -czf nginx.tgz nginx
#popd
#
#tar -xzf ./nginx.tgz -C /usr/bin/
#
#$(ROMFSINST) -p +x /opt/rt-n56u/trunk/user/nginx/nginx /usr/bin/nginx
#$(ROMFSINST) -p +x $(THISDIR)/nginx /usr/bin/nginx
#
#cp libgcc_s.so.1 /opt/rt-n56u/trunk/romfs/usr/lib/libgcc_s.so.1
#
THISDIR = $(shell pwd)

all:

clean:

romfs:
	chmod 777 nginx
	cp nginx /opt/rt-n56u/trunk/romfs/usr/bin/nginx
	$(ROMFSINST) ./nginx.conf /usr/bin/nginx.conf
