THISDIR = $(shell pwd)

all:

clean:

romfs:
	chmod 777 smartdns
	cp smartdns /opt/rt-n56u/trunk/romfs/usr/bin/smartdns
	$(ROMFSINST) $(THISDIR)/smartdns.conf /usr/bin/smartdns.conf
	cp libgcc_s.so.1 /opt/rt-n56u/trunk/romfs/usr/lib/libgcc_s.so.1
