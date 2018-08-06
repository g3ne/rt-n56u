THISDIR = $(shell pwd)
#$(ROMFSINST) -p +x $(THISDIR)/chinadns /usr/bin/chinadns

all:

clean:

romfs:
	chmod -R +x ./scripts chinadns
	$(ROMFSINST) $(THISDIR)/scripts /usr/bin/
	cp ./chinadns /opt/rt-n56u/trunk/romfs/usr/bin/chinadns
	$(ROMFSINST) $(THISDIR)/chinadns_iplist.txt /etc/storage/chinadns/chinadns_iplist.txt
	$(ROMFSINST) $(THISDIR)/chinadns_chnroute.txt /etc/storage/chinadns/chinadns_chnroute.txt
