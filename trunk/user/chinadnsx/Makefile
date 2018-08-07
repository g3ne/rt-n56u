THISDIR = $(shell pwd)

all:

clean:

romfs:
	chmod -R +x ./scripts
	$(ROMFSINST) $(THISDIR)/scripts /usr/bin/
	$(ROMFSINST) -p +x $(THISDIR)/chinadns /usr/bin/chinadns
	$(ROMFSINST) $(THISDIR)/chinadns_iplist.txt /etc/storage/chinadns/chinadns_iplist.txt
	$(ROMFSINST) $(THISDIR)/chinadns_chnroute.txt /etc/storage/chinadns/chinadns_chnroute.txt
