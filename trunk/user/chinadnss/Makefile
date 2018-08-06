THISDIR = $(shell pwd)

all:

clean:

romfs:
	$(ROMFSINST) -p +x $(THISDIR)/chinadns /usr/bin/chinadns
	mkdir /etc/storage/chinadns
	$(ROMFSINST) $(THISDIR)/chinadns_chnroute.txt /etc/storage/chinadns_chnroute.txt
	$(ROMFSINST) $(THISDIR)/chinadns_iplist.txt /etc/storage/chinadns_iplist.txt
	$(ROMFSINST) -p +x $(THISDIR)/chinadns.sh /usr/bin/chinadns.sh
