# $Id: Makefile.in,v 1.5 2014/06/17 13:06:08 dtucker Exp $

sysconfdir=/etc/storage/openssh
piddir=/var/run
srcdir=.
top_srcdir=../..


CC=/opt/rt-n56u/toolchain-mipsel/toolchain-3.4.x/bin/mipsel-linux-uclibc-gcc -mips32r2 -march=mips32r2
LD=/opt/rt-n56u/toolchain-mipsel/toolchain-3.4.x/bin/mipsel-linux-uclibc-gcc -mips32r2 -march=mips32r2
CFLAGS=-Os -fomit-frame-pointer -pipe  -Dlinux -D__linux__ -Dunix -DEMBED -I/opt/rt-n56u/trunk/stage/include -Wall -Wno-trigraphs -Wno-strict-aliasing -Wno-format-security   -Wno-pointer-sign -ffunction-sections -fdata-sections -ffunction-sections -fdata-sections -Wall -Wpointer-arith -Wuninitialized -Wsign-compare -Wformat-security -Wno-pointer-sign -fno-strict-aliasing -D_FORTIFY_SOURCE=2 -ftrapv -fno-builtin-memset -fPIE 
CPPFLAGS=-I. -I.. -I$(srcdir) -I$(srcdir)/..  -DHAVE_CONFIG_H
EXEEXT=
LIBCOMPAT=../libopenbsd-compat.a
LIBS=-lcrypto -ldl -lutil -lz  -lcrypt
LDFLAGS=-L/opt/rt-n56u/trunk/stage/lib -Wl,--gc-sections -Wl,--gc-sections -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -pie $(LIBCOMPAT)

TESTPROGS=closefromtest$(EXEEXT) snprintftest$(EXEEXT) strduptest$(EXEEXT) \
	strtonumtest$(EXEEXT) opensslvertest$(EXEEXT)

all:	t-exec ${OTHERTESTS}

%$(EXEEXT):	%.c $(LIBCOMPAT)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $< $(LIBCOMPAT) $(LIBS)

t-exec:	$(TESTPROGS)
	@echo running compat regress tests
	@for TEST in ""$?; do \
		echo "run test $${TEST}" ... 1>&2; \
		./$${TEST}$(EXEEXT) || exit $$? ; \
	done
	@echo finished compat regress tests

clean:
	rm -f *.o *.a core $(TESTPROGS) valid.out

distclean: clean
	rm -f Makefile *~
