# $Id: Makefile.in,v 1.56 2014/09/30 23:43:08 djm Exp $

sysconfdir=/etc/storage/openssh
piddir=/var/run
srcdir=.
top_srcdir=..


CC=/opt/rt-n56u/toolchain-mipsel/toolchain-3.4.x/bin/mipsel-linux-uclibc-gcc -mips32r2 -march=mips32r2
LD=/opt/rt-n56u/toolchain-mipsel/toolchain-3.4.x/bin/mipsel-linux-uclibc-gcc -mips32r2 -march=mips32r2
CFLAGS=-Os -fomit-frame-pointer -pipe  -Dlinux -D__linux__ -Dunix -DEMBED -I/opt/rt-n56u/trunk/stage/include -Wall -Wno-trigraphs -Wno-strict-aliasing -Wno-format-security   -Wno-pointer-sign -ffunction-sections -fdata-sections -ffunction-sections -fdata-sections -Wall -Wpointer-arith -Wuninitialized -Wsign-compare -Wformat-security -Wno-pointer-sign -fno-strict-aliasing -D_FORTIFY_SOURCE=2 -ftrapv -fno-builtin-memset -fPIE 
CPPFLAGS=-I. -I.. -I$(srcdir) -I$(srcdir)/..  -DHAVE_CONFIG_H
LIBS=-lcrypto -ldl -lutil -lz  -lcrypt
AR=/opt/rt-n56u/toolchain-mipsel/toolchain-3.4.x/bin/mipsel-linux-uclibc-ar
RANLIB=/opt/rt-n56u/toolchain-mipsel/toolchain-3.4.x/bin/mipsel-linux-uclibc-ranlib
INSTALL=/usr/bin/install -c
LDFLAGS=-L. -L/opt/rt-n56u/trunk/stage/lib -Wl,--gc-sections -Wl,--gc-sections -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -pie

OPENBSD=base64.o basename.o bcrypt_pbkdf.o bindresvport.o blowfish.o daemon.o dirname.o fmt_scaled.o getcwd.o getgrouplist.o getopt_long.o getrrsetbyname.o glob.o inet_aton.o inet_ntoa.o inet_ntop.o mktemp.o pwcache.o readpassphrase.o reallocarray.o realpath.o rresvport.o setenv.o setproctitle.o sha1.o sha2.o rmd160.o md5.o sigact.o strcasestr.o strlcat.o strlcpy.o strmode.o strnlen.o strptime.o strsep.o strtonum.o strtoll.o strtoul.o strtoull.o timingsafe_bcmp.o vis.o blowfish.o bcrypt_pbkdf.o explicit_bzero.o

COMPAT=arc4random.o bsd-asprintf.o bsd-closefrom.o bsd-cray.o bsd-cygwin_util.o bsd-getpeereid.o getrrsetbyname-ldns.o bsd-err.o bsd-misc.o bsd-nextstep.o bsd-openpty.o bsd-poll.o bsd-setres_id.o bsd-snprintf.o bsd-statvfs.o bsd-waitpid.o fake-rfc2553.o openssl-compat.o xcrypt.o kludge-fd_set.o

PORTS=port-aix.o port-irix.o port-linux.o port-solaris.o port-tun.o port-uw.o

.c.o:
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<

all: libopenbsd-compat.a

$(COMPAT): ../config.h
$(OPENBSD): ../config.h
$(PORTS): ../config.h

libopenbsd-compat.a:  $(COMPAT) $(OPENBSD) $(PORTS)
	$(AR) rv $@ $(COMPAT) $(OPENBSD) $(PORTS)
	$(RANLIB) $@

clean:
	rm -f *.o *.a core

distclean: clean
	rm -f Makefile *~
