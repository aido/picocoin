
INCLUDES	= @GLIB_CFLAGS@ -I$(top_srcdir)/include -I$(top_srcdir)/polarssl/include

bin_PROGRAMS	= brd picocoin blkscan blkstats rawtx

noinst_LIBRARIES= libnode.a

libnode_a_SOURCES=	\
	peerman.c	\
	peerman.h

brd_SOURCES=		\
	brd.c		\
	brd.h

brd_LDADD	= libnode.a ../lib/libccoin.a $(top_srcdir)/polarssl/library/libpolarssl.a \
		  @GLIB_LIBS@ @EVENT_LIBS@

picocoin_SOURCES=	\
	main.c		\
	net.c		\
	fakepoll.h	\
	picocoin.h	\
	wallet.c wallet.h

picocoin_LDADD	= libnode.a ../lib/libccoin.a $(top_srcdir)/polarssl/library/libpolarssl.a \
		  @GLIB_LIBS@ @EVENT_LIBS@ @JANSSON_LIBS@

blkscan_LDADD	= ../lib/libccoin.a $(top_srcdir)/polarssl/library/libpolarssl.a \
		  @GLIB_LIBS@

blkstats_LDADD	= ../lib/libccoin.a $(top_srcdir)/polarssl/library/libpolarssl.a \
		  @GLIB_LIBS@

rawtx_LDADD	= ../lib/libccoin.a $(top_srcdir)/polarssl/library/libpolarssl.a \
		  @GLIB_LIBS@ @JANSSON_LIBS@
