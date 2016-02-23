#

CFLAGS+=-Wall -Wmissing-prototypes -Wshadow -Werror

LDADD+=	-levent
DPADD+=	${LIBEVENT}

PROG=	lumberjack
SRCS=	lumberjack.c syslog_parser.c strbuf.c
MAN=	

.include <bsd.prog.mk>
