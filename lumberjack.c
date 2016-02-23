/*
 * Copyright (c) 2015 David Gwynne <dlg@uq.edu.au>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <ctype.h>
#include <netdb.h>
#include <pwd.h>
#include <errno.h>
#include <err.h>
#include <event.h>
#include <assert.h>

#include "syslog_parser.h"
#include "bunyan.h"
#include "strbuf.h"

#define LUMBERJACK_USER "_lumberjack"
#define LUMBERJACK_HOST "localhost"
#define LUMBERJACK_PORT "syslog"

struct syslog_listener {
	struct event ev;
	struct event pause;
	TAILQ_ENTRY(syslog_listener) entry;
	int s;
};

#define SOURCE_BUF_LEN	65536

struct syslog_source {
	struct syslog_parser	 p;
	struct event		 ev;
	char			*addr;

	void			*buf;
	size_t			 off;
	size_t			 len_io;
	size_t			 len_msg;

	int			 pri;
	int			 facility;
	struct strbuf		 msg;
};

int	syslog_pri_ev(void *, int, int);
int	syslog_tm_ev(void *, const struct tm *);
int	syslog_msg_ev(void *, const char *, size_t);
int	syslog_end_ev(void *);

const struct syslog_parser_settings lumberjack_settings = {
	syslog_pri_ev,
	syslog_tm_ev,
	syslog_msg_ev,
	syslog_end_ev
};

void	syslog_listen(int, const char *, const char *);
void	syslog_events(void);
void	syslog_paused(int, short, void *);
void	syslog_accept(int, short, void *);
void	syslog_read(int, short, void *);
ssize_t	syslog_parse(struct syslog_source *, size_t, ssize_t);
int	syslog_errmsg(struct syslog_source *);
void	syslog_close(struct syslog_source *);

int	ring_used_iov(struct iovec *, void *, size_t, size_t, size_t);
int	ring_free_iov(struct iovec *, void *, size_t, size_t, size_t);

#define sa(_ss) ((struct sockaddr *)(_ss))
char	*sockname(const struct sockaddr *, socklen_t);

__dead void usage(void);

TAILQ_HEAD(, syslog_listener) syslog_listeners =
    TAILQ_HEAD_INITIALIZER(syslog_listeners);

int	log_fd;
char	log_host[NI_MAXHOST];
pid_t	log_self;

struct loggers {
	void (*err)(int, const char *, ...);
	void (*errx)(int, const char *, ...);
	void (*warn)(const char *, ...);
	void (*warnx)(const char *, ...);
	void (*notice)(const char *, ...);
	void (*debug)(const char *, ...);
};

const struct loggers conslogger = {
	err,
	errx,
	warn,
	warnx,
	warnx, /* notice */
	warnx /* debug */
};

int		 bunyan_level(int);
const char	*bunyan_facility(int);

void    	 bunyan_err(int, const char *, ...);
void    	 bunyan_errx(int, const char *, ...);
void    	 bunyan_warn(const char *, ...);
void    	 bunyan_warnx(const char *, ...);
void    	 bunyan_notice(const char *, ...);
void    	 bunyan_debug(const char *, ...);
void    	 bunyan_vstrerror(int, int, const char *, va_list);

void		 bunyan(int, const char *, ...);
void		 vbunyan(int, const char *, va_list);
void		 _bunyan(int, const char *s, size_t);

const struct loggers bunyanlogger = {
	bunyan_err,
	bunyan_errx,
	bunyan_warn,
	bunyan_warnx,
	bunyan_notice,
	bunyan_debug
};

const struct loggers *logger = &conslogger;

#define lerr(_e, _f...) logger->err((_e), _f)
#define lerrx(_e, _f...) logger->errx((_e), _f)
#define lwarn(_f...) logger->warn(_f)
#define lwarnx(_f...) logger->warnx(_f)
#define lnotice(_f...) logger->notice(_f)
#define ldebug(_f...) logger->debug(_f)

void
hexdump(const void *d, size_t datalen);

__dead void
usage(void)
{
	fprintf(stderr, "usage: %s [-46d] [-a address] [-p port] [logfile]\n",
	    getprogname());
	exit(1);
}

int
main(int argc, char *argv[])
{
	const char *host = LUMBERJACK_HOST;
	const char *port = LUMBERJACK_PORT;
	const char *user = LUMBERJACK_USER;
	int family = PF_UNSPEC;
	struct passwd *pw;
	int debug = 0;
	int ch;

	while ((ch = getopt(argc, argv, "46Aa:dp:u:")) != -1) {
		switch (ch) {
		case '4':
			family = PF_INET;
			break;
		case '6':
			family = PF_INET6;
			break;
		case 'A':
			host = NULL;
			break;
		case 'a':
			host = optarg;
			break;
		case 'd':
			debug = 1;
			break;
		case 'p':
			port = optarg;
			break;
		case 'u':
			user = optarg;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (geteuid() != 0)
		errx(1, "need root privileges");

	if (gethostname(log_host, sizeof(log_host)) == -1)
		err(1, "unable to get host name");

	log_self = getpid();

	pw = getpwnam(user);
	if (pw == NULL)
		errx(1, "unable to find user %s", user);

	switch (argc) {
	case 0:
		log_fd = dup(STDOUT_FILENO);
		if (log_fd == -1)
			err(1, "dup(stdout)");
		break;
	case 1:
		log_fd = open(argv[0], O_WRONLY | O_APPEND | O_CREAT);
		if (log_fd == -1)
			err(1, "open(%s)", argv[0]);
		break;
	default:
		usage();
	}

	syslog_listen(family, host, port);

	if (chroot(pw->pw_dir) == -1)
		err(1, "chroot(%s)", pw->pw_dir);
	if (chdir("/") == -1)
		err(1, "chdir(%s)", pw->pw_dir);

	if (setgroups(1, &pw->pw_gid) == -1)
		err(1, "setgroups %u", pw->pw_gid);
	if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1)
		err(1, "setresgid %u", pw->pw_gid);
	if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
		err(1, "setresuid %u", pw->pw_uid);

	if (!debug && daemon(1, 0) == -1)
		err(1, "unable to daemonize");

	event_init();
	syslog_events();
	event_dispatch();

	return (0);
}

void
syslog_listen(int family, const char *host, const char *port)
{
	struct addrinfo hints, *res, *res0;
	struct syslog_listener *listener;
	int error;
	int s;
	int on = 1;

	int cerrno = EADDRNOTAVAIL;
	const char *cause = "getaddrinfo";

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	error = getaddrinfo(host, port, &hints, &res0);
	if (error) {
		errx(1, "[%s]:%s: %s", host == NULL ? "*" : host, port,
		    gai_strerror(error));
	}

	for (res = res0; res != NULL; res = res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype | SOCK_NONBLOCK,
		    res->ai_protocol);
		if (s == -1) {
			cause = "socket";
			cerrno = errno;
			continue;
		}

		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
		    &on, sizeof(on)) == -1)
			err(1, "listener setsockopt(SO_REUSEADDR)");

		if (bind(s, res->ai_addr, res->ai_addrlen) == -1) {
			cause = "bind";
			cerrno = errno;
			close(s);
			continue;
		}

		listener = malloc(sizeof(*listener));
		if (listener == NULL)
			err(1, "listener malloc");

		listener->s = s;
		TAILQ_INSERT_TAIL(&syslog_listeners, listener, entry);
	}

	if (TAILQ_EMPTY(&syslog_listeners))
		errc(1, cerrno, "%s", cause);

	freeaddrinfo(res0);
}

void
syslog_events(void)
{
	struct syslog_listener *listener;

	TAILQ_FOREACH(listener, &syslog_listeners, entry) {
		evtimer_set(&listener->pause, syslog_paused, listener);
		event_set(&listener->ev, listener->s, EV_READ | EV_PERSIST,
		    syslog_accept, listener);
		event_add(&listener->ev, NULL);
		listen(listener->s, 8);
	}
}

void
syslog_accept(int fd, short revents, void *l)
{
	static const struct timeval pause_tv = { 1, 0 };
	struct syslog_listener *listener = l;
	struct sockaddr_storage ss;
	struct syslog_source *source;
	socklen_t len;
	int s;

	len = sizeof(ss);
	s = accept4(fd, sa(&ss), &len, SOCK_NONBLOCK);
	if (s == -1) {
		switch (errno) {
		case EINTR:
		case EWOULDBLOCK:
		case ECONNABORTED:
			return;
		case EMFILE:
		case ENFILE:
			event_del(&listener->ev);
			evtimer_add(&listener->pause, &pause_tv);
			return;
		default:
			lerr(1, "accept");
		}
	}

	source = malloc(sizeof(*source));
	if (source == NULL) {
		lwarn("source alloc");
		close(s);
		return;
	}

	memset(source, 0, sizeof(*source));
	event_set(&source->ev, s, EV_READ | EV_PERSIST, syslog_read, source);
	source->buf = malloc(SOURCE_BUF_LEN);
	if (source->buf == NULL) {
		lwarn("source buffer allocation");
		goto close;
	}
	source->addr = sockname(sa(&ss), len);
	if (source->addr == NULL)
		goto close;
	if (strbuf_ctor(&source->msg) == -1) {
		lwarn("accept: strbuf");
		goto close;
	}
	syslog_parser_init(&source->p, 1, source);

	event_add(&source->ev, NULL);
	return;

close:
	syslog_close(source);
}

int
ring_free_iov(struct iovec *iov, void *ring, size_t size,
    size_t off, size_t len)
{
	char *end, *buf;
	size_t space = size - len;

	end = ring;
	end += size;

	buf = ring;
	buf += off + len;
	if (buf >= end)
		buf -= size;

	iov[0].iov_base = buf;
	if (buf + space <= end) {
		iov[0].iov_len = space;

		return (1);
	} else {
		iov[0].iov_len = end - buf;
		iov[1].iov_base = ring;
		iov[1].iov_len = space - iov[0].iov_len;

		return (2);
	}
}

int
ring_used_iov(struct iovec *iov, void *ring, size_t size,
    size_t off, size_t len)
{
	char *end, *buf;

	end = ring;
	end += size;
	buf = ring;
	buf += off;

	iov[0].iov_base = buf;
	if (buf + len <= end) {
		iov[0].iov_len = len;

		return (1);
	} else {
		iov[0].iov_len = end - buf;
		iov[1].iov_base = ring;
		iov[1].iov_len = len - iov[0].iov_len;

		return (2);
	}
}

void
syslog_read(int fd, short revents, void *s)
{
	struct syslog_source *source = s;
	struct iovec iov[2];
	int iovcnt;
	size_t b;
	ssize_t n, m;

	iovcnt = ring_free_iov(iov, source->buf, SOURCE_BUF_LEN,
	    source->off, source->len_io);
	n = readv(fd, iov, iovcnt);
	switch (n) {
	case -1:
		switch (errno) {
		case EINTR:
		case EAGAIN:
			return;

		case ECONNRESET:
			break;
		default:
			lwarn("syslog %s read", source->addr);
			break;
		}
		/* FALLTHROUGH */
	case 0:
		syslog_close(source);
		return;
	default:
		source->len_io += n;
		break;
	}

	b = (char *)iov[0].iov_base - (char *)source->buf;

	while ((m = syslog_parse(source, b, n)) != 0) {
		if (m == -1)
			return;

		b += m;
		if (b >= SOURCE_BUF_LEN)
			b -= SOURCE_BUF_LEN;

		n -= m;
		assert(n <= SOURCE_BUF_LEN);
	}

	if (source->len_msg == SOURCE_BUF_LEN) {
		lwarnx("%s: message too large, closing");
		syslog_close(source);
	}
}

ssize_t
syslog_parse(struct syslog_source *source, size_t base, ssize_t len)
{
	struct iovec iov[2];
	int iovcnt, i;
	ssize_t n, l = 0;

	if (len == 0)
		return (0);

	iovcnt = ring_used_iov(iov, source->buf, SOURCE_BUF_LEN,
	    base, len);
	for (i = 0; i < iovcnt; i++) {
		n = syslog_parser_exec(&source->p, &lumberjack_settings,
		    iov[i].iov_base, iov[i].iov_len);
		if (n == -1)
			return (syslog_errmsg(source));

		source->len_msg += n;
		l += n;

		if (syslog_parser_done(&source->p)) {
			syslog_parser_init(&source->p, 1, source);
			strbuf_ctor(&source->msg);

			source->len_io -= source->len_msg;
			source->off += source->len_msg;
			if (source->off >= SOURCE_BUF_LEN)
				source->off -= SOURCE_BUF_LEN;

			source->len_msg = 0;
			return (l);
		}
	}

	return (0);
}

int
syslog_errmsg(struct syslog_source *source)
{
	lwarnx("%s: error parsing syslog message (state %d), closing",
	    source->addr, source->p.state);
	syslog_close(source);
	return (-1);
}

int
bunyan_level(int pri)
{
	switch (pri) {
	case LOG_EMERG:
		return (BUNYAN_LOG_FATAL + 5);
	case LOG_ALERT:
		return (BUNYAN_LOG_FATAL+1);
	case LOG_CRIT:
		return (BUNYAN_LOG_FATAL);
	case LOG_ERR:
		return (BUNYAN_LOG_ERROR);
	case LOG_WARNING:
		return (BUNYAN_LOG_WARN);
	case LOG_NOTICE:
		return (BUNYAN_LOG_INFO+5);
	case LOG_INFO:
		return (BUNYAN_LOG_INFO);
	case LOG_DEBUG:
		return (BUNYAN_LOG_DEBUG);

	default:
		return (0);
	}
}

const char *
bunyan_facility(int facility)
{
	static char unknown[16];
	int rv;

	switch (facility) {
	case LOG_FAC(LOG_KERN):
		return ("kern");
	case LOG_FAC(LOG_USER):
		return ("user");
	case LOG_FAC(LOG_MAIL):
		return ("mail");
	case LOG_FAC(LOG_DAEMON):
		return ("daemon");
	case LOG_FAC(LOG_AUTH):
		return ("auth");
	case LOG_FAC(LOG_SYSLOG):
		return ("syslog");
	case LOG_FAC(LOG_LPR):
		return ("lpr");
	case LOG_FAC(LOG_NEWS):
		return ("news");
	case LOG_FAC(LOG_UUCP):
		return ("uucp");
	case LOG_FAC(LOG_CRON):
		return ("cron");
	case LOG_FAC(LOG_AUTHPRIV):
		return ("authpriv");
	case LOG_FAC(LOG_FTP):
		return ("ftp");

	case LOG_FAC(LOG_LOCAL0):
		return ("local0");
	case LOG_FAC(LOG_LOCAL1):
		return ("local1");
	case LOG_FAC(LOG_LOCAL2):
		return ("local2");
	case LOG_FAC(LOG_LOCAL3):
		return ("local3");
	case LOG_FAC(LOG_LOCAL4):
		return ("local4");
	case LOG_FAC(LOG_LOCAL5):
		return ("local5");
	case LOG_FAC(LOG_LOCAL6):
		return ("local6");
	case LOG_FAC(LOG_LOCAL7):
		return ("local7");

	default:
		rv = snprintf(unknown, sizeof(unknown), "%d", facility);
		if (rv == -1 || rv >= sizeof(unknown))
			return ("(unknown)");

		return (unknown);
	}
}

void
syslog_close(struct syslog_source *source)
{
	event_del(&source->ev);
	free(source->addr);
	free(source->buf);
	close(EVENT_FD(&source->ev));
	free(source);
}

void
syslog_paused(int fd, short events, void *l)
{
	struct syslog_listener *listener = l;

	event_add(&listener->ev, NULL);
}

char *
sockname(const struct sockaddr *sa, socklen_t len)
{
	char host[NI_MAXHOST];
	char port[NI_MAXHOST];
	char *name;
	int error;

	error = getnameinfo(sa, len, host, sizeof(host), port, sizeof(port),
	    NI_NUMERICHOST | NI_NUMERICSERV);
	if (error != 0) {
		lwarnx("sockname: %s", gai_strerror(error));
		return (NULL);
	}

	if (asprintf(&name, "[%s]:%s", host, port) == -1) {
		lwarn("sockname: print");
		return (NULL);
	}

	return (name);
}

int
syslog_pri_ev(void *ctx, int pri, int facility)
{
	struct syslog_source *source = ctx;

	source->pri = pri;
	source->facility = facility;

	return (0);
}

int
syslog_tm_ev(void *ctx, const struct tm *tm)
{
	return (0); /* XXX */
}

int
syslog_msg_ev(void *ctx, const char *msg, size_t len)
{
	struct syslog_source *source = ctx;

	return (strbuf_addmem2json(&source->msg, msg, len));
}

int
syslog_end_ev(void *ctx)
{
	struct syslog_source *source = ctx;
	char when[64], whenrx[64], *w = when;
	struct tm t, *tp;
	int rv;
	size_t off;

	if (gmtime_r(&source->p.begin_ts.tv_sec, &t) == NULL)
		exit(1);

	rv = snprintf(whenrx, sizeof(whenrx),
	    "%04u-%02u-%02uT%02u:%02u:%02u.%03ldZ",
	    t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
	    t.tm_hour, t.tm_min, t.tm_sec,
	    source->p.begin_ts.tv_nsec / 1000000);
	if (rv == -1 || rv >= sizeof(whenrx))
		exit(1);

	if (source->p.flags & SYSLOG_PARSER_TM) {
		tp = &source->p.tm;

		if (!(source->p.flags & SYSLOG_PARSER_TM_RFC)) {
			if (localtime_r(&source->p.begin_ts.tv_sec, &t) == NULL)
				exit(1);

			/* borrow year/tz from rx time */
			tp->tm_year = t.tm_year;
			tp->tm_gmtoff = t.tm_gmtoff;
		}

		rv = snprintf(when, sizeof(when), 
		    "%04u-%02u-%02uT%02u:%02u:%02u",
		    t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
		    t.tm_hour, t.tm_min, t.tm_sec);
		if (rv == -1)
			exit(1);

		off = rv;

		if (source->p.fs_width) {
			rv = snprintf(when + off, sizeof(when) - off,
			    ".%0*u", source->p.fs_width, source->p.fs);
			if (rv == -1)
				exit(1);

			off += rv;
		}

		if (tp->tm_gmtoff == 0)
			rv = snprintf(when + off, sizeof(when) - off, "Z");
		else {
			rv = snprintf(when + off, sizeof(when) - off,
			    "%c%02lu:%02lu", tp->tm_gmtoff < 0 ? '-' : '+',
			    labs(tp->tm_gmtoff) / 3600,
			    (labs(tp->tm_gmtoff) / 60) % 60);
		}
		if (rv == -1)
			exit(1);
	} else
		w = whenrx;

	if (flock(log_fd, LOCK_EX) == -1)
		exit(1);
	if (dprintf(log_fd, "{"
	    "\"v\":%u,"
	    "\"level\":%u,"
	    "\"name\":\"%s\","
	    "\"hostname\":\"%s\","
	    "\"pid\":%d,"
	    "\"time\":\"%s\","
	    "\"msg\":\"%s\","
	    "\"facility\":\"%s\","
	    "\"_\":[{\"src\":\"%s\",\"dst\":\"%s\",\"time\":\"%s\"}]"
	"}\n", BUNYAN_VERSION, bunyan_level(source->pri), "syslog", log_host,
	    0, w, strbuf_str(&source->msg), bunyan_facility(source->facility),
	    source->addr, log_host, whenrx) == -1)
		exit(1);
	if (flock(log_fd, LOCK_UN) == -1)
		exit(1);

	strbuf_dtor(&source->msg);

	return (0);
}

void
bunyan_vstrerror(int e, int priority, const char *fmt, va_list ap)
{
	char *s;

	if (vasprintf(&s, fmt, ap) == -1)
		return;

	bunyan(priority, "%s: %s", s, strerror(e));
	free(s);
}

void
bunyan_err(int ecode, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	bunyan_vstrerror(errno, BUNYAN_LOG_ERROR, fmt, ap);
	va_end(ap);
	exit(ecode);
}

void
bunyan_errx(int ecode, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vbunyan(BUNYAN_LOG_ERROR, fmt, ap);
	va_end(ap);
	exit(ecode);
}

void
bunyan_warn(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	bunyan_vstrerror(errno, BUNYAN_LOG_WARN, fmt, ap);
	va_end(ap);
}

void
bunyan_warnx(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vbunyan(BUNYAN_LOG_WARN, fmt, ap);
	va_end(ap);
}

void
bunyan_notice(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vbunyan(BUNYAN_LOG_INFO, fmt, ap);
	va_end(ap);
}

void
bunyan_debug(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vbunyan(BUNYAN_LOG_DEBUG, fmt, ap);
	va_end(ap);
}

void
bunyan(int level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vbunyan(level, fmt, ap);
	va_end(ap);
}

void
vbunyan(int level, const char *fmt, va_list ap)
{
	char *s;
	int len;

	len = vasprintf(&s, fmt, ap);
	if (len == -1)
		return; /* ugh */

	_bunyan(level, s, len);

	free(s);
}

void
_bunyan(int level, const char *s, size_t slen)
{
	extern char *__progname;
	char when[128];
	struct strbuf sb;
	struct timespec tv;
	struct tm tm;

	if (strbuf_ctor(&sb) == -1)
		return;

	if (strbuf_addmem2json(&sb, s, slen) == -1)
		goto dtor;

	if (clock_gettime(CLOCK_REALTIME, &tv) == -1)
		exit(1);
	if (gmtime_r(&tv.tv_sec, &tm) == NULL)
		exit(1);

	if (snprintf(when, sizeof(when),
	    "%04u-%02u-%02uT%02u:%02u:%02u.%03luZ",
	    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
	    tm.tm_hour, tm.tm_min, tm.tm_sec,
	    tv.tv_nsec / 1000000) == -1)
		goto dtor;

	if (flock(log_fd, LOCK_EX) == -1)
		exit(1);
	if (dprintf(log_fd, "{"
	    "\"v\":%u,"
	    "\"level\":%u,"
	    "\"name\":\"%s\","
	    "\"hostname\":\"%s\","
	    "\"pid\":%d,"
	    "\"time\":\"%s\","
	    "\"msg\":\"%s\""
	"}\n", BUNYAN_VERSION, level, __progname, log_host, log_self,
	    when, strbuf_str(&sb)) == -1)
		exit(1);
	if (flock(log_fd, LOCK_UN) == -1)
		exit(1);

dtor:
	strbuf_dtor(&sb);
}

void
hexdump(const void *d, size_t datalen)
{
	const u_int8_t *data = d;
	int i, j = 0;

	for (i = 0; i < datalen; i += j) {
		printf("% 4d: ", i);
		for (j = 0; j < 16 && i+j < datalen; j++)
			printf("%02x ", data[i + j]);
		while (j++ < 16)
			printf("   ");
		printf("|");
		for (j = 0; j < 16 && i+j < datalen; j++)
			putchar(isprint(data[i + j]) ? data[i + j] : '.');
		printf("|\n");
	}
}

