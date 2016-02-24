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
#include <signal.h>
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

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

#define LUMBERJACK_USER "_lumberjack"

#define LUMBERJACK_PROTO "tcp"
#define LUMBERJACK_HOST "localhost"
#define LUMBERJACK_PORT "514"

#define LUMBERJACK_DEFAULT_LISTENER \
	(LUMBERJACK_PROTO "://[" LUMBERJACK_HOST "]:" LUMBERJACK_PORT)

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

struct syslog_protocol {
	const char *name;
	int family;
	int socktype;
};

struct syslog_uri {
	char			*_str;
	const char		*proto;
	const char		*host;
	const char		*port;
};

const struct syslog_protocol *
	syslog_name2proto(const char *);
struct syslog_uri *
	syslog_uri_parse(const char *);
void	syslog_uri_free(struct syslog_uri *);

void	syslog_listen(const char *);
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

TAILQ_HEAD(syslog_listeners, syslog_listener);
struct syslog_listeners syslog_listeners =
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
	fprintf(stderr, "usage: %s [-d] [-u user] [-l listener] [logfile]\n",
	    getprogname());
	exit(1);
}

int
main(int argc, char *argv[])
{
	const char *user = LUMBERJACK_USER;
	struct passwd *pw;
	int debug = 0;
	int ch;

	while ((ch = getopt(argc, argv, "dl:u:")) != -1) {
		switch (ch) {
		case 'l':
			syslog_listen(optarg); /* this errs on failure */
			break;
		case 'd':
			debug = 1;
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

	if (TAILQ_EMPTY(&syslog_listeners))
		syslog_listen(LUMBERJACK_DEFAULT_LISTENER);

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

	signal(SIGPIPE, SIG_IGN);

	event_init();
	syslog_events();
	event_dispatch();

	return (0);
}

const struct syslog_protocol *
syslog_name2proto(const char *name)
{
	static const struct syslog_protocol protocols[] = {
		{ "tcp",	AF_UNSPEC,	SOCK_STREAM },
		{ "tcp4",	AF_INET,	SOCK_STREAM },
		{ "tcp6",	AF_INET6,	SOCK_STREAM },
#if 0
		{ "udp",	AF_UNSPEC,	SOCK_DGRAM },
		{ "udp4",	AF_INET,	SOCK_DGRAM },
		{ "udp6",	AF_IENT6,	SOCK_DGRAM },
#endif
	};

	const struct syslog_protocol *proto;
	int i;

	for (i = 0; i < nitems(protocols); i++) {
		proto = &protocols[i];

		if (strcmp(proto->name, name) == 0)
			return (proto);
	}

	return (NULL);
}

void
syslog_listen(const char *arg)
{
	struct syslog_uri *uri;
	const struct syslog_protocol *proto;

	struct addrinfo hints, *res, *res0;
	int cerrno = EADDRNOTAVAIL;
	const char *cause = "getaddrinfo";

	int error;
	int s;
	int on = 1;

	struct syslog_listener *listener;
	struct syslog_listeners listeners = TAILQ_HEAD_INITIALIZER(listeners);

	uri = syslog_uri_parse(arg);
	if (uri == NULL)
		errx(1, "\"%s\": unable to parse", arg);

	proto = syslog_name2proto(uri->proto);
	if (proto == NULL)
		errx(1, "\"%s\": unsupported protocol \"%s\"", arg, uri->proto);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = proto->family;
	hints.ai_socktype = proto->socktype;
	hints.ai_flags = AI_PASSIVE;

	error = getaddrinfo(uri->host, uri->port, &hints, &res0);
	if (error)
		errx(1, "\"%s\": %s", arg, gai_strerror(error));

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
		TAILQ_INSERT_TAIL(&listeners, listener, entry);
	}

	if (TAILQ_EMPTY(&listeners))
		errc(1, cerrno, "%s", cause);

	freeaddrinfo(res0);
	syslog_uri_free(uri);

	while ((listener = TAILQ_FIRST(&listeners)) != NULL) {
		TAILQ_REMOVE(&listeners, listener, entry);
		TAILQ_INSERT_TAIL(&syslog_listeners, listener, entry);
	}
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

struct syslog_uri *
syslog_uri_parse(const char *in)
{
	struct syslog_uri *uri;
	char *str, *p;

	uri = malloc(sizeof(*uri));
	if (uri == NULL)
		return (NULL);

	str = strdup(in);
	if (str == NULL)
		goto err;

	uri->_str = str;
	/* defaults */
	uri->proto = LUMBERJACK_PROTO;
	uri->host = LUMBERJACK_HOST;
	uri->port = LUMBERJACK_PORT;

	p = strstr(str, "://");
	if (p != NULL) {
		uri->proto = str;

		*p = '\0';

		str = p + 3; /* + strlen("://") */
	}

	switch (*str) {
	case '\0':
		goto err;
	case '[':
		str++;
		uri->host = str;

		p = strchr(str, ']');
		if (p == NULL)
			goto err;

		*p = '\0';
		str = p + 1; /* move past the ']' */

		switch (*str) {
		case '\0':
			break;
		case ':':
			*str = '\0';
			str++;

			uri->port = str;
			break;
		default:
			goto err;
		}

		break;

	default:
		uri->host = str;

		p = strchr(str, ':');
		if (p != NULL) {
			*p = '\0';
			str = p + 1;

			uri->port = str;
		}

		break;
	}

	if (strcmp(uri->host, "*") == 0)
		uri->host = NULL;

	return (uri);

err:
	syslog_uri_free(uri);
	return (NULL);
}

void
syslog_uri_free(struct syslog_uri *uri)
{
	free(uri->_str);
	free(uri);
}
