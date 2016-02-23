/* */

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

#ifndef SYSLOG_PARSER_H_
#define SYSLOG_PARSER_H_

#include <time.h>
#include <sys/types.h>

enum syslog_parser_state {
	S_STREAM_BEGINNING,
	S_STREAM_SIZE,

	S_PRI_BEGINNING,
	S_PRI_FIRST,
	S_PRI,

	S_TS_BEGINNING,

	S_TS_NIL_SP,

	S_TS_RFC_YY,
	S_TS_RFC_YYY,
	S_TS_RFC_YYYY,
	S_TS_RFC_YYYY_,
	S_TS_RFC_YYYY_M,
	S_TS_RFC_YYYY_MM,
	S_TS_RFC_YYYY_MM_,
	S_TS_RFC_YYYY_MM_D,
	S_TS_RFC_YYYY_MM_DD,
	S_TS_RFC_T,
	S_TS_RFC_H,
	S_TS_RFC_HH,
	S_TS_RFC_HH_,
	S_TS_RFC_HH_M,
	S_TS_RFC_HH_MM,
	S_TS_RFC_HH_MM_,
	S_TS_RFC_HH_MM_S,
	S_TS_RFC_HH_MM_SS,
	S_TS_RFC_HH_MM_SS_,
	S_TS_RFC_F,
	S_TS_RFC_FF,
	S_TS_RFC_FFF,
	S_TS_RFC_FFFF,
	S_TS_RFC_FFFFF,
	S_TS_RFC_FFFFFF,
	S_TS_RFC_FFFFFF_,

	S_TS_RFC_TZ_H,
	S_TS_RFC_TZ_HH,
	S_TS_RFC_TZ_HH_,
	S_TS_RFC_TZ_HH_M,
	S_TS_RFC_TZ_HH_MM,

	S_TS_RFC_SP,

	S_TS_BSD_Jx,
	S_TS_BSD_Jan,
	S_TS_BSD_Jux,
	S_TS_BSD_Fe,
	S_TS_BSD_Feb,
	S_TS_BSD_Ma,
	S_TS_BSD_Max,
	S_TS_BSD_Ax,
	S_TS_BSD_Apr,
	S_TS_BSD_Aug,
	S_TS_BSD_Se,
	S_TS_BSD_Sep,
	S_TS_BSD_Oc,
	S_TS_BSD_Oct,
	S_TS_BSD_No,
	S_TS_BSD_Nov,
	S_TS_BSD_De,
	S_TS_BSD_Dec,

	S_TS_BSD_MON_SP,

	S_TS_BSD_D,
	S_TS_BSD_DD,
	S_TS_BSD_DD_SP,

	S_TS_BSD_H,
	S_TS_BSD_HH,
	S_TS_BSD_HH_,
	S_TS_BSD_HH_M,
	S_TS_BSD_HH_MM,
	S_TS_BSD_HH_MM_,
	S_TS_BSD_HH_MM_S,
	S_TS_BSD_HH_MM_SS,

	S_TS_BSD_SP,

	S_MSG,
	S_MSG_ESC,

	S_END,

	S_DEAD
};

struct syslog_parser {
	void *				ctx;

	enum syslog_parser_state	state;
	unsigned int			flags;
#define SYSLOG_PARSER_TM			(1<<0) /* tm is valid */
#define SYSLOG_PARSER_TM_RFC			(1<<1) /* tm has year and tz */
#define SYSLOG_PARSER_TM_MS			(1<<2) /* tm has ms */

	struct timespec			begin_ts;

	struct tm			tm;
	unsigned int			fs;
	unsigned int			fs_width;
	int				digits;
};

struct syslog_parser_settings {
	int (*syslog_pri)(void *, int, int);
	int (*syslog_tm)(void *, const struct tm *);
	int (*syslog_msg)(void *, const char *, size_t);
	int (*syslog_end)(void *);
};

void	syslog_parser_init(struct syslog_parser *, int, void *);
ssize_t	syslog_parser_exec(struct syslog_parser *,
	    const struct syslog_parser_settings *,
	    const char *, ssize_t);
int	syslog_parser_done(struct syslog_parser *);

#endif /* SYSLOG_PARSER_H_ */
