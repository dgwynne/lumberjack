
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

#include <string.h>
#include <ctype.h>
#include <syslog.h>

#include "syslog_parser.h"

void
syslog_parser_init(struct syslog_parser *parser, int stream, void *ctx)
{
	memset(parser, 0, sizeof(*parser));
	
	parser->state = stream ? S_STREAM_BEGINNING : S_PRI_BEGINNING;
	parser->ctx = ctx;
}

static inline int
syslog_parser_pri(const struct syslog_parser_settings *settings, void *ctx,
    int pri)
{
	return (*settings->syslog_pri)(ctx, LOG_PRI(pri), LOG_FAC(pri));
}

static inline int
syslog_parser_tm(const struct syslog_parser_settings *settings, void *ctx,
    const struct tm *tm)
{
	return (*settings->syslog_tm)(ctx, tm);
}

static inline int
syslog_parser_msg(const struct syslog_parser_settings *settings, void *ctx,
    const char *buf, size_t len)
{
	return (*settings->syslog_msg)(ctx, buf, len);
}

static inline int
syslog_parser_end(const struct syslog_parser_settings *settings, void *ctx)
{
	return (*settings->syslog_end)(ctx);
}

static inline enum syslog_parser_state
syslog_parser_run(struct syslog_parser *parser,
    const struct syslog_parser_settings *settings, int ch)
{
	enum syslog_parser_state s = parser->state;
	const char *esc;

	switch (s) {
	case S_STREAM_SIZE:
		if (ch == ' ')
			return (S_PRI_BEGINNING);

		if (!isdigit(ch))
			return (S_DEAD);

		parser->digits *= 10;
		parser->digits += ch - '0';

		return (s);

	case S_STREAM_BEGINNING:
		if (isdigit(ch)) {
			parser->digits = ch - '0';
			return (S_STREAM_SIZE);
		}

		/* FALLTHROUGH */
	case S_PRI_BEGINNING:
		if (ch != '<')
			return (S_DEAD);

		if (clock_gettime(CLOCK_REALTIME, &parser->begin_ts) == -1)
			return (S_DEAD);

		parser->digits = 0;
		return (S_PRI_FIRST);

	case S_PRI:
		if (ch == '>') {
			if (syslog_parser_pri(settings, parser->ctx,
			    parser->digits) != 0)
				return (S_DEAD);

			return (S_TS_BEGINNING);
		}

		if (parser->digits & ~(LOG_FACMASK | LOG_PRIMASK))
			return (S_DEAD);

		/* FALLTHROUGH */
	case S_PRI_FIRST:
		if (!isdigit(ch))
			return (S_DEAD);

		parser->digits *= 10;
		parser->digits += ch - '0';

		return (S_PRI);

	case S_TS_BEGINNING:
		if (ch == '-') {
			/* NIL timestamp */
			return (S_TS_NIL_SP);
		}

		parser->flags |= SYSLOG_PARSER_TM;

		if (isdigit(ch)) {
			parser->flags |= SYSLOG_PARSER_TM_RFC;
			parser->digits = ch - '0';
			return (S_TS_RFC_YY);
		}

		switch (ch) {
		case 'J':
			return (S_TS_BSD_Jx);
		case 'F':
			return (S_TS_BSD_Fe);
		case 'M':
			return (S_TS_BSD_Ma);
		case 'A':
			return (S_TS_BSD_Ax);
		case 'S':
			return (S_TS_BSD_Se);
		case 'O':
			return (S_TS_BSD_Oc);
		case 'N':
			return (S_TS_BSD_No);
		case 'D':
			return (S_TS_BSD_De);
		}

		return (S_DEAD);

	case S_TS_RFC_YY:
	case S_TS_RFC_YYY:
	case S_TS_RFC_YYYY:
	case S_TS_RFC_YYYY_M:
	case S_TS_RFC_YYYY_MM:
	case S_TS_RFC_YYYY_MM_D:
	case S_TS_RFC_YYYY_MM_DD:
	case S_TS_RFC_H:
	case S_TS_RFC_HH:
	case S_TS_RFC_HH_M:
	case S_TS_RFC_HH_MM:
	case S_TS_RFC_HH_MM_S:
	case S_TS_RFC_HH_MM_SS:
	case S_TS_RFC_F:
	case S_TS_BSD_DD:
	case S_TS_BSD_H:
	case S_TS_BSD_HH:
	case S_TS_BSD_HH_M:
	case S_TS_BSD_HH_MM:
	case S_TS_BSD_HH_MM_S:
	case S_TS_BSD_HH_MM_SS:
		if (!isdigit(ch))
			return (S_DEAD);

		parser->digits *= 10;
		parser->digits += ch - '0';
		return (s + 1);

	case S_TS_RFC_YYYY_:
		if (ch != '-')
			return (S_DEAD);

		if (parser->digits < 1900)
			return (S_DEAD);

		parser->tm.tm_year = parser->digits - 1900;
		parser->digits = 0;

		return (S_TS_RFC_YYYY_M);

	case S_TS_RFC_YYYY_MM_:
		if (ch != '-')
			return (S_DEAD);

		if (parser->digits > 12 || parser->digits < 1)
			return (S_DEAD);

		parser->tm.tm_mon = parser->digits - 1;
		parser->digits = 0;

		return (S_TS_RFC_YYYY_MM_D);

	case S_TS_RFC_T:
		if (ch != 'T')
			return (S_DEAD);

		if (parser->digits > 31 || parser->digits < 1)
			return (S_DEAD);

		parser->tm.tm_mday = parser->digits;
		parser->digits = 0;

		return (S_TS_RFC_H);

	case S_TS_RFC_HH_:
	case S_TS_BSD_HH_:
		if (ch != ':')
			return (S_DEAD);

		if (parser->digits > 23)
			return (S_DEAD);

		parser->tm.tm_hour = parser->digits;
		parser->digits = 0;

		return (s + 1);

	case S_TS_RFC_HH_MM_:
	case S_TS_BSD_HH_MM_:
		if (ch != ':')
			return (S_DEAD);

		if (parser->digits > 59)
			return (S_DEAD);

		parser->tm.tm_min = parser->digits;
		parser->digits = 0;

		return (s + 1);

	case S_TS_RFC_HH_MM_SS_:
		if (parser->digits > 60)
			return (S_DEAD);

		parser->tm.tm_sec = parser->digits;
		parser->digits = 0;

		switch (ch) {
		case '.':
			parser->fs_width = 1;
			return (S_TS_RFC_F);
		case 'Z':
			return (S_TS_RFC_SP);
		case '-':
			parser->tm.tm_gmtoff = -1;
			return (S_TS_RFC_TZ_H);
		case '+':
			parser->tm.tm_gmtoff = 1;
			return (S_TS_RFC_TZ_H);
		}

		return (S_DEAD);

	case S_TS_RFC_FF:
	case S_TS_RFC_FFF:
	case S_TS_RFC_FFFF:
	case S_TS_RFC_FFFFF:
	case S_TS_RFC_FFFFFF:
		if (isdigit(ch)) {
			parser->digits *= 10;
			parser->digits += ch - '0';
			parser->fs_width++;
			return (s + 1);
		}

		/* FALLTHROUGH */
	case S_TS_RFC_FFFFFF_:
		parser->fs = parser->digits;

		switch (ch) {
		case 'Z':
			return (S_TS_RFC_SP);
		case '-':
			parser->tm.tm_gmtoff = -1;
			return (S_TS_RFC_TZ_H);
		case '+':
			parser->tm.tm_gmtoff = 1;
			return (S_TS_RFC_TZ_H);
		}

		return (S_DEAD);

	case S_TS_RFC_TZ_H:
		if (!isdigit(ch))
			return (S_DEAD);

		parser->digits += (ch - '0') * 10 * 3600;
		return (S_TS_RFC_TZ_HH);
	case S_TS_RFC_TZ_HH:
		if (!isdigit(ch))
			return (S_DEAD);

		parser->digits += (ch - '0') * 3600;
		return (S_TS_RFC_TZ_HH);
	case S_TS_RFC_TZ_HH_:
		if (ch != ':')
			return (S_DEAD);
		return (S_TS_RFC_TZ_HH_M);
	case S_TS_RFC_TZ_HH_M:
		if (!isdigit(ch))
			return (S_DEAD);

		parser->digits += (ch - '0') * 10 * 60;
		return (S_TS_RFC_TZ_HH_M);
	case S_TS_RFC_TZ_HH_MM:
		if (!isdigit(ch))
			return (S_DEAD);

		parser->digits += (ch - '0') * 60;

		parser->tm.tm_gmtoff *= parser->digits;
		return (S_TS_RFC_SP);

	case S_TS_BSD_Jx:
		switch (ch) {
		case 'a':
			return (S_TS_BSD_Jan);
		case 'u':
			return (S_TS_BSD_Jux);
		}

		return (S_DEAD);

	case S_TS_BSD_Fe:
		if (ch == 'e')
			return (S_TS_BSD_Feb);

		return (S_DEAD);

	case S_TS_BSD_Ma:
		if (ch == 'a')
			return (S_TS_BSD_Max);

		return (S_DEAD);

	case S_TS_BSD_Ax:
		switch (ch) {
		case 'p':
			return (S_TS_BSD_Apr);
		case 'u':
			return (S_TS_BSD_Aug);
		}

		return (S_DEAD);

	case S_TS_BSD_Se:
		if (ch == 'e')
			return (S_TS_BSD_Apr);

		return (S_DEAD);

	case S_TS_BSD_Oc:
		if (ch == 'c')
			return (S_TS_BSD_Oct);

		return (S_DEAD);

	case S_TS_BSD_No:
		if (ch == 'o')
			return (S_TS_BSD_Nov);

		return (S_DEAD);

	case S_TS_BSD_De:
		if (ch == 'e')
			return (S_TS_BSD_Dec);

		return (S_DEAD);

	case S_TS_BSD_Jan:
		if (ch == 'n') {
			parser->tm.tm_mon = 0;
			return (S_TS_BSD_MON_SP);
		}

		return (S_DEAD);

	case S_TS_BSD_Feb:
		if (ch == 'b') {
			parser->tm.tm_mon = 1;
			return (S_TS_BSD_MON_SP);
		}

		return (S_DEAD);

	case S_TS_BSD_Max:
		switch (ch) {
		case 'r':
			parser->tm.tm_mon = 2;
			return (S_TS_BSD_MON_SP);
		case 'y':
			parser->tm.tm_mon = 4;
			return (S_TS_BSD_MON_SP);
		}

		return (S_DEAD);

	case S_TS_BSD_Apr:
		if (ch == 'r') {
			parser->tm.tm_mon = 3;
			return (S_TS_BSD_MON_SP);
		}

		return (S_DEAD);

	case S_TS_BSD_Jux:
		switch (ch) {
		case 'n':
			parser->tm.tm_mon = 5;
			return (S_TS_BSD_MON_SP);
		case 'l':
			parser->tm.tm_mon = 6;
			return (S_TS_BSD_MON_SP);
		}

		return (S_DEAD);

	case S_TS_BSD_Aug:
		if (ch == 'g') {
			parser->tm.tm_mon = 7;
			return (S_TS_BSD_MON_SP);
		}

		return (S_DEAD);

	case S_TS_BSD_Sep:
		if (ch == 'p') {
			parser->tm.tm_mon = 8;
			return (S_TS_BSD_MON_SP);
		}

		return (S_DEAD);

	case S_TS_BSD_Oct:
		if (ch == 't') {
			parser->tm.tm_mon = 9;
			return (S_TS_BSD_MON_SP);
		}

		return (S_DEAD);

	case S_TS_BSD_Nov:
		if (ch == 'v') {
			parser->tm.tm_mon = 10;
			return (S_TS_BSD_MON_SP);
		}

		return (S_DEAD);

	case S_TS_BSD_Dec:
		if (ch == 'c') {
			parser->tm.tm_mon = 11;
			return (S_TS_BSD_MON_SP);
		}

		return (S_DEAD);

	case S_TS_BSD_MON_SP:
		if (ch != ' ')
			return (S_DEAD);

		return (S_TS_BSD_D);

	case S_TS_BSD_D:
		switch (ch) {
		case ' ':
			parser->digits = 0;
			break;
		case '1':
		case '2':
		case '3':
			parser->digits = ch - '0';
			break;
		default:
			return (S_DEAD);
		}

		return (S_TS_BSD_DD);

	case S_TS_BSD_DD_SP:
		if (ch != ' ')
			return (S_DEAD);

		if (parser->digits > 31 || parser->digits < 1)
			return (S_DEAD);

		parser->tm.tm_mday = parser->digits;
		parser->digits = 0;

		return (S_TS_BSD_H);

	case S_TS_BSD_SP:
		if (parser->digits > 61)
			return (S_DEAD);

		parser->tm.tm_sec = parser->digits;
		parser->digits = 0;

		/* FALLTHROUGH */
	case S_TS_RFC_SP:
		if (ch != ' ')
			return (S_DEAD);

		if (syslog_parser_tm(settings, parser->ctx, &parser->tm) != 0)
			return (S_DEAD);

		return (S_MSG);
	case S_TS_NIL_SP:
		if (ch != ' ')
			return (S_DEAD);

		if (syslog_parser_tm(settings, parser->ctx, NULL) != 0)
			return (S_DEAD);

		return (S_MSG);

	case S_MSG:
		switch (ch) {
		case '\\':
			return (S_MSG_ESC);
		case '\n':
			return (S_END);
		}
		return (s);

	case S_MSG_ESC:
		switch (ch) {
		case '\\':
			esc = "\\";
			break;
		case '\n':
			esc = "\n";
			break;
		default:
			return (S_DEAD);
		}

		if (syslog_parser_msg(settings, parser->ctx, esc, 1) != 0)
			return (S_DEAD);

		return (S_MSG);

	case S_DEAD:
	case S_END:
		return (S_DEAD);
	}

	return (S_DEAD);
}

ssize_t
syslog_parser_exec(struct syslog_parser *parser,
    const struct syslog_parser_settings *settings,
    const char *buf, ssize_t len)
{
	enum syslog_parser_state s = S_DEAD;
	const char *cur, *msg = buf;
	const char *end = buf + len;

	if (len == 0) { /* eof */
		switch (parser->state) {
		case S_PRI_BEGINNING:
			return (0);
		case S_MSG:
			parser->state = S_END;
			if (syslog_parser_end(settings, parser->ctx) != 0)
				return (-1);
			return (0);
		default:
			return (-1);
		}
	}

	cur = buf;
	do {
		s = syslog_parser_run(parser, settings, *cur);
		switch (s) {
		case S_DEAD:
			return (-1);
		case S_MSG_ESC:
		case S_END:
			if (cur != msg) {
				if (syslog_parser_msg(settings, parser->ctx,
				    msg, cur - msg) != 0)
					return (-1);
			}
			break;
		default:
			break;
		}

		cur++;

		if (s == S_MSG && parser->state != S_MSG)
			msg = cur;

		parser->state = s;

		if (s == S_END) {
			if (syslog_parser_end(settings, parser->ctx) != 0)
				return (-1);
			break;
		}
	} while (cur < end);

	if (s == S_MSG && cur != msg) {
		if (syslog_parser_msg(settings, parser->ctx,
		    msg, cur - msg) != 0)
			return (-1);
	}

	return (cur - buf);
}

int
syslog_parser_done(struct syslog_parser *parser)
{
	return (parser->state == S_END);
}
