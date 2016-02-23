
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

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "strbuf.h"

static int	strbuf_grow(struct strbuf *, size_t);

int
strbuf_ctor(struct strbuf *sb)
{
	sb->buf = malloc(STRBUF_SIZE);
	if (sb->buf == NULL)
		return (-1);

	sb->size = STRBUF_SIZE - 1;
	sb->cursor = 0;

	return (0);
}

static int
strbuf_grow(struct strbuf *sb, size_t min)
{
	char *buf;
	size_t space;

	space = sb->size - sb->cursor;
	if (space > min)
		return (0);

	min -= space;
	if (min < STRBUF_SIZE)
		min = STRBUF_SIZE;

	buf = realloc(sb->buf, sb->size + min + 1);
	if (buf == NULL)
		return (-1);

	sb->buf = buf;
	sb->size += min;

	return (0);
}

void
strbuf_dtor(struct strbuf *sb)
{
	free(sb->buf);
}

const char *
strbuf_str(struct strbuf *sb)
{
	sb->buf[sb->cursor] = '\0';

	return (sb->buf);
}

char *
strbuf_dup(struct strbuf *sb)
{
	char *str;

	str = malloc(sb->cursor + 1);
	if (str == NULL)
		return (NULL);

	memcpy(str, sb->buf, sb->cursor);
	str[sb->cursor] = '\0';

	return (str);
}

ssize_t
strbuf_addchar(struct strbuf *sb, char ch)
{
	if (sb->cursor == sb->size && strbuf_grow(sb, 1) == -1)
		return (-1);

	sb->buf[sb->cursor++] = ch;

	return (sb->cursor);
}

ssize_t
strbuf_addmem(struct strbuf *sb, const char *mem, size_t l)
{
	if (sb->cursor + l >= sb->size && strbuf_grow(sb, l) == -1)
		return (-1);

	memcpy(sb->buf + sb->cursor, mem, l);
	sb->cursor += l;

	return (sb->cursor);
}

ssize_t
strbuf_addstr(struct strbuf *sb, const char *str)
{
	return (strbuf_addmem(sb, str, strlen(str)));
}

ssize_t
strbuf_addmem2json(struct strbuf *sb, const char *mem, size_t l)
{
	const char *end = mem + l;
	const char *p;
	int rv;

	for (p = mem; p < end; p++) {
		switch (*p) {
		case '\b':
			rv = strbuf_addmem(sb, "\\b", 2);
			break;
		case '\t':
			rv = strbuf_addmem(sb, "\\t", 2);
			break;
		case '\n':
			rv = strbuf_addmem(sb, "\\n", 2);
			break;
		case '\f':
			rv = strbuf_addmem(sb, "\\f", 2);
			break;
		case '\r':
			rv = strbuf_addmem(sb, "\\r", 2);
			break;
		case '\"':
			rv = strbuf_addmem(sb, "\\\"", 2);
			break;
		case '/':
			rv = strbuf_addmem(sb, "\\/", 2);
			break;
		case '\\':
			rv = strbuf_addmem(sb, "\\\\", 2);
			break;
		default:
			rv = isprint((int)*p) ? strbuf_addchar(sb, *p) : -1;
			break;
		}

		if (rv == -1)
			return (-1);
	}

	return (0);
}
