
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

#ifndef _STRBUF_H_
#define _STRBUF_H_

struct strbuf {
	char *buf;
	size_t size;
	size_t cursor;
};

#define STRBUF_SIZE 256

int		 strbuf_ctor(struct strbuf *);
void		 strbuf_dtor(struct strbuf *);

ssize_t		 strbuf_addchar(struct strbuf *, char);
ssize_t		 strbuf_addmem(struct strbuf *, const char *, size_t);
ssize_t		 strbuf_addstr(struct strbuf *, const char *);
ssize_t		 strbuf_addmem2json(struct strbuf *, const char *, size_t);

const char	*strbuf_str(struct strbuf *);
char		*strbuf_dup(struct strbuf *);
size_t		 strbuf_len(struct strbuf *);

#endif /* _STRBUF_H_ */
