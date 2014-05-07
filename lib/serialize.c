/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <stdint.h>
#include <string.h>
#include <glib.h>
#include <openssl/sha.h>
#include <ccoin/serialize.h>
#include <ccoin/util.h>
#include <ccoin/compat.h>

void ser_bytes(GString *s, const void *p, size_t len)
{
	g_string_append_len(s, p, len);
}

void ser_u16(GString *s, uint16_t v_)
{
	uint16_t v = GUINT16_TO_LE(v_);
	g_string_append_len(s, (gchar *) &v, sizeof(v));
}

void ser_u32(GString *s, uint32_t v_)
{
	uint32_t v = GUINT32_TO_LE(v_);
	g_string_append_len(s, (gchar *) &v, sizeof(v));
}

void ser_u64(GString *s, uint64_t v_)
{
	uint64_t v = GUINT64_TO_LE(v_);
	g_string_append_len(s, (gchar *) &v, sizeof(v));
}

void ser_varlen(GString *s, uint32_t vlen)
{
	unsigned char c;

	if (vlen < 253) {
		c = vlen;
		ser_bytes(s, &c, 1);
	}

	else if (vlen < 0x10000) {
		c = 253;
		ser_bytes(s, &c, 1);
		ser_u16(s, (uint16_t) vlen);
	}

	else {
		c = 254;
		ser_bytes(s, &c, 1);
		ser_u32(s, vlen);
	}

	/* u64 case intentionally not implemented */
}

void ser_str(GString *s, const char *s_in, size_t maxlen)
{
	size_t slen = strnlen(s_in, maxlen);

	ser_varlen(s, slen);
	ser_bytes(s, s_in, slen);
}

void ser_varstr(GString *s, GString *s_in)
{
	if (!s_in || !s_in->len) {
		ser_varlen(s, 0);
		return;
	}

	ser_varlen(s, s_in->len);
	ser_bytes(s, s_in->str, s_in->len);
}

void ser_u256_array(GString *s, GPtrArray *arr)
{
	unsigned int arr_len = arr ? arr->len : 0;

	ser_varlen(s, arr_len);

	unsigned int i;
	for (i = 0; i < arr_len; i++) {
		bu256_t *av;

		av = g_ptr_array_index(arr, i);
		ser_u256(s, av);
	}
}

bool deser_skip(struct const_buffer *buf, size_t len)
{
	if (buf->len < len)
		return false;

	buf->p += len;
	buf->len -= len;

	return true;
}

bool deser_bytes(void *po, struct const_buffer *buf, size_t len)
{
	if (buf->len < len)
		return false;

	memcpy(po, buf->p, len);
	buf->p += len;
	buf->len -= len;

	return true;
}

bool deser_u16(uint16_t *vo, struct const_buffer *buf)
{
	uint16_t v;

	if (!deser_bytes(&v, buf, sizeof(v)))
		return false;

	*vo = GUINT16_FROM_LE(v);
	return true;
}

bool deser_u32(uint32_t *vo, struct const_buffer *buf)
{
	uint32_t v;

	if (!deser_bytes(&v, buf, sizeof(v)))
		return false;

	*vo = GUINT32_FROM_LE(v);
	return true;
}

bool deser_u64(uint64_t *vo, struct const_buffer *buf)
{
	uint64_t v;

	if (!deser_bytes(&v, buf, sizeof(v)))
		return false;

	*vo = GUINT64_FROM_LE(v);
	return true;
}

bool deser_varlen(uint32_t *lo, struct const_buffer *buf)
{
	uint32_t len;

	unsigned char c;
	if (!deser_bytes(&c, buf, 1)) return false;

	if (c == 253) {
		uint16_t v16;
		if (!deser_u16(&v16, buf)) return false;
		len = v16;
	}
	else if (c == 254) {
		uint32_t v32;
		if (!deser_u32(&v32, buf)) return false;
		len = v32;
	}
	else if (c == 255) {
		uint64_t v64;
		if (!deser_u64(&v64, buf)) return false;
		len = (uint32_t) v64;	/* WARNING: truncate */
	}
	else
		len = c;

	*lo = len;
	return true;
}

bool deser_str(char *so, struct const_buffer *buf, size_t maxlen)
{
	uint32_t len;
	if (!deser_varlen(&len, buf)) return false;

	/* if input larger than buffer, truncate copy, skip remainder */
	uint32_t skip_len = 0;
	if (len > maxlen) {
		skip_len = len - maxlen;
		len = maxlen;
	}

	if (!deser_bytes(so, buf, len)) return false;
	if (!deser_skip(buf, skip_len)) return false;

	/* add C string null */
	if (len < maxlen)
		so[len] = 0;
	else
		so[maxlen - 1] = 0;

	return true;
}

bool deser_varstr(GString **so, struct const_buffer *buf)
{
	if (*so) {
		g_string_free(*so, TRUE);
		*so = NULL;
	}

	uint32_t len;
	if (!deser_varlen(&len, buf)) return false;

	if (buf->len < len)
		return false;

	GString *s = g_string_sized_new(len);
	g_string_append_len(s, buf->p, len);

	buf->p += len;
	buf->len -= len;

	*so = s;

	return true;
}

bool deser_u256_array(GPtrArray **ao, struct const_buffer *buf)
{
	GPtrArray *arr = *ao;
	if (arr) {
		g_ptr_array_free(arr, TRUE);
		*ao = arr = NULL;
	}

	uint32_t vlen;
	if (!deser_varlen(&vlen, buf)) return false;

	if (!vlen)
		return true;

	arr = g_ptr_array_new_full(vlen, g_bu256_free);
	if (!arr)
		return false;

	unsigned int i;
	for (i = 0; i < vlen; i++) {
		bu256_t *n;

		n = bu256_new(NULL);
		if (!deser_u256(n, buf)) {
			bu256_free(n);
			goto err_out;
		}

		g_ptr_array_add(arr, n);
	}

	*ao = arr;
	return true;

err_out:
	g_ptr_array_free(arr, TRUE);
	return false;
}

void u256_from_compact(mpi *vo, uint32_t c)
{
	uint32_t nbytes = (c >> 24) & 0xFF;
	uint32_t cv = c & 0xFFFFFF;

	mpi_lset(vo, cv);
	mpi_shift_l(vo, (8 * (nbytes - 3)));
}

