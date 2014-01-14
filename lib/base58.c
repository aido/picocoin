/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <ctype.h>
#include <string.h>
#include <glib.h>
#include <ccoin/util.h>

static const char base58_chars[] =
	"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Encode a byte sequence as a base58-encoded string
GString *base58_encode(const void *data_, size_t data_len)
{
	const unsigned char *data = data_;
	t_uint c;
	mpi bn;

	// Convert mpi to base58 string
	// Expected size increase from base58 conversion is approximately 137%
	// use 138% to be safe
	GString *rs = g_string_sized_new(data_len * 138 / 100 + 1);

	// Convert data to mpi
        mpi_init(&bn);
	
	if (!(mpi_read_binary(&bn, data, data_len) == 0))
		goto err_out;
	
	while (mpi_cmp_int(&bn, 0) > 0) {
                if (!(mpi_mod_int(&c, &bn, 58) == 0))
                        goto err_out;
                g_string_append_c(rs, base58_chars[c]);

		if (!(mpi_div_int(&bn, NULL, &bn, 58) == 0))
			goto err_out;
	}

	// Leading zeroes encoded as base58 zeros
	unsigned int i;
	for (i = 0; i < data_len; i++) {
		if (data[i] == 0)
			g_string_append_c(rs, base58_chars[0]);
		else
			break;
	}

	// Convert little endian string to big endian
	GString *rs_swap = g_string_sized_new(rs->len);
	g_string_set_size(rs_swap, rs->len);
	bu_reverse_copy((unsigned char *) rs_swap->str,
		     (unsigned char *) rs->str, rs->len);

	g_string_free(rs, TRUE);
	rs = rs_swap;

out:
	mpi_free(&bn);

	return rs;

err_out:
	g_string_free(rs, TRUE);
	rs = NULL;
	goto out;
}

GString *base58_encode_check(unsigned char addrtype, bool have_addrtype,
			     const void *data, size_t data_len)
{
	GString *s = g_string_sized_new(data_len + 1 + 4);

	if (have_addrtype)
		g_string_append_c(s, addrtype);
	g_string_append_len(s, data, data_len);

	unsigned char md32[4];
	bu_Hash4(md32, s->str, s->len);

	g_string_append_len(s, (gchar *) md32, 4);

	GString *s_enc = base58_encode(s->str, s->len);

	g_string_free(s, TRUE);

	return s_enc;
}

// Decode a base58-encoded string
GString *base58_decode(const char *s_in)
{
	mpi bn;
	GString *ret = NULL;

	mpi_init(&bn);
	mpi_lset(&bn, 0);

	while (isspace(*s_in))
		s_in++;

	// Convert big endian string to mpi
	const char *p;
	for (p = s_in; *p; p++) {
		const char *p1 = strchr(base58_chars, *p);
		if (!p1) {
			while (isspace(*p))
				p++;
			if (*p != '\0') {
				mpi_free(&bn);
				return ret;
			}
			break;
		}
		if (!(mpi_mul_int(&bn, &bn, 58) == 0)) {
			mpi_free(&bn);
			return ret;
		}
		if (!(mpi_add_int(&bn, &bn,  p1 - base58_chars) == 0)) {
			mpi_free(&bn);
			return ret;
		}
	}

	// Get mpi as big endian data
	GString *tmp_be = g_string_sized_new(mpi_size(&bn));
	g_string_set_size(tmp_be, mpi_size(&bn));

	if (!(mpi_write_binary(&bn, (unsigned char *)tmp_be->str, mpi_size(&bn)) == 0))
		goto out;

	// Restore leading zeros
	for (p = s_in; *p == base58_chars[0]; p++)
		g_string_prepend_c(tmp_be,0);

	ret = tmp_be;

out:
        mpi_free(&bn);
        return ret;
}

GString *base58_decode_check(unsigned char *addrtype, const char *s_in)
{
	/* decode base58 string */
	GString *s = base58_decode(s_in);
	if (!s)
		return NULL;
	if (s->len < 4)
		goto err_out;

	/* validate with trailing hash, then remove hash */
	unsigned char md32[4];
	bu_Hash4(md32, s->str, s->len - 4);

	if (memcmp(md32, &s->str[s->len - 4], 4))
		goto err_out;

	g_string_set_size(s, s->len - 4);

	/* if addrtype requested, remove from front of data string */
	if (addrtype) {
		*addrtype = (unsigned char) s->str[0];
		g_string_erase(s, 0, 1);
	}

	return s;

err_out:
	g_string_free(s, TRUE);
	return NULL;
}
