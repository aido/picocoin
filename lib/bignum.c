/* Copyright 2012 exMULTI, Inc.
* Distributed under the MIT/X11 software license, see the accompanying
* file COPYING or http://www.opensource.org/licenses/mit-license.php.
*/
#include "picocoin-config.h"

#include <ccoin/util.h>

void bn_setvch(mpi *vo, const void *data_, size_t data_len)
{
	unsigned char data[data_len];

	bu_reverse_copy(data, data_, data_len);

	mpi_read_binary(vo, data, data_len);

	if (data[0] & 0x80) {
		mpi_set_bit(vo, mpi_msb(vo) - 1, 0);
		vo->s = -1;
	}
}

GString *bn_getvch(const mpi *v)
{
	/* get MPI format size */
	unsigned int sz = mpi_size(v);

	/* store MPI as string */
	GString *s = g_string_sized_new(sz);
	g_string_set_size(s, sz);

	if ((mpi_write_binary(v, (unsigned char *) s->str, sz) != 0))
		return g_string_new(NULL);

	/* check if sign bit is available */
	unsigned int msb = mpi_msb(v);
	if ((!(msb & 0x07)) && (msb > 0))
		g_string_prepend_c(s, 0x00);

	/* set sign bit */
	if (mpi_cmp_int(v, 0) < 0)
		s->str[0] = (s->str[0] & 0xff) | 0x80;

	GString *swap = g_string_sized_new(s->len);
	g_string_set_size(swap, s->len);
	bu_reverse_copy((unsigned char *) swap->str,
		     (unsigned char *) s->str, s->len);

	g_string_free(s, TRUE);
	s = swap;

	return s;
}
