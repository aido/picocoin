#ifndef __LIBCCOIN_UTIL_H__
#define __LIBCCOIN_UTIL_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <glib.h>
#include <polarssl/bignum.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

enum {
	VALSTR_SZ	= 18,
#define VALSTR_SZ VALSTR_SZ
};

extern void btc_decimal(char *valstr, size_t valstr_sz, int64_t val);
extern GString *bn_getvch(const mpi *v);
extern void bn_setvch(mpi *vo, const void *data_, size_t data_len);

extern void bu_reverse_copy(unsigned char *dst, const unsigned char *src, size_t len);
extern void bu_Hash(unsigned char *md256, const void *data, size_t data_len);
extern void bu_Hash_(unsigned char *md256,
		     const void *data1, size_t data_len1,
		     const void *data2, size_t data_len2);
extern void bu_Hash4(unsigned char *md32, const void *data, size_t data_len);
extern void bu_Hash160(unsigned char *md160, const void *data, size_t data_len);
extern bool bu_read_file(const char *filename, void **data_, size_t *data_len_,
	       size_t max_file_len);
extern bool bu_write_file(const char *filename, const void *data, size_t data_len);
extern int file_seq_open(const char *filename);

extern GList *bu_dns_lookup(GList *l, const char *seedname, unsigned int def_port);
extern GList *bu_dns_seed_addrs(void);

extern unsigned long djb2_hash(unsigned long hash, const void *_buf, size_t buflen);

extern void g_list_shuffle(GList *l);

#endif /* __LIBCCOIN_UTIL_H__ */