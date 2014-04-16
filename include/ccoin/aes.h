#ifndef __LIBCCOIN_AES_H__
#define __LIBCCOIN_AES_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdbool.h>
#include <glib.h>

extern GString *read_aes_file(const char *filename, void *key, size_t key_len);

extern bool write_aes_file(const char *filename, void *key, size_t key_len,
		    const void *plaintext, size_t pt_len);

#endif /* __LIBCCOIN_AES_H__ */