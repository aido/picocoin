#ifndef __LIBCCOIN_SERIALIZE_H__
#define __LIBCCOIN_SERIALIZE_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdint.h>
#include <stdbool.h>
#include <glib.h>
#include <ccoin/buffer.h>
#include <ccoin/buint.h>

extern void ser_bytes(GString *s, const void *p, size_t len);
extern void ser_u16(GString *s, uint16_t v_);
extern void ser_u32(GString *s, uint32_t v_);
extern void ser_u64(GString *s, uint64_t v_);

static inline void ser_u256(GString *s, const bu256_t *v_)
{
	ser_bytes(s, v_, sizeof(bu256_t));
}

extern void ser_varlen(GString *s, uint32_t vlen);
extern void ser_str(GString *s, const char *s_in, size_t maxlen);
extern void ser_varstr(GString *s, GString *s_in);

static inline void ser_s32(GString *s, int32_t v_)
{
	ser_u32(s, (uint32_t) v_);
}

static inline void ser_s64(GString *s, int64_t v_)
{
	ser_u64(s, (uint64_t) v_);
}

extern void ser_u256_array(GString *s, GPtrArray *arr);

extern bool deser_skip(struct const_buffer *buf, size_t len);
extern bool deser_bytes(void *po, struct const_buffer *buf, size_t len);
extern bool deser_u16(uint16_t *vo, struct const_buffer *buf);
extern bool deser_u32(uint32_t *vo, struct const_buffer *buf);
extern bool deser_u64(uint64_t *vo, struct const_buffer *buf);

static inline bool deser_u256(bu256_t *vo, struct const_buffer *buf)
{
	return deser_bytes(vo, buf, sizeof(bu256_t));
}

extern bool deser_varlen(uint32_t *lo, struct const_buffer *buf);
extern bool deser_str(char *so, struct const_buffer *buf, size_t maxlen);
extern bool deser_varstr(GString **so, struct const_buffer *buf);

static inline bool deser_s64(int64_t *vo, struct const_buffer *buf)
{
	return deser_u64((uint64_t *) vo, buf);
}

extern bool deser_u256_array(GPtrArray **ao, struct const_buffer *buf);

extern void u256_from_compact(mpi *vo, uint32_t c);

#endif /* __LIBCCOIN_SERIALIZE_H__ */
