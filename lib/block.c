/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <string.h>
#include <time.h>
#include <ccoin/core.h>
#include <ccoin/util.h>
#include <ccoin/coredefs.h>
#include <ccoin/serialize.h>

static bool bp_has_dup_inputs(const struct bp_tx *tx)
{
	if (!tx->vin || !tx->vin->len || tx->vin->len == 1)
		return false;

	struct bp_txin *txin, *txin_tmp;
	unsigned int i, j;
	for (i = 0; i < tx->vin->len; i++) {
		txin = g_ptr_array_index(tx->vin, i);
		for (j = 0; j < tx->vin->len; j++) {
			if (i == j)
				continue;
			txin_tmp = g_ptr_array_index(tx->vin, j);

			if (bp_outpt_equal(&txin->prevout,
					   &txin_tmp->prevout))
				return true;
		}
	}

	return false;
}

bool bp_tx_valid(const struct bp_tx *tx)
{
	unsigned int i;

	if (!tx->vin || !tx->vin->len)
		return false;
	if (!tx->vout || !tx->vout->len)
		return false;

	if (bp_tx_ser_size(tx) > MAX_BLOCK_SIZE)
		return false;

	if (bp_tx_coinbase(tx)) {
		struct bp_txin *txin = g_ptr_array_index(tx->vin, 0);

		if (txin->scriptSig->len < 2 ||
		    txin->scriptSig->len > 100)
			return false;
	} else {
		for (i = 0; i < tx->vin->len; i++) {
			struct bp_txin *txin;

			txin = g_ptr_array_index(tx->vin, i);
			if (!bp_txin_valid(txin))
				return false;
		}
	}

	int64_t value_total = 0;
	for (i = 0; i < tx->vout->len; i++) {
		struct bp_txout *txout;

		txout = g_ptr_array_index(tx->vout, i);
		if (!bp_txout_valid(txout))
			return false;

		value_total += txout->nValue;
	}

	if (!bp_valid_value(value_total))
		return false;

	if (bp_has_dup_inputs(tx))
		return false;

	return true;
}

GArray *bp_block_merkle_tree(const struct bp_block *block)
{
	if (!block->vtx || !block->vtx->len)
		return NULL;

	GArray *arr = g_array_new(FALSE, TRUE, sizeof(bu256_t));

	unsigned int i;
	for (i = 0; i < block->vtx->len; i++) {
		struct bp_tx *tx;

		tx = g_ptr_array_index(block->vtx, i);
		bp_tx_calc_sha256(tx);

		g_array_append_val(arr, tx->sha256);
	}

	unsigned int j = 0, nSize;
	for (nSize = block->vtx->len; nSize > 1; nSize = (nSize + 1) / 2) {
		for (i = 0; i < nSize; i += 2) {
			unsigned int i2 = MIN(i+1, nSize-1);
			bu256_t hash;
			bu_Hash_((unsigned char *) &hash,
			   &g_array_index(arr, bu256_t, j+i), sizeof(bu256_t),
			   &g_array_index(arr, bu256_t, j+i2),sizeof(bu256_t));

			g_array_append_val(arr, hash);
		}

		j += nSize;
	}

	return arr;
}

void bp_block_merkle(bu256_t *vo, const struct bp_block *block)
{
	memset(vo, 0, sizeof(*vo));

	if (!block->vtx || !block->vtx->len)
		return;

	GArray *arr = bp_block_merkle_tree(block);
	if (!arr)
		return;

	*vo = g_array_index(arr, bu256_t, arr->len - 1);

	g_array_free(arr, TRUE);
}

GArray *bp_block_merkle_branch(const struct bp_block *block,
			       const GArray *mrktree,
			       unsigned int txidx)
{
	if (!block || !block->vtx || !mrktree || (txidx >= block->vtx->len))
		return NULL;

	GArray *ret = g_array_new(FALSE, TRUE, sizeof(bu256_t));

	unsigned int j = 0, nSize;
	for (nSize = block->vtx->len; nSize > 1; nSize = (nSize + 1) / 2) {
		unsigned int i = MIN(txidx ^ 1, nSize - 1);
		g_array_append_val(ret, g_array_index(mrktree, bu256_t, j+i));
		txidx >>= 1;
		j += nSize;
	}

	return ret;
}

void bp_check_merkle_branch(bu256_t *hash, const bu256_t *txhash_in,
			    const GArray *mrkbranch, unsigned int txidx)
{
	bu256_copy(hash, txhash_in);

	unsigned int i;
	for (i = 0; i < mrkbranch->len; i++) {
		const bu256_t *otherside = &g_array_index(mrkbranch, bu256_t,i);
		if (txidx & 1)
			bu_Hash_((unsigned char *)hash,
				 otherside, sizeof(bu256_t),
				 hash, sizeof(bu256_t));
		else
			bu_Hash_((unsigned char *)hash,
				 hash, sizeof(bu256_t),
				 otherside, sizeof(bu256_t));

		txidx >>= 1;
	}
}

static bool bp_block_valid_target(struct bp_block *block)
{
	mpi target, sha256;
	mpi_init(&target);
	mpi_init(&sha256);

	u256_from_compact(&target, block->nBits);
	bu256_bn(&sha256, &block->sha256);

	int cmp = mpi_cmp_mpi(&sha256, &target);

	mpi_free(&target);
	mpi_free(&sha256);

	if (cmp > 0)			/* sha256 > target */
		return false;

	return true;
}

static bool bp_block_valid_merkle(struct bp_block *block)
{
	bu256_t merkle;

	bp_block_merkle(&merkle, block);

	return bu256_equal(&merkle, &block->hashMerkleRoot);
}

bool bp_block_valid(struct bp_block *block)
{
	bp_block_calc_sha256(block);

	if (!block->vtx || !block->vtx->len)
		return false;

	if (bp_block_ser_size(block) > MAX_BLOCK_SIZE)
		return false;

	if (!bp_block_valid_target(block)) return false;

	time_t now = time(NULL);
	if (block->nTime > (now + (2 * 60 * 60)))
		return false;

	if (!bp_block_valid_merkle(block)) return false;

	unsigned int i;
	for (i = 0; i < block->vtx->len; i++) {
		struct bp_tx *tx;

		tx = g_ptr_array_index(block->vtx, i);
		if (!bp_tx_valid(tx))
			return false;

		bool is_coinbase_idx = (i == 0);
		bool is_coinbase = bp_tx_coinbase(tx);

		if (is_coinbase != is_coinbase_idx)
			return false;
	}

	return true;
}

